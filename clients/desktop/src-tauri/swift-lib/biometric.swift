// Touch ID unlock — native Keychain + biometric helper.
//
// Design: docs/desktop-touch-id.md. A random 32-byte *unlock key* is stored
// in a Secure-Enclave-gated Keychain item (.biometryCurrentSet, this device
// only); it AES-256-GCM-wraps the caller's master key, and the wrapped blob
// is stored in a second (non-biometric, this-device-only) Keychain item.
// Touch ID releases the unlock key → we decrypt the blob → return the master
// key. The macOS login password is never an unlock path (no device-passcode
// fallback in the access-control flags).
//
// All queries set `kSecUseDataProtectionKeychain: true`: on macOS,
// `kSecAttrAccessControl` (biometric ACLs) is only honored by the data
// protection keychain, not the default file keychain. Items added with that
// flag must also be read/deleted with it, so it's set on every call.
//
// Exposed to Rust as a C ABI (`@_cdecl`); strings cross as NUL-terminated
// C strings. `hekate_bio_unlock` returns a malloc'd string the caller must
// release with `hekate_bio_free`. `hekate_bio_enable` returns an OSStatus
// (0 = success) so the Rust side can surface the real failure code.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let serviceUnlockKey = "com.synapticcyber.hekate.touchid.unlockkey"
private let serviceBlob = "com.synapticcyber.hekate.touchid.blob"

// Non-Keychain failure sentinels for hekate_bio_enable (Keychain itself
// returns standard OSStatus values, which are distinct from these).
private let errBadBase64: Int32 = -2001
private let errSealFailed: Int32 = -2002
private let errAccessControl: Int32 = -2003

private func deleteItem(service: String, account: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
    SecItemDelete(query as CFDictionary)
}

/// True if this Mac can evaluate biometrics (Touch ID present + enrolled).
@_cdecl("hekate_bio_available")
public func hekate_bio_available() -> Bool {
    let context = LAContext()
    var error: NSError?
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}

/// Store a biometric-gated unlock key wrapping `masterKeyB64`. Replaces any
/// existing entry for this account. Returns an OSStatus: 0 (errSecSuccess) on
/// success, a standard Keychain error, or one of the err* sentinels above.
@_cdecl("hekate_bio_enable")
public func hekate_bio_enable(
    _ accountC: UnsafePointer<CChar>,
    _ masterKeyB64C: UnsafePointer<CChar>
) -> Int32 {
    let account = String(cString: accountC)
    let masterKeyB64 = String(cString: masterKeyB64C)
    guard let masterKeyData = Data(base64Encoded: masterKeyB64) else { return errBadBase64 }

    // 1. Random 32-byte unlock key.
    var unlockKeyBytes = [UInt8](repeating: 0, count: 32)
    let randStatus = SecRandomCopyBytes(kSecRandomDefault, unlockKeyBytes.count, &unlockKeyBytes)
    guard randStatus == errSecSuccess else { return randStatus }
    let unlockKeyData = Data(unlockKeyBytes)
    let symKey = SymmetricKey(data: unlockKeyData)

    // 2. AES-256-GCM wrap the master key under the unlock key.
    guard let sealed = try? AES.GCM.seal(masterKeyData, using: symKey),
        let combined = sealed.combined else { return errSealFailed }

    // 3. Replace any prior entries.
    deleteItem(service: serviceUnlockKey, account: account)
    deleteItem(service: serviceBlob, account: account)

    // 4. Biometric access control: Touch ID only, invalidated if the
    //    fingerprint set changes, this device only, no passcode fallback.
    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,
        &acError
    ) else { return errAccessControl }

    let unlockQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceUnlockKey,
        kSecAttrAccount as String: account,
        kSecValueData as String: unlockKeyData,
        kSecAttrAccessControl as String: access,
        kSecUseDataProtectionKeychain as String: true,
    ]
    let unlockStatus = SecItemAdd(unlockQuery as CFDictionary, nil)
    guard unlockStatus == errSecSuccess else { return unlockStatus }

    // 5. Store the wrapped blob (no biometric gate; this device only).
    let blobQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceBlob,
        kSecAttrAccount as String: account,
        kSecValueData as String: combined,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecUseDataProtectionKeychain as String: true,
    ]
    let blobStatus = SecItemAdd(blobQuery as CFDictionary, nil)
    guard blobStatus == errSecSuccess else {
        // Roll back the unlock-key item so we never leave a half-written pair.
        deleteItem(service: serviceUnlockKey, account: account)
        return blobStatus
    }
    return errSecSuccess
}

/// Trigger Touch ID, decrypt the blob, and return the master key as a
/// malloc'd base64 C string (caller frees via `hekate_bio_free`). Returns
/// nil on cancel/failure/no-entry.
@_cdecl("hekate_bio_unlock")
public func hekate_bio_unlock(_ accountC: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>? {
    let account = String(cString: accountC)

    // 1. Read the unlock key — this is what triggers the Touch ID prompt.
    let unlockQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceUnlockKey,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecUseDataProtectionKeychain as String: true,
        kSecUseOperationPrompt as String: "Unlock your Hekate vault",
    ]
    var unlockRef: CFTypeRef?
    guard SecItemCopyMatching(unlockQuery as CFDictionary, &unlockRef) == errSecSuccess,
        let unlockKeyData = unlockRef as? Data else { return nil }

    // 2. Read the wrapped blob.
    let blobQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceBlob,
        kSecAttrAccount as String: account,
        kSecReturnData as String: true,
        kSecUseDataProtectionKeychain as String: true,
    ]
    var blobRef: CFTypeRef?
    guard SecItemCopyMatching(blobQuery as CFDictionary, &blobRef) == errSecSuccess,
        let combined = blobRef as? Data else { return nil }

    // 3. Unwrap the master key.
    let symKey = SymmetricKey(data: unlockKeyData)
    guard let box = try? AES.GCM.SealedBox(combined: combined),
        let masterKeyData = try? AES.GCM.open(box, using: symKey) else { return nil }

    return strdup(masterKeyData.base64EncodedString())
}

/// Whether Touch ID is enrolled for this account. Checks the non-biometric
/// blob item, so it never triggers a Touch ID prompt.
@_cdecl("hekate_bio_enrolled")
public func hekate_bio_enrolled(_ accountC: UnsafePointer<CChar>) -> Bool {
    let account = String(cString: accountC)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceBlob,
        kSecAttrAccount as String: account,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseDataProtectionKeychain as String: true,
    ]
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
}

/// Remove both Keychain items for this account.
@_cdecl("hekate_bio_disable")
public func hekate_bio_disable(_ accountC: UnsafePointer<CChar>) -> Bool {
    let account = String(cString: accountC)
    deleteItem(service: serviceUnlockKey, account: account)
    deleteItem(service: serviceBlob, account: account)
    return true
}

/// Free a string returned by `hekate_bio_unlock`.
@_cdecl("hekate_bio_free")
public func hekate_bio_free(_ ptr: UnsafeMutablePointer<CChar>?) {
    if let ptr = ptr { free(ptr) }
}
