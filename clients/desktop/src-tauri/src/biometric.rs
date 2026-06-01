//! Touch ID unlock — Tauri commands bridging the webview to the native
//! Keychain/biometric helper (`swift-lib/`). See `docs/desktop-touch-id.md`.
//!
//! These are the desktop app's first custom IPC commands. They never expose
//! the unlock key to JS; only the master key (which the SPA already holds in
//! memory after a normal login) crosses the boundary, as base64. The macOS
//! login password is never an unlock path — the access control is
//! `.biometryCurrentSet` with no device-passcode fallback (set in Swift).

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    use zeroize::Zeroize;

    // Implemented in `swift-lib/biometric.swift`, compiled with `swiftc` and
    // linked by build.rs.
    extern "C" {
        fn hekate_bio_available() -> bool;
        fn hekate_bio_enable(account: *const c_char, master_key_b64: *const c_char) -> bool;
        fn hekate_bio_unlock(account: *const c_char) -> *mut c_char;
        fn hekate_bio_disable(account: *const c_char) -> bool;
        fn hekate_bio_free(ptr: *mut c_char);
    }

    /// Whether this Mac can do biometric unlock (Touch ID present + enrolled).
    #[tauri::command]
    pub fn biometric_available() -> bool {
        // SAFETY: no arguments; the Swift fn only queries LAContext state.
        unsafe { hekate_bio_available() }
    }

    /// Enroll Touch ID for `account`, storing the (biometric-gated) wrap of
    /// the master key. The master key is wiped from this process after the call.
    #[tauri::command]
    pub fn biometric_enable(account: String, master_key_b64: String) -> Result<(), String> {
        let acc = CString::new(account).map_err(|_| "invalid account".to_string())?;
        let mk = CString::new(master_key_b64).map_err(|_| "invalid key".to_string())?;
        // SAFETY: both pointers are valid NUL-terminated C strings for the
        // duration of the call; the Swift side copies the bytes it needs.
        let ok = unsafe { hekate_bio_enable(acc.as_ptr(), mk.as_ptr()) };
        // Best-effort wipe of the key bytes this process held.
        let mut bytes = mk.into_bytes_with_nul();
        bytes.zeroize();
        if ok {
            Ok(())
        } else {
            Err("could not enable Touch ID".to_string())
        }
    }

    /// Prompt Touch ID and return the master key (base64) on success.
    #[tauri::command]
    pub fn biometric_unlock(account: String) -> Result<String, String> {
        let acc = CString::new(account).map_err(|_| "invalid account".to_string())?;
        // SAFETY: `acc` is a valid C string. The returned pointer is either
        // null or a malloc'd C string we own and must release via
        // `hekate_bio_free`.
        let ptr = unsafe { hekate_bio_unlock(acc.as_ptr()) };
        if ptr.is_null() {
            return Err("Touch ID unlock failed or was cancelled".to_string());
        }
        // SAFETY: non-null `ptr` is a valid NUL-terminated C string.
        let key = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `ptr` came from `hekate_bio_unlock` and is freed exactly once.
        unsafe { hekate_bio_free(ptr) };
        Ok(key)
    }

    /// Remove the stored Touch ID material for `account`.
    #[tauri::command]
    pub fn biometric_disable(account: String) -> Result<(), String> {
        let acc = CString::new(account).map_err(|_| "invalid account".to_string())?;
        // SAFETY: `acc` is a valid C string.
        let ok = unsafe { hekate_bio_disable(acc.as_ptr()) };
        if ok {
            Ok(())
        } else {
            Err("could not disable Touch ID".to_string())
        }
    }
}

// Non-macOS stub so the workspace still type-checks off-Mac. The desktop
// target is Apple-Silicon macOS; these never run in a shipped build.
#[cfg(not(target_os = "macos"))]
mod imp {
    #[tauri::command]
    pub fn biometric_available() -> bool {
        false
    }
    #[tauri::command]
    pub fn biometric_enable(_account: String, _master_key_b64: String) -> Result<(), String> {
        Err("Touch ID is only supported on macOS".to_string())
    }
    #[tauri::command]
    pub fn biometric_unlock(_account: String) -> Result<String, String> {
        Err("Touch ID is only supported on macOS".to_string())
    }
    #[tauri::command]
    pub fn biometric_disable(_account: String) -> Result<(), String> {
        Err("Touch ID is only supported on macOS".to_string())
    }
}

pub use imp::*;
