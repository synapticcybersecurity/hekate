/* Account export (C.7d-3) — port of
 * crates/hekate-cli/src/commands/account.rs::export.
 *
 * Pure client-side: there is no `/api/v1/account/export` endpoint. The
 * web vault fetches `/api/v1/sync` for the user's encrypted ciphers +
 * folders, looks up the user's own pubkey bundle for `user_id` /
 * `account_public_key`, builds an `ExportContents` JSON blob (matches
 * the CLI's struct verbatim so the file is interchangeable), encrypts
 * it under a fresh Argon2id key derived from the user-typed export
 * password, and wraps the ciphertext in an `ExportFile` envelope.
 *
 * Threat model: the file alone is opaque. The export password is the
 * only thing that decrypts it. The bundle includes the plaintext
 * `account_key` (so a holder of the file + password gets full read
 * access to every cipher) — treat the file like the master password
 * itself.
 */
import { apiGet } from "./api";
import { b64encode } from "./base64";
import { getSession } from "./session";
import { fetchSync } from "./sync";
import { loadHekateCore } from "../wasm";
import type { KdfParams } from "../wasm-types";

/** AAD for the inner-bundle EncString. Must match the CLI's
 *  `b"pmgr-export-v1"` so a CLI-side decryptor would also work. */
const AAD_EXPORT = "pmgr-export-v1";
const enc = new TextEncoder();

/** KDF params chosen to match `KdfParams::default_argon2id()` in
 *  hekate-core. `kdfParamsAreSafe` will sign off on these. */
const EXPORT_KDF_PARAMS: KdfParams = {
  alg: "argon2id",
  m_kib: 131072,
  t: 3,
  p: 4,
};

interface PubkeyBundle {
  user_id: string;
  account_signing_pubkey: string;
  account_public_key: string;
  account_pubkey_bundle_sig: string;
}

interface ExportFile {
  format: "pmgr-export-v1";
  version: number;
  /** KDF parameters (opaque to JS — the WASM binding owns the shape). */
  kdf: KdfParams;
  salt_b64: string;
  /** EncString v3 envelope of the inner bundle. */
  encrypted: string;
}

interface ExportContents {
  exported_at: string;
  server_url: string;
  email: string;
  /** Plaintext account_key, base64-no-pad. The bundle is encrypted
   *  under the export password, so this is only at risk if the file
   *  AND the password leak together. */
  account_key_b64: string;
  account_public_key_b64: string;
  /** Wire-form ciphers from /sync (each cipher is still encrypted
   *  under its own protected_cipher_key, which is wrapped under the
   *  account_key — the export bundle gives the holder both). */
  ciphers: unknown[];
  folders: unknown[];
}

export interface ExportResult {
  /** UTF-8 JSON bytes of the ExportFile envelope, ready to download. */
  bytes: Uint8Array;
  /** Suggested filename, e.g. `pmgr-export-2026-05-04T01-30-00.json`. */
  filename: string;
  cipherCount: number;
  folderCount: number;
}

/** Build an encrypted export of the caller's account. `exportPassword`
 *  is what the user types to encrypt the file — it is independent of
 *  the master password and is NOT stored anywhere. */
export async function exportAccount(exportPassword: string): Promise<ExportResult> {
  const session = getSession();
  if (!session) throw new Error("session expired — log in again");
  const hekate = await loadHekateCore();

  // 1. Fetch what we need from the server: encrypted ciphers + folders
  //    via /sync, and our own pubkey bundle via the lookup endpoint
  //    (gets us account_public_key, which the session doesn't carry).
  const [sync, bundle] = await Promise.all([
    fetchSync(),
    apiGet<PubkeyBundle>(
      `/api/v1/users/lookup?email=${encodeURIComponent(session.email)}`,
    ),
  ]);

  // 2. Build the inner bundle. account_key is the unwrapped 32-byte
  //    symmetric key from session memory.
  const contents: ExportContents = {
    exported_at: new Date().toISOString(),
    server_url: window.location.origin,
    email: session.email,
    account_key_b64: b64encode(session.accountKey),
    account_public_key_b64: bundle.account_public_key,
    ciphers: sync.changes.ciphers ?? [],
    folders: sync.changes.folders ?? [],
  };
  const innerJson = enc.encode(JSON.stringify(contents));

  // 3. Derive a fresh Argon2id key from the export password. Reject
  //    weak params via the same BW07 floor login uses.
  if (!hekate.kdfParamsAreSafe(EXPORT_KDF_PARAMS)) {
    throw new Error("EXPORT_KDF_PARAMS below the safety floor — bug.");
  }
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const exportMk = hekate.deriveMasterKey(
    enc.encode(exportPassword),
    EXPORT_KDF_PARAMS,
    salt,
  );
  const exportSmk = hekate.deriveStretchedMasterKey(exportMk);

  // 4. EncString v3 envelope under the stretched export key. Same wire
  //    form the CLI uses, so a `hekate account import` (when one exists)
  //    or the CLI's own decryption helper can open this file.
  const encrypted = hekate.encStringEncryptXc20p(
    "expk:1",
    exportSmk,
    innerJson,
    enc.encode(AAD_EXPORT),
  );

  // 5. Outer envelope. JSON-pretty so the file is human-readable for
  //    debugging without compromising the inner ciphertext.
  const file: ExportFile = {
    format: "pmgr-export-v1",
    version: 1,
    kdf: EXPORT_KDF_PARAMS,
    salt_b64: b64encode(salt),
    encrypted,
  };
  const bytes = enc.encode(JSON.stringify(file, null, 2));

  // 6. Filename: pmgr-export-<ISO timestamp without colons>.json. Avoid
  //    colons because Windows + macOS Finder both reject them in
  //    user-saved filenames.
  const ts = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  const filename = `pmgr-export-${ts}.json`;

  return {
    bytes,
    filename,
    cipherCount: contents.ciphers.length,
    folderCount: contents.folders.length,
  };
}

/** Trigger a browser download of the bytes as `filename`. Uses an
 *  ephemeral object URL that's revoked once the click fires. */
export function triggerDownload(bytes: Uint8Array, filename: string): void {
  const buf = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const blob = new Blob([buf], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // Defer revoke so Safari has a tick to start the download. The
    // tab's lifecycle eventually GCs the URL anyway; this is paranoia.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
