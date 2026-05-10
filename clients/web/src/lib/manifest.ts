/* BW04 vault-manifest verification on the read path.
 *
 * Every `/api/v1/sync` response carries the latest `ManifestView`
 * signed by the user's Ed25519 account signing key. The pubkey is
 * pinned at first login (C.2) and lives in
 * `localStorage["hekate.signing_pubkey_b64"]`. We verify the signature
 * here on every sync; mismatches surface a banner so the user sees
 * the warning even when decryption succeeds (warn-mode by default —
 * matches popup's strict-manifest off-by-default).
 *
 * Cross-checking each manifest entry against the returned cipher set
 * (drop / replay / forked-chain detection) is a follow-up; this file
 * only does the signature step.
 */
import { authedFetch, apiGet } from "./api";
import { b64decode, b64encode, b64urlDecode } from "./base64";
import { getSession } from "./session";
import { loadHekateCore } from "../wasm";
import type { ManifestView, SyncResponse } from "./sync";

export type ManifestVerifyResult =
  | { ok: true; version: number }
  | { ok: false; reason: string };

export async function verifyVaultManifest(
  manifest: ManifestView,
  signingPubkeyB64Url: string,
): Promise<ManifestVerifyResult> {
  let pubkey: Uint8Array;
  try {
    pubkey = b64urlDecode(signingPubkeyB64Url);
  } catch (err) {
    return {
      ok: false,
      reason: `pinned signing pubkey is not valid base64url: ${messageOf(err)}`,
    };
  }
  if (pubkey.length !== 32) {
    return {
      ok: false,
      reason: `pinned signing pubkey is ${pubkey.length} bytes, expected 32`,
    };
  }

  let canonical: Uint8Array;
  let signature: Uint8Array;
  try {
    canonical = b64decode(manifest.canonical_b64);
    signature = b64decode(manifest.signature_b64);
  } catch (err) {
    return {
      ok: false,
      reason: `manifest payload is not valid base64: ${messageOf(err)}`,
    };
  }

  try {
    const hekate = await loadHekateCore();
    const parsed = hekate.verifyManifestSignature(pubkey, canonical, signature);
    return { ok: true, version: parsed.version };
  } catch (err) {
    return {
      ok: false,
      reason: `manifest signature did not verify: ${messageOf(err)}`,
    };
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* BW04 manifest re-sign on the write path.
 *
 * Mirrors clients/extension/popup/popup.js:731-762 (`syncAndUploadManifest`).
 * Called after every successful cipher write so the signed manifest
 * version increments and the server's "latest" record stays in sync
 * with the cipher set the user just modified. Failures here are
 * non-fatal — the cipher write already succeeded; a stale manifest
 * just means the next sync will surface a "manifest stale" warning
 * until the next write resyncs.
 */
export async function uploadManifestQuiet(): Promise<void> {
  try {
    const session = getSession();
    if (!session) {
      console.warn("manifest upload skipped: no session");
      return;
    }
    const sync = await apiGet<SyncResponse>("/api/v1/sync");
    const hekate = await loadHekateCore();

    const entries = sync.changes.ciphers.map((c) => ({
      cipherId: c.id,
      revisionDate: c.revision_date,
      deleted: !!c.deleted_date,
    }));

    let nextVersion = 1;
    let parentHash = new Uint8Array(32); // genesis = all zeros
    if (sync.manifest) {
      nextVersion = sync.manifest.version + 1;
      // Copy into a fresh Uint8Array so its underlying buffer is
      // typed as ArrayBuffer (TS strict-DOM rejects the wider
      // `ArrayBufferLike` shape that wasm-bindgen returns).
      parentHash = new Uint8Array(
        hekate.sha256(b64decode(sync.manifest.canonical_b64)),
      );
    }

    const signed = hekate.signManifestCanonical(session.signingSeed, {
      version: nextVersion,
      timestamp: new Date().toISOString(),
      parentCanonicalSha256: parentHash,
      entries,
    });

    const r = await authedFetch("POST", "/api/v1/vault/manifest", {
      body: {
        version: nextVersion,
        canonical_b64: b64encode(signed.canonicalBytes),
        signature_b64: b64encode(signed.signature),
      },
    });
    if (!r.ok) {
      console.warn(`manifest upload returned ${r.status} ${r.statusText}`);
    }
  } catch (err) {
    console.warn("manifest upload failed:", err);
  }
}
