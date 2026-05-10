/* Attachment encrypt / upload / download / delete (C.8).
 *
 * Mirrors clients/extension/popup/popup.js:2667-2906. Per-attachment
 * AEAD key (32 random bytes) wraps the body via the PMGRA1 chunked
 * format; the att_key itself wraps under the cipher key with a
 * location-bound AAD (`<att_id>|key|<cipher_id>`); the filename wraps
 * under the cipher key with a separate AAD so list views can decrypt
 * it without unwrapping each attachment.
 *
 * tus single-shot upload — the entire ciphertext goes in the POST
 * body of the creation-with-upload call. Server enforces
 * `content_hash_b3` and `size_pt` on finalize.
 */
import { ApiError, apiGet, authedFetch } from "./api";
import { uploadManifestQuiet } from "./manifest";
import { loadHekateCore } from "../wasm";

const enc = new TextEncoder();
const dec = new TextDecoder();

export interface AttachmentView {
  id: string;
  cipher_id: string;
  filename: string;
  content_key: string;
  size_pt: number;
  size_ct: number;
  content_hash_b3: string;
  revision_date: string;
  creation_date: string;
  deleted_date?: string | null;
}

export interface DecryptedAttachment {
  view: AttachmentView;
  filename: string;
}

/** Decrypt a list of AttachmentViews into display rows.
 *  Filename failures fall back to a synthesized name; the row still
 *  shows up so the user can delete a corrupt entry. */
export function decryptAttachmentRows(
  hekate: import("../wasm-types").HekateCore,
  list: AttachmentView[],
  cipherId: string,
  cipherKey: Uint8Array,
): DecryptedAttachment[] {
  return list.map((view) => {
    let filename = `attachment-${view.id.slice(0, 8)}.bin`;
    try {
      const aad = filenameAad(view.id, cipherId);
      filename = dec.decode(hekate.encStringDecryptXc20p(view.filename, cipherKey, aad));
    } catch {
      /* keep synthesized name */
    }
    return { view, filename };
  });
}

/** Fetch a single attachment's metadata. The `/sync` payload has the
 *  same shape but reads through the typed Changes path; for one-off
 *  download/upload we hit the dedicated GET. */
export async function getAttachment(id: string): Promise<AttachmentView> {
  return apiGet<AttachmentView>(`/api/v1/attachments/${encodeURIComponent(id)}`);
}

export interface UploadProgress {
  /** Free-form status string the UI surfaces to the user. */
  message: string;
}

/** Encrypt + tus single-shot POST. Returns the server-issued view
 *  on success. Caller should re-sign the BW04 manifest after. */
export async function uploadAttachment(
  file: File,
  cipherId: string,
  cipherKey: Uint8Array,
  onProgress?: (p: UploadProgress) => void,
): Promise<AttachmentView> {
  if (file.size === 0) {
    throw new Error("Empty files can't be uploaded.");
  }
  onProgress?.({ message: `Reading ${file.name}…` });
  const plaintext = new Uint8Array(await file.arrayBuffer());

  const hekate = await loadHekateCore();
  const attId = crypto.randomUUID();
  const attKey = hekate.randomKey32();

  onProgress?.({ message: "Encrypting…" });
  const ciphertext = hekate.attachmentEncrypt(attKey, attId, plaintext);
  const hashB64 = hekate.blake3HashB64(ciphertext);

  const wrapAad = hekate.attachmentKeyWrapAad(attId, cipherId);
  const contentKeyWire = hekate.encStringEncryptXc20p("ak:1", cipherKey, attKey, wrapAad);
  const filenameWire = hekate.encStringEncryptXc20p(
    "ak:1",
    cipherKey,
    enc.encode(file.name),
    filenameAad(attId, cipherId),
  );

  const meta = buildTusMetadata([
    ["attachment_id", attId],
    ["cipher_id", cipherId],
    ["filename", filenameWire],
    ["content_key", contentKeyWire],
    ["content_hash_b3", hashB64],
    ["size_pt", String(plaintext.length)],
  ]);

  // Slice into a fresh ArrayBuffer so the BodyInit type is unambiguous
  // (TS strict-DOM rejects `Uint8Array<ArrayBufferLike>`).
  const buf = ciphertext.buffer.slice(
    ciphertext.byteOffset,
    ciphertext.byteOffset + ciphertext.byteLength,
  ) as ArrayBuffer;

  onProgress?.({ message: `Uploading ${formatBytes(ciphertext.length)}…` });
  const r = await authedFetch("POST", "/api/v1/attachments", {
    body: buf,
    headers: {
      "tus-resumable": "1.0.0",
      "upload-length": String(ciphertext.length),
      "upload-metadata": meta,
      "content-type": "application/offset+octet-stream",
    },
  });
  if (!r.ok) throw await asApiError(r);
  return (await r.json()) as AttachmentView;
}

/** Fetch + verify + decrypt. Returns plaintext bytes + filename. */
export async function downloadAttachment(
  attId: string,
  cipherId: string,
  cipherKey: Uint8Array,
): Promise<{ bytes: Uint8Array; filename: string }> {
  const view = await getAttachment(attId);

  const hekate = await loadHekateCore();
  const wrapAad = hekate.attachmentKeyWrapAad(attId, cipherId);
  const attKey = hekate.encStringDecryptXc20p(view.content_key, cipherKey, wrapAad);

  const r = await authedFetch(
    "GET",
    `/api/v1/attachments/${encodeURIComponent(attId)}/blob`,
  );
  if (!r.ok) throw await asApiError(r);
  const ciphertext = new Uint8Array(await r.arrayBuffer());

  // BLAKE3 integrity guard before we throw the bytes at the AEAD —
  // a tampered body would cause a confusing AEAD-tag failure
  // otherwise.
  const observed = hekate.blake3HashB64(ciphertext);
  if (observed !== view.content_hash_b3) {
    throw new Error("BLAKE3 mismatch — body may have been tampered in transit");
  }

  const bytes = hekate.attachmentDecrypt(attKey, attId, ciphertext);

  let filename = `attachment-${attId.slice(0, 8)}.bin`;
  try {
    filename = dec.decode(
      hekate.encStringDecryptXc20p(view.filename, cipherKey, filenameAad(attId, cipherId)),
    );
  } catch {
    /* keep fallback */
  }
  return { bytes, filename };
}

export async function deleteAttachment(id: string): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/attachments/${encodeURIComponent(id)}`,
  );
  if (!r.ok && r.status !== 204) throw await asApiError(r);
}

/** Convenience wrapper: trigger the browser's Save dialog with the
 *  decrypted bytes. */
export function triggerAttachmentSave(bytes: Uint8Array, filename: string): void {
  const buf = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const blob = new Blob([buf], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** Re-sign the BW04 manifest. Wrapper exists so the AttachmentsSection
 *  doesn't need to import lib/manifest directly. */
export async function syncManifestAfterAttachmentChange(): Promise<void> {
  await uploadManifestQuiet();
}

function filenameAad(attId: string, cipherId: string): Uint8Array {
  return enc.encode(`pmgr-attachment-filename-v1:${attId}:${cipherId}`);
}

function buildTusMetadata(pairs: Array<[string, string]>): string {
  return pairs
    .map(([k, v]) => {
      const bytes = enc.encode(v);
      let s = "";
      for (let i = 0; i < bytes.length; i += 1) {
        s += String.fromCharCode(bytes[i]);
      }
      return `${k} ${btoa(s)}`;
    })
    .join(", ");
}

async function asApiError(r: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await r.json();
  } catch {
    /* */
  }
  let msg = `${r.status} ${r.statusText}`;
  if (body && typeof body === "object" && "error" in body) {
    const e = (body as { error?: unknown }).error;
    if (typeof e === "string" && e) msg = e;
  }
  return new ApiError(r.status, msg, body);
}

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
