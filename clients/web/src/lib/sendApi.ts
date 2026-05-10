/* Send-row API client (owner-side, C.4).
 *
 * Mirrors `crates/hekate-server/src/routes/sends.rs::SendView` shape.
 * The encrypt-and-create flow lives in the route components rather
 * than here since it's tightly coupled to the form data; this module
 * is the wire-level wrapper.
 */
import { ApiError, apiGet, authedFetch } from "./api";

export interface SendListItem {
  id: string;
  send_type: 1 | 2;
  /** EncString of the display name under the account_key + sendNameAad. */
  name: string;
  /** EncString of the send_key wrapped under the account_key + sendKeyWrapAad. */
  protected_send_key: string;
  data: string;
  has_password: boolean;
  max_access_count: number | null;
  access_count: number;
  expiration_date: string | null;
  deletion_date: string;
  revision_date: string;
  creation_date: string;
  disabled: boolean;
}

export interface CreateSendRequest {
  id: string;
  send_type: 1 | 2;
  name: string;
  protected_send_key: string;
  data: string;
  deletion_date: string;
  disabled: boolean;
  password?: string;
  max_access_count?: number;
}

export async function listSends(): Promise<SendListItem[]> {
  return apiGet<SendListItem[]>("/api/v1/sends");
}

export async function getSend(id: string): Promise<SendListItem> {
  return apiGet<SendListItem>(`/api/v1/sends/${encodeURIComponent(id)}`);
}

export async function createSend(req: CreateSendRequest): Promise<SendListItem> {
  const r = await authedFetch("POST", "/api/v1/sends", { body: req });
  if (!r.ok) throw await asApiError(r);
  return (await r.json()) as SendListItem;
}

export async function disableSend(id: string): Promise<void> {
  await mutate(`/api/v1/sends/${encodeURIComponent(id)}/disable`, "POST");
}

export async function enableSend(id: string): Promise<void> {
  await mutate(`/api/v1/sends/${encodeURIComponent(id)}/enable`, "POST");
}

export async function deleteSend(id: string): Promise<void> {
  await mutate(`/api/v1/sends/${encodeURIComponent(id)}`, "DELETE");
}

/** Single-shot tus 1.0 upload — body is the entire ciphertext. The
 *  server validates `Upload-Length` matches the payload size and the
 *  `content_hash_b3` metadata pair matches BLAKE3 of the body. */
export async function uploadSendBody(
  id: string,
  ciphertext: Uint8Array,
  hashB64: string,
  plaintextLength: number,
): Promise<void> {
  const meta = buildTusMetadata([
    ["content_hash_b3", hashB64],
    ["size_pt", String(plaintextLength)],
  ]);
  // Pull the bytes through a fresh ArrayBuffer so the request body is
  // typed unambiguously as ArrayBuffer (TS strict-DOM rejects
  // Uint8Array<ArrayBufferLike>).
  const buf = ciphertext.buffer.slice(
    ciphertext.byteOffset,
    ciphertext.byteOffset + ciphertext.byteLength,
  ) as ArrayBuffer;
  const r = await authedFetch(
    "POST",
    `/api/v1/sends/${encodeURIComponent(id)}/upload`,
    {
      body: buf,
      headers: {
        "tus-resumable": "1.0.0",
        "upload-length": String(ciphertext.length),
        "upload-metadata": meta,
        "content-type": "application/offset+octet-stream",
      },
    },
  );
  if (!r.ok && r.status !== 204) {
    throw await asApiError(r);
  }
}

async function mutate(path: string, method: "POST" | "DELETE"): Promise<void> {
  const r = await authedFetch(method, path);
  if (!r.ok && r.status !== 204) throw await asApiError(r);
}

async function asApiError(r: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await r.json();
  } catch {
    /* no body */
  }
  let msg = `${r.status} ${r.statusText}`;
  if (body && typeof body === "object" && "error" in body) {
    const e = (body as { error?: unknown }).error;
    if (typeof e === "string" && e) msg = e;
  }
  return new ApiError(r.status, msg, body);
}

/** tus Upload-Metadata is a comma-separated list of `key b64(value)`
 *  pairs (https://tus.io/protocols/resumable-upload#upload-metadata).
 */
function buildTusMetadata(pairs: Array<[string, string]>): string {
  const enc = new TextEncoder();
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
