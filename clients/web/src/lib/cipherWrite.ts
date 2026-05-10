/* Cipher encryption + POST/PUT.
 *
 * Mirrors clients/extension/popup/popup.js:3118-3215 (`onSaveCipher`).
 * Every per-cipher field commits to the cipher's id (and type) via AAD
 * — see lib/cipher.ts for the AAD constructors. The protocol-frozen
 * key-id strings (`ak:1`, `ck:1`) are EncString labels that the
 * decrypt path doesn't introspect; they exist only so a future
 * key-rotation can disambiguate ciphertexts produced under different
 * keys.
 */
import { authedFetch, ApiError } from "./api";
import {
  aadCipherData,
  aadCipherName,
  aadCipherNotes,
  aadProtectedCipherKey,
  type CipherView,
} from "./cipher";
import { loadHekateCore } from "../wasm";

const enc = new TextEncoder();

export interface CipherDraft {
  id: string | null; // null → create
  type: number;
  name: string;
  notes: string | null;
  data: Record<string, string>;
  favorite: boolean;
  folderId: string | null;
}

interface SavePayload {
  id: string;
  type: number;
  folder_id: string | null;
  protected_cipher_key: string;
  name: string;
  notes: string | null;
  data: string;
  favorite: boolean;
}

/** Encrypt + POST/PUT. Returns the server-issued `revision_date` so
 *  the caller can update its local cache. On edit, requires `ifMatch`
 *  (the cipher's prior revision_date) for optimistic concurrency. */
export async function saveCipher(
  draft: CipherDraft,
  accountKey: Uint8Array,
  prior?: CipherView,
): Promise<CipherView> {
  const hekate = await loadHekateCore();
  const isCreate = draft.id === null;

  let cipherId: string;
  let cipherKey: Uint8Array;
  let protectedCipherKey: string;

  if (isCreate) {
    cipherId = newCipherId();
    cipherKey = hekate.randomKey32();
    protectedCipherKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      cipherKey,
      aadProtectedCipherKey(cipherId),
    );
  } else {
    if (!prior) {
      throw new Error("editing requires prior CipherView for revision + key reuse");
    }
    cipherId = prior.id;
    cipherKey = hekate.encStringDecryptXc20p(
      prior.protected_cipher_key,
      accountKey,
      aadProtectedCipherKey(cipherId),
    );
    protectedCipherKey = prior.protected_cipher_key;
  }

  const dataJson = JSON.stringify(draft.data);
  const payload: SavePayload = {
    id: cipherId,
    type: draft.type,
    folder_id: draft.folderId,
    protected_cipher_key: protectedCipherKey,
    name: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(draft.name),
      aadCipherName(cipherId, draft.type),
    ),
    notes: draft.notes
      ? hekate.encStringEncryptXc20p(
          "ck:1",
          cipherKey,
          enc.encode(draft.notes),
          aadCipherNotes(cipherId, draft.type),
        )
      : null,
    data: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(dataJson),
      aadCipherData(cipherId, draft.type),
    ),
    favorite: draft.favorite,
  };

  if (isCreate) {
    const r = await authedFetch("POST", "/api/v1/ciphers", { body: payload });
    if (!r.ok) throw await apiErrorFromResponse(r);
    return (await r.json()) as CipherView;
  }
  // PUT: use If-Match for optimistic concurrency.
  const r = await authedFetch(
    "PUT",
    `/api/v1/ciphers/${encodeURIComponent(cipherId)}`,
    {
      body: payload,
      headers: prior ? { "if-match": `"${prior.revision_date}"` } : undefined,
    },
  );
  if (!r.ok) throw await apiErrorFromResponse(r);
  return (await r.json()) as CipherView;
}

/** Generate a fresh UUIDv4 for a new cipher id. The server only
 *  validates "is a UUID" — v4 from `crypto.randomUUID()` is enough. */
function newCipherId(): string {
  return crypto.randomUUID();
}

/** Soft-delete: server sets `deleted_date`. Cipher row stays around
 *  in the trash until purged or restored. */
export async function deleteCipher(cipherId: string): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/ciphers/${encodeURIComponent(cipherId)}`,
  );
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

/** Restore from trash: server clears `deleted_date`. */
export async function restoreCipher(cipherId: string): Promise<void> {
  const r = await authedFetch(
    "POST",
    `/api/v1/ciphers/${encodeURIComponent(cipherId)}/restore`,
  );
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

/** Permanent delete: writes a tombstone. Irreversible. */
export async function purgeCipher(cipherId: string): Promise<void> {
  const r = await authedFetch(
    "DELETE",
    `/api/v1/ciphers/${encodeURIComponent(cipherId)}/permanent`,
  );
  if (!r.ok && r.status !== 204) throw await apiErrorFromResponse(r);
}

async function apiErrorFromResponse(r: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await r.json();
  } catch {
    /* empty / non-JSON */
  }
  let msg = `${r.status} ${r.statusText}`;
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: unknown }).error;
    if (typeof err === "string" && err) msg = err;
  }
  return new ApiError(r.status, msg, body);
}
