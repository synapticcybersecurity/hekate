/* Typed wrapper around `/api/v1/sync`.
 *
 * Wire shape mirrors `crates/hekate-server/src/routes/sync.rs::SyncResponse`.
 * Only fields C.3a actually consumes are typed strictly; the rest are
 * left as `unknown` until later milestones reach for them.
 */
import { apiGet } from "./api";
import type { AttachmentView } from "./attachments";
import type { CipherView } from "./cipher";
import type { OrgSyncEntry } from "./orgs";

/** Subset of the sender-side Send row needed for rotate-keys
 *  rewrapping. The full SendListItem lives in lib/sendApi.ts but
 *  carrying it through `Changes` would be circular. */
export interface SyncSend {
  id: string;
  send_type: number;
  name: string;
  protected_send_key: string;
  data: string;
  deletion_date: string;
  disabled: boolean;
}

export interface ManifestView {
  version: number;
  canonical_b64: string;
  signature_b64: string;
  updated_at: string;
}

export interface FolderView {
  id: string;
  name: string; // EncString under account_key
  revision_date: string;
}

export interface Tombstone {
  kind: "cipher" | "folder";
  id: string;
  deleted_at: string;
}

export interface Changes {
  ciphers: CipherView[];
  folders: FolderView[];
  tombstones: Tombstone[];
  collections?: unknown[];
  attachments?: AttachmentView[];
  sends?: SyncSend[];
}

export interface SyncResponse {
  changes: Changes;
  high_water: string;
  server_time: string;
  complete: boolean;
  manifest: ManifestView | null;
  orgs: OrgSyncEntry[];
}

export async function fetchSync(since?: string): Promise<SyncResponse> {
  const path = since
    ? `/api/v1/sync?since=${encodeURIComponent(since)}`
    : "/api/v1/sync";
  return apiGet<SyncResponse>(path);
}
