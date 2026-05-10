/* Attachments — the sub-section of CipherDetail that lists, uploads,
 * downloads, and deletes per-cipher attachments.
 *
 * The cipher_key passed in here is the already-unwrapped per-cipher
 * AEAD key; it's needed both to encrypt new attachments' filenames /
 * content_keys on upload and to decrypt them on download.
 */
import {
  createEffect,
  createSignal,
  For,
  Show,
} from "solid-js";

import { ApiError } from "../../lib/api";
import {
  decryptAttachmentRows,
  deleteAttachment,
  downloadAttachment,
  syncManifestAfterAttachmentChange,
  triggerAttachmentSave,
  uploadAttachment,
  type DecryptedAttachment,
} from "../../lib/attachments";
import { fetchSync } from "../../lib/sync";
import { loadHekateCore } from "../../wasm";

export interface AttachmentsSectionProps {
  cipherId: string;
  cipherKey: Uint8Array;
}

export function AttachmentsSection(props: AttachmentsSectionProps) {
  const [rows, setRows] = createSignal<DecryptedAttachment[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [progress, setProgress] = createSignal<string | null>(null);
  const [reloadKey, setReloadKey] = createSignal(0);

  let fileInput: HTMLInputElement | undefined;

  createEffect(() => {
    void reloadKey();
    void load();
  });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const sync = await fetchSync();
      const mine = (sync.changes.attachments ?? []).filter(
        (a) => a.cipher_id === props.cipherId,
      );
      const hekate = await loadHekateCore();
      const decoded = decryptAttachmentRows(hekate, mine, props.cipherId, props.cipherKey);
      decoded.sort((a, b) => a.filename.localeCompare(b.filename));
      setRows(decoded);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setLoading(false);
    }
  }

  async function onFileChosen(file: File | null) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await uploadAttachment(file, props.cipherId, props.cipherKey, (p) =>
        setProgress(p.message),
      );
      setProgress("Re-signing manifest…");
      await syncManifestAfterAttachmentChange();
      setProgress(null);
      setReloadKey(reloadKey() + 1);
    } catch (err) {
      setError(messageOf(err));
      setProgress(null);
    } finally {
      setBusy(false);
      if (fileInput) fileInput.value = "";
    }
  }

  async function onDownload(row: DecryptedAttachment) {
    setBusy(true);
    setError(null);
    try {
      const { bytes, filename } = await downloadAttachment(
        row.view.id,
        props.cipherId,
        props.cipherKey,
      );
      triggerAttachmentSave(bytes, filename);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(row: DecryptedAttachment) {
    if (!window.confirm(`Permanently delete "${row.filename}"?`)) return;
    setBusy(true);
    setError(null);
    try {
      await deleteAttachment(row.view.id);
      await syncManifestAfterAttachmentChange();
      setReloadKey(reloadKey() + 1);
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="card">
      <div
        style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;"
      >
        <p style="margin: 0;">
          <strong>Attachments</strong>
        </p>
        <div>
          <input
            ref={fileInput}
            type="file"
            style="display: none;"
            onChange={(e) => void onFileChosen(e.currentTarget.files?.[0] ?? null)}
          />
          <button
            class="btn btn-secondary"
            type="button"
            disabled={busy()}
            style="padding: 0.3rem 0.65rem; font-size: 0.85rem;"
            onClick={() => fileInput?.click()}
          >
            + Add file
          </button>
        </div>
      </div>

      <Show when={progress()}>
        <div class="banner">{progress()}</div>
      </Show>
      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <Show when={loading()}>
        <p class="muted">Loading…</p>
      </Show>

      <Show when={!loading() && rows().length === 0 && !error()}>
        <p class="muted">No attachments yet.</p>
      </Show>

      <div role="list">
        <For each={rows()}>
          {(row) => (
            <div
              role="listitem"
              style="display: flex; align-items: center; gap: 0.5rem; padding: 0.45rem 0; border-bottom: 1px solid var(--border);"
            >
              <div style="flex: 1 1 auto; min-width: 0;">
                <div class="row-name">{row.filename}</div>
                <div class="row-sub muted">
                  {formatBytes(row.view.size_pt)} · {new Date(row.view.revision_date).toLocaleString()}
                </div>
              </div>
              <button
                type="button"
                class="btn btn-secondary"
                style="padding: 0.3rem 0.65rem; font-size: 0.85rem;"
                disabled={busy()}
                onClick={() => onDownload(row)}
              >
                Download
              </button>
              <button
                type="button"
                class="btn"
                style="padding: 0.3rem 0.65rem; font-size: 0.85rem; background: var(--danger);"
                disabled={busy()}
                onClick={() => onDelete(row)}
              >
                Delete
              </button>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}

function messageOf(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
