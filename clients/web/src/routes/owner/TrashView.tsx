/* Trash view — soft-deleted ciphers with Restore + Purge actions.
 *
 * Mirrors the popup's `renderVault({showTrash: true})` shape: same
 * decrypted-row presentation as the main Vault, but with action
 * buttons that call DELETE /restore (restore) and DELETE /permanent
 * (purge). Each successful action re-signs the BW04 manifest so the
 * signed set tracks the change.
 */
import {
  createEffect,
  createSignal,
  For,
  Show,
} from "solid-js";

import { ApiError, SessionExpiredError } from "../../lib/api";
import {
  decryptForList,
  type CipherView,
  type DecryptedListItem,
} from "../../lib/cipher";
import {
  purgeCipher,
  restoreCipher,
} from "../../lib/cipherWrite";
import { uploadManifestQuiet } from "../../lib/manifest";
import { fetchSync } from "../../lib/sync";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import { iconForCipherType } from "../../ui/icons";
import { SubShell } from "../../ui/Shell";

export interface TrashViewProps {
  onBack: () => void;
  onSessionExpired: () => void;
  /** Bumped after each successful Restore/Purge so the parent's vault
   *  list re-syncs when the user navigates back. */
  onChanged: () => void;
}

interface Row {
  raw: CipherView;
  view: DecryptedListItem;
}

export function TrashView(props: TrashViewProps) {
  const [rows, setRows] = createSignal<Row[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [busyId, setBusyId] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);
  const [reloadKey, setReloadKey] = createSignal(0);

  createEffect(() => {
    void reloadKey();
    void load();
  });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      if (!session) throw new SessionExpiredError("no session");
      const sync = await fetchSync();
      const hekate = await loadHekateCore();
      const trashed: Row[] = sync.changes.ciphers
        .filter((c) => !!c.deleted_date)
        .map((c) => ({ raw: c, view: decryptForList(hekate, c, session.accountKey) }));
      trashed.sort((a, b) =>
        a.view.name.localeCompare(b.view.name, undefined, { sensitivity: "base" }),
      );
      setRows(trashed);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        props.onSessionExpired();
        return;
      }
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setLoading(false);
    }
  }

  function showToast(msg: string) {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2200);
  }

  async function onRestore(id: string) {
    setBusyId(id);
    try {
      await restoreCipher(id);
      await uploadManifestQuiet();
      showToast("Restored");
      setReloadKey(reloadKey() + 1);
      props.onChanged();
    } catch (err) {
      showToast(
        err instanceof ApiError
          ? `Restore failed: ${err.message}`
          : `Restore failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setBusyId(null);
    }
  }

  async function onPurge(id: string, name: string) {
    if (!window.confirm(`Permanently delete "${name}"? This cannot be undone.`)) {
      return;
    }
    setBusyId(id);
    try {
      await purgeCipher(id);
      await uploadManifestQuiet();
      showToast("Purged");
      setReloadKey(reloadKey() + 1);
      props.onChanged();
    } catch (err) {
      showToast(
        err instanceof ApiError
          ? `Purge failed: ${err.message}`
          : `Purge failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setBusyId(null);
    }
  }

  return (
    <SubShell title="Trash" onBack={props.onBack}>
      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <Show when={loading()}>
        <p class="muted">Loading…</p>
      </Show>

      <Show when={!loading() && rows().length === 0 && !error()}>
        <p class="muted">Trash is empty.</p>
      </Show>

      <div role="list">
        <For each={rows()}>
          {(row) => {
            const Icon = iconForCipherType(row.view.type);
            const busy = () => busyId() === row.view.id;
            return (
              <div class="cipher-row" role="listitem" style="cursor: default;">
                <span class="row-icon" data-type={row.view.type}>
                  <Icon />
                </span>
                <span class="row-body">
                  <div class="row-name">{row.view.name}</div>
                  <div class="row-sub muted">
                    Trashed{" "}
                    {row.raw.deleted_date
                      ? new Date(row.raw.deleted_date).toLocaleString()
                      : "—"}
                  </div>
                </span>
                <span class="row-actions">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    style="padding: 0.35rem 0.75rem; font-size: 0.85rem;"
                    disabled={busy()}
                    onClick={() => onRestore(row.view.id)}
                  >
                    Restore
                  </button>
                  <button
                    type="button"
                    class="btn"
                    style="padding: 0.35rem 0.75rem; font-size: 0.85rem; background: var(--danger);"
                    disabled={busy()}
                    onClick={() => onPurge(row.view.id, row.view.name)}
                  >
                    Purge
                  </button>
                </span>
              </div>
            );
          }}
        </For>
      </div>

      <Show when={toast()}>
        <div class="toast" role="status">
          {toast()}
        </div>
      </Show>
    </SubShell>
  );
}
