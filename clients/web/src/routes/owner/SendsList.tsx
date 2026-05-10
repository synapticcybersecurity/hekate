/* Sends list — owner side. Renders the Share tab content.
 *
 * Mirrors the popup's `renderSendsList`. List shows decrypted name +
 * access counters + flags + per-row actions (Copy URL / Disable or
 * Enable / Delete). The header row offers two creation buttons.
 */
import {
  createEffect,
  createSignal,
  For,
  Show,
} from "solid-js";

import { ApiError, SessionExpiredError } from "../../lib/api";
import {
  deleteSend,
  disableSend,
  enableSend,
  listSends,
  type SendListItem,
} from "../../lib/sendApi";
import { copy } from "../../lib/clipboard";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";

export interface SendsListProps {
  /** Bumped by the parent after a create finishes — re-fetches list. */
  reloadKey: number;
  onSessionExpired: () => void;
  onNewText: () => void;
  onNewFile: () => void;
}

interface DecodedSend extends SendListItem {
  /** Decrypted display name (from popup-only sender-side `name` field). */
  displayName: string;
}

export function SendsList(props: SendsListProps) {
  const [sends, setSends] = createSignal<DecodedSend[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [busyId, setBusyId] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);
  const [internalReload, setInternalReload] = createSignal(0);

  createEffect(() => {
    void props.reloadKey;
    void internalReload();
    void load();
  });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      if (!session) throw new SessionExpiredError("no session");
      const rows = await listSends();
      const hekate = await loadHekateCore();
      const dec = new TextDecoder();
      const decoded: DecodedSend[] = rows.map((sd) => {
        let displayName = "<undecryptable>";
        try {
          const pt = hekate.encStringDecryptXc20p(
            sd.name,
            session.accountKey,
            hekate.sendNameAad(sd.id),
          );
          displayName = dec.decode(pt);
        } catch {
          /* leave placeholder */
        }
        return { ...sd, displayName };
      });
      decoded.sort((a, b) => b.creation_date.localeCompare(a.creation_date));
      setSends(decoded);
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

  async function onCopyUrl(sd: DecodedSend) {
    setBusyId(sd.id);
    try {
      const session = getSession();
      if (!session) throw new SessionExpiredError("no session");
      const hekate = await loadHekateCore();
      const sendKey = hekate.encStringDecryptXc20p(
        sd.protected_send_key,
        session.accountKey,
        hekate.sendKeyWrapAad(sd.id),
      );
      const origin = window.location.origin;
      const url = `${origin}/send/#/${sd.id}/${hekate.sendEncodeKey(sendKey)}`;
      await copy(url);
      showToast("URL copied (auto-clears in 30s)");
    } catch (err) {
      showToast(
        err instanceof Error ? `Copy failed: ${err.message}` : String(err),
      );
    } finally {
      setBusyId(null);
    }
  }

  async function onToggle(sd: DecodedSend) {
    setBusyId(sd.id);
    try {
      if (sd.disabled) await enableSend(sd.id);
      else await disableSend(sd.id);
      showToast(sd.disabled ? "Enabled" : "Disabled");
      setInternalReload(internalReload() + 1);
    } catch (err) {
      showToast(
        err instanceof ApiError
          ? `Error: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setBusyId(null);
    }
  }

  async function onDelete(sd: DecodedSend) {
    if (
      !window.confirm(
        `Permanently delete share "${sd.displayName}"? Recipients will get 410 Gone.`,
      )
    ) {
      return;
    }
    setBusyId(sd.id);
    try {
      await deleteSend(sd.id);
      showToast("Deleted");
      setInternalReload(internalReload() + 1);
    } catch (err) {
      showToast(
        err instanceof ApiError
          ? `Error: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <p class="muted" style="margin: 0 0 0.85rem;">
        Ephemeral encrypted shares. Recipients open the URL anonymously;
        the server can revoke (delete / disable / expire / max-access)
        but cannot decrypt.
      </p>

      <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap;">
        <button class="btn" type="button" onClick={props.onNewText}>
          + New text share
        </button>
        <button class="btn btn-secondary" type="button" onClick={props.onNewFile}>
          + New file share
        </button>
      </div>

      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <Show when={loading()}>
        <p class="muted">Loading…</p>
      </Show>

      <Show when={!loading() && sends().length === 0 && !error()}>
        <p class="muted">No shares yet.</p>
      </Show>

      <div role="list">
        <For each={sends()}>
          {(sd) => {
            const max = sd.max_access_count ? `/ ${sd.max_access_count}` : "/ ∞";
            const flags: string[] = [];
            if (sd.disabled) flags.push("disabled");
            if (sd.has_password) flags.push("password");
            if (sd.send_type === 2) flags.push("file");
            const busy = () => busyId() === sd.id;
            return (
              <div
                role="listitem"
                style="display: flex; align-items: center; gap: 0.75rem; padding: 0.65rem 0.5rem; border-radius: var(--radius-sm); background: transparent;"
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "var(--surface)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "transparent")
                }
              >
                <div style="flex: 1 1 auto; min-width: 0;">
                  <div class="row-name">
                    {sd.displayName}
                    <Show when={flags.length > 0}>
                      <span class="muted" style="margin-left: 0.4rem; font-size: 0.85em;">
                        [{flags.join(", ")}]
                      </span>
                    </Show>
                  </div>
                  <div class="row-sub muted">
                    access {sd.access_count} {max} · expires{" "}
                    {new Date(sd.deletion_date).toLocaleString()}
                  </div>
                </div>
                <div style="display: flex; gap: 0.35rem; flex-wrap: wrap;">
                  <button
                    type="button"
                    class="btn btn-secondary"
                    style="padding: 0.3rem 0.65rem; font-size: 0.85rem;"
                    disabled={busy()}
                    onClick={() => onCopyUrl(sd)}
                  >
                    Copy URL
                  </button>
                  <button
                    type="button"
                    class="btn btn-secondary"
                    style="padding: 0.3rem 0.65rem; font-size: 0.85rem;"
                    disabled={busy()}
                    onClick={() => onToggle(sd)}
                  >
                    {sd.disabled ? "Enable" : "Disable"}
                  </button>
                  <button
                    type="button"
                    class="btn"
                    style="padding: 0.3rem 0.65rem; font-size: 0.85rem; background: var(--danger);"
                    disabled={busy()}
                    onClick={() => onDelete(sd)}
                  >
                    Delete
                  </button>
                </div>
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
    </>
  );
}
