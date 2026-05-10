/* New text Send — create form.
 *
 * Mirrors `renderNewSend` + `onCreateTextSend` from popup.js. The
 * server only sees ciphertext + opaque metadata; the send_key never
 * leaves the browser (returned via the URL fragment to recipients).
 */
import { createSignal, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { b64encode } from "../../lib/base64";
import { createSend } from "../../lib/sendApi";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import { SubShell } from "../../ui/Shell";

const enc = new TextEncoder();

export interface NewTextSendProps {
  onCancel: () => void;
  /** Called with the recipient share URL after a successful create. */
  onCreated: (url: string) => void;
}

export function NewTextSend(props: NewTextSendProps) {
  const [name, setName] = createSignal("");
  const [body, setBody] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [maxAccess, setMaxAccess] = createSignal("");
  const [ttl, setTtl] = createSignal("7d");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!name().trim()) {
      setError("Name is required.");
      return;
    }
    if (!body().trim()) {
      setError("Body is required.");
      return;
    }
    setSubmitting(true);
    setError(null);

    try {
      const session = getSession();
      if (!session) throw new Error("session expired");
      const hekate = await loadHekateCore();

      const sendId = crypto.randomUUID();
      const sendKey = hekate.sendGenerateKey();

      const dataWire = hekate.sendEncryptText(sendKey, sendId, enc.encode(body()));
      const protectedSendKey = hekate.encStringEncryptXc20p(
        "ak:1",
        session.accountKey,
        sendKey,
        hekate.sendKeyWrapAad(sendId),
      );
      const nameWire = hekate.encStringEncryptXc20p(
        "ak:1",
        session.accountKey,
        enc.encode(name().trim()),
        hekate.sendNameAad(sendId),
      );

      const deletionDate = new Date(Date.now() + parseTtlMs(ttl())).toISOString();
      const max = parseInt(maxAccess(), 10);

      await createSend({
        id: sendId,
        send_type: 1,
        name: nameWire,
        protected_send_key: protectedSendKey,
        data: dataWire,
        deletion_date: deletionDate,
        disabled: false,
        ...(password() ? { password: password() } : {}),
        ...(Number.isFinite(max) && max > 0 ? { max_access_count: max } : {}),
      });

      const url = `${window.location.origin}/send/#/${sendId}/${hekate.sendEncodeKey(sendKey)}`;
      // Suppress unused import warning when no password is set.
      void b64encode;
      props.onCreated(url);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setSubmitting(false);
    }
  }

  return (
    <SubShell title="New text share" onBack={props.onCancel}>
      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="send-name">
            Display name <span class="muted">(sender-side; recipients won't see this)</span>
          </label>
          <input
            id="send-name"
            type="text"
            required
            autofocus
            placeholder="e.g. Wifi for Alice"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="send-body">Body (text)</label>
          <textarea
            id="send-body"
            class="input"
            rows={6}
            required
            value={body()}
            onInput={(e) => setBody(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="send-password">
            Access password <span class="muted">(optional gate)</span>
          </label>
          <input
            id="send-password"
            type="password"
            autocomplete="new-password"
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="send-max">
            Max accesses <span class="muted">(blank = unlimited)</span>
          </label>
          <input
            id="send-max"
            type="number"
            min="1"
            placeholder="e.g. 3"
            value={maxAccess()}
            onInput={(e) => setMaxAccess(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="send-ttl">TTL — auto-delete after</label>
          <select
            id="send-ttl"
            class="input"
            value={ttl()}
            onChange={(e) => setTtl(e.currentTarget.value)}
          >
            <option value="1h">1 hour</option>
            <option value="1d">1 day</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
          </select>
        </div>

        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>

        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Creating…" : "Create + copy URL"}
          </button>
          <button
            class="btn btn-secondary"
            type="button"
            disabled={submitting()}
            onClick={props.onCancel}
          >
            Cancel
          </button>
        </div>
      </form>
    </SubShell>
  );
}

function parseTtlMs(s: string): number {
  const m = /^(\d+)([smhd])$/.exec(String(s).trim());
  if (!m) return 7 * 86400 * 1000;
  const n = parseInt(m[1], 10);
  const mul: Record<string, number> = {
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };
  return n * (mul[m[2]] ?? 86_400_000);
}
