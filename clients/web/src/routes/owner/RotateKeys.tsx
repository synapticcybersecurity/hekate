/* Rotate-keys confirm screen.
 *
 * Master pw → triggers the lib/rotateKeys.ts pipeline. Toast shows
 * the rewrap counters on success (matching the popup's UX). 2FA
 * accounts get a clear "use the CLI" message because the web vault
 * doesn't drive the second-factor challenge inside this flow yet
 * (the server requires the password grant inside rotation, not the
 * existing access token).
 */
import { createSignal, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { rotateKeys, type RotateKeysSuccess } from "../../lib/rotateKeys";
import { SubShell } from "../../ui/Shell";

export interface RotateKeysProps {
  onCancel: () => void;
  onDone: (result: RotateKeysSuccess) => void;
}

export function RotateKeys(props: RotateKeysProps) {
  const [password, setPassword] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!password()) {
      setError("Master password required.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await rotateKeys(password());
      props.onDone(result);
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
    <SubShell title="Rotate account keys" onBack={props.onCancel}>
      <p class="muted" style="margin: 0 0 0.85rem;">
        Generates a fresh symmetric vault key (<code>account_key</code>)
        and re-wraps every dependent: the X25519 private key, every
        personal cipher, every Send (key + name), and every org
        membership. Master password is unchanged. Other devices keep
        working through their refresh tokens — this device gets new
        ones from the rotation response.
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
        Atomic on the server side: either every dependent is re-wrapped
        or none are. Orphaned shares are skipped with a warning rather
        than aborting the rotation.
      </p>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="rotate-pw">Master password</label>
          <input
            id="rotate-pw"
            type="password"
            autocomplete="current-password"
            required
            autofocus
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
          />
        </div>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Rotating…" : "Rotate keys"}
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
