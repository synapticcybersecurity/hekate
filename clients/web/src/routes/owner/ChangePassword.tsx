/* Change master password (C.7d-2).
 *
 * Three-field form (current pw / new pw / repeat new pw) → triggers the
 * lib/changePassword.ts pipeline. Same SubShell pattern as RotateKeys.
 *
 * Client-side checks before any keys are derived (length, match, differ
 * from current). Server-side verification of the current password is
 * the source of truth — the client check is just to avoid a round-trip
 * on obvious typos.
 */
import { createSignal, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { changePassword } from "../../lib/changePassword";
import { SubShell } from "../../ui/Shell";

const MIN_LENGTH = 8;

export interface ChangePasswordProps {
  onCancel: () => void;
  onDone: () => void;
}

export function ChangePassword(props: ChangePasswordProps) {
  const [current, setCurrent] = createSignal("");
  const [next, setNext] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  function localValidate(): string | null {
    if (!current()) return "Current master password required.";
    if (!next()) return "New master password required.";
    if (next().length < MIN_LENGTH) {
      return `New master password must be at least ${MIN_LENGTH} characters.`;
    }
    if (next() !== confirm()) return "New passwords do not match.";
    if (current() === next()) {
      return "New master password must differ from the current one.";
    }
    return null;
  }

  async function onSubmit(e: Event) {
    e.preventDefault();
    const localErr = localValidate();
    if (localErr) {
      setError(localErr);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await changePassword(current(), next());
      props.onDone();
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
    <SubShell title="Change master password" onBack={props.onCancel}>
      <p class="muted" style="margin: 0 0 0.85rem;">
        Rotates your KDF salt + master_password_hash + the wrapping of
        your <code>account_key</code> + your BW04 signing key. The
        unwrapped account key is unchanged, so all your ciphers, shares,
        and orgs keep decrypting. Other devices will be logged out and
        need to re-authenticate.
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
        2FA-enabled accounts are fine — no second-factor challenge is
        needed because re-auth is via the current master password.
      </p>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="cp-current">Current master password</label>
          <input
            id="cp-current"
            type="password"
            autocomplete="current-password"
            required
            autofocus
            value={current()}
            onInput={(e) => setCurrent(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="cp-new">New master password</label>
          <input
            id="cp-new"
            type="password"
            autocomplete="new-password"
            required
            minlength={MIN_LENGTH}
            value={next()}
            onInput={(e) => setNext(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="cp-confirm">Repeat new master password</label>
          <input
            id="cp-confirm"
            type="password"
            autocomplete="new-password"
            required
            value={confirm()}
            onInput={(e) => setConfirm(e.currentTarget.value)}
          />
        </div>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Changing…" : "Change password"}
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
