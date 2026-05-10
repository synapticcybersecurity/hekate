/* New-account registration form (C.2b).
 *
 * Three-field form (email + master pw + repeat) → runs the
 * lib/register.ts pipeline. On success the in-memory session is
 * already populated, so the parent routes straight into the
 * unlocked shell.
 */
import { createSignal, onMount, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { register } from "../../lib/register";
import { loadHints } from "../../lib/session";
import { loadHekateCore } from "../../wasm";

const MIN_LENGTH = 8;

export interface RegisterProps {
  onRegistered: () => void;
  onBackToLogin: () => void;
}

export function Register(props: RegisterProps) {
  const hints = loadHints();
  const [email, setEmail] = createSignal(hints.email ?? "");
  const [pw, setPw] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [rememberMe, setRememberMe] = createSignal(hints.rememberMe);
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Warm WASM so the first Argon2id derive doesn't pay the load cost.
  onMount(() => {
    void loadHekateCore().catch(() => undefined);
  });

  function localValidate(): string | null {
    if (!email().trim()) return "Email required.";
    if (!email().includes("@")) return "Invalid email address.";
    if (!pw()) return "Master password required.";
    if (pw().length < MIN_LENGTH) {
      return `Master password must be at least ${MIN_LENGTH} characters.`;
    }
    if (pw() !== confirm()) return "Passwords do not match.";
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
      await register(email(), pw(), rememberMe());
      props.onRegistered();
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
    <main class="page">
      <h1>Create account</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Pick a strong master password — Hekate has no recovery route if
        you forget it. Key derivation runs in your browser; the server
        only ever sees a hashed verifier.
      </p>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="reg-email">Email</label>
          <input
            id="reg-email"
            type="email"
            autocomplete="username"
            required
            autofocus={!hints.email}
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="reg-pw">Master password</label>
          <input
            id="reg-pw"
            type="password"
            autocomplete="new-password"
            required
            minlength={MIN_LENGTH}
            value={pw()}
            onInput={(e) => setPw(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="reg-confirm">Repeat master password</label>
          <input
            id="reg-confirm"
            type="password"
            autocomplete="new-password"
            required
            value={confirm()}
            onInput={(e) => setConfirm(e.currentTarget.value)}
          />
        </div>
        <label
          style="display: flex; gap: 0.5rem; align-items: center; margin: 0 0 1rem; font-size: 0.95rem;"
        >
          <input
            type="checkbox"
            checked={rememberMe()}
            onChange={(e) => setRememberMe(e.currentTarget.checked)}
          />
          Remember me on this browser
        </label>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Deriving key…" : "Create account"}
          </button>
          <button
            class="btn btn-secondary"
            type="button"
            disabled={submitting()}
            onClick={props.onBackToLogin}
          >
            Back to login
          </button>
        </div>
      </form>

      <p class="muted" style="font-size: 0.85rem; margin-top: 1rem;">
        Already have an account? <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            props.onBackToLogin();
          }}
        >Log in instead</a>.
      </p>
    </main>
  );
}
