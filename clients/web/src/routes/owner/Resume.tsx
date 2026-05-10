/* Resume — slim re-auth form for users who chose "Remember me" at
 * their last login.
 *
 * Shows on page load when localStorage has a remember-me flag + email,
 * instead of the full Login form. The flow itself is identical to
 * Login: prelogin → derive master_key → password grant → unwrap
 * protected_account_key. We can't skip the password grant because the
 * refresh-token grant doesn't carry protected_account_key, so the
 * vault stays sealed without the master password. The slim form just
 * spares the user from retyping the email field every reload.
 */
import { createSignal, onMount, Show } from "solid-js";

import { login, type LoginResult } from "../../lib/auth";
import { loadHints } from "../../lib/session";
import { loadHekateCore } from "../../wasm";

export interface ResumeProps {
  onAuthenticated: () => void;
  onTwoFactor: (
    result: Extract<LoginResult, { kind: "needTwoFactor" }>,
    rememberMe: boolean,
  ) => void;
  onUseDifferentAccount: () => void;
}

export function Resume(props: ResumeProps) {
  const hints = loadHints();
  const email = hints.email ?? "";
  const [password, setPassword] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Warm WASM so the first keystroke after submit doesn't pay the load cost.
  onMount(() => {
    void loadHekateCore().catch(() => undefined);
  });

  async function onSubmit(e: Event) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      // Always pass rememberMe=true here — we only render Resume when
      // remember-me was on at last login, and the user hasn't changed
      // their mind by clicking "Use a different account".
      const result = await login(email, password(), true);
      if (result.kind === "ok") {
        props.onAuthenticated();
        return;
      }
      props.onTwoFactor(result, true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  }

  return (
    <main class="page">
      <h1>Welcome back</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Signed in as <strong>{email}</strong>. Re-enter your master
        password to unlock — your vault key never persists across page
        reloads, even with Remember me on.
      </p>

      <form class="card" onSubmit={onSubmit}>
        <input type="email" autocomplete="username" value={email} hidden />
        <div class="field">
          <label for="password">Master password</label>
          <input
            id="password"
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
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Deriving key…" : "Unlock"}
          </button>
          <button
            class="btn btn-secondary"
            type="button"
            disabled={submitting()}
            onClick={props.onUseDifferentAccount}
          >
            Use a different account
          </button>
        </div>
      </form>
    </main>
  );
}
