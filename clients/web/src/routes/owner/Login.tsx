/* Login form for owner mode.
 *
 * Same-origin: server URL is implicit, no field needed (the SPA is
 * served by the hekate-server it talks to).
 *
 * Pre-fills email + remember-me from localStorage hints. The actual
 * key derivation, BW07 mitigations, and token exchange live in
 * `lib/auth.ts`.
 */
import { createSignal, onMount, Show } from "solid-js";

import { login, type LoginResult } from "../../lib/auth";
import { loadHints } from "../../lib/session";
import { loadHekateCore } from "../../wasm";

export interface LoginProps {
  onAuthenticated: () => void;
  onTwoFactor: (
    result: Extract<LoginResult, { kind: "needTwoFactor" }>,
    rememberMe: boolean,
  ) => void;
  onCreateAccount: () => void;
}

export function Login(props: LoginProps) {
  const hints = loadHints();
  const [email, setEmail] = createSignal(hints.email ?? "");
  const [password, setPassword] = createSignal("");
  const [rememberMe, setRememberMe] = createSignal(hints.rememberMe);
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Warm the WASM module so the first keystroke after submit doesn't
  // pay the load cost. Best-effort; surfaces nothing on failure.
  onMount(() => {
    void loadHekateCore().catch(() => undefined);
  });

  async function onSubmit(e: Event) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const result = await login(email(), password(), rememberMe());
      if (result.kind === "ok") {
        props.onAuthenticated();
        return;
      }
      props.onTwoFactor(result, rememberMe());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  }

  return (
    <main class="page">
      <h1>Hekate</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Unlock your vault. Decryption happens in your browser; the server never sees your master password.
      </p>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="email">Email</label>
          <input
            id="email"
            type="email"
            autocomplete="username"
            required
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
          />
        </div>
        <div class="field">
          <label for="password">Master password</label>
          <input
            id="password"
            type="password"
            autocomplete="current-password"
            required
            autofocus={!!hints.email}
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
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
        <button class="btn" type="submit" disabled={submitting()}>
          {submitting() ? "Deriving key…" : "Unlock"}
        </button>
      </form>

      <p class="muted" style="font-size: 0.85rem; margin-top: 1rem;">
        Remember me keeps your refresh token across browser restarts, so
        you only re-enter the master password — never the email or
        server. Without it, the token clears when you close this tab.
      </p>

      <p class="muted" style="font-size: 0.9rem; margin-top: 1rem;">
        New here? <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            props.onCreateAccount();
          }}
        >Create an account</a> on this server.
      </p>
    </main>
  );
}
