/* Second-factor prompt — TOTP, recovery code, and WebAuthn paths.
 *
 * Server signals via 401 + `{error: "two_factor_required",
 * two_factor_token, two_factor_providers, webauthn_challenge?}` on the
 * password grant. We carry the in-memory `PendingLogin` (email, mph,
 * master key) and retry the same grant with the second-factor envelope.
 *
 * WebAuthn (C.2a): when the challenge body includes `webauthn_challenge`,
 * we render a "Use security key / passkey" button that decodes the
 * challenge, calls `navigator.credentials.get()`, encodes the assertion
 * for the server, and JSON-stringifies it into `two_factor_value`. If
 * WebAuthn is the only enrolled factor (no TOTP, no recovery), we
 * auto-trigger so the OS sheet pops without an extra click.
 */
import { createSignal, onMount, Show } from "solid-js";

import {
  completeTwoFactor,
  type PendingLogin,
  type TwoFactorChallenge,
} from "../../lib/auth";
import { decodeRequestOptions, encodeCredentialForServer } from "../../lib/webauthn";

type Provider = "totp" | "recovery";

export interface TwoFactorProps {
  pending: PendingLogin;
  challenge: TwoFactorChallenge;
  rememberMe: boolean;
  onAuthenticated: () => void;
  onCancel: () => void;
}

export function TwoFactor(props: TwoFactorProps) {
  const [provider, setProvider] = createSignal<Provider>("totp");
  const [value, setValue] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [webauthnRunning, setWebauthnRunning] = createSignal(false);

  const providers = props.challenge.twoFactorProviders;
  const hasWebauthn =
    providers.includes("webauthn") && !!props.challenge.webauthnChallenge;
  const hasTotp = providers.includes("totp");
  const hasRecovery = providers.includes("recovery");
  const codeProviders = providers.filter(
    (p): p is Provider => p === "totp" || p === "recovery",
  );

  // Auto-trigger WebAuthn if it's the only enrolled factor — the OS
  // sheet pops immediately and the user doesn't have to click through
  // a button that says nothing else can be done from here.
  onMount(() => {
    if (hasWebauthn && !hasTotp && !hasRecovery) {
      void runWebauthn();
    }
  });

  async function runWebauthn() {
    if (webauthnRunning()) return;
    setError(null);
    setWebauthnRunning(true);
    try {
      const opts = decodeRequestOptions(props.challenge.webauthnChallenge);
      const cred = (await navigator.credentials.get(opts)) as PublicKeyCredential | null;
      if (!cred) throw new Error("authenticator returned no credential");
      const wire = encodeCredentialForServer(cred);
      await completeTwoFactor(
        props.pending,
        props.challenge,
        "webauthn",
        JSON.stringify(wire),
        props.rememberMe,
      );
      props.onAuthenticated();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setWebauthnRunning(false);
    }
  }

  async function onSubmitCode(e: Event) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await completeTwoFactor(
        props.pending,
        props.challenge,
        provider(),
        value().trim(),
        props.rememberMe,
      );
      props.onAuthenticated();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  }

  // No code-based factor and no WebAuthn challenge ⇒ server enrolled
  // an unknown provider. Surface clearly so the user can fall back.
  const nothingUsable = !hasWebauthn && codeProviders.length === 0;

  return (
    <main class="page">
      <h1>Two-factor required</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Master password verified. Now finish unlocking with your second factor.
      </p>

      <Show when={nothingUsable}>
        <div class="banner banner-error">
          The server reported a second-factor type the web vault can't
          handle. Use the browser extension or the <code>hekate</code> CLI
          to unlock.
        </div>
      </Show>

      <Show when={hasWebauthn}>
        <div class="card">
          <p style="margin: 0 0 0.5rem;">
            <strong>Security key / passkey</strong>
          </p>
          <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.9rem;">
            Touch your authenticator to finish unlocking.
          </p>
          <Show when={error() && webauthnRunning() === false}>
            <div class="banner banner-error">{error()}</div>
          </Show>
          <button
            class="btn"
            type="button"
            disabled={webauthnRunning()}
            onClick={() => void runWebauthn()}
          >
            {webauthnRunning() ? "Touch your authenticator…" : "Use security key / passkey"}
          </button>
        </div>
      </Show>

      <Show when={codeProviders.length > 0}>
        <form class="card" onSubmit={onSubmitCode}>
          <Show when={codeProviders.length > 1}>
            <div
              class="field"
              role="radiogroup"
              aria-label="Second-factor method"
            >
              <label>Method</label>
              <div style="display:flex; gap:0.5rem;">
                <label style="display:flex; gap:0.35rem; align-items:center;">
                  <input
                    type="radio"
                    name="provider"
                    checked={provider() === "totp"}
                    onChange={() => setProvider("totp")}
                  />
                  Authenticator code
                </label>
                <label style="display:flex; gap:0.35rem; align-items:center;">
                  <input
                    type="radio"
                    name="provider"
                    checked={provider() === "recovery"}
                    onChange={() => setProvider("recovery")}
                  />
                  Recovery code
                </label>
              </div>
            </div>
          </Show>
          <div class="field">
            <label for="totp">
              {provider() === "totp" ? "6-digit code" : "Recovery code"}
            </label>
            <input
              id="totp"
              type="text"
              inputmode={provider() === "totp" ? "numeric" : "text"}
              autocomplete="one-time-code"
              required
              autofocus={!hasWebauthn}
              value={value()}
              onInput={(e) => setValue(e.currentTarget.value)}
            />
          </div>
          <Show when={error() && !webauthnRunning()}>
            <div class="banner banner-error">{error()}</div>
          </Show>
          <div style="display:flex; gap:0.5rem;">
            <button class="btn" type="submit" disabled={submitting()}>
              {submitting() ? "Verifying…" : "Verify"}
            </button>
            <button
              class="btn btn-secondary"
              type="button"
              onClick={props.onCancel}
              disabled={submitting()}
            >
              Cancel
            </button>
          </div>
        </form>
      </Show>

      <Show when={!codeProviders.length && hasWebauthn}>
        <p class="muted" style="font-size: 0.85rem; margin-top: 1rem;">
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              props.onCancel();
            }}
          >Cancel and start over</a>
        </p>
      </Show>
    </main>
  );
}
