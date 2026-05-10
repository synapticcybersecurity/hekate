/* TOTP + WebAuthn 2FA settings (C.7d-1 + C.2a).
 *
 * Status → Enable / Disable / Regenerate recovery codes for TOTP, plus
 * full WebAuthn passkey management (enroll / list / rename / delete).
 * Mirrors the popup's two-step TOTP enrollment (QR scan → manual
 * fallback collapsed in <details> → 6-digit confirm → recovery codes
 * shown on a dedicated screen) and the popup's WebAuthn flow (master-pw
 * re-auth → register/start → navigator.credentials.create →
 * register/finish).
 *
 * Phase machine — single SubShell with the contents swapped per phase
 * rather than separate routed sub-views, because the panel transitions
 * are a self-contained flow (phase starts at "status" and returns to it
 * after every action, except enrollment which lands on "show-codes").
 *
 * Re-auth pattern: every privileged endpoint takes a master_password_hash
 * computed by re-running prelogin + Argon2 + the BW07/LP04 verification
 * chain. The pw never leaves this component; only the derived MPH does.
 */
import { createSignal, For, Match, onMount, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import { loadHekateCore } from "../../wasm";
import { getSession } from "../../lib/session";
import {
  confirmTotpEnrollment,
  deriveMphB64,
  disableTotp,
  getTwoFactorStatus,
  regenerateRecoveryCodes,
  startTotpEnrollment,
  type TotpSetupResponse,
  type TwoFactorStatus,
} from "../../lib/twoFactorApi";
import {
  decodeCreationOptions,
  encodeCredentialForServer,
  listWebauthnCredentials,
  webauthnDeleteCredential,
  webauthnRegisterFinish,
  webauthnRegisterStart,
  webauthnRenameCredential,
  type WebauthnCredential,
} from "../../lib/webauthn";
import { SubShell } from "../../ui/Shell";

export interface TwoFactorSettingsProps {
  onBack: () => void;
  onSessionExpired: () => void;
}

type Phase =
  | { kind: "loading" }
  | { kind: "load-error"; message: string }
  | { kind: "status"; status: TwoFactorStatus; webauthn: WebauthnCredential[] }
  | {
      kind: "enable-prompt";
      // True once the user submits — keeps the Cancel button live but
      // disables the form submit while we round-trip prelogin + setup.
      submitting: boolean;
    }
  | { kind: "enroll-scan"; setup: TotpSetupResponse; qrSvg: string | null }
  | { kind: "disable-prompt"; submitting: boolean }
  | { kind: "regenerate-prompt"; submitting: boolean }
  | { kind: "show-codes"; codes: string[]; afterEnroll: boolean }
  | {
      kind: "webauthn-enroll-prompt";
      submitting: boolean;
      message: string | null;
    };

export function TwoFactorSettings(props: TwoFactorSettingsProps) {
  const [phase, setPhase] = createSignal<Phase>({ kind: "loading" });

  onMount(() => {
    void refreshStatus();
  });

  async function refreshStatus(): Promise<void> {
    setPhase({ kind: "loading" });
    try {
      const [status, webauthn] = await Promise.all([
        getTwoFactorStatus(),
        listWebauthnCredentials(),
      ]);
      setPhase({ kind: "status", status, webauthn });
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
    }
  }

  return (
    <SubShell title="Two-factor authentication" onBack={props.onBack}>
      <Switch>
        <Match when={phase().kind === "loading"}>
          <p class="muted">Loading…</p>
        </Match>

        <Match when={phase().kind === "load-error"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "load-error" }>;
            return (
              <>
                <div class="banner banner-error">{p.message}</div>
                <button class="btn btn-secondary" onClick={() => void refreshStatus()}>
                  Retry
                </button>
              </>
            );
          })()}
        </Match>

        <Match when={phase().kind === "status"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "status" }>;
            return (
              <StatusPanel
                status={p.status}
                webauthn={p.webauthn}
                onEnable={() => setPhase({ kind: "enable-prompt", submitting: false })}
                onDisable={() => setPhase({ kind: "disable-prompt", submitting: false })}
                onRegenerate={() =>
                  setPhase({ kind: "regenerate-prompt", submitting: false })
                }
                onWebauthnEnroll={() =>
                  setPhase({
                    kind: "webauthn-enroll-prompt",
                    submitting: false,
                    message: null,
                  })
                }
                onWebauthnRename={(id, current) => void onWebauthnRename(id, current)}
                onWebauthnDelete={(id, name) => void onWebauthnDelete(id, name)}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "enable-prompt"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "enable-prompt" }>;
            return (
              <PasswordPrompt
                title="Enable TOTP"
                explainer="Re-enter your master password. We'll generate a fresh secret and recovery codes; nothing's active until you confirm a code from your authenticator."
                submitLabel="Continue"
                submitting={p.submitting}
                onCancel={() => void refreshStatus()}
                onSubmit={(pw) => void onEnableSubmit(pw)}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "enroll-scan"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "enroll-scan" }>;
            return (
              <EnrollScanPanel
                setup={p.setup}
                qrSvg={p.qrSvg}
                onCancel={() => void refreshStatus()}
                onConfirmed={(codes) =>
                  setPhase({ kind: "show-codes", codes, afterEnroll: true })
                }
                onSessionExpired={props.onSessionExpired}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "disable-prompt"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "disable-prompt" }>;
            return (
              <PasswordPrompt
                title="Disable TOTP"
                explainer="Disabling TOTP wipes all recovery codes and invalidates every other session for this account. Re-enter your master password to confirm."
                submitLabel="Disable TOTP"
                submitting={p.submitting}
                destructive
                onCancel={() => void refreshStatus()}
                onSubmit={(pw) => void onDisableSubmit(pw)}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "regenerate-prompt"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "regenerate-prompt" }>;
            return (
              <PasswordPrompt
                title="Regenerate recovery codes"
                explainer="All existing recovery codes (consumed and unconsumed) are invalidated and replaced with a new set. No vault keys rotate."
                submitLabel="Regenerate codes"
                submitting={p.submitting}
                onCancel={() => void refreshStatus()}
                onSubmit={(pw) => void onRegenerateSubmit(pw)}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "show-codes"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "show-codes" }>;
            return (
              <RecoveryCodesPanel
                codes={p.codes}
                afterEnroll={p.afterEnroll}
                onDone={() => void refreshStatus()}
              />
            );
          })()}
        </Match>

        <Match when={phase().kind === "webauthn-enroll-prompt"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "webauthn-enroll-prompt" }>;
            return (
              <WebauthnEnrollPanel
                submitting={p.submitting}
                message={p.message}
                onCancel={() => void refreshStatus()}
                onSubmit={(name, pw) => void onWebauthnEnrollSubmit(name, pw)}
              />
            );
          })()}
        </Match>
      </Switch>
    </SubShell>
  );

  // --- phase actions ------------------------------------------------------

  async function onEnableSubmit(pw: string): Promise<void> {
    setPhase({ kind: "enable-prompt", submitting: true });
    let mphB64: string;
    try {
      mphB64 = await deriveMphB64(pw);
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
      return;
    }
    const session = getSession();
    const label = session?.email ?? "hekate";
    let setup: TotpSetupResponse;
    try {
      setup = await startTotpEnrollment(mphB64, label);
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
      return;
    }
    let qrSvg: string | null = null;
    try {
      const hekate = await loadHekateCore();
      qrSvg = hekate.qrCodeSvg(setup.otpauth_url);
    } catch (err) {
      // Non-fatal — manual entry still works through the fallback
      // <details>. Log so a real bug shows up in the console.
      console.warn("qr render failed", err);
    }
    setPhase({ kind: "enroll-scan", setup, qrSvg });
  }

  async function onDisableSubmit(pw: string): Promise<void> {
    setPhase({ kind: "disable-prompt", submitting: true });
    try {
      const mphB64 = await deriveMphB64(pw);
      await disableTotp(mphB64);
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
      return;
    }
    await refreshStatus();
  }

  async function onRegenerateSubmit(pw: string): Promise<void> {
    setPhase({ kind: "regenerate-prompt", submitting: true });
    try {
      const mphB64 = await deriveMphB64(pw);
      const resp = await regenerateRecoveryCodes(mphB64);
      setPhase({ kind: "show-codes", codes: resp.recovery_codes, afterEnroll: false });
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
    }
  }

  async function onWebauthnEnrollSubmit(rawName: string, pw: string): Promise<void> {
    const name = rawName.trim();
    if (!name) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: "Name required (1..64 chars)." });
      return;
    }
    if (name.length > 64) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: "Name must be 64 characters or fewer." });
      return;
    }
    setPhase({ kind: "webauthn-enroll-prompt", submitting: true, message: "Working…" });
    let mphB64: string;
    try {
      mphB64 = await deriveMphB64(pw);
    } catch (err) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: errMsg(err) });
      return;
    }
    let creationOptions: unknown;
    try {
      const start = await webauthnRegisterStart(mphB64, name);
      creationOptions = start.creation_options;
    } catch (err) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: errMsg(err) });
      return;
    }
    setPhase({ kind: "webauthn-enroll-prompt", submitting: true, message: "Touch your authenticator…" });
    let credential: PublicKeyCredential | null;
    try {
      const opts = decodeCreationOptions(creationOptions);
      credential = (await navigator.credentials.create(opts)) as PublicKeyCredential | null;
    } catch (err) {
      setPhase({
        kind: "webauthn-enroll-prompt",
        submitting: false,
        message: `Authenticator declined: ${err instanceof Error ? err.message : String(err)}`,
      });
      return;
    }
    if (!credential) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: "No credential produced." });
      return;
    }
    try {
      await webauthnRegisterFinish(encodeCredentialForServer(credential));
    } catch (err) {
      setPhase({ kind: "webauthn-enroll-prompt", submitting: false, message: `Server rejected: ${errMsg(err)}` });
      return;
    }
    await refreshStatus();
  }

  async function onWebauthnRename(id: string, current: string): Promise<void> {
    const next = window.prompt("New name:", current);
    if (next == null) return;
    const trimmed = next.trim();
    if (!trimmed || trimmed.length > 64) {
      window.alert("Name must be 1..64 characters.");
      return;
    }
    try {
      await webauthnRenameCredential(id, trimmed);
    } catch (err) {
      window.alert(`Rename failed: ${errMsg(err)}`);
      return;
    }
    await refreshStatus();
  }

  async function onWebauthnDelete(id: string, name: string): Promise<void> {
    if (
      !window.confirm(
        `Delete credential "${name}"? You'll no longer be able to authenticate with it. This cannot be undone.`,
      )
    ) {
      return;
    }
    try {
      await webauthnDeleteCredential(id);
    } catch (err) {
      window.alert(`Delete failed: ${errMsg(err)}`);
      return;
    }
    await refreshStatus();
  }
}

// --- sub-panels -----------------------------------------------------------

interface StatusPanelProps {
  status: TwoFactorStatus;
  webauthn: WebauthnCredential[];
  onEnable: () => void;
  onDisable: () => void;
  onRegenerate: () => void;
  onWebauthnEnroll: () => void;
  onWebauthnRename: (id: string, currentName: string) => void;
  onWebauthnDelete: (id: string, name: string) => void;
}

function StatusPanel(props: StatusPanelProps) {
  const lowCodes = () =>
    props.status.enabled && props.status.recovery_codes_remaining <= 3;

  return (
    <>
      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>TOTP (authenticator app)</strong>
        </p>
        <Show
          when={props.status.enabled}
          fallback={
            <>
              <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
                Not enabled. Adding TOTP means a one-time code from your
                authenticator app is required at every login, in addition to
                your master password.
              </p>
              <button class="btn" onClick={props.onEnable}>
                Enable TOTP…
              </button>
            </>
          }
        >
          <p style="margin: 0 0 0.4rem;">
            Enabled. Recovery codes remaining:{" "}
            <strong>{props.status.recovery_codes_remaining}</strong>
            <Show when={lowCodes()}>
              <span class="muted"> (consider regenerating)</span>
            </Show>
          </p>
          <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
            Recovery codes authenticate when your authenticator is gone.
            They do <strong>not</strong> decrypt the vault — the master
            password is the only path to plaintext.
          </p>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <button class="btn btn-secondary" onClick={props.onDisable}>
              Disable TOTP
            </button>
            <button class="btn btn-secondary" onClick={props.onRegenerate}>
              Regenerate recovery codes
            </button>
          </div>
        </Show>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Security keys / passkeys (WebAuthn)</strong>
        </p>
        <Show
          when={props.webauthn.length > 0}
          fallback={
            <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
              No security keys enrolled. Enrolling a passkey or hardware
              key adds a phishing-resistant second factor.
            </p>
          }
        >
          <ul style="list-style: none; margin: 0 0 0.85rem; padding: 0;">
            <For each={props.webauthn}>
              {(c) => (
                <li style="border-top: 1px solid var(--border); padding: 0.6rem 0;">
                  <p style="margin: 0 0 0.2rem; font-weight: 500;">{c.name}</p>
                  <p class="muted" style="margin: 0 0 0.4rem; font-size: 0.8rem;">
                    added {(c.created_at || "").slice(0, 10)}
                    <Show when={c.last_used_at}>
                      {" · last used "}
                      {(c.last_used_at ?? "").slice(0, 10)}
                    </Show>
                  </p>
                  <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
                    <button
                      class="btn btn-secondary"
                      type="button"
                      style="padding: 0.3rem 0.75rem; font-size: 0.85rem;"
                      onClick={() => props.onWebauthnRename(c.id, c.name)}
                    >
                      Rename
                    </button>
                    <button
                      class="btn btn-secondary"
                      type="button"
                      style="padding: 0.3rem 0.75rem; font-size: 0.85rem; border-color: var(--danger); color: var(--danger);"
                      onClick={() => props.onWebauthnDelete(c.id, c.name)}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <button class="btn" type="button" onClick={props.onWebauthnEnroll}>
          Add security key / passkey…
        </button>
      </div>
    </>
  );
}

interface PasswordPromptProps {
  title: string;
  explainer: string;
  submitLabel: string;
  submitting: boolean;
  destructive?: boolean;
  onCancel: () => void;
  onSubmit: (password: string) => void;
}

function PasswordPrompt(props: PasswordPromptProps) {
  const [pw, setPw] = createSignal("");

  function onFormSubmit(e: Event) {
    e.preventDefault();
    if (!pw() || props.submitting) return;
    props.onSubmit(pw());
  }

  return (
    <form class="card" onSubmit={onFormSubmit}>
      <p style="margin: 0 0 0.4rem;">
        <strong>{props.title}</strong>
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
        {props.explainer}
      </p>
      <div class="field">
        <label for="twofa-pw">Master password</label>
        <input
          id="twofa-pw"
          type="password"
          autocomplete="current-password"
          required
          autofocus
          value={pw()}
          onInput={(e) => setPw(e.currentTarget.value)}
        />
      </div>
      <div style="display: flex; gap: 0.5rem;">
        <button
          class="btn"
          type="submit"
          disabled={props.submitting || !pw()}
          style={props.destructive ? "background: var(--danger);" : ""}
        >
          {props.submitting ? "Working…" : props.submitLabel}
        </button>
        <button
          class="btn btn-secondary"
          type="button"
          disabled={props.submitting}
          onClick={props.onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

interface WebauthnEnrollPanelProps {
  submitting: boolean;
  message: string | null;
  onCancel: () => void;
  onSubmit: (name: string, password: string) => void;
}

function WebauthnEnrollPanel(props: WebauthnEnrollPanelProps) {
  // name + pw stay LOCAL — keeping them in the parent's phase signal
  // would cause the input to lose focus on every keystroke (the Switch
  // re-runs the IIFE that creates this component each phase update).
  const [name, setName] = createSignal("");
  const [pw, setPw] = createSignal("");

  function onFormSubmit(e: Event) {
    e.preventDefault();
    if (props.submitting) return;
    if (!name().trim() || !pw()) return;
    props.onSubmit(name(), pw());
  }

  return (
    <form class="card" onSubmit={onFormSubmit}>
      <p style="margin: 0 0 0.4rem;">
        <strong>Add security key / passkey</strong>
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
        Re-enter your master password and pick a label for this
        credential. After you submit, your browser will prompt you to
        touch / present the authenticator.
      </p>
      <div class="field">
        <label for="wa-name">Credential name</label>
        <input
          id="wa-name"
          type="text"
          required
          autofocus
          maxlength="64"
          placeholder="YubiKey 5C, MacBook Touch ID, …"
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
        />
      </div>
      <div class="field">
        <label for="wa-pw">Master password</label>
        <input
          id="wa-pw"
          type="password"
          autocomplete="current-password"
          required
          value={pw()}
          onInput={(e) => setPw(e.currentTarget.value)}
        />
      </div>
      <Show when={props.message}>
        <div class="banner banner-error">{props.message}</div>
      </Show>
      <div style="display: flex; gap: 0.5rem;">
        <button
          class="btn"
          type="submit"
          disabled={props.submitting || !name().trim() || !pw()}
        >
          {props.submitting ? "Working…" : "Continue"}
        </button>
        <button
          class="btn btn-secondary"
          type="button"
          disabled={props.submitting}
          onClick={props.onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

interface EnrollScanPanelProps {
  setup: TotpSetupResponse;
  qrSvg: string | null;
  onCancel: () => void;
  onConfirmed: (codes: string[]) => void;
  onSessionExpired: () => void;
}

function EnrollScanPanel(props: EnrollScanPanelProps) {
  const [code, setCode] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [secretCopied, setSecretCopied] = createSignal(false);
  const [urlCopied, setUrlCopied] = createSignal(false);

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!/^\d{6}$/.test(code())) {
      setError("Enter the 6-digit code your authenticator shows.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await confirmTotpEnrollment(code());
      props.onConfirmed(props.setup.recovery_codes);
    } catch (err) {
      setError(errMsg(err));
      setSubmitting(false);
    }
  }

  async function copy(text: string, which: "secret" | "url") {
    try {
      await navigator.clipboard.writeText(text);
      if (which === "secret") {
        setSecretCopied(true);
        setTimeout(() => setSecretCopied(false), 1200);
      } else {
        setUrlCopied(true);
        setTimeout(() => setUrlCopied(false), 1200);
      }
    } catch {
      /* clipboard refusal; user can manually select */
    }
  }

  return (
    <>
      <p style="margin: 0 0 0.5rem;">
        Scan this QR with your authenticator (1Password, Aegis, Google
        Authenticator, …):
      </p>
      <Show
        when={props.qrSvg}
        fallback={
          <p class="muted">(QR rendering failed — use the secret below.)</p>
        }
      >
        {/* SVG comes from our WASM binding (no untrusted input). */}
        <div class="totp-qr" innerHTML={props.qrSvg ?? ""} />
      </Show>

      <details class="totp-fallback">
        <summary>Trouble scanning? Enter the secret manually</summary>
        <p class="muted" style="font-size: 0.85rem; margin: 0.4rem 0;">
          Most authenticators take either form.
        </p>
        <p style="margin: 0.4rem 0;">
          <strong>Secret:</strong>{" "}
          <code>{props.setup.secret_b32}</code>{" "}
          <button
            class="btn btn-secondary"
            type="button"
            style="padding: 0.25rem 0.6rem; font-size: 0.85rem;"
            onClick={() => void copy(props.setup.secret_b32, "secret")}
          >
            {secretCopied() ? "Copied" : "Copy"}
          </button>
        </p>
        <p class="muted" style="font-size: 0.85rem; margin: 0.4rem 0;">
          Or paste this <code>otpauth://</code> URL into the app:
        </p>
        <p style="margin: 0.4rem 0;">
          <code>{props.setup.otpauth_url}</code>{" "}
          <button
            class="btn btn-secondary"
            type="button"
            style="padding: 0.25rem 0.6rem; font-size: 0.85rem;"
            onClick={() => void copy(props.setup.otpauth_url, "url")}
          >
            {urlCopied() ? "Copied" : "Copy URL"}
          </button>
        </p>
      </details>

      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="totp-code">Enter the 6-digit code your app shows</label>
          <input
            id="totp-code"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            required
            autofocus
            pattern="[0-9]{6}"
            maxlength="6"
            value={code()}
            onInput={(e) => setCode(e.currentTarget.value)}
          />
        </div>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Confirming…" : "Confirm + enable"}
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
    </>
  );
}

interface RecoveryCodesPanelProps {
  codes: string[];
  afterEnroll: boolean;
  onDone: () => void;
}

function RecoveryCodesPanel(props: RecoveryCodesPanelProps) {
  const [copied, setCopied] = createSignal(false);
  const text = () => props.codes.join("\n");

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(text());
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard refusal */
    }
  }

  return (
    <div class="card">
      <p style="margin: 0 0 0.5rem;">
        <strong>
          {props.afterEnroll
            ? "TOTP enabled — save these recovery codes now."
            : "New recovery codes — save them now."}
        </strong>
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
        Shown once. Each code works once and authenticates when your
        authenticator is gone — they do <strong>not</strong> decrypt the
        vault.
      </p>
      <pre class="recovery-codes">{text()}</pre>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn btn-secondary" type="button" onClick={() => void onCopy()}>
          {copied() ? "Copied" : "Copy all"}
        </button>
        <button class="btn" type="button" onClick={props.onDone}>
          I've saved them — done
        </button>
      </div>
    </div>
  );
}

// --- helpers --------------------------------------------------------------

function errMsg(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
