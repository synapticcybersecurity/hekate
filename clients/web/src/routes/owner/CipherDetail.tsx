/* CipherDetail — read-only decrypted view of a single cipher.
 *
 * Decrypts everything (incl. notes) up front, then renders type-aware
 * fields with mask/reveal/copy controls. No edit (C.3b).
 *
 * Lives inside a SubShell so the user can return to the vault list
 * without losing scroll position there.
 */
import {
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";

import { AttachmentsSection } from "./AttachmentsSection";
import { copy } from "../../lib/clipboard";
import {
  aadProtectedCipherKey,
  CipherType,
  decryptFull,
  type CipherView,
  type DecryptedFullItem,
} from "../../lib/cipher";
import { totpCode } from "../../lib/totp";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import { IconCopy, IconEdit, IconEye, IconEyeOff, iconForCipherType } from "../../ui/icons";
import { SubShell } from "../../ui/Shell";

export interface CipherDetailProps {
  cipher: CipherView;
  onBack: () => void;
  onEdit: () => void;
}

export function CipherDetail(props: CipherDetailProps) {
  const [item, setItem] = createSignal<DecryptedFullItem | null>(null);
  // Cipher key kept alongside the decrypted view so AttachmentsSection
  // can encrypt new uploads / decrypt downloads without re-running the
  // outer unwrap. null when decryption failed (we still render the
  // placeholder fields).
  const [cipherKey, setCipherKey] = createSignal<Uint8Array | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);

  void (async () => {
    try {
      const hekate = await loadHekateCore();
      const session = getSession();
      if (!session) throw new Error("session expired");
      setItem(decryptFull(hekate, props.cipher, session.accountKey));
      try {
        const ck = hekate.encStringDecryptXc20p(
          props.cipher.protected_cipher_key,
          session.accountKey,
          aadProtectedCipherKey(props.cipher.id),
        );
        setCipherKey(ck);
      } catch {
        // Org ciphers can't unwrap with the user's account_key — the
        // attachments section just won't render in that case.
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  })();

  function showToast(msg: string) {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2200);
  }

  async function copyValue(label: string, value: string | undefined) {
    if (!value) {
      showToast(`${label} is empty`);
      return;
    }
    try {
      await copy(value);
      showToast(`${label} copied`);
    } catch (err) {
      showToast(`Copy failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Cipher type is fixed for the lifetime of this view, so resolve the
  // icon component once instead of through a memo wrapper.
  const Icon = iconForCipherType(props.cipher.type);
  const title = createMemo(() => item()?.name ?? "…");

  return (
    <SubShell
      title={title()}
      onBack={props.onBack}
      headerAction={{
        Icon: IconEdit,
        ariaLabel: "Edit",
        onClick: props.onEdit,
      }}
    >
      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>
      <Show when={item()}>
        {(it) => (
          <>
            <div
              style="display: flex; gap: 0.85rem; align-items: center; margin-bottom: 1rem;"
            >
              <span class="row-icon" data-type={props.cipher.type}>
                <Icon />
              </span>
              <div>
                <div style="font-size: 1.15rem; font-weight: 600;">{it().name}</div>
                <Show when={it().favorite}>
                  <div class="muted" style="font-size: 0.85rem;">Favorite</div>
                </Show>
              </div>
            </div>

            <div class="card">
              <TypeFields item={it()} onCopy={copyValue} />
            </div>

            <Show when={it().notes}>
              <div class="card">
                <div class="muted" style="font-size: 0.85rem; margin-bottom: 0.35rem;">
                  Notes
                </div>
                <pre class="output">{it().notes}</pre>
              </div>
            </Show>

            <Show
              when={
                cipherKey() && it().permissions !== "read_hide_passwords"
              }
            >
              <AttachmentsSection
                cipherId={props.cipher.id}
                cipherKey={cipherKey() as Uint8Array}
              />
            </Show>
          </>
        )}
      </Show>

      <Show when={toast()}>
        <div class="toast" role="status">
          {toast()}
        </div>
      </Show>
    </SubShell>
  );
}

function TypeFields(props: {
  item: DecryptedFullItem;
  onCopy: (label: string, value: string | undefined) => Promise<void>;
}) {
  const d = props.item.data ?? {};
  switch (props.item.type) {
    case CipherType.Login:
      return (
        <FieldList>
          <Field label="Username" value={str(d.username)} onCopy={props.onCopy} />
          <SecretField
            label="Password"
            value={str(d.password)}
            onCopy={props.onCopy}
          />
          <Field label="URI" value={str(d.uri)} onCopy={props.onCopy} />
        </FieldList>
      );
    case CipherType.Card:
      return (
        <FieldList>
          <Field
            label="Cardholder"
            value={str(d.cardholderName)}
            onCopy={props.onCopy}
          />
          <Field label="Brand" value={str(d.brand)} />
          <SecretField label="Number" value={str(d.number)} onCopy={props.onCopy} />
          <Field
            label="Expires"
            value={joinExpiration(str(d.expMonth), str(d.expYear))}
            onCopy={props.onCopy}
          />
          <SecretField label="CVV" value={str(d.code)} onCopy={props.onCopy} />
        </FieldList>
      );
    case CipherType.Identity:
      return (
        <FieldList>
          <Field
            label="Name"
            value={joinName(d)}
            onCopy={props.onCopy}
          />
          <Field label="Email" value={str(d.email)} onCopy={props.onCopy} />
          <Field label="Phone" value={str(d.phone)} onCopy={props.onCopy} />
          <Field label="Address" value={joinAddress(d)} onCopy={props.onCopy} />
          <SecretField label="SSN" value={str(d.ssn)} onCopy={props.onCopy} />
          <Field
            label="Passport"
            value={str(d.passportNumber)}
            onCopy={props.onCopy}
          />
          <Field
            label="License"
            value={str(d.licenseNumber)}
            onCopy={props.onCopy}
          />
        </FieldList>
      );
    case CipherType.SshKey:
      return (
        <FieldList>
          <Field
            label="Fingerprint"
            value={str(d.keyFingerprint)}
            onCopy={props.onCopy}
          />
          <Field label="Public key" value={str(d.publicKey)} onCopy={props.onCopy} />
          <SecretField
            label="Private key"
            value={str(d.privateKey)}
            multiline
            onCopy={props.onCopy}
          />
        </FieldList>
      );
    case CipherType.Totp:
      return <TotpField secret={str(d.secret) ?? ""} onCopy={props.onCopy} standalone />;
    case CipherType.Note:
      // No structured fields; notes render in their own card above.
      return <p class="muted">Secure note — see Notes below.</p>;
    case CipherType.Api:
      return (
        <FieldList>
          <Field label="Client ID" value={str(d.clientId)} onCopy={props.onCopy} />
          <SecretField
            label="Client secret"
            value={str(d.clientSecret)}
            onCopy={props.onCopy}
          />
        </FieldList>
      );
    default:
      return <p class="muted">Unknown cipher type ({props.item.type}).</p>;
  }
}

function FieldList(props: { children: any }) {
  return <div style="display: flex; flex-direction: column; gap: 0.4rem;">{props.children}</div>;
}

function Field(props: {
  label: string;
  value: string | undefined;
  onCopy?: (label: string, value: string | undefined) => Promise<void>;
}) {
  return (
    <div style="display: flex; align-items: center; gap: 0.5rem;">
      <div style="flex: 0 0 130px; color: var(--fg-muted); font-size: 0.85rem;">
        {props.label}
      </div>
      <div style="flex: 1 1 auto; word-break: break-word;">
        {props.value || <span class="muted">—</span>}
      </div>
      <Show when={props.onCopy && props.value}>
        <button
          type="button"
          class="icon-btn"
          aria-label={`Copy ${props.label}`}
          title={`Copy ${props.label}`}
          onClick={() => props.onCopy?.(props.label, props.value)}
        >
          <IconCopy />
        </button>
      </Show>
    </div>
  );
}

function SecretField(props: {
  label: string;
  value: string | undefined;
  multiline?: boolean;
  onCopy: (label: string, value: string | undefined) => Promise<void>;
}) {
  const [revealed, setRevealed] = createSignal(false);
  const masked = "•".repeat(8);
  return (
    <div style="display: flex; align-items: flex-start; gap: 0.5rem;">
      <div
        style="flex: 0 0 130px; color: var(--fg-muted); font-size: 0.85rem; padding-top: 0.2rem;"
      >
        {props.label}
      </div>
      <div style="flex: 1 1 auto; word-break: break-all;">
        <Show
          when={props.value}
          fallback={<span class="muted">—</span>}
        >
          <Show when={revealed()} fallback={<span>{masked}</span>}>
            {props.multiline ? (
              <pre class="output">{props.value}</pre>
            ) : (
              <span style="font-family: ui-monospace, Menlo, monospace;">{props.value}</span>
            )}
          </Show>
        </Show>
      </div>
      <Show when={props.value}>
        <button
          type="button"
          class="icon-btn"
          aria-label={revealed() ? `Hide ${props.label}` : `Reveal ${props.label}`}
          title={revealed() ? `Hide ${props.label}` : `Reveal ${props.label}`}
          onClick={() => setRevealed(!revealed())}
        >
          {revealed() ? <IconEyeOff /> : <IconEye />}
        </button>
        <button
          type="button"
          class="icon-btn"
          aria-label={`Copy ${props.label}`}
          title={`Copy ${props.label}`}
          onClick={() => props.onCopy(props.label, props.value)}
        >
          <IconCopy />
        </button>
      </Show>
    </div>
  );
}

function TotpField(props: {
  secret: string;
  standalone?: boolean;
  onCopy: (label: string, value: string | undefined) => Promise<void>;
}) {
  const [code, setCode] = createSignal("…");
  const [remaining, setRemaining] = createSignal(0);
  const [err, setErr] = createSignal<string | null>(null);

  async function refresh() {
    if (!props.secret) {
      setErr("(no secret)");
      return;
    }
    try {
      const r = await totpCode(props.secret);
      setCode(r.code);
      setRemaining(r.remaining);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }
  void refresh();
  const t = window.setInterval(() => void refresh(), 1000);
  onCleanup(() => clearInterval(t));

  return (
    <div style="display: flex; align-items: center; gap: 0.5rem;">
      <div style="flex: 0 0 130px; color: var(--fg-muted); font-size: 0.85rem;">
        TOTP code
      </div>
      <div style="flex: 1 1 auto; font-family: ui-monospace, Menlo, monospace; letter-spacing: 0.08em;">
        <Show when={!err()} fallback={<span class="muted">{err()}</span>}>
          <span style="font-size: 1.1rem;">{code()}</span>{" "}
          <span class="muted">({remaining()}s)</span>
        </Show>
      </div>
      <button
        type="button"
        class="icon-btn"
        aria-label="Copy TOTP code"
        title="Copy TOTP code"
        onClick={() => props.onCopy("Code", code())}
      >
        <IconCopy />
      </button>
    </div>
  );
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

function joinExpiration(month?: string, year?: string): string | undefined {
  const m = month?.padStart(2, "0");
  if (!m && !year) return undefined;
  return [m, year].filter(Boolean).join(" / ");
}

function joinName(d: Record<string, unknown>): string | undefined {
  const parts = [str(d.firstName), str(d.middleName), str(d.lastName)].filter(Boolean);
  return parts.length > 0 ? parts.join(" ") : undefined;
}

function joinAddress(d: Record<string, unknown>): string | undefined {
  const line1 = [str(d.address1), str(d.address2)].filter(Boolean).join(", ");
  const stateZip = [str(d.state), str(d.postalCode)].filter(Boolean).join(" ");
  const parts = [line1, str(d.city), stateZip, str(d.country)].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : undefined;
}

// Suppress the unused import warning when no `<For>` is rendered.
void For;
