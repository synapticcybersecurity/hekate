/* New file Send — create form.
 *
 * Mirrors `renderNewFileSend` + `onCreateFileSend` from popup.js. The
 * file body is encrypted with a per-file AEAD key (separate from the
 * URL-fragment send_key) via the PMGRA1 chunked-AEAD format. The
 * encrypted metadata blob (filename + size_pt + file_aead_key_b64) is
 * the Send's `data` field, encrypted under the send_key. Recipients
 * decrypt the metadata first, then fetch the body via a 5-minute
 * download token.
 *
 * Body upload uses tus 1.0 single-shot — entire ciphertext goes in
 * the POST body. For very large files the CLI offers chunked PATCH
 * uploads; the web vault accepts the same memory-bounded ergonomics
 * the popup ships.
 */
import { createSignal, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { b64encode } from "../../lib/base64";
import { createSend, deleteSend, uploadSendBody } from "../../lib/sendApi";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import { SubShell } from "../../ui/Shell";

const enc = new TextEncoder();

export interface NewFileSendProps {
  onCancel: () => void;
  onCreated: (url: string) => void;
}

export function NewFileSend(props: NewFileSendProps) {
  const [file, setFile] = createSignal<File | null>(null);
  const [name, setName] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [maxAccess, setMaxAccess] = createSignal("");
  const [ttl, setTtl] = createSignal("7d");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [progressMsg, setProgressMsg] = createSignal<string | null>(null);

  async function onSubmit(e: Event) {
    e.preventDefault();
    const f = file();
    if (!f) {
      setError("Pick a file first.");
      return;
    }
    if (f.size === 0) {
      setError("Empty files can't be uploaded.");
      return;
    }
    setSubmitting(true);
    setError(null);

    try {
      const session = getSession();
      if (!session) throw new Error("session expired");
      const hekate = await loadHekateCore();

      setProgressMsg(`Reading ${f.name}…`);
      const plaintext = new Uint8Array(await f.arrayBuffer());

      const sendId = crypto.randomUUID();
      const sendKey = hekate.sendGenerateKey();
      const fileAeadKey = hekate.randomKey32();

      setProgressMsg("Encrypting…");
      const ciphertext = hekate.attachmentEncrypt(fileAeadKey, sendId, plaintext);
      const hashB64 = hekate.blake3HashB64(ciphertext);

      // Encrypted metadata payload — recipient HKDFs the URL-fragment
      // send_key + send_id into a content key, decrypts this blob, and
      // pulls `file_aead_key_b64` out for the body fetch.
      const metadataJson = JSON.stringify({
        filename: f.name,
        size_pt: plaintext.length,
        file_aead_key_b64: b64encode(fileAeadKey),
      });

      const dataWire = hekate.sendEncryptText(
        sendKey,
        sendId,
        enc.encode(metadataJson),
      );
      const protectedSendKey = hekate.encStringEncryptXc20p(
        "ak:1",
        session.accountKey,
        sendKey,
        hekate.sendKeyWrapAad(sendId),
      );
      const displayName = name().trim() || f.name;
      const nameWire = hekate.encStringEncryptXc20p(
        "ak:1",
        session.accountKey,
        enc.encode(displayName),
        hekate.sendNameAad(sendId),
      );

      const deletionDate = new Date(Date.now() + parseTtlMs(ttl())).toISOString();
      const max = parseInt(maxAccess(), 10);

      setProgressMsg("Creating share row…");
      await createSend({
        id: sendId,
        send_type: 2,
        name: nameWire,
        protected_send_key: protectedSendKey,
        data: dataWire,
        deletion_date: deletionDate,
        disabled: false,
        ...(password() ? { password: password() } : {}),
        ...(Number.isFinite(max) && max > 0 ? { max_access_count: max } : {}),
      });

      setProgressMsg(`Uploading ${formatBytes(ciphertext.length)}…`);
      try {
        await uploadSendBody(sendId, ciphertext, hashB64, plaintext.length);
      } catch (uploadErr) {
        // Best-effort cleanup so the user doesn't see a dangling
        // upload-pending row that recipients will hit and fail on.
        deleteSend(sendId).catch(() => undefined);
        throw uploadErr;
      }

      const url = `${window.location.origin}/send/#/${sendId}/${hekate.sendEncodeKey(sendKey)}`;
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
      setProgressMsg(null);
    }
  }

  return (
    <SubShell title="New file share" onBack={props.onCancel}>
      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="send-file">File</label>
          <input
            id="send-file"
            type="file"
            required
            onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)}
          />
          <Show when={file()}>
            <div class="muted" style="font-size: 0.85rem; margin-top: 0.25rem;">
              {file()!.name} — {formatBytes(file()!.size)}
            </div>
          </Show>
        </div>
        <div class="field">
          <label for="send-name">
            Display name <span class="muted">(sender-side; recipients won't see this)</span>
          </label>
          <input
            id="send-name"
            type="text"
            placeholder="Defaults to the file's basename"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
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
        <p class="muted" style="font-size: 0.85rem; margin: 0 0 0.85rem;">
          File body is encrypted client-side with a fresh per-file AEAD
          key (separate from the URL-fragment send_key). Server gets
          opaque ciphertext + a tus upload; recipients fetch via a
          5-minute download token granted by /access.
        </p>

        <Show when={progressMsg() && !error()}>
          <div class="banner">{progressMsg()}</div>
        </Show>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>

        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? progressMsg() ?? "Creating…" : "Create + upload"}
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

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
