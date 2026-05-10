/* Recipient flow — anonymous decryption of share URLs.
 *
 * Visiting `<server>/send/#/<send_id>/<send_key>` lands here directly
 * (the SPA reads the fragment, the server never sees the recipient
 * key). We POST `/api/v1/public/sends/{id}/access` with no body,
 * decrypt the response payload client-side, and either render the
 * text body or trigger a browser save dialog for file Sends.
 *
 * Ported from clients/extension/popup/popup.js:2499-2624 (`onOpenSend`).
 * Differences from the popup:
 *   - URL fragment is auto-read; no paste form needed.
 *   - Password input only appears if the server returns 401 (i.e. the
 *     Send is gated). The popup always shows the password field; here
 *     we let the common no-password path run silently.
 *   - Errors render full-page (banner) instead of toast.
 */
import { createSignal, onMount, Show } from "solid-js";

import { ApiError, postJSON } from "../../lib/api";
import { b64decode } from "../../lib/base64";
import { parseShareFragment, type ParsedShareUrl } from "../../lib/shareUrl";
import type { HekateCore } from "../../wasm-types";
import { loadHekateCore } from "../../wasm";

interface PublicAccessResponse {
  id: string;
  send_type: 1 | 2;
  data: string;
  access_count: number;
  max_access_count: number | null;
  expiration_date: string | null;
  download_token?: string;
  size_ct?: number;
}

interface FileMeta {
  filename: string;
  size_pt?: number;
  file_aead_key_b64: string;
}

type Phase =
  | { kind: "loading" }
  | { kind: "needPassword"; submitting: boolean; lastError?: string }
  | { kind: "text"; body: string }
  | { kind: "file"; filename: string; size: number }
  | { kind: "error"; message: string };

export function Recipient() {
  const [phase, setPhase] = createSignal<Phase>({ kind: "loading" });

  let parsed: ParsedShareUrl | undefined;
  let hekate: HekateCore | undefined;

  onMount(async () => {
    try {
      parsed = parseShareFragment(window.location.hash);
    } catch (err) {
      setPhase({ kind: "error", message: messageOf(err) });
      return;
    }
    try {
      hekate = await loadHekateCore();
    } catch (err) {
      setPhase({ kind: "error", message: `WASM load failed: ${messageOf(err)}` });
      return;
    }
    await access(undefined);
  });

  async function access(password: string | undefined) {
    if (!parsed || !hekate) return;
    let resp: PublicAccessResponse;
    try {
      resp = await postJSON<PublicAccessResponse>(
        `/api/v1/public/sends/${encodeURIComponent(parsed.sendId)}/access`,
        password !== undefined ? { password } : {},
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // Password gate: surface the input, keep prior message if any.
        setPhase((prev) => ({
          kind: "needPassword",
          submitting: false,
          lastError: prev.kind === "needPassword" ? err.message : undefined,
        }));
        return;
      }
      setPhase({ kind: "error", message: messageOf(err) });
      return;
    }

    let sendKey: Uint8Array;
    try {
      sendKey = hekate.sendDecodeKey(parsed.sendKeyB64);
    } catch (err) {
      setPhase({
        kind: "error",
        message: `Bad URL fragment: ${messageOf(err)}`,
      });
      return;
    }

    if (resp.send_type === 1) {
      try {
        const ptBytes = hekate.sendDecryptText(sendKey, parsed.sendId, resp.data);
        setPhase({ kind: "text", body: new TextDecoder().decode(ptBytes) });
      } catch (err) {
        setPhase({ kind: "error", message: `Decrypt failed: ${messageOf(err)}` });
      }
      return;
    }

    if (resp.send_type === 2) {
      await decryptFile(resp, sendKey);
      return;
    }

    setPhase({
      kind: "error",
      message: `Unknown send_type ${(resp as { send_type: number }).send_type}.`,
    });
  }

  async function decryptFile(resp: PublicAccessResponse, sendKey: Uint8Array) {
    if (!parsed || !hekate) return;
    if (!resp.download_token) {
      setPhase({
        kind: "error",
        message: "Server didn't return a download token (body still uploading?).",
      });
      return;
    }

    let meta: FileMeta;
    try {
      const metaBytes = hekate.sendDecryptText(sendKey, parsed.sendId, resp.data);
      meta = JSON.parse(new TextDecoder().decode(metaBytes)) as FileMeta;
    } catch (err) {
      setPhase({ kind: "error", message: `Decrypt metadata failed: ${messageOf(err)}` });
      return;
    }
    if (!meta.file_aead_key_b64 || !meta.filename) {
      setPhase({ kind: "error", message: "Share metadata is missing fields." });
      return;
    }

    const fileAeadKey = b64decode(meta.file_aead_key_b64);
    const blobUrl = `/api/v1/public/sends/${encodeURIComponent(
      parsed.sendId,
    )}/blob/${encodeURIComponent(resp.download_token)}`;

    let ciphertext: Uint8Array;
    try {
      const r = await fetch(blobUrl);
      if (!r.ok) {
        setPhase({ kind: "error", message: `Server: ${r.status} ${r.statusText}` });
        return;
      }
      ciphertext = new Uint8Array(await r.arrayBuffer());
    } catch (err) {
      setPhase({ kind: "error", message: `Network error: ${messageOf(err)}` });
      return;
    }

    if (typeof resp.size_ct === "number" && ciphertext.length !== resp.size_ct) {
      setPhase({
        kind: "error",
        message: `Downloaded ${ciphertext.length} bytes; server claimed ${resp.size_ct}.`,
      });
      return;
    }

    let plaintext: Uint8Array;
    try {
      plaintext = hekate.attachmentDecrypt(fileAeadKey, parsed.sendId, ciphertext);
    } catch (err) {
      setPhase({ kind: "error", message: `Decrypt body failed: ${messageOf(err)}` });
      return;
    }

    triggerDownload(plaintext, meta.filename);
    setPhase({ kind: "file", filename: meta.filename, size: plaintext.length });
  }

  function onPasswordSubmit(e: Event) {
    e.preventDefault();
    const form = e.currentTarget as HTMLFormElement;
    const password = (new FormData(form).get("password") || "").toString();
    setPhase({ kind: "needPassword", submitting: true });
    void access(password);
  }

  return (
    <main class="page">
      <h1>Hekate — shared link</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Decrypted in your browser. The server never sees the recipient key.
      </p>

      <Show when={phase().kind === "loading"}>
        <p class="muted">Decrypting…</p>
      </Show>

      <Show when={phase().kind === "needPassword"}>
        {(() => {
          const p = phase() as Extract<Phase, { kind: "needPassword" }>;
          return (
            <form class="card" onSubmit={onPasswordSubmit}>
              <p style="margin: 0 0 0.75rem;">
                The sender protected this share with an access password.
              </p>
              <div class="field">
                <label for="pw">Access password</label>
                <input
                  id="pw"
                  name="password"
                  type="password"
                  autocomplete="off"
                  autofocus
                  required
                />
              </div>
              <Show when={p.lastError}>
                <div class="banner banner-error">{p.lastError}</div>
              </Show>
              <button class="btn" type="submit" disabled={p.submitting}>
                {p.submitting ? "Decrypting…" : "Decrypt"}
              </button>
            </form>
          );
        })()}
      </Show>

      <Show when={phase().kind === "text"}>
        {(() => {
          const p = phase() as Extract<Phase, { kind: "text" }>;
          return (
            <div class="card">
              <p style="margin: 0 0 0.5rem;" class="muted">
                Shared text
              </p>
              <pre class="output">{p.body}</pre>
              <button
                class="btn btn-secondary"
                style="margin-top: 0.75rem;"
                onClick={() => void navigator.clipboard?.writeText(p.body)}
              >
                Copy
              </button>
            </div>
          );
        })()}
      </Show>

      <Show when={phase().kind === "file"}>
        {(() => {
          const p = phase() as Extract<Phase, { kind: "file" }>;
          return (
            <div class="card">
              <p style="margin: 0 0 0.25rem;">
                Downloaded <strong>{p.filename}</strong>
              </p>
              <p class="muted" style="margin: 0;">
                {p.size.toLocaleString()} bytes — saved by your browser.
              </p>
            </div>
          );
        })()}
      </Show>

      <Show when={phase().kind === "error"}>
        {(() => {
          const p = phase() as Extract<Phase, { kind: "error" }>;
          return <div class="banner banner-error">{p.message}</div>;
        })()}
      </Show>
    </main>
  );
}

function triggerDownload(bytes: Uint8Array, filename: string) {
  // Slice into a dedicated ArrayBuffer so the BlobPart is unambiguously
  // an ArrayBuffer (TS strict-DOM rejects the SharedArrayBuffer-tagged
  // `Uint8Array<ArrayBufferLike>` shape that wasm-bindgen returns).
  const buf = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  const blob = new Blob([buf], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
