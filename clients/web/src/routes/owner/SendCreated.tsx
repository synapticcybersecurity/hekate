/* Shared "share created" result screen. Same shape for text and file
 * Sends — show the URL with a Copy button + a Done that returns to
 * the list.
 */
import { createSignal } from "solid-js";

import { copy } from "../../lib/clipboard";
import { SubShell } from "../../ui/Shell";

export interface SendCreatedProps {
  url: string;
  /** "text" | "file" — only changes the title copy. */
  kind: "text" | "file";
  onDone: () => void;
}

export function SendCreated(props: SendCreatedProps) {
  const [toast, setToast] = createSignal<string | null>(null);

  async function onCopy() {
    try {
      await copy(props.url);
      setToast("Copied (auto-clears in 30 s)");
      window.setTimeout(() => setToast(null), 2200);
    } catch (err) {
      setToast(err instanceof Error ? err.message : String(err));
      window.setTimeout(() => setToast(null), 2200);
    }
  }

  return (
    <SubShell
      title={props.kind === "text" ? "Text share created" : "File share created"}
      onBack={props.onDone}
    >
      <p class="muted" style="margin: 0 0 1rem;">
        The recipient URL is below. <strong>Anyone with this URL can
        decrypt the share</strong> until it expires, hits its access
        limit, or you disable / delete it. The fragment (after the{" "}
        <code>#</code>) is the recipient's decryption key — your
        browser does not transmit it to the server.
      </p>
      <div class="card">
        <textarea class="input" rows={3} readOnly value={props.url} />
        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
          <button class="btn" type="button" onClick={onCopy}>
            Copy URL
          </button>
          <button class="btn btn-secondary" type="button" onClick={props.onDone}>
            Done
          </button>
        </div>
      </div>
      {toast() && (
        <div class="toast" role="status">
          {toast()}
        </div>
      )}
    </SubShell>
  );
}
