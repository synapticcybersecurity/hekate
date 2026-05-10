/* Account export (C.7d-3).
 *
 * Two-field form: export password + repeat. On submit, runs the
 * lib/accountExport.ts pipeline, triggers a browser download, then
 * shows a "saved" confirmation. The export password is independent of
 * the master password — it's only used to encrypt this specific file.
 */
import { createSignal, Match, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  exportAccount,
  triggerDownload,
  type ExportResult,
} from "../../lib/accountExport";
import { SubShell } from "../../ui/Shell";

const MIN_LENGTH = 8;

export interface AccountExportProps {
  onBack: () => void;
}

type Phase =
  | { kind: "form"; submitting: boolean }
  | { kind: "done"; result: ExportResult };

export function AccountExport(props: AccountExportProps) {
  const [phase, setPhase] = createSignal<Phase>({ kind: "form", submitting: false });
  const [pw, setPw] = createSignal("");
  const [confirmPw, setConfirmPw] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);

  function localValidate(): string | null {
    if (!pw()) return "Export password required.";
    if (pw().length < MIN_LENGTH) {
      return `Export password must be at least ${MIN_LENGTH} characters.`;
    }
    if (pw() !== confirmPw()) return "Passwords do not match.";
    return null;
  }

  async function onSubmit(e: Event) {
    e.preventDefault();
    const localErr = localValidate();
    if (localErr) {
      setError(localErr);
      return;
    }
    setPhase({ kind: "form", submitting: true });
    setError(null);
    try {
      const result = await exportAccount(pw());
      triggerDownload(result.bytes, result.filename);
      setPhase({ kind: "done", result });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setPhase({ kind: "form", submitting: false });
    }
  }

  function reDownload() {
    const p = phase();
    if (p.kind !== "done") return;
    triggerDownload(p.result.bytes, p.result.filename);
  }

  return (
    <SubShell title="Export account" onBack={props.onBack}>
      <Switch>
        <Match when={phase().kind === "form"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "form" }>;
            return (
              <>
                <p class="muted" style="margin: 0 0 0.85rem;">
                  Saves an encrypted JSON snapshot of your account: the{" "}
                  <code>account_key</code>, every cipher, and every
                  folder. The file is encrypted under a password you
                  choose <strong>now</strong> — it's NOT your master
                  password and isn't stored anywhere.
                </p>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
                  Treat the file as you would the master password
                  itself: anyone with the file <em>and</em> the export
                  password can read every cipher.
                </p>

                <form class="card" onSubmit={onSubmit}>
                  <div class="field">
                    <label for="export-pw">Export password</label>
                    <input
                      id="export-pw"
                      type="password"
                      autocomplete="new-password"
                      required
                      autofocus
                      minlength={MIN_LENGTH}
                      value={pw()}
                      onInput={(e) => setPw(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label for="export-pw-confirm">Repeat export password</label>
                    <input
                      id="export-pw-confirm"
                      type="password"
                      autocomplete="new-password"
                      required
                      value={confirmPw()}
                      onInput={(e) => setConfirmPw(e.currentTarget.value)}
                    />
                  </div>
                  <Show when={error()}>
                    <div class="banner banner-error">{error()}</div>
                  </Show>
                  <div style="display: flex; gap: 0.5rem;">
                    <button class="btn" type="submit" disabled={p.submitting}>
                      {p.submitting
                        ? "Encrypting…"
                        : "Encrypt + download"}
                    </button>
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={p.submitting}
                      onClick={props.onBack}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </>
            );
          })()}
        </Match>

        <Match when={phase().kind === "done"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "done" }>;
            return (
              <div class="card">
                <p style="margin: 0 0 0.5rem;">
                  <strong>Export saved.</strong>
                </p>
                <p class="muted" style="margin: 0 0 0.4rem; font-size: 0.9rem;">
                  Filename: <code>{p.result.filename}</code>
                </p>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
                  Bundled <strong>{p.result.cipherCount}</strong>{" "}
                  cipher
                  {p.result.cipherCount === 1 ? "" : "s"} and{" "}
                  <strong>{p.result.folderCount}</strong> folder
                  {p.result.folderCount === 1 ? "" : "s"}.
                </p>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
                  Browser didn't prompt? Re-download — the file stays
                  in memory until you leave this page. The export
                  password isn't kept; if you need a new file, run the
                  export again.
                </p>
                <div style="display: flex; gap: 0.5rem;">
                  <button class="btn btn-secondary" type="button" onClick={reDownload}>
                    Re-download
                  </button>
                  <button class="btn" type="button" onClick={props.onBack}>
                    Done
                  </button>
                </div>
              </div>
            );
          })()}
        </Match>
      </Switch>
    </SubShell>
  );
}
