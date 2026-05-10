/* Delete account (C.7d-rest).
 *
 * Two-phase SubShell: a warning screen the user has to acknowledge,
 * then a confirm form that requires (a) typing the account email
 * verbatim and (b) entering the current master password. Both gates
 * exist for the same reason as the CLI's `hekate account delete` flow —
 * the operation is irreversible and there's no undo. Server cascades
 * through every cipher / folder / token / webhook on success.
 *
 * Mirrors ChangePassword/AccountExport in shape, but the destructive
 * button uses the `--danger` token and the layout adds the email-typed
 * gate on top of the master-password re-auth that change-password
 * already does.
 */
import { createSignal, Match, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import { deleteAccount } from "../../lib/deleteAccount";
import { getSession } from "../../lib/session";
import { SubShell } from "../../ui/Shell";

export interface DeleteAccountProps {
  onCancel: () => void;
  onDeleted: () => void;
}

type Phase = { kind: "warn" } | { kind: "confirm"; submitting: boolean };

export function DeleteAccount(props: DeleteAccountProps) {
  const session = getSession();
  const email = session?.email ?? "";

  const [phase, setPhase] = createSignal<Phase>({ kind: "warn" });
  const [typedEmail, setTypedEmail] = createSignal("");
  const [pw, setPw] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);

  function emailMatches(): boolean {
    // Trim only — case must match what the server stored, same as the
    // CLI behavior (it compares the typed line against st.user.email
    // verbatim).
    return typedEmail().trim() === email;
  }

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!emailMatches()) {
      setError(`Email must match exactly: ${email}`);
      return;
    }
    if (!pw()) {
      setError("Master password required.");
      return;
    }
    setPhase({ kind: "confirm", submitting: true });
    setError(null);
    try {
      await deleteAccount(pw());
      props.onDeleted();
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setPhase({ kind: "confirm", submitting: false });
    }
  }

  return (
    <SubShell title="Delete account" onBack={props.onCancel}>
      <Switch>
        <Match when={phase().kind === "warn"}>
          <div class="card">
            <p style="margin: 0 0 0.5rem;">
              <strong>Permanently delete this account?</strong>
            </p>
            <p style="margin: 0 0 0.85rem;">
              You're about to delete <strong>{email}</strong> on{" "}
              <code>{window.location.origin}</code>.
            </p>
            <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.9rem;">
              The server will cascade and remove:
            </p>
            <ul class="muted" style="margin: 0 0 0.85rem 1.25rem; font-size: 0.9rem;">
              <li>every cipher and folder</li>
              <li>every Send (text + file) and its attachments</li>
              <li>every refresh token, PAT, and webhook subscription</li>
              <li>your signed vault manifest</li>
            </ul>
            <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
              Org memberships you own will also be torn down — coordinate
              with members first if you have shared data. <strong>This
              cannot be undone</strong>; if you only need a backup before
              leaving, run Export account instead.
            </p>
            <div style="display: flex; gap: 0.5rem;">
              <button
                class="btn"
                type="button"
                style="background: var(--danger); color: white;"
                onClick={() => setPhase({ kind: "confirm", submitting: false })}
              >
                I understand, continue
              </button>
              <button
                class="btn btn-secondary"
                type="button"
                onClick={props.onCancel}
              >
                Cancel
              </button>
            </div>
          </div>
        </Match>

        <Match when={phase().kind === "confirm"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "confirm" }>;
            return (
              <>
                <p class="muted" style="margin: 0 0 0.85rem;">
                  Confirm by typing your email exactly and re-entering
                  your master password. The request goes out the moment
                  you click <strong>Delete account</strong> — there's no
                  second chance.
                </p>
                <form class="card" onSubmit={onSubmit}>
                  <div class="field">
                    <label for="da-email">
                      Type <code>{email}</code> to confirm
                    </label>
                    <input
                      id="da-email"
                      type="text"
                      autocomplete="off"
                      autocapitalize="off"
                      spellcheck={false}
                      required
                      autofocus
                      value={typedEmail()}
                      onInput={(e) => setTypedEmail(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label for="da-pw">Master password</label>
                    <input
                      id="da-pw"
                      type="password"
                      autocomplete="current-password"
                      required
                      value={pw()}
                      onInput={(e) => setPw(e.currentTarget.value)}
                    />
                  </div>
                  <Show when={error()}>
                    <div class="banner banner-error">{error()}</div>
                  </Show>
                  <div style="display: flex; gap: 0.5rem;">
                    <button
                      class="btn"
                      type="submit"
                      disabled={p.submitting || !emailMatches() || !pw()}
                      style="background: var(--danger); color: white;"
                    >
                      {p.submitting ? "Deleting…" : "Delete account"}
                    </button>
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={p.submitting}
                      onClick={props.onCancel}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </>
            );
          })()}
        </Match>
      </Switch>
    </SubShell>
  );
}
