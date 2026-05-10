/* C.2 placeholder — the post-login landing.
 *
 * C.3+ replaces this with the vault list, sends list, orgs list,
 * settings, and the rest of the popup's owner-mode surface. For now
 * we just confirm the unlock worked and offer a Logout button.
 */
import { Show } from "solid-js";

import { clearSession, getSession } from "../../lib/session";

export interface UnlockedProps {
  onLoggedOut: () => void;
}

export function Unlocked(props: UnlockedProps) {
  const session = getSession();

  function onLogout() {
    clearSession();
    props.onLoggedOut();
  }

  return (
    <main class="page">
      <h1>Hekate</h1>
      <p class="muted" style="margin: 0 0 1.25rem;">
        Unlocked. Vault list ships in C.3.
      </p>

      <Show when={session}>
        {(s) => (
          <div class="card">
            <p style="margin: 0 0 0.25rem;">
              Signed in as <strong>{s().email}</strong>
            </p>
            <p class="muted" style="margin: 0 0 1rem; font-size: 0.85rem;">
              account_key + signing seed are loaded in memory.
              Refresh token persisted via{" "}
              {localStorage.getItem("hekate.refresh_token") ? "localStorage" : "sessionStorage"}.
            </p>
            <button class="btn btn-secondary" onClick={onLogout}>
              Log out
            </button>
          </div>
        )}
      </Show>
    </main>
  );
}
