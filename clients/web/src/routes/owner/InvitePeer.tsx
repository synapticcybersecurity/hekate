/* Invite peer to org (C.6).
 *
 * Two-phase SubShell mirroring the popup's flow:
 *   - lookup: form (peer email/uuid + role) → resolvePeerForInvite
 *     fetches bundle, verifies self-sig, decides match/fresh.
 *   - confirm-fresh: TOFU dialog showing fingerprint; "Pin + invite"
 *     commits the pin and posts the invite.
 *   - on a match, skip the dialog and go straight to invite.
 */
import { createSignal, Match, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  commitInvitePeer,
  resolvePeerForInvite,
  type PendingInviteFingerprint,
} from "../../lib/orgWrite";
import { SubShell } from "../../ui/Shell";

export interface InvitePeerProps {
  orgId: string;
  orgName: string;
  onCancel: () => void;
  onInvited: () => void;
}

type Phase =
  | { kind: "form" }
  | { kind: "resolving" }
  | { kind: "confirm-fresh"; pending: PendingInviteFingerprint }
  | { kind: "submitting" };

export function InvitePeer(props: InvitePeerProps) {
  const [peerInput, setPeerInput] = createSignal("");
  const [role, setRole] = createSignal<"admin" | "user">("user");
  const [phase, setPhase] = createSignal<Phase>({ kind: "form" });
  const [error, setError] = createSignal<string | null>(null);

  async function onLookup(e: Event) {
    e.preventDefault();
    if (!peerInput().trim()) {
      setError("Peer email or user_id required.");
      return;
    }
    setError(null);
    setPhase({ kind: "resolving" });
    try {
      const result = await resolvePeerForInvite(peerInput());
      if (result.kind === "match") {
        // Pin matches — skip TOFU dialog, go straight to invite POST.
        await runCommit(result.bundle);
        return;
      }
      setPhase({ kind: "confirm-fresh", pending: result.pending });
    } catch (err) {
      setError(errMsg(err));
      setPhase({ kind: "form" });
    }
  }

  async function onConfirmCommit() {
    const p = phase();
    if (p.kind !== "confirm-fresh") return;
    await runCommit(p.pending.bundle);
  }

  async function runCommit(bundle: PendingInviteFingerprint["bundle"]) {
    setPhase({ kind: "submitting" });
    setError(null);
    try {
      await commitInvitePeer(props.orgId, bundle, role());
      props.onInvited();
    } catch (err) {
      setError(errMsg(err));
      setPhase({ kind: "form" });
    }
  }

  return (
    <SubShell title="Invite peer" onBack={props.onCancel}>
      <Switch>
        <Match when={phase().kind === "confirm-fresh"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "confirm-fresh" }>;
            return (
              <div class="card">
                <p style="margin: 0 0 0.5rem;">
                  <strong>Pin new peer?</strong>
                </p>
                <Show when={p.pending.email}>
                  <p style="margin: 0 0 0.4rem;">
                    <strong>{p.pending.email}</strong>
                  </p>
                </Show>
                <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.9rem;">
                  user_id:{" "}
                  <code style="word-break: break-all;">{p.pending.bundle.user_id}</code>
                </p>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
                  Fingerprint:
                </p>
                <pre class="recovery-codes" style="margin: 0 0 0.85rem;">
                  {p.pending.fingerprint}
                </pre>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
                  Verify this matches what the peer reads to you out of
                  band (Signal, voice, in person) before clicking Pin.
                  Once pinned, future invites + shares to this peer skip
                  the dialog.
                </p>
                <Show when={error()}>
                  <div class="banner banner-error">{error()}</div>
                </Show>
                <div style="display: flex; gap: 0.5rem;">
                  <button class="btn" type="button" onClick={() => void onConfirmCommit()}>
                    Pin + invite as {role()}
                  </button>
                  <button
                    class="btn btn-secondary"
                    type="button"
                    onClick={() => setPhase({ kind: "form" })}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            );
          })()}
        </Match>

        <Match when={phase().kind !== "confirm-fresh"}>
          <p class="muted" style="margin: 0 0 0.85rem;">
            Inviting to <strong>{props.orgName}</strong>. The peer must
            already have a Hekate account on this server (we need their
            pubkey bundle to encrypt the org symmetric key to them). On
            submit, the popup fetches + verifies the bundle, asks for
            your TOFU confirmation if you haven't pinned them, then
            posts the invite.
          </p>
          <form class="card" onSubmit={onLookup}>
            <div class="field">
              <label for="peer-input">Peer email or user_id</label>
              <input
                id="peer-input"
                type="text"
                required
                autofocus
                placeholder="alice@example.com or 0192e0a0-…"
                value={peerInput()}
                onInput={(e) => setPeerInput(e.currentTarget.value)}
                disabled={phase().kind !== "form"}
              />
            </div>
            <div class="field">
              <label for="role">Role</label>
              <select
                id="role"
                value={role()}
                onChange={(e) => setRole(e.currentTarget.value as "admin" | "user")}
                disabled={phase().kind !== "form"}
              >
                <option value="user">user</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <Show when={error()}>
              <div class="banner banner-error">{error()}</div>
            </Show>
            <div style="display: flex; gap: 0.5rem;">
              <button
                class="btn"
                type="submit"
                disabled={phase().kind !== "form"}
              >
                {phase().kind === "resolving"
                  ? "Looking up…"
                  : phase().kind === "submitting"
                    ? "Inviting…"
                    : "Continue"}
              </button>
              <button
                class="btn btn-secondary"
                type="button"
                onClick={props.onCancel}
                disabled={phase().kind === "submitting"}
              >
                Cancel
              </button>
            </div>
          </form>
        </Match>
      </Switch>
    </SubShell>
  );
}

function errMsg(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
