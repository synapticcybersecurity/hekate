/* Pending org invites for the current account (C.6).
 *
 * Lists invites returned by /api/v1/account/invites. Each row shows
 * the org name, the inviter, the offered role, and an Accept button.
 * Accept verifies the envelope under the inviter's PINNED signing
 * key — if the inviter isn't pinned, the user must pin them first
 * (link to Peer pins panel surfaces the explanation inline).
 */
import { createSignal, For, Match, onMount, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  acceptInvite,
  listInvites,
  type InviteView,
} from "../../lib/orgWrite";
import { SubShell } from "../../ui/Shell";

export interface InvitesListProps {
  onBack: () => void;
  /** After at least one accept, parent re-fetches /sync so the orgs
   *  list shows the freshly-joined org. */
  onAccepted: () => void;
}

type Phase =
  | { kind: "loading" }
  | { kind: "list"; invites: InviteView[] }
  | { kind: "load-error"; message: string }
  | { kind: "accepting"; orgId: string; invites: InviteView[] };

export function InvitesList(props: InvitesListProps) {
  const [phase, setPhase] = createSignal<Phase>({ kind: "loading" });
  const [actionError, setActionError] = createSignal<string | null>(null);
  const [didAccept, setDidAccept] = createSignal(false);

  onMount(() => {
    void refresh();
  });

  async function refresh(): Promise<void> {
    setPhase({ kind: "loading" });
    setActionError(null);
    try {
      const invites = await listInvites();
      setPhase({ kind: "list", invites });
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
    }
  }

  async function onAccept(invite: InviteView) {
    const cur = phase();
    const invites = cur.kind === "list" ? cur.invites : [];
    setActionError(null);
    setPhase({ kind: "accepting", orgId: invite.org_id, invites });
    try {
      await acceptInvite(invite);
      setDidAccept(true);
      // refresh shows the remaining list (this one is gone server-side)
      await refresh();
    } catch (err) {
      setActionError(errMsg(err));
      setPhase({ kind: "list", invites });
    }
  }

  function onBackClick() {
    if (didAccept()) props.onAccepted();
    props.onBack();
  }

  return (
    <SubShell title="Pending invites" onBack={onBackClick}>
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
                <button class="btn btn-secondary" onClick={() => void refresh()}>
                  Retry
                </button>
              </>
            );
          })()}
        </Match>

        <Match
          when={
            (phase().kind === "list" || phase().kind === "accepting") &&
            visibleInvites(phase()).length === 0
          }
        >
          <p class="muted">No pending invites for this account.</p>
        </Match>

        <Match
          when={
            (phase().kind === "list" || phase().kind === "accepting") &&
            visibleInvites(phase()).length > 0
          }
        >
          <Show when={actionError()}>
            <div class="banner banner-error">{actionError()}</div>
          </Show>
          <Show when={actionError()?.includes("not pinned")}>
            <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
              Pin the inviter via <strong>Settings → Manage peer pins</strong>
              {" "}first. You'll need their fingerprint out of band; once
              pinned, retry Accept.
            </p>
          </Show>
          <For each={visibleInvites(phase())}>
            {(inv) => {
              const isAccepting = () =>
                phase().kind === "accepting" &&
                (phase() as Extract<Phase, { kind: "accepting" }>).orgId === inv.org_id;
              return (
                <div class="card">
                  <p style="margin: 0 0 0.4rem;">
                    <strong>{inv.org_name}</strong>{" "}
                    <span class="muted" style="font-size: 0.85rem;">
                      ({inv.role})
                    </span>
                  </p>
                  <p class="muted" style="margin: 0 0 0.4rem; font-size: 0.85rem;">
                    Inviter:{" "}
                    <code style="word-break: break-all;">{inv.inviter_user_id}</code>
                  </p>
                  <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
                    Invited {new Date(inv.invited_at).toLocaleString()} ·
                    roster v{inv.roster_version}
                  </p>
                  <button
                    class="btn"
                    type="button"
                    disabled={phase().kind === "accepting"}
                    onClick={() => void onAccept(inv)}
                  >
                    {isAccepting() ? "Accepting…" : "Accept"}
                  </button>
                </div>
              );
            }}
          </For>
        </Match>
      </Switch>
    </SubShell>
  );
}

function visibleInvites(p: Phase): InviteView[] {
  if (p.kind === "list" || p.kind === "accepting") return p.invites;
  return [];
}

function errMsg(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
