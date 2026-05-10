/* Orgs list — read-only (C.5).
 *
 * Renders orgs from `/sync` with name + role + member count + policy
 * count + pending-rotation tag. No create / invite / accept buttons —
 * those are C.6, gated on the popup-side M3.14a-d browser smoke
 * (see `project_m3_14_deferred_pending_smoketest.md` memory).
 */
import {
  createEffect,
  createSignal,
  For,
  Show,
} from "solid-js";

import { ApiError, SessionExpiredError } from "../../lib/api";
import { decodeRoster, type OrgSyncEntry } from "../../lib/orgs";
import { fetchSync } from "../../lib/sync";

export interface OrgsListProps {
  reloadKey: number;
  onSelect: (org: OrgSyncEntry) => void;
  onCreateOrg: () => void;
  onViewInvites: () => void;
  onSessionExpired: () => void;
}

interface OrgRow {
  entry: OrgSyncEntry;
  /** Decoded member count from canonical roster bytes; -1 on parse failure. */
  memberCount: number;
}

export function OrgsList(props: OrgsListProps) {
  const [rows, setRows] = createSignal<OrgRow[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    void props.reloadKey;
    void load();
  });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const sync = await fetchSync();
      const decoded: OrgRow[] = await Promise.all(
        (sync.orgs ?? []).map(async (entry) => {
          let memberCount = -1;
          try {
            const roster = await decodeRoster(entry.roster);
            memberCount = roster.entries.length;
          } catch {
            /* leave -1 → renders as "?" */
          }
          return { entry, memberCount };
        }),
      );
      decoded.sort((a, b) =>
        a.entry.name.localeCompare(b.entry.name, undefined, { sensitivity: "base" }),
      );
      setRows(decoded);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        props.onSessionExpired();
        return;
      }
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <p class="muted" style="margin: 0 0 0.85rem;">
        Organizations you own or belong to. Click + Create to spin up a
        new one, or check Pending invites for orgs you've been invited
        to.
      </p>

      <div style="display: flex; gap: 0.5rem; margin: 0 0 0.85rem; flex-wrap: wrap;">
        <button class="btn" type="button" onClick={props.onCreateOrg}>
          + Create org
        </button>
        <button class="btn btn-secondary" type="button" onClick={props.onViewInvites}>
          Pending invites
        </button>
      </div>

      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <Show when={loading()}>
        <p class="muted">Loading…</p>
      </Show>

      <Show when={!loading() && rows().length === 0 && !error()}>
        <p class="muted">
          No organizations yet — click + Create above, or Pending
          invites if you're expecting one.
        </p>
      </Show>

      <div role="list">
        <For each={rows()}>
          {(row) => {
            const policiesEnabled =
              (row.entry.policies ?? []).filter((p) => p.enabled).length;
            const flags: string[] = [];
            if (policiesEnabled > 0) {
              flags.push(
                `${policiesEnabled} polic${policiesEnabled === 1 ? "y" : "ies"}`,
              );
            }
            if (row.entry.pending_envelope) flags.push("rotation pending");
            const memberLabel =
              row.memberCount < 0
                ? "? members"
                : `${row.memberCount} member${row.memberCount === 1 ? "" : "s"}`;
            return (
              <button
                type="button"
                class="cipher-row"
                role="listitem"
                onClick={() => props.onSelect(row.entry)}
              >
                <span class="row-icon" data-type={4}>
                  {/* Reuse the identity-row tint for orgs — neutral
                      enough that it stays distinct from cipher types. */}
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  >
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <path d="M9 21V9h6v12" />
                    <path d="M3 9h18" />
                  </svg>
                </span>
                <span class="row-body">
                  <div class="row-name">
                    {row.entry.name}
                    <Show when={flags.length > 0}>
                      <span class="muted" style="margin-left: 0.4rem; font-size: 0.85em;">
                        [{flags.join(", ")}]
                      </span>
                    </Show>
                  </div>
                  <div class="row-sub">
                    {row.entry.role} · {memberLabel} · roster v
                    {row.entry.roster_version}
                  </div>
                </span>
              </button>
            );
          }}
        </For>
      </div>
    </>
  );
}
