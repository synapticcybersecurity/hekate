/* Org detail — roster + actions view (C.5 / C.6).
 *
 * Shows org info, decoded roster entries with each member's role,
 * active policies, and the cipher manifest version (when an org has
 * one). Owner-only buttons let you remove members, confirm rotations,
 * and toggle policies (M4.6).
 */
import { createSignal, For, onMount, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  decodeRoster,
  fetchOrgFull,
  type DecodedRoster,
  type OrgSyncEntry,
  type PolicyView,
} from "../../lib/orgs";
import {
  cancelInvite,
  confirmRotation,
  listPolicies,
  POLICY_TYPES,
  pruneRoster,
  revokeMember,
  setPolicy,
} from "../../lib/orgWrite";
import { SubShell } from "../../ui/Shell";

/** Display labels for the M4.6 known policy set. Keys match
 *  `POLICY_TYPES` from lib/orgWrite.ts. */
const POLICY_LABELS: Record<string, string> = {
  master_password_complexity: "Master password complexity",
  vault_timeout: "Vault timeout",
  password_generator_rules: "Password generator rules",
  single_org: "Single organization",
  restrict_send: "Restrict Send",
};

const POLICY_DESCRIPTIONS: Record<string, string> = {
  master_password_complexity:
    "Client-enforced rules on master-password length / complexity at register / change-password.",
  vault_timeout:
    "Client-enforced max idle before the vault re-locks or logs out.",
  password_generator_rules:
    "Client-enforced floors for `hekate generate` (length, character classes).",
  single_org:
    "Server-enforced. Members of this org cannot accept invites to a second org.",
  restrict_send:
    "Reserved. Send subsystem will honor this once enforcement lands.",
};

export interface OrgDetailProps {
  org: OrgSyncEntry;
  onBack: () => void;
  onInvitePeer: () => void;
  onManageCollections: () => void;
}

export function OrgDetail(props: OrgDetailProps) {
  const [decoded, setDecoded] = createSignal<DecodedRoster | null>(null);
  const [memberEmails, setMemberEmails] = createSignal<Record<string, string>>({});
  const [pendingInvitees, setPendingInvitees] = createSignal<
    Record<string, { role: string; email?: string }>
  >({});
  const [ownerUserId, setOwnerUserId] = createSignal<string | null>(null);
  const [revokingUserId, setRevokingUserId] = createSignal<string | null>(null);
  const [revokeError, setRevokeError] = createSignal<string | null>(null);
  const [cancellingInvite, setCancellingInvite] = createSignal<string | null>(null);
  const [cancelInviteError, setCancelInviteError] = createSignal<string | null>(null);
  const [pruning, setPruning] = createSignal(false);
  const [pruneError, setPruneError] = createSignal<string | null>(null);
  const [confirming, setConfirming] = createSignal(false);
  const [confirmError, setConfirmError] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  // M4.6 — local view of the policy table. Seeded from
  // `props.org.policies` (which /sync already inlines) and mutated in
  // place after each toggle so the UI doesn't depend on the parent
  // re-syncing for ack.
  const [policies, setPolicies] = createSignal<Record<string, PolicyView>>(
    Object.fromEntries((props.org.policies ?? []).map((p) => [p.policy_type, p])),
  );
  const [togglingPolicy, setTogglingPolicy] = createSignal<string | null>(null);
  const [policyError, setPolicyError] = createSignal<string | null>(null);

  const isOwner = () => props.org.role === "owner";

  onMount(async () => {
    try {
      setDecoded(await decodeRoster(props.org.roster));
    } catch (err) {
      setError(
        `Roster decode failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    // Best-effort enrichment — failures here shouldn't block the
    // roster rendering, just silently skip.
    try {
      const full = await fetchOrgFull(props.org.org_id);
      if (full.member_emails) setMemberEmails(full.member_emails);
      if (full.pending_invitees) setPendingInvitees(full.pending_invitees);
      setOwnerUserId(full.owner_user_id);
    } catch (err) {
      console.warn("org detail enrichment fetch failed:", err);
    }
    // M4.6 — owners get a fresh policy read so disabled rows (which
    // /sync also surfaces but the parent may have cached) reflect the
    // latest server state. Best-effort; the cached props.org.policies
    // is the fallback.
    if (isOwner()) {
      try {
        const fresh = await listPolicies(props.org.org_id);
        setPolicies(Object.fromEntries(fresh.map((p) => [p.policy_type, p])));
      } catch (err) {
        console.warn("policies fetch failed:", err);
      }
    }
  });

  /** Roster entries that aren't in `member_emails` (server's join
   *  against `organization_members`). Pre-GH#2 invitees who never
   *  accepted live here — they're in the signed roster but have no
   *  membership row, so /revoke 404s on them. The Prune button
   *  re-signs the roster dropping these. Owner is excluded from the
   *  set even if `member_emails` is somehow missing — we never want
   *  to suggest pruning ourselves. */
  const orphanUserIds = () => {
    const decodedRoster = decoded();
    if (!decodedRoster) return [] as string[];
    const knownOwner = ownerUserId() ?? props.org.org_id; // owner unknown → fallback that won't match
    const emails = memberEmails();
    return decodedRoster.entries
      .map((e) => e.userId)
      .filter((uid) => uid !== knownOwner && !emails[uid]);
  };

  async function onPruneOrphans() {
    const ids = orphanUserIds();
    if (ids.length === 0) return;
    if (
      !window.confirm(
        `Prune ${ids.length} orphan ${ids.length === 1 ? "entry" : "entries"} ` +
          `from the signed roster?\n\n` +
          "These user_ids are in the cryptographic roster but have no " +
          "membership row server-side — they were never able to access this " +
          "org's data. Pruning re-signs the roster without them. The org " +
          "symmetric key is NOT rotated (orphans never received it).",
      )
    ) {
      return;
    }
    setPruning(true);
    setPruneError(null);
    try {
      await pruneRoster(props.org.org_id, ids);
      // Roster + version changed; bounce back to orgs list so the
      // parent re-fetches /sync.
      props.onBack();
    } catch (err) {
      setPruneError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setPruning(false);
    }
  }

  async function onTogglePolicy(policyType: string, nextEnabled: boolean) {
    setTogglingPolicy(policyType);
    setPolicyError(null);
    try {
      const existing = policies()[policyType];
      const updated = await setPolicy(
        props.org.org_id,
        policyType,
        nextEnabled,
        existing?.config ?? {},
      );
      setPolicies({ ...policies(), [policyType]: updated });
    } catch (err) {
      setPolicyError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setTogglingPolicy(null);
    }
  }

  async function onConfirmRotation() {
    setConfirming(true);
    setConfirmError(null);
    try {
      await confirmRotation({
        org_id: props.org.org_id,
        pending_envelope: props.org.pending_envelope,
        roster: { canonical_b64: props.org.roster.canonical_b64 },
      });
      // Pending envelope cleared server-side + our pin updated; bounce
      // back to the orgs list so the parent re-fetches /sync (which
      // refreshes my_protected_org_key + drops the pending tag).
      props.onBack();
    } catch (err) {
      setConfirmError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setConfirming(false);
    }
  }

  async function onCancelInvite(userId: string, label: string) {
    if (
      !window.confirm(
        `Cancel the invitation to ${label}?\n\n` +
          "They'll lose the pending invite. The org's signed roster is unaffected " +
          "since the invite never advanced it. You can re-invite later.",
      )
    ) {
      return;
    }
    setCancellingInvite(userId);
    setCancelInviteError(null);
    try {
      await cancelInvite(props.org.org_id, userId);
      // Drop the row from local state so the UI updates without a parent
      // re-sync. The server returned 204, the row is gone for real.
      const remaining = { ...pendingInvitees() };
      delete remaining[userId];
      setPendingInvitees(remaining);
    } catch (err) {
      setCancelInviteError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
    } finally {
      setCancellingInvite(null);
    }
  }

  async function onRemoveMember(userId: string, label: string) {
    if (
      !window.confirm(
        `Remove ${label} from "${props.org.name}"?\n\n` +
          "This rotates the org symmetric key, re-wraps every org-owned " +
          "cipher under the new key, and signcrypts the new key to every " +
          "remaining member. They'll auto-confirm on next sync. The " +
          "removed member loses access immediately.\n\n" +
          "All remaining members must already be peer-pinned with " +
          "fingerprints verified out of band.",
      )
    ) {
      return;
    }
    setRevokingUserId(userId);
    setRevokeError(null);
    try {
      await revokeMember(props.org.org_id, userId);
      // Roster + sym key id changed; the simplest refresh is to bounce
      // back to the orgs list, where the parent re-fetches /sync.
      props.onBack();
    } catch (err) {
      setRevokeError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setRevokingUserId(null);
    }
  }

  return (
    <SubShell title={props.org.name} onBack={props.onBack}>
      <div class="card">
        <p style="margin: 0 0 0.25rem;">
          <strong>{props.org.name}</strong>
        </p>
        <p class="muted" style="margin: 0; font-size: 0.85rem;">
          Your role: <strong>{props.org.role}</strong> · roster v
          {props.org.roster_version} · updated{" "}
          {new Date(props.org.roster_updated_at).toLocaleString()}
        </p>
        <p class="muted" style="margin: 0.4rem 0 0; font-size: 0.85rem;">
          Org sym key: <code>{props.org.org_sym_key_id}</code>
        </p>
        <Show when={props.org.pending_envelope}>
          <div class="banner banner-error" style="margin-top: 0.75rem;">
            <p style="margin: 0 0 0.4rem;">
              <strong>Rotation pending.</strong> The org owner rotated the
              symmetric key (likely after removing a member). Confirm to
              re-wrap the new key under your account_key — until then
              org-owned ciphers can still decrypt under the old wrap, but
              new writes will fail.
            </p>
            <Show when={confirmError()}>
              <p style="margin: 0.4rem 0;">{confirmError()}</p>
            </Show>
            <button
              class="btn"
              type="button"
              disabled={confirming()}
              onClick={() => void onConfirmRotation()}
            >
              {confirming() ? "Confirming…" : "Confirm rotation"}
            </button>
          </div>
        </Show>
      </div>

      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Actions</strong>
        </p>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <Show when={props.org.role === "owner"}>
            <button class="btn" type="button" onClick={props.onInvitePeer}>
              Invite peer…
            </button>
          </Show>
          <button class="btn btn-secondary" type="button" onClick={props.onManageCollections}>
            Collections…
          </button>
        </div>
      </div>

      <Show when={isOwner() && orphanUserIds().length > 0}>
        <div class="card">
          <p style="margin: 0 0 0.25rem;">
            <strong>Roster needs cleanup</strong>
          </p>
          <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.85rem;">
            {orphanUserIds().length}{" "}
            {orphanUserIds().length === 1 ? "user_id is" : "user_ids are"} in
            this org's signed roster but{" "}
            {orphanUserIds().length === 1 ? "has" : "have"} no membership row
            server-side. They can't access any data — most likely a pre-GH#2
            invite that was never accepted. Prune re-signs the roster dropping
            them. The org symmetric key is not rotated.
          </p>
          <Show when={pruneError()}>
            <div class="banner banner-error">{pruneError()}</div>
          </Show>
          <ul style="margin: 0.4rem 0; padding-left: 1.2rem;">
            <For each={orphanUserIds()}>
              {(uid) => (
                <li>
                  <code style="font-size: 0.8rem;">{uid}</code>
                </li>
              )}
            </For>
          </ul>
          <button
            class="btn"
            type="button"
            disabled={pruning()}
            onClick={() => void onPruneOrphans()}
          >
            {pruning()
              ? "Pruning…"
              : `Prune ${orphanUserIds().length} orphan ${orphanUserIds().length === 1 ? "entry" : "entries"}`}
          </button>
        </div>
      </Show>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Members</strong>
        </p>
        <Show when={revokeError()}>
          <div class="banner banner-error">{revokeError()}</div>
        </Show>
        <Show when={decoded()} fallback={<p class="muted">Decoding roster…</p>}>
          {(d) => (
            <div role="list">
              <For each={d().entries}>
                {(entry) => {
                  const email = () => memberEmails()[entry.userId];
                  const label = () => email() ?? entry.userId;
                  const canRemove = () =>
                    isOwner() &&
                    entry.role !== "owner" &&
                    entry.userId !== ownerUserId();
                  const removing = () => revokingUserId() === entry.userId;
                  return (
                    <div
                      role="listitem"
                      style="display: flex; gap: 0.5rem; padding: 0.4rem 0; border-bottom: 1px solid var(--border); align-items: baseline;"
                    >
                      <div style="flex: 1 1 auto; min-width: 0; word-break: break-all;">
                        <Show
                          when={email()}
                          fallback={
                            <code style="font-size: 0.85rem;">{entry.userId}</code>
                          }
                        >
                          <div>{email()}</div>
                          <code class="muted" style="font-size: 0.75rem;">
                            {entry.userId}
                          </code>
                        </Show>
                      </div>
                      <span class="muted" style="flex: 0 0 auto;">
                        {entry.role}
                      </span>
                      <Show when={canRemove()}>
                        <button
                          class="btn btn-secondary"
                          type="button"
                          style="flex: 0 0 auto; padding: 0.3rem 0.65rem; font-size: 0.85rem; border-color: var(--danger); color: var(--danger);"
                          disabled={revokingUserId() !== null}
                          onClick={() => void onRemoveMember(entry.userId, label())}
                        >
                          {removing() ? "Rotating…" : "Remove"}
                        </button>
                      </Show>
                    </div>
                  );
                }}
              </For>
            </div>
          )}
        </Show>
      </div>

      <Show when={Object.keys(pendingInvitees()).length > 0}>
        <div class="card">
          <p style="margin: 0 0 0.5rem;">
            <strong>Pending invites ({Object.keys(pendingInvitees()).length})</strong>
          </p>
          <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.85rem;">
            Invited but haven't accepted yet — they're not in the
            signed roster until they do.
          </p>
          <Show when={cancelInviteError()}>
            <div class="banner banner-error">{cancelInviteError()}</div>
          </Show>
          <div role="list">
            <For each={Object.entries(pendingInvitees())}>
              {([userId, info]) => {
                const label = () => info.email ?? userId;
                const cancelling = () => cancellingInvite() === userId;
                return (
                  <div
                    role="listitem"
                    style="display: flex; gap: 0.5rem; padding: 0.4rem 0; border-bottom: 1px solid var(--border); align-items: baseline;"
                  >
                    <div style="flex: 1 1 auto; min-width: 0; word-break: break-all;">
                      <Show
                        when={info.email}
                        fallback={<code style="font-size: 0.85rem;">{userId}</code>}
                      >
                        <div>{info.email}</div>
                        <code class="muted" style="font-size: 0.75rem;">{userId}</code>
                      </Show>
                    </div>
                    <span class="muted" style="flex: 0 0 auto;">
                      {info.role} · invited
                    </span>
                    <Show when={isOwner()}>
                      <button
                        class="btn btn-secondary"
                        type="button"
                        style="flex: 0 0 auto; padding: 0.3rem 0.65rem; font-size: 0.85rem; border-color: var(--danger); color: var(--danger);"
                        disabled={cancellingInvite() !== null}
                        onClick={() => void onCancelInvite(userId, label())}
                      >
                        {cancelling() ? "Cancelling…" : "Cancel"}
                      </button>
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </div>
      </Show>

      <Show
        when={isOwner()}
        fallback={
          <Show when={(props.org.policies ?? []).some((p) => p.enabled)}>
            <div class="card">
              <p style="margin: 0 0 0.5rem;">
                <strong>Policies</strong>
              </p>
              <For each={(props.org.policies ?? []).filter((p) => p.enabled)}>
                {(p) => (
                  <div style="display: flex; gap: 0.5rem; padding: 0.3rem 0; border-bottom: 1px solid var(--border);">
                    <code style="flex: 1 1 auto; font-size: 0.85rem;">
                      {POLICY_LABELS[p.policy_type] ?? p.policy_type}
                    </code>
                    <span class="muted">enabled</span>
                  </div>
                )}
              </For>
            </div>
          </Show>
        }
      >
        <div class="card">
          <p style="margin: 0 0 0.25rem;">
            <strong>Policies</strong>
          </p>
          <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.85rem;">
            Toggle policies on or off for this org. Server enforces
            <code>single_org</code> at /accept; the rest are delivered
            via /sync and applied client-side at max strictness.
          </p>
          <Show when={policyError()}>
            <div class="banner banner-error">{policyError()}</div>
          </Show>
          <For each={POLICY_TYPES}>
            {(policyType) => (
              <div
                style="display: flex; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); align-items: baseline;"
              >
                <div style="flex: 1 1 auto; min-width: 0;">
                  <div>{POLICY_LABELS[policyType] ?? policyType}</div>
                  <div class="muted" style="font-size: 0.8rem;">
                    {POLICY_DESCRIPTIONS[policyType] ?? ""}
                  </div>
                  <code class="muted" style="font-size: 0.75rem;">
                    {policyType}
                  </code>
                </div>
                <span class="muted" style="flex: 0 0 auto;">
                  {policies()[policyType]?.enabled ? "enabled" : "disabled"}
                </span>
                <button
                  class="btn btn-secondary"
                  type="button"
                  style="flex: 0 0 auto; padding: 0.3rem 0.65rem; font-size: 0.85rem;"
                  disabled={togglingPolicy() !== null}
                  onClick={() =>
                    void onTogglePolicy(
                      policyType,
                      !policies()[policyType]?.enabled,
                    )
                  }
                >
                  {togglingPolicy() === policyType
                    ? "Saving…"
                    : policies()[policyType]?.enabled
                      ? "Disable"
                      : "Enable"}
                </button>
              </div>
            )}
          </For>
        </div>
      </Show>

      <Show when={props.org.cipher_manifest}>
        {(cm) => (
          <div class="card">
            <p style="margin: 0 0 0.5rem;">
              <strong>Org cipher manifest</strong>
            </p>
            <p class="muted" style="margin: 0; font-size: 0.85rem;">
              Version {cm().version} · updated{" "}
              {new Date(cm().updated_at).toLocaleString()}
            </p>
          </div>
        )}
      </Show>
    </SubShell>
  );
}
