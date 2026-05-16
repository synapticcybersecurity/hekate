/* Owner-mode router.
 *
 * Phases (pre-unlock and post-unlock):
 *   login       → full Login form
 *   resume      → slim Resume form (remember-me path)
 *   twoFactor   → 2FA prompt
 *   unlocked    → tabbed shell with Vault / Share / Orgs / Settings
 *                  · vault tab → list, with sub-views:
 *                      detail (CipherDetail)
 *                      typePicker (TypePicker)
 *                      edit (EditCipher; create-from-type or edit-existing)
 */
import { createSignal, Match, Show, Switch } from "solid-js";

import type { LoginResult } from "../../lib/auth";
import type { CipherView } from "../../lib/cipher";
import {
  clearSession,
  expireSession,
  getSession,
  loadHints,
} from "../../lib/session";
import { IconPlus } from "../../ui/icons";
import { TopShell, type TabId } from "../../ui/Shell";

import { AccountExport } from "./AccountExport";
import { ChangePassword } from "./ChangePassword";
import { Collections } from "./Collections";
import { CreateOrg } from "./CreateOrg";
import { DeleteAccount } from "./DeleteAccount";
import { InvitePeer } from "./InvitePeer";
import { InvitesList } from "./InvitesList";
import { Login } from "./Login";
import { PeerPins } from "./PeerPins";
import { Register } from "./Register";
import { Resume } from "./Resume";
import { RotateKeys } from "./RotateKeys";
import { TwoFactor } from "./TwoFactor";
import { CipherDetail } from "./CipherDetail";
import { EditCipher } from "./EditCipher";
import { Import } from "./Import";
import { NewFileSend } from "./NewFileSend";
import { NewTextSend } from "./NewTextSend";
import { OrgDetail } from "./OrgDetail";
import { OrgsList } from "./OrgsList";
import { SendCreated } from "./SendCreated";
import { SendsList } from "./SendsList";
import { TrashView } from "./TrashView";
import { TwoFactorSettings } from "./TwoFactorSettings";
import { TypePicker } from "./TypePicker";
import { Vault } from "./Vault";

import type { OrgSyncEntry } from "../../lib/orgs";
import { isStrictManifest, setStrictManifest } from "../../lib/strictManifest";

type Phase =
  | { kind: "login" }
  | { kind: "register" }
  | { kind: "resume" }
  | {
      kind: "twoFactor";
      pending: Extract<LoginResult, { kind: "needTwoFactor" }>["pending"];
      challenge: Extract<LoginResult, { kind: "needTwoFactor" }>["challenge"];
      rememberMe: boolean;
    }
  | { kind: "unlocked" };

type SubView =
  | { kind: "list" }
  | { kind: "detail"; cipher: CipherView }
  | { kind: "typePicker" }
  | { kind: "edit-new"; type: number }
  | { kind: "edit-existing"; cipher: CipherView }
  | { kind: "trash" }
  | { kind: "sends-new-text" }
  | { kind: "sends-new-file" }
  | { kind: "sends-created"; url: string; sendKind: "text" | "file" }
  | { kind: "org-detail"; org: OrgSyncEntry }
  | { kind: "rotate-keys" }
  | { kind: "two-factor" }
  | { kind: "change-password" }
  | { kind: "account-export" }
  | { kind: "import" }
  | { kind: "peer-pins" }
  | { kind: "delete-account" }
  | { kind: "create-org" }
  | { kind: "invites-list" }
  | { kind: "invite-peer"; orgId: string; orgName: string }
  | { kind: "collections"; orgId: string; orgName: string; isOwner: boolean };

function initialPhase(): Phase {
  const hints = loadHints();
  if (hints.rememberMe && hints.email) {
    return { kind: "resume" };
  }
  return { kind: "login" };
}

export function Owner() {
  const [phase, setPhase] = createSignal<Phase>(initialPhase());
  const [tab, setTab] = createSignal<TabId>("vault");
  const [view, setView] = createSignal<SubView>({ kind: "list" });
  const [reloadKey, setReloadKey] = createSignal(0);

  function onAuthenticated() {
    setPhase({ kind: "unlocked" });
    setTab("vault");
    setView({ kind: "list" });
  }

  function onTwoFactor(
    result: Extract<LoginResult, { kind: "needTwoFactor" }>,
    rememberMe: boolean,
  ) {
    setPhase({
      kind: "twoFactor",
      pending: result.pending,
      challenge: result.challenge,
      rememberMe,
    });
  }

  function onLogout() {
    clearSession();
    setView({ kind: "list" });
    setPhase({ kind: "login" });
  }

  function onSessionExpired() {
    expireSession();
    setView({ kind: "list" });
    setPhase(initialPhase());
  }

  return (
    <Switch>
      <Match when={phase().kind === "login"}>
        <Login
          onAuthenticated={onAuthenticated}
          onTwoFactor={onTwoFactor}
          onCreateAccount={() => setPhase({ kind: "register" })}
        />
      </Match>
      <Match when={phase().kind === "register"}>
        <Register
          onRegistered={onAuthenticated}
          onBackToLogin={() => setPhase({ kind: "login" })}
        />
      </Match>
      <Match when={phase().kind === "resume"}>
        <Resume
          onAuthenticated={onAuthenticated}
          onTwoFactor={onTwoFactor}
          onUseDifferentAccount={() => {
            clearSession();
            setPhase({ kind: "login" });
          }}
        />
      </Match>
      <Match when={phase().kind === "twoFactor"}>
        {(() => {
          const p = phase() as Extract<Phase, { kind: "twoFactor" }>;
          return (
            <TwoFactor
              pending={p.pending}
              challenge={p.challenge}
              rememberMe={p.rememberMe}
              onAuthenticated={onAuthenticated}
              onCancel={() => setPhase({ kind: "login" })}
            />
          );
        })()}
      </Match>
      <Match when={phase().kind === "unlocked"}>
        <Switch>
          <Match when={view().kind === "detail"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "detail" }>;
              return (
                <CipherDetail
                  cipher={v.cipher}
                  onBack={() => setView({ kind: "list" })}
                  onEdit={() =>
                    setView({ kind: "edit-existing", cipher: v.cipher })
                  }
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "typePicker"}>
            <TypePicker
              onSelect={(type) => setView({ kind: "edit-new", type })}
              onBack={() => setView({ kind: "list" })}
            />
          </Match>
          <Match when={view().kind === "edit-new"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "edit-new" }>;
              return (
                <EditCipher
                  newType={v.type}
                  onCancel={() => setView({ kind: "list" })}
                  onSaved={() => {
                    setView({ kind: "list" });
                    setReloadKey(reloadKey() + 1);
                  }}
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "edit-existing"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "edit-existing" }>;
              return (
                <EditCipher
                  existing={v.cipher}
                  onCancel={() => setView({ kind: "detail", cipher: v.cipher })}
                  onSaved={() => {
                    setView({ kind: "list" });
                    setReloadKey(reloadKey() + 1);
                  }}
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "trash"}>
            <TrashView
              onBack={() => {
                // The user reached Trash from Settings; bounce back
                // there rather than the Vault tab.
                setTab("settings");
                setView({ kind: "list" });
              }}
              onSessionExpired={onSessionExpired}
              onChanged={() => setReloadKey(reloadKey() + 1)}
            />
          </Match>
          <Match when={view().kind === "sends-new-text"}>
            <NewTextSend
              onCancel={() => setView({ kind: "list" })}
              onCreated={(url) => {
                setReloadKey(reloadKey() + 1);
                setView({ kind: "sends-created", url, sendKind: "text" });
              }}
            />
          </Match>
          <Match when={view().kind === "sends-new-file"}>
            <NewFileSend
              onCancel={() => setView({ kind: "list" })}
              onCreated={(url) => {
                setReloadKey(reloadKey() + 1);
                setView({ kind: "sends-created", url, sendKind: "file" });
              }}
            />
          </Match>
          <Match when={view().kind === "sends-created"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "sends-created" }>;
              return (
                <SendCreated
                  url={v.url}
                  kind={v.sendKind}
                  onDone={() => setView({ kind: "list" })}
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "org-detail"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "org-detail" }>;
              return (
                <OrgDetail
                  org={v.org}
                  onBack={() => setView({ kind: "list" })}
                  onInvitePeer={() =>
                    setView({
                      kind: "invite-peer",
                      orgId: v.org.org_id,
                      orgName: v.org.name,
                    })
                  }
                  onManageCollections={() =>
                    setView({
                      kind: "collections",
                      orgId: v.org.org_id,
                      orgName: v.org.name,
                      isOwner: v.org.role === "owner",
                    })
                  }
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "create-org"}>
            <CreateOrg
              onCancel={() => setView({ kind: "list" })}
              onCreated={() => {
                setView({ kind: "list" });
                setReloadKey(reloadKey() + 1);
              }}
            />
          </Match>
          <Match when={view().kind === "invites-list"}>
            <InvitesList
              onBack={() => setView({ kind: "list" })}
              onAccepted={() => setReloadKey(reloadKey() + 1)}
            />
          </Match>
          <Match when={view().kind === "invite-peer"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "invite-peer" }>;
              return (
                <InvitePeer
                  orgId={v.orgId}
                  orgName={v.orgName}
                  onCancel={() => setView({ kind: "list" })}
                  onInvited={() => {
                    setView({ kind: "list" });
                    setReloadKey(reloadKey() + 1);
                  }}
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "collections"}>
            {(() => {
              const v = view() as Extract<SubView, { kind: "collections" }>;
              return (
                <Collections
                  orgId={v.orgId}
                  orgName={v.orgName}
                  isOwner={v.isOwner}
                  onBack={() => setView({ kind: "list" })}
                />
              );
            })()}
          </Match>
          <Match when={view().kind === "two-factor"}>
            <TwoFactorSettings
              onBack={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
              onSessionExpired={onSessionExpired}
            />
          </Match>
          <Match when={view().kind === "account-export"}>
            <AccountExport
              onBack={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
            />
          </Match>
          <Match when={view().kind === "import"}>
            <Import
              onBack={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
              onImported={() => setReloadKey(reloadKey() + 1)}
            />
          </Match>
          <Match when={view().kind === "peer-pins"}>
            <PeerPins
              onBack={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
            />
          </Match>
          <Match when={view().kind === "delete-account"}>
            <DeleteAccount
              onCancel={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
              onDeleted={() => {
                // deleteAccount() already cleared in-memory + persisted
                // state. Just route back to the login screen.
                setView({ kind: "list" });
                setPhase({ kind: "login" });
                window.alert(
                  "Account deleted. All ciphers, shares, and tokens have been removed from the server.",
                );
              }}
            />
          </Match>
          <Match when={view().kind === "change-password"}>
            <ChangePassword
              onCancel={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
              onDone={() => {
                setTab("settings");
                setView({ kind: "list" });
                setReloadKey(reloadKey() + 1);
                window.alert(
                  "Master password changed. Other sessions are now invalid; re-authenticate on each device.",
                );
              }}
            />
          </Match>
          <Match when={view().kind === "rotate-keys"}>
            <RotateKeys
              onCancel={() => {
                setTab("settings");
                setView({ kind: "list" });
              }}
              onDone={(result) => {
                setTab("settings");
                setView({ kind: "list" });
                setReloadKey(reloadKey() + 1);
                window.alert(
                  `Rotated. Re-wrote ${result.rewroteCiphers} cipher(s), ${result.rewroteSends} share(s), ${result.rewroteOrgMemberships} org membership(s).` +
                    (result.skippedSendIds.length
                      ? ` Skipped ${result.skippedSendIds.length} orphaned share(s) — delete them and retry.`
                      : ""),
                );
              }}
            />
          </Match>
          <Match when={view().kind === "list"}>
            <UnlockedShell
              tab={tab()}
              onTabChange={(t) => {
                setTab(t);
              }}
              reloadKey={reloadKey()}
              onSelectCipher={(c) => setView({ kind: "detail", cipher: c })}
              onAddCipher={() => setView({ kind: "typePicker" })}
              onNewTextSend={() => setView({ kind: "sends-new-text" })}
              onNewFileSend={() => setView({ kind: "sends-new-file" })}
              onSelectOrg={(o) => setView({ kind: "org-detail", org: o })}
              onCreateOrg={() => setView({ kind: "create-org" })}
              onViewInvites={() => setView({ kind: "invites-list" })}
              onViewTrash={() => setView({ kind: "trash" })}
              onLock={onSessionExpired}
              onRotateKeys={() => setView({ kind: "rotate-keys" })}
              onManageTwoFactor={() => setView({ kind: "two-factor" })}
              onChangePassword={() => setView({ kind: "change-password" })}
              onAccountExport={() => setView({ kind: "account-export" })}
              onImport={() => setView({ kind: "import" })}
              onPeerPins={() => setView({ kind: "peer-pins" })}
              onDeleteAccount={() => setView({ kind: "delete-account" })}
              onSessionExpired={onSessionExpired}
              onLogout={onLogout}
            />
          </Match>
        </Switch>
      </Match>
    </Switch>
  );
}

interface UnlockedShellProps {
  tab: TabId;
  onTabChange: (id: TabId) => void;
  reloadKey: number;
  onSelectCipher: (c: CipherView) => void;
  onAddCipher: () => void;
  onNewTextSend: () => void;
  onNewFileSend: () => void;
  onSelectOrg: (o: OrgSyncEntry) => void;
  onCreateOrg: () => void;
  onViewInvites: () => void;
  onViewTrash: () => void;
  onLock: () => void;
  onRotateKeys: () => void;
  onManageTwoFactor: () => void;
  onChangePassword: () => void;
  onAccountExport: () => void;
  onImport: () => void;
  onPeerPins: () => void;
  onDeleteAccount: () => void;
  onSessionExpired: () => void;
  onLogout: () => void;
}

function UnlockedShell(props: UnlockedShellProps) {
  const title = () =>
    ({
      vault: "Vault",
      send: "Share",
      org: "Orgs",
      settings: "Settings",
    })[props.tab];

  // The header `+` button only makes sense on the Vault tab. Other tabs
  // skip it so the header reads as informative, not aspirational.
  const headerAction = () =>
    props.tab === "vault"
      ? {
          Icon: IconPlus,
          ariaLabel: "Add item",
          onClick: props.onAddCipher,
        }
      : undefined;

  return (
    <TopShell
      title={title()}
      activeTab={props.tab}
      onTabChange={props.onTabChange}
      headerAction={headerAction()}
    >
      <Switch>
        <Match when={props.tab === "vault"}>
          <Vault
            reloadKey={props.reloadKey}
            onSelect={props.onSelectCipher}
            onSessionExpired={props.onSessionExpired}
          />
        </Match>
        <Match when={props.tab === "send"}>
          <SendsList
            reloadKey={props.reloadKey}
            onSessionExpired={props.onSessionExpired}
            onNewText={props.onNewTextSend}
            onNewFile={props.onNewFileSend}
          />
        </Match>
        <Match when={props.tab === "org"}>
          <OrgsList
            reloadKey={props.reloadKey}
            onSelect={props.onSelectOrg}
            onCreateOrg={props.onCreateOrg}
            onViewInvites={props.onViewInvites}
            onSessionExpired={props.onSessionExpired}
          />
        </Match>
        <Match when={props.tab === "settings"}>
          <SettingsTab
            onLogout={props.onLogout}
            onViewTrash={props.onViewTrash}
            onLock={props.onLock}
            onRotateKeys={props.onRotateKeys}
            onManageTwoFactor={props.onManageTwoFactor}
            onChangePassword={props.onChangePassword}
            onAccountExport={props.onAccountExport}
            onImport={props.onImport}
            onPeerPins={props.onPeerPins}
            onDeleteAccount={props.onDeleteAccount}
          />
        </Match>
      </Switch>
    </TopShell>
  );
}

function SettingsTab(props: {
  onLogout: () => void;
  onViewTrash: () => void;
  onLock: () => void;
  onRotateKeys: () => void;
  onManageTwoFactor: () => void;
  onChangePassword: () => void;
  onAccountExport: () => void;
  onImport: () => void;
  onPeerPins: () => void;
  onDeleteAccount: () => void;
}) {
  const session = getSession();
  const [strict, setStrict] = createSignal(isStrictManifest());
  return (
    <>
      <Show when={session}>
        {(s) => (
          <div class="card">
            <p style="margin: 0 0 0.25rem;">
              Signed in as <strong>{s().email}</strong>
            </p>
            <p class="muted" style="margin: 0; font-size: 0.85rem;">
              Server: <code>{window.location.origin}</code>
            </p>
            <p class="muted" style="margin: 0.4rem 0 0; font-size: 0.85rem;">
              account_key + signing seed are loaded in memory. Refresh
              token persisted via{" "}
              {localStorage.getItem("hekate.refresh_token")
                ? "localStorage"
                : "sessionStorage"}
              .
            </p>
          </div>
        )}
      </Show>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Session</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Lock clears the in-memory keys but keeps your refresh-token
          tier — you'll see the slim Resume form on next visit. Log out
          fully clears Remember me and forces the full login form.
        </p>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn btn-secondary" onClick={props.onLock}>
            Lock vault
          </button>
          <button class="btn btn-secondary" onClick={props.onLogout}>
            Log out
          </button>
        </div>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Vault</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Soft-deleted items live in the trash until you restore or
          purge them.
        </p>
        <button class="btn btn-secondary" onClick={props.onViewTrash}>
          View trash
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Security</strong>
        </p>
        <label
          style="display: flex; align-items: flex-start; gap: 0.5rem; margin: 0 0 0.75rem;"
        >
          <input
            type="checkbox"
            checked={strict()}
            style="margin-top: 0.25rem;"
            onChange={(e) => {
              setStrict(e.currentTarget.checked);
              setStrictManifest(e.currentTarget.checked);
            }}
          />
          <span>
            <span style="font-weight: 500;">Strict manifest verification</span>
            <span
              class="muted"
              style="display: block; font-size: 0.85rem; margin-top: 0.15rem;"
            >
              Block vault rendering on a BW04 manifest mismatch instead
              of just warning. Off by default; turn on if you want the
              extra paranoia.
            </span>
          </span>
        </label>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Rotate keys generates a fresh <code>account_key</code> and
          re-wraps every dependent. Master password unchanged.
        </p>
        <button class="btn btn-secondary" onClick={props.onRotateKeys}>
          Rotate keys…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Two-factor authentication</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Manage TOTP enrollment and recovery codes. WebAuthn keys
          still require the browser extension or CLI.
        </p>
        <button class="btn btn-secondary" onClick={props.onManageTwoFactor}>
          Manage 2FA…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Master password</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Rotates the KDF salt and the wrapping of your{" "}
          <code>account_key</code> + BW04 signing key. Other devices get
          logged out.
        </p>
        <button class="btn btn-secondary" onClick={props.onChangePassword}>
          Change master password…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Backup</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Download an encrypted JSON snapshot — the{" "}
          <code>account_key</code> plus every cipher and folder, sealed
          under a password you choose.
        </p>
        <button class="btn btn-secondary" onClick={props.onAccountExport}>
          Export account…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Import</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Bring items in from another password manager. Bitwarden
          (unencrypted JSON) today; CSV, 1Password, and KeePass land
          in follow-ups. Parsing happens in your browser — the export
          file is not uploaded to the server.
        </p>
        <button class="btn btn-secondary" onClick={props.onImport}>
          Import items…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Peer pins</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          TOFU trust anchors for peers you share with. Web-vault pins
          are local to this browser; popup and CLI pins live in their
          own stores.
        </p>
        <button class="btn btn-secondary" onClick={props.onPeerPins}>
          Manage peer pins…
        </button>
      </div>

      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Danger zone</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
          Permanently delete this account, including every cipher, Send,
          token, and webhook. Cannot be undone.
        </p>
        <button
          class="btn btn-secondary"
          style="border-color: var(--danger); color: var(--danger);"
          onClick={props.onDeleteAccount}
        >
          Delete account…
        </button>
      </div>
    </>
  );
}
