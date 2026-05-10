/* Reusable layout shells, modeled on the popup's topShell / subShell.
 *
 *   <TopShell>   header + content + bottom tab bar      → Vault, Sends, Orgs, Settings
 *   <SubShell>   header w/ back button + content        → Cipher detail, Add/Edit (C.3b+)
 *
 * Tabs are owned by the parent (Owner.tsx) — TopShell takes the active
 * tab id + a callback. Keeps tab state out of the shell so children
 * don't have to prop-drill.
 */
import type { JSX } from "solid-js";
import { For, Show } from "solid-js";

import {
  IconBack,
  IconOrg,
  IconSend,
  IconSettings,
  IconVault,
} from "./icons";

export type TabId = "vault" | "send" | "org" | "settings";

const TAB_DEFS: Array<{
  id: TabId;
  label: string;
  Icon: (p: { class?: string }) => JSX.Element;
}> = [
  { id: "vault", label: "Vault", Icon: IconVault },
  { id: "send", label: "Share", Icon: IconSend },
  { id: "org", label: "Orgs", Icon: IconOrg },
  { id: "settings", label: "Settings", Icon: IconSettings },
];

export interface HeaderAction {
  Icon: (p: { class?: string }) => JSX.Element;
  ariaLabel: string;
  onClick: () => void;
}

export interface TopShellProps {
  title: string;
  activeTab: TabId;
  onTabChange: (id: TabId) => void;
  headerAction?: HeaderAction;
  children: JSX.Element;
}

export function TopShell(props: TopShellProps): JSX.Element {
  return (
    <div class="shell">
      <div class="shell-header">
        <div class="header-title">{props.title}</div>
        <Show when={props.headerAction}>
          {(action) => {
            const A = action();
            const Icon = A.Icon;
            return (
              <button
                class="header-action"
                type="button"
                aria-label={A.ariaLabel}
                title={A.ariaLabel}
                onClick={A.onClick}
              >
                <Icon />
              </button>
            );
          }}
        </Show>
      </div>
      <div class="shell-content">
        <div class="shell-inner">{props.children}</div>
      </div>
      <div class="shell-tabbar">
        <For each={TAB_DEFS}>
          {(t) => {
            const Icon = t.Icon;
            return (
              <button
                type="button"
                class={`tab ${t.id === props.activeTab ? "active" : ""}`}
                aria-label={t.label}
                onClick={() => props.onTabChange(t.id)}
              >
                <Icon />
                <span>{t.label}</span>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
}

export interface SubShellProps {
  title: string;
  onBack: () => void;
  headerAction?: HeaderAction;
  children: JSX.Element;
}

export function SubShell(props: SubShellProps): JSX.Element {
  return (
    <div class="shell">
      <div class="shell-header">
        <button
          class="header-back"
          type="button"
          aria-label="Back"
          onClick={props.onBack}
        >
          <IconBack />
          <span>Back</span>
        </button>
        <div class="header-title">{props.title}</div>
        <Show when={props.headerAction}>
          {(action) => {
            const A = action();
            const Icon = A.Icon;
            return (
              <button
                class="header-action"
                type="button"
                aria-label={A.ariaLabel}
                title={A.ariaLabel}
                onClick={A.onClick}
              >
                <Icon />
              </button>
            );
          }}
        </Show>
      </div>
      <div class="shell-content">
        <div class="shell-inner">{props.children}</div>
      </div>
    </div>
  );
}
