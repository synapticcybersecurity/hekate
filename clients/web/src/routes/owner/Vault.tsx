/* Vault list — read-only.
 *
 * Pulls /api/v1/sync, BW04-verifies the manifest signature under the
 * locally-pinned signing pubkey (warn-mode banner on mismatch),
 * decrypts every cipher into a list-view shape, and renders rows
 * with type-tinted icons + per-type copy actions.
 *
 * Read-only in C.3a — no add/edit/delete. The header `+` button and
 * row-level edit/trash buttons land in C.3b/c.
 */
import {
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";

import { copy } from "../../lib/clipboard";
import {
  CipherType,
  decryptForList,
  type CipherView,
  type DecryptedListItem,
} from "../../lib/cipher";
import { ApiError, SessionExpiredError } from "../../lib/api";
import { fetchSync } from "../../lib/sync";
import { verifyVaultManifest } from "../../lib/manifest";
import { getSession, loadHints } from "../../lib/session";
import { isStrictManifest } from "../../lib/strictManifest";
import { totpCode } from "../../lib/totp";
import { loadHekateCore } from "../../wasm";
import {
  IconCopy,
  IconSearch,
  iconForCipherType,
} from "../../ui/icons";

interface FilterOption {
  id: number;
  label: string;
}
const FILTERS: FilterOption[] = [
  { id: 0, label: "All" },
  { id: CipherType.Login, label: "Logins" },
  { id: CipherType.Totp, label: "TOTP" },
  { id: CipherType.Card, label: "Cards" },
  { id: CipherType.Identity, label: "Identities" },
  { id: CipherType.Note, label: "Notes" },
  { id: CipherType.SshKey, label: "SSH" },
  { id: CipherType.Api, label: "API" },
];

export interface VaultProps {
  onSelect: (raw: CipherView) => void;
  onSessionExpired: () => void;
  /** Bumped by the parent after an add/edit finishes — Vault watches
   *  it via createEffect and re-runs the sync. */
  reloadKey: number;
}

export function Vault(props: VaultProps) {
  const [items, setItems] = createSignal<DecryptedListItem[]>([]);
  // Keep the raw sync rows around so CipherDetail can do a full decrypt
  // (including notes) without a second round trip. Cleared on every
  // re-sync. C.3b will revisit this when add/edit lands.
  let rawById = new Map<string, CipherView>();
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [manifestWarning, setManifestWarning] = createSignal<string | null>(null);
  const [filter, setFilter] = createSignal<number>(0);
  const [search, setSearch] = createSignal("");
  const [toast, setToast] = createSignal<string | null>(null);
  const [now, setNow] = createSignal(Math.floor(Date.now() / 1000));

  // Re-tick once a second so the TOTP "X s" countdown updates without
  // re-running HMAC every frame.
  const tickHandle = window.setInterval(() => {
    setNow(Math.floor(Date.now() / 1000));
  }, 1000);
  onCleanup(() => clearInterval(tickHandle));

  // Initial load + reload-on-bump. Solid auto-tracks props.reloadKey
  // through this effect, so the parent only needs to bump the counter.
  createEffect(() => {
    void props.reloadKey;
    void loadVault();
  });

  async function loadVault() {
    setLoading(true);
    setError(null);
    try {
      const session = getSession();
      if (!session) throw new SessionExpiredError("no session");
      const sync = await fetchSync();
      const hekate = await loadHekateCore();

      // Manifest verification. Strict mode (Settings toggle) blocks
      // rendering on real disagreement; warn mode (default) shows a
      // banner above the rows. The fresh-account / pre-genesis case
      // (no manifest yet AND no ciphers) is silenced — the genesis
      // manifest gets created on the first cipher write, so alarming
      // before then is just noise. A missing manifest WITH ciphers,
      // by contrast, is a real disagreement.
      let strictBlock = false;
      if (sync.manifest) {
        const hints = loadHints();
        if (hints.signingPubkeyB64) {
          const v = await verifyVaultManifest(sync.manifest, hints.signingPubkeyB64);
          if (!v.ok) {
            setManifestWarning(v.reason);
            if (isStrictManifest()) strictBlock = true;
          } else {
            setManifestWarning(null);
          }
        } else {
          setManifestWarning(
            "No locally-pinned signing pubkey — manifest signature unchecked. Re-login may be needed.",
          );
        }
      } else if (sync.changes.ciphers.length > 0) {
        setManifestWarning(
          "server returned ciphers but no signed manifest — refusing to trust the cipher list",
        );
        if (isStrictManifest()) strictBlock = true;
      } else {
        setManifestWarning(null);
      }

      if (strictBlock) {
        rawById = new Map();
        setItems([]);
        return;
      }

      rawById = new Map();
      const decrypted = sync.changes.ciphers
        // Trash filter: non-deleted only on the main list.
        .filter((c) => !c.deleted_date)
        .map((c) => {
          rawById.set(c.id, c);
          return decryptForList(hekate, c, session.accountKey);
        });
      // Sort by name (case-insensitive); favorites surface to the top.
      decrypted.sort((a, b) => {
        if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
        return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
      });
      setItems(decrypted);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        props.onSessionExpired();
        return;
      }
      const msg =
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  const filtered = createMemo(() => {
    const f = filter();
    const q = search().trim().toLowerCase();
    return items().filter((item) => {
      if (f !== 0 && item.type !== f) return false;
      if (!q) return true;
      return item.name.toLowerCase().includes(q);
    });
  });

  function showToast(message: string) {
    setToast(message);
    window.setTimeout(() => setToast(null), 2200);
  }

  async function copyField(label: string, value: string | undefined) {
    if (!value) {
      showToast(`${label} is empty`);
      return;
    }
    try {
      await copy(value);
      showToast(`${label} copied`);
    } catch (err) {
      showToast(`Copy failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return (
    <>
      <div class="search-bar">
        <IconSearch />
        <input
          type="search"
          autocomplete="off"
          placeholder="Search vault…"
          value={search()}
          onInput={(e) => setSearch(e.currentTarget.value)}
        />
      </div>

      <div class="filter-chips">
        <For each={FILTERS}>
          {(f) => (
            <button
              type="button"
              class={`chip ${filter() === f.id ? "active" : ""}`}
              onClick={() => setFilter(f.id)}
            >
              {f.label}
            </button>
          )}
        </For>
      </div>

      <Show when={manifestWarning()}>
        <div class="banner banner-error" style="margin-bottom: 0.75rem;">
          <strong>Vault manifest:</strong> {manifestWarning()}
        </div>
      </Show>

      <Show when={error()}>
        <div class="banner banner-error">{error()}</div>
      </Show>

      <Show when={loading()}>
        <p class="muted">Loading…</p>
      </Show>

      <Show when={!loading() && filtered().length === 0 && !error()}>
        <p class="muted">
          {items().length === 0
            ? "No vault items yet. Add one from the CLI or browser extension; web add ships in C.3b."
            : "Nothing matches the current filter."}
        </p>
      </Show>

      <div role="list">
        <For each={filtered()}>
          {(item) => (
            <CipherRow
              item={item}
              now={now()}
              onSelect={() => {
                const raw = rawById.get(item.id);
                if (raw) props.onSelect(raw);
              }}
              onCopy={copyField}
            />
          )}
        </For>
      </div>

      <Show when={toast()}>
        <div class="toast" role="status">
          {toast()}
        </div>
      </Show>
    </>
  );
}

interface CipherRowProps {
  item: DecryptedListItem;
  now: number;
  onSelect: () => void;
  onCopy: (label: string, value: string | undefined) => Promise<void>;
}

function CipherRow(p: CipherRowProps) {
  const Icon = iconForCipherType(p.item.type);
  const sub = createMemo(() => subForRow(p.item));

  // TOTP rows tick a separate signal that depends on `now()`. Recompute
  // the displayed code whenever the second-tick fires (cheap HMAC).
  const [totpDisplay, setTotpDisplay] = createSignal<string>("");
  const isTotp = p.item.type === CipherType.Totp;
  if (isTotp) {
    const secret =
      typeof p.item.data?.secret === "string" ? p.item.data.secret : undefined;
    const issuer =
      typeof p.item.data?.issuer === "string" ? p.item.data.issuer : "";
    const account =
      typeof p.item.data?.accountName === "string" ? p.item.data.accountName : "";
    const prefix = [issuer, account].filter(Boolean).join(" / ");
    const refresh = async () => {
      if (!secret) {
        setTotpDisplay("(no secret)");
        return;
      }
      try {
        const { code, remaining } = await totpCode(secret);
        setTotpDisplay(`${prefix ? `${prefix}  ` : ""}${code}  (${remaining}s)`);
      } catch (err) {
        setTotpDisplay(`(error: ${err instanceof Error ? err.message : String(err)})`);
      }
    };
    void refresh();
    // Re-run whenever `now()` changes (Solid memos auto-track signals).
    createMemo(() => {
      void p.now;
      void refresh();
    });
  }

  return (
    <button class="cipher-row" type="button" role="listitem" onClick={p.onSelect}>
      <span class="row-icon" data-type={p.item.type}>
        <Icon />
      </span>
      <span class="row-body">
        <div class="row-name">{p.item.name}</div>
        <Show when={isTotp}>
          <div class="row-sub">{totpDisplay()}</div>
        </Show>
        <Show when={!isTotp && sub()}>
          <div class="row-sub">{sub()}</div>
        </Show>
      </span>
      <span class="row-actions" onClick={(e) => e.stopPropagation()}>
        <Show when={p.item.type === CipherType.Login}>
          <button
            type="button"
            class="icon-btn"
            title="Copy username"
            aria-label="Copy username"
            onClick={() =>
              p.onCopy("Username", str(p.item.data?.username))
            }
          >
            <IconCopy />
          </button>
          <button
            type="button"
            class="icon-btn"
            title="Copy password"
            aria-label="Copy password"
            onClick={() =>
              p.onCopy("Password", str(p.item.data?.password))
            }
          >
            <IconCopy />
          </button>
        </Show>
        <Show when={p.item.type === CipherType.Totp}>
          <button
            type="button"
            class="icon-btn"
            title="Copy code"
            aria-label="Copy TOTP code"
            onClick={async () => {
              const secret = str(p.item.data?.secret);
              if (!secret) {
                await p.onCopy("Code", undefined);
                return;
              }
              try {
                const { code } = await totpCode(secret);
                await p.onCopy("Code", code);
              } catch (err) {
                await p.onCopy(
                  "Code",
                  // Surface error via the toast.
                  undefined,
                );
                console.error(err);
              }
            }}
          >
            <IconCopy />
          </button>
        </Show>
      </span>
    </button>
  );
}

function subForRow(item: DecryptedListItem): string | null {
  const d = item.data;
  if (!d) return null;
  switch (item.type) {
    case CipherType.Login: {
      const username = str(d.username);
      const uri = str(d.uri);
      return [username, uri].filter(Boolean).join(" — ") || null;
    }
    case CipherType.Card: {
      const brand = str(d.brand);
      const num = str(d.number);
      const last4 = num ? num.replace(/\s+/g, "").slice(-4) : "";
      return [brand, last4 ? `•••• ${last4}` : ""].filter(Boolean).join(" ") || null;
    }
    case CipherType.Identity: {
      return [str(d.firstName), str(d.lastName)].filter(Boolean).join(" ") || null;
    }
    case CipherType.SshKey: {
      return str(d.fingerprint) || null;
    }
    default:
      return null;
  }
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}
