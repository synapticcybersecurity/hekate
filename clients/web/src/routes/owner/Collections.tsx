/* Org collections list + create + delete (C.6).
 *
 * Reads /api/v1/orgs/{org_id}/collections, decrypts each name client-
 * side under the org_sym_key (AAD-bound to (collection_id, org_id)).
 * Owners get Delete buttons; create is open to any member with VAULT_WRITE.
 */
import { createSignal, For, Match, onMount, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  createCollection,
  deleteCollection,
  listCollections,
  type DecodedCollection,
} from "../../lib/orgWrite";
import { SubShell } from "../../ui/Shell";

export interface CollectionsProps {
  orgId: string;
  orgName: string;
  isOwner: boolean;
  onBack: () => void;
}

type Phase =
  | { kind: "loading" }
  | { kind: "load-error"; message: string }
  | { kind: "list"; collections: DecodedCollection[] }
  | {
      kind: "create";
      name: string;
      submitting: boolean;
      message: string | null;
    };

export function Collections(props: CollectionsProps) {
  const [phase, setPhase] = createSignal<Phase>({ kind: "loading" });
  const [deleteError, setDeleteError] = createSignal<string | null>(null);

  onMount(() => {
    void refresh();
  });

  async function refresh(): Promise<void> {
    setPhase({ kind: "loading" });
    setDeleteError(null);
    try {
      const collections = await listCollections(props.orgId);
      setPhase({ kind: "list", collections });
    } catch (err) {
      setPhase({ kind: "load-error", message: errMsg(err) });
    }
  }

  function startCreate() {
    setPhase({ kind: "create", name: "", submitting: false, message: null });
  }

  async function onCreateSubmit(rawName: string) {
    const name = rawName.trim();
    if (!name) {
      setPhase({ kind: "create", name: rawName, submitting: false, message: "Name required." });
      return;
    }
    setPhase({ kind: "create", name: rawName, submitting: true, message: "Creating…" });
    try {
      await createCollection(props.orgId, name);
      await refresh();
    } catch (err) {
      setPhase({
        kind: "create",
        name: rawName,
        submitting: false,
        message: errMsg(err),
      });
    }
  }

  async function onDelete(c: DecodedCollection) {
    if (
      !window.confirm(
        `Delete collection "${c.decryptedName}"? Ciphers in it will lose the org-side membership.`,
      )
    ) {
      return;
    }
    setDeleteError(null);
    try {
      await deleteCollection(props.orgId, c.id);
      await refresh();
    } catch (err) {
      setDeleteError(errMsg(err));
    }
  }

  return (
    <SubShell title={`Collections — ${props.orgName}`} onBack={props.onBack}>
      <Switch>
        <Match when={phase().kind === "create"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "create" }>;
            return (
              <CreateCollectionForm
                submitting={p.submitting}
                message={p.message}
                onSubmit={(name) => void onCreateSubmit(name)}
                onCancel={() => void refresh()}
              />
            );
          })()}
        </Match>

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

        <Match when={phase().kind === "list"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "list" }>;
            return (
              <>
                <div style="display: flex; gap: 0.5rem; margin: 0 0 0.85rem;">
                  <button class="btn" type="button" onClick={startCreate}>
                    + New collection
                  </button>
                </div>
                <Show when={deleteError()}>
                  <div class="banner banner-error">{deleteError()}</div>
                </Show>
                <Show
                  when={p.collections.length > 0}
                  fallback={
                    <p class="muted" style="margin: 0; font-size: 0.85rem;">
                      No collections in this org yet.
                    </p>
                  }
                >
                  <ul style="list-style: none; margin: 0; padding: 0;">
                    <For each={p.collections}>
                      {(c) => (
                        <li style="border-top: 1px solid var(--border); padding: 0.6rem 0;">
                          <p style="margin: 0 0 0.2rem; font-weight: 500;">
                            {c.decryptedName}
                          </p>
                          <p class="muted" style="margin: 0 0 0.4rem; font-size: 0.8rem;">
                            <code style="word-break: break-all;">{c.id}</code>
                          </p>
                          <Show when={props.isOwner}>
                            <button
                              class="btn btn-secondary"
                              type="button"
                              style="padding: 0.3rem 0.75rem; font-size: 0.85rem; border-color: var(--danger); color: var(--danger);"
                              onClick={() => void onDelete(c)}
                            >
                              Delete
                            </button>
                          </Show>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </>
            );
          })()}
        </Match>
      </Switch>
    </SubShell>
  );
}

interface CreateCollectionFormProps {
  submitting: boolean;
  message: string | null;
  onSubmit: (name: string) => void;
  onCancel: () => void;
}

function CreateCollectionForm(props: CreateCollectionFormProps) {
  // Local signal to avoid the Match+IIFE focus-loss gotcha.
  const [name, setName] = createSignal("");

  function onFormSubmit(e: Event) {
    e.preventDefault();
    if (props.submitting || !name().trim()) return;
    props.onSubmit(name());
  }

  return (
    <form class="card" onSubmit={onFormSubmit}>
      <p style="margin: 0 0 0.4rem;">
        <strong>New collection</strong>
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
        The name is encrypted under the org symmetric key in your
        browser before upload. The server only sees ciphertext.
      </p>
      <div class="field">
        <label for="coll-name">Name</label>
        <input
          id="coll-name"
          type="text"
          required
          autofocus
          maxlength="120"
          placeholder="e.g. Engineering"
          value={name()}
          onInput={(e) => setName(e.currentTarget.value)}
        />
      </div>
      <Show when={props.message}>
        <div class="banner banner-error">{props.message}</div>
      </Show>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn" type="submit" disabled={props.submitting || !name().trim()}>
          {props.submitting ? "Creating…" : "Create"}
        </button>
        <button
          class="btn btn-secondary"
          type="button"
          disabled={props.submitting}
          onClick={props.onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

function errMsg(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
