/* Create org (C.6).
 *
 * Single-field form (name) → runs the lib/orgWrite.ts createOrg
 * pipeline. On success the parent re-fetches /sync and routes the
 * user back to the orgs list. Org auto-pins locally so subsequent
 * read-only renders verify the signed roster against a trust anchor.
 */
import { createSignal, Show } from "solid-js";

import { ApiError } from "../../lib/api";
import { createOrg } from "../../lib/orgWrite";
import { SubShell } from "../../ui/Shell";

export interface CreateOrgProps {
  onCancel: () => void;
  onCreated: (result: { orgId: string; fingerprint: string }) => void;
}

export function CreateOrg(props: CreateOrgProps) {
  const [name, setName] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!name().trim()) {
      setError("Name required.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await createOrg(name());
      props.onCreated(result);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err),
      );
      setSubmitting(false);
    }
  }

  return (
    <SubShell title="Create organization" onBack={props.onCancel}>
      <p class="muted" style="margin: 0 0 0.85rem;">
        You'll be the sole owner. The org gets its own Ed25519 signing
        key (you'll sign rosters when inviting members) and a 32-byte
        symmetric key (wraps collection names + future org-side
        ciphers). Both are encrypted in your browser before upload.
      </p>
      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="org-name">Name</label>
          <input
            id="org-name"
            type="text"
            required
            autofocus
            maxlength="120"
            placeholder="e.g. Engineering"
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </div>
        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Creating…" : "Create"}
          </button>
          <button
            class="btn btn-secondary"
            type="button"
            disabled={submitting()}
            onClick={props.onCancel}
          >
            Cancel
          </button>
        </div>
      </form>
    </SubShell>
  );
}
