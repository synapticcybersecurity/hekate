/* Add/edit form — type-aware, single component for both create and
 * update. Mirrors the popup's renderAddEdit + onSaveCipher.
 *
 * On submit:
 *   1. Build the encrypted payload via `saveCipher` (XChaCha20-Poly1305
 *      with AAD bound to id+type — see lib/cipherWrite.ts).
 *   2. POST `/api/v1/ciphers` (create) or PUT with `If-Match`
 *      (edit; revision_date enforces optimistic concurrency).
 *   3. Re-sign the BW04 manifest so the signed set tracks the new
 *      cipher list.
 *   4. Toast + bubble back to the parent (Owner.tsx) which re-renders
 *      the vault with a fresh sync.
 */
import {
  createMemo,
  createSignal,
  For,
  Show,
} from "solid-js";

import { ApiError } from "../../lib/api";
import {
  CIPHER_TYPE_DEFS,
  CipherType,
  decryptFull,
  type CipherView,
  type FieldDef,
} from "../../lib/cipher";
import { deleteCipher, saveCipher, type CipherDraft } from "../../lib/cipherWrite";
import { copy } from "../../lib/clipboard";
import { uploadManifestQuiet } from "../../lib/manifest";
import { generatePassword } from "../../lib/passwordGen";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import { IconCopy, IconEye, IconEyeOff } from "../../ui/icons";
import { SubShell } from "../../ui/Shell";

export interface EditCipherProps {
  /** Existing cipher (edit mode). Mutually exclusive with `newType`. */
  existing?: CipherView;
  /** New-cipher type id (create mode). Mutually exclusive with `existing`. */
  newType?: number;
  onCancel: () => void;
  /** Called after successful save with the server's freshly-issued view. */
  onSaved: (saved: CipherView) => void;
}

export function EditCipher(props: EditCipherProps) {
  const cipherType =
    props.newType ?? (props.existing ? props.existing.type : CipherType.Login);
  const isCreate = !props.existing;
  const def = CIPHER_TYPE_DEFS[cipherType];
  if (!def) {
    return (
      <SubShell title="Unsupported type" onBack={props.onCancel}>
        <div class="banner banner-error">
          Cipher type {cipherType} can't be edited from the web vault yet.
        </div>
      </SubShell>
    );
  }

  const [name, setName] = createSignal("");
  const [notes, setNotes] = createSignal("");
  const initialFields: Record<string, string> = {};
  for (const f of def.fields) initialFields[f.name] = "";
  const [fields, setFields] = createSignal<Record<string, string>>(initialFields);
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [toast, setToast] = createSignal<string | null>(null);

  // For edit mode, decrypt existing values into the form on mount.
  void (async () => {
    if (!props.existing) return;
    try {
      const hekate = await loadHekateCore();
      const session = getSession();
      if (!session) throw new Error("session expired");
      const full = decryptFull(hekate, props.existing, session.accountKey);
      setName(full.name === "<undecryptable>" ? "" : full.name);
      setNotes(full.notes);
      const next = { ...initialFields };
      for (const f of def.fields) {
        const v = full.data?.[f.name];
        if (typeof v === "string") next[f.name] = v;
      }
      setFields(next);
    } catch (err) {
      setError(`Couldn't decrypt for editing: ${messageOf(err)}`);
    }
  })();

  const title = createMemo(() =>
    isCreate ? `New ${def.label.toLowerCase()}` : `Edit ${name() || def.label}`,
  );

  function setField(key: string, value: string) {
    setFields({ ...fields(), [key]: value });
  }

  function showToast(msg: string) {
    setToast(msg);
    window.setTimeout(() => setToast(null), 2200);
  }

  async function copyValue(label: string, value: string | undefined) {
    if (!value) {
      showToast(`${label} is empty`);
      return;
    }
    try {
      await copy(value);
      showToast(`${label} copied`);
    } catch (err) {
      showToast(`Copy failed: ${messageOf(err)}`);
    }
  }

  async function onMoveToTrash() {
    if (!props.existing) return;
    if (!window.confirm(`Move "${name() || "this item"}" to trash?`)) return;
    setSubmitting(true);
    setError(null);
    try {
      await deleteCipher(props.existing.id);
      // Best-effort manifest re-sign — same trade-off as save.
      await uploadManifestQuiet();
      // The parent's onSaved callback also returns to the list and
      // bumps the reload counter, which is what we want here too.
      props.onSaved(props.existing);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : messageOf(err),
      );
      setSubmitting(false);
    }
  }

  async function onSubmit(e: Event) {
    e.preventDefault();
    if (!name().trim()) {
      setError("Name is required.");
      return;
    }
    if (cipherType === CipherType.Note && !notes().trim()) {
      setError("Note body is required.");
      return;
    }
    setSubmitting(true);
    setError(null);

    try {
      const session = getSession();
      if (!session) throw new Error("session expired");

      // Strip blanks from data so we don't persist empty-string keys.
      const data: Record<string, string> = {};
      for (const f of def.fields) {
        const v = (fields()[f.name] ?? "").trim();
        if (v !== "") data[f.name] = v;
      }

      const draft: CipherDraft = {
        id: props.existing?.id ?? null,
        type: cipherType,
        name: name().trim(),
        notes: notes().trim() || null,
        data,
        favorite: props.existing?.favorite ?? false,
        folderId: props.existing?.folder_id ?? null,
      };
      const saved = await saveCipher(draft, session.accountKey, props.existing);
      // Best-effort manifest re-sign; failure logs to console but
      // doesn't roll back the cipher write.
      await uploadManifestQuiet();
      props.onSaved(saved);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : messageOf(err),
      );
      setSubmitting(false);
    }
  }

  return (
    <SubShell title={title()} onBack={props.onCancel}>
      <form class="card" onSubmit={onSubmit}>
        <div class="field">
          <label for="cipher-name">Name</label>
          <input
            id="cipher-name"
            type="text"
            required
            autofocus
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </div>

        <For each={def.fields}>
          {(f) => (
            <DynamicField
              field={f}
              value={fields()[f.name] ?? ""}
              onChange={(v) => setField(f.name, v)}
              onCopy={copyValue}
            />
          )}
        </For>

        <div class="field">
          <label for="cipher-notes">Notes</label>
          <textarea
            id="cipher-notes"
            class="input"
            rows={cipherType === CipherType.Note ? 8 : 3}
            value={notes()}
            onInput={(e) => setNotes(e.currentTarget.value)}
          />
        </div>

        <Show when={error()}>
          <div class="banner banner-error">{error()}</div>
        </Show>

        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
          <button class="btn" type="submit" disabled={submitting()}>
            {submitting() ? "Saving…" : isCreate ? "Create" : "Save"}
          </button>
          <button
            class="btn btn-secondary"
            type="button"
            disabled={submitting()}
            onClick={props.onCancel}
          >
            Cancel
          </button>
          <Show when={props.existing}>
            <button
              type="button"
              class="btn"
              style="margin-left: auto; background: var(--danger);"
              disabled={submitting()}
              onClick={onMoveToTrash}
            >
              Move to trash
            </button>
          </Show>
        </div>
      </form>

      <Show when={toast()}>
        <div class="toast" role="status">
          {toast()}
        </div>
      </Show>
    </SubShell>
  );
}

interface DynamicFieldProps {
  field: FieldDef;
  value: string;
  onChange: (v: string) => void;
  onCopy: (label: string, value: string | undefined) => Promise<void>;
}

function DynamicField(props: DynamicFieldProps) {
  const [revealed, setRevealed] = createSignal(false);
  const f = props.field;
  const isReveal = !!f.reveal;
  const isTextarea = f.kind === "textarea";

  const inputType = () => {
    if (isReveal) return revealed() ? "text" : "password";
    if (f.kind === "password") return "password";
    if (f.kind === "email") return "email";
    if (f.kind === "url") return "url";
    if (f.kind === "tel") return "tel";
    return "text";
  };

  return (
    <div class="field">
      <label for={`cipher-${f.name}`}>{f.label}</label>
      <div style="display: flex; gap: 0.35rem; align-items: stretch;">
        <Show
          when={!isTextarea}
          fallback={
            <textarea
              id={`cipher-${f.name}`}
              class="input"
              rows={f.rows ?? 3}
              placeholder={f.placeholder}
              value={props.value}
              onInput={(e) => props.onChange(e.currentTarget.value)}
              autocomplete={f.autocompleteOff ? "off" : undefined}
            />
          }
        >
          <input
            id={`cipher-${f.name}`}
            type={inputType()}
            placeholder={f.placeholder}
            value={props.value}
            onInput={(e) => props.onChange(e.currentTarget.value)}
            maxLength={f.maxLength}
            autocomplete={f.autocompleteOff ? "off" : undefined}
            style="flex: 1 1 auto;"
          />
        </Show>
        <Show when={isReveal}>
          <button
            type="button"
            class="icon-btn"
            aria-label={revealed() ? `Hide ${f.label}` : `Reveal ${f.label}`}
            title={revealed() ? `Hide ${f.label}` : `Reveal ${f.label}`}
            onClick={() => setRevealed(!revealed())}
          >
            {revealed() ? <IconEyeOff /> : <IconEye />}
          </button>
        </Show>
        <Show when={f.generate}>
          <button
            type="button"
            class="btn btn-secondary"
            style="white-space: nowrap;"
            title="Generate password"
            onClick={() => props.onChange(generatePassword(20))}
          >
            Generate
          </button>
        </Show>
        <Show when={isReveal && props.value}>
          <button
            type="button"
            class="icon-btn"
            aria-label={`Copy ${f.label}`}
            title={`Copy ${f.label}`}
            onClick={() => props.onCopy(f.label, props.value)}
          >
            <IconCopy />
          </button>
        </Show>
      </div>
    </div>
  );
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
