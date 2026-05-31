/* Renders the active in-app dialog (see lib/dialog.ts). Mount once per
 * render root. A singleton store drives it, so a single instance anywhere
 * in the tree handles every confirmDialog/alertDialog/promptDialog call.
 */
import { createEffect, onCleanup, Show } from "solid-js";

import { activeDialog, settleDialog } from "../lib/dialog";

export function DialogHost() {
  let inputRef: HTMLInputElement | undefined;

  function onOk() {
    const d = activeDialog();
    if (!d) return;
    settleDialog(d.kind === "prompt" ? (inputRef?.value ?? "") : true);
  }

  function onCancel() {
    const d = activeDialog();
    if (!d) return;
    settleDialog(d.kind === "prompt" ? null : false);
  }

  // Seed + focus the prompt input when a dialog opens, and wire Enter/Esc
  // to OK/Cancel. The effect re-runs (with cleanup) whenever the active
  // dialog changes, so listeners never leak across dialogs.
  createEffect(() => {
    const d = activeDialog();
    if (!d) return;
    if (d.kind === "prompt") {
      queueMicrotask(() => {
        if (inputRef) {
          inputRef.value = d.defaultValue;
          inputRef.focus();
          inputRef.select();
        }
      });
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && d.kind !== "alert") {
        e.preventDefault();
        onCancel();
      } else if (e.key === "Enter" && d.kind !== "prompt") {
        e.preventDefault();
        onOk();
      }
    };
    document.addEventListener("keydown", onKey);
    onCleanup(() => document.removeEventListener("keydown", onKey));
  });

  return (
    <Show when={activeDialog()}>
      {(d) => (
        <div
          class="dialog-backdrop"
          onClick={(e) => {
            // Click outside the card cancels (except alerts, which only
            // have an OK action).
            if (e.target === e.currentTarget && d().kind !== "alert") onCancel();
          }}
        >
          <div class="dialog" role="dialog" aria-modal="true">
            <p class="dialog-message">{d().message}</p>
            <Show when={d().kind === "prompt"}>
              <input
                ref={inputRef}
                class="input"
                type="text"
                value={d().defaultValue}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    onOk();
                  }
                }}
              />
            </Show>
            <div class="dialog-actions">
              <Show when={d().kind !== "alert"}>
                <button class="btn btn-secondary" type="button" onClick={onCancel}>
                  Cancel
                </button>
              </Show>
              <button
                classList={{ btn: true, "btn-danger": d().danger }}
                type="button"
                onClick={onOk}
              >
                {d().okLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </Show>
  );
}
