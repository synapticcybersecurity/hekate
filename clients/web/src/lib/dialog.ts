/* Cross-platform dialog helpers — replacements for window.confirm /
 * window.alert / window.prompt.
 *
 * wry (the WebKit webview behind the Tauri desktop build) does not
 * implement the WKUIDelegate panels for confirm / alert / prompt, so in
 * the desktop app those return false / undefined / null *without showing
 * any UI* — silently breaking every destructive flow gated on a confirm
 * (issue #26: Send delete did nothing because window.confirm returned
 * false). These promise-based helpers render an in-app modal instead, so
 * they behave identically in the browser and the desktop shell and add no
 * native IPC surface. Mount <DialogHost/> once at each render root.
 */
import { createSignal } from "solid-js";

export type DialogKind = "alert" | "confirm" | "prompt";

export interface DialogRequest {
  kind: DialogKind;
  message: string;
  /** prompt only: initial text-input value. */
  defaultValue: string;
  /** OK/confirm button label. */
  okLabel: string;
  /** Whether the OK action is destructive (red styling). */
  danger: boolean;
  resolve: (value: boolean | string | null) => void;
}

const [request, setRequest] = createSignal<DialogRequest | null>(null);

/** Current dialog request (null = none open). Read by <DialogHost/>. */
export const activeDialog = request;

export interface ConfirmOptions {
  okLabel?: string;
  /** Style the OK button as destructive (red). */
  danger?: boolean;
}

/** Replacement for window.confirm. Resolves true iff the user confirms. */
export function confirmDialog(
  message: string,
  opts: ConfirmOptions = {},
): Promise<boolean> {
  return new Promise((resolve) => {
    openDialog({
      kind: "confirm",
      message,
      defaultValue: "",
      okLabel: opts.okLabel ?? "OK",
      danger: opts.danger ?? false,
      resolve: (v) => resolve(v === true),
    });
  });
}

/** Replacement for window.alert. Resolves when dismissed. */
export function alertDialog(message: string): Promise<void> {
  return new Promise((resolve) => {
    openDialog({
      kind: "alert",
      message,
      defaultValue: "",
      okLabel: "OK",
      danger: false,
      resolve: () => resolve(),
    });
  });
}

/** Replacement for window.prompt. Resolves to the entered string, or null
 *  if cancelled. */
export function promptDialog(
  message: string,
  defaultValue = "",
): Promise<string | null> {
  return new Promise((resolve) => {
    openDialog({
      kind: "prompt",
      message,
      defaultValue,
      okLabel: "OK",
      danger: false,
      resolve: (v) => resolve(typeof v === "string" ? v : null),
    });
  });
}

function openDialog(req: DialogRequest): void {
  // If a dialog is somehow already open, cancel it first so its promise
  // never dangles.
  const prev = request();
  if (prev) prev.resolve(prev.kind === "confirm" ? false : null);
  setRequest(req);
}

/** Called by <DialogHost/> when the user acts: the prompt text on OK,
 *  true for a confirmed confirm/alert, or false/null on cancel. */
export function settleDialog(value: boolean | string | null): void {
  const req = request();
  if (!req) return;
  setRequest(null);
  req.resolve(value);
}
