/* Clipboard helper with auto-clear after 30 s, modeled on the popup's
 * `copyWithAutoClear`. Auto-clear is best-effort; some browsers reject
 * `clipboard.writeText("")` from a non-user-gesture context, in which
 * case the password just persists until the next copy.
 */

const AUTO_CLEAR_MS = 30_000;
let timer: number | undefined;

export async function copy(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  if (timer !== undefined) {
    clearTimeout(timer);
  }
  timer = window.setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => undefined);
    timer = undefined;
  }, AUTO_CLEAR_MS);
}
