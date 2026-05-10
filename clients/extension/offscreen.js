/**
 * Offscreen document — receives a single `hekate:clipboard_clear` from the
 * service worker and writes "" to the clipboard. The SW closes us
 * immediately afterward.
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Audit X-H2 (2026-05-07): defense-in-depth — refuse messages from
  // anything but our own extension contexts.
  if (!sender || sender.id !== chrome.runtime.id) return false;
  if (msg && msg.type === "hekate:clipboard_clear") {
    navigator.clipboard
      .writeText("")
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true; // async response
  }
  return false;
});
