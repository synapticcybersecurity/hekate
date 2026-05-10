/**
 * hekate browser extension — service worker.
 *
 * Owns the long-lived SSE connection to /push/v1/stream. Survives popup
 * close so vault edits made elsewhere can still wake the popup the next
 * time the user opens it (and broadcast immediately if the popup is
 * already open).
 *
 * Lifecycle limitations (Manifest V3): the SW idles after ~30s with no
 * activity. An open `fetch` stream counts as activity, so as long as the
 * SSE connection is up the SW stays alive. When the connection drops —
 * disconnect, network change, or Chrome forcibly evicting the SW — we
 * reconnect on next wake (popup open, alarm, or chrome.runtime event).
 *
 * Wire protocol matches the popup's `parseSseChunk` from M3.7. We can't
 * use `EventSource` because it doesn't allow custom Authorization
 * headers; we go through `fetch` + manual parsing instead.
 */

const MSG_VAULT_CHANGED = "hekate:vault_changed";
const MSG_START_SSE = "hekate:start_sse";
const MSG_STOP_SSE = "hekate:stop_sse";
const MSG_SCHEDULE_CLEAR = "hekate:schedule_clipboard_clear";
const MSG_CANCEL_CLEAR = "hekate:cancel_clipboard_clear";
const MSG_OFFSCREEN_CLEAR = "hekate:clipboard_clear";
const ALARM_CLIPBOARD = "hekate-clipboard-clear";
const OFFSCREEN_DOC = "offscreen.html";

// GH #1 — passkey provider. The SW hooks chrome.webAuthenticationProxy
// and dispatches each ceremony to the popup for user approval. Replies
// flow back via MSG_PASSKEY_REPLY; if the popup never opens within 60s
// we synthesize a NotAllowedError so the RP doesn't hang.
const MSG_PASSKEY_REQUEST = "hekate:passkey_request";
const MSG_PASSKEY_REPLY = "hekate:passkey_reply";
const PASSKEY_REQUEST_TIMEOUT_MS = 60_000;
// Pending ceremonies, keyed by Chrome's `requestId`. Each entry is the
// resolver pair we hand back when the popup replies (or we time out).
const _passkeyPending = new Map();
let _passkeyAttached = false;
// Tracks an open standalone approval window (the fallback when
// chrome.action.openPopup() can't be used). Cleared via
// chrome.windows.onRemoved so we don't try to focus a dead window.
let _passkeyApprovalWindowId = null;

let _sseAbort = null;
let _sseRunning = false;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// Wake-up paths: popup explicitly asks to start, or the SW comes up on its
// own after a previous shutdown. In both cases we attempt to start the
// stream — `startSse` is idempotent.
chrome.runtime.onStartup.addListener(() => {
  startSse().catch(() => {
    /* nothing useful to do — popup will retry on its next open */
  });
  attachPasskeyProxy().catch(() => {});
  prunePasskeyQueue().catch(() => {});
});
chrome.runtime.onInstalled.addListener(() => {
  startSse().catch(() => {});
  attachPasskeyProxy().catch(() => {});
  prunePasskeyQueue().catch(() => {});
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Audit X-H2 (2026-05-07): only accept messages from this exact
  // extension. Today the manifest declares no `externally_connectable`
  // policy and no content_scripts, so cross-extension / page-context
  // sends already can't reach us — but adding this gate is one line
  // and prevents a future regression (e.g. someone adding a content
  // script for inline autofill) from instantly opening MSG_PASSKEY_REPLY
  // / MSG_SCHEDULE_CLEAR / etc. to any page that loads.
  if (!sender || sender.id !== chrome.runtime.id) return false;
  if (msg && msg.type === MSG_START_SSE) {
    startSse()
      .then(() => sendResponse({ ok: true, running: _sseRunning }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true; // async response
  }
  if (msg && msg.type === MSG_STOP_SSE) {
    stopSse();
    sendResponse({ ok: true, running: false });
    return false;
  }
  if (msg && msg.type === MSG_SCHEDULE_CLEAR) {
    scheduleClipboardClear(msg.secs)
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: String(e) }));
    return true;
  }
  if (msg && msg.type === MSG_CANCEL_CLEAR) {
    chrome.alarms.clear(ALARM_CLIPBOARD).finally(() => sendResponse({ ok: true }));
    return true;
  }
  // Popup → SW: response to a passkey ceremony the SW dispatched. Body:
  //   { type, requestId, kind: "create"|"get"|"isUvpaa", payload?, error? }
  // payload shape depends on kind — see resolvePasskeyRequest below.
  if (msg && msg.type === MSG_PASSKEY_REPLY) {
    resolvePasskeyRequest(msg);
    sendResponse({ ok: true });
    return false;
  }
  return false;
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_CLIPBOARD) return;
  try {
    await ensureOffscreen();
    await chrome.runtime.sendMessage({ type: MSG_OFFSCREEN_CLEAR });
  } catch (_) {
    /* offscreen doc unreachable; nothing else to try */
  } finally {
    try {
      await chrome.offscreen.closeDocument();
    } catch (_) {
      /* already closed */
    }
  }
});

async function scheduleClipboardClear(secs) {
  if (!secs || secs <= 0) {
    await chrome.alarms.clear(ALARM_CLIPBOARD);
    return;
  }
  // chrome.alarms.create's `delayInMinutes` is the only sub-second
  // unit; minimum is 0.5 minutes (30s) prior to MV3 manifest >= 0.0.0
  // unrestricted-alarm releases. Browsers since Chromium 117 accept
  // smaller values but quietly clamp; for our 30s default this is
  // already at the legal floor.
  await chrome.alarms.create(ALARM_CLIPBOARD, { delayInMinutes: secs / 60 });
}

async function ensureOffscreen() {
  // chrome.offscreen.hasDocument is Chromium 116+. We try-catch the
  // call so older builds still get a best-effort attempt.
  try {
    if (await chrome.offscreen.hasDocument()) return;
  } catch (_) {
    /* fall through and try to create */
  }
  try {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_DOC,
      reasons: ["CLIPBOARD"],
      justification: "Clear the clipboard after the user-configured timeout",
    });
  } catch (e) {
    // Already exists is fine; anything else surfaces to the alarm handler.
    if (!String(e).includes("Only a single offscreen document")) throw e;
  }
}

async function startSse() {
  if (_sseRunning) return;
  const session = await chrome.storage.session.get([
    "server_url",
    "access_token",
    "refresh_token",
  ]);
  if (!session.server_url || !session.access_token) {
    return; // not logged in; popup will start us once login completes
  }

  _sseRunning = true;
  const controller = new AbortController();
  _sseAbort = controller;

  let token = session.access_token;
  let rt = session.refresh_token;
  let backoff = 1000;
  let pendingBroadcast = null;

  const broadcast = () => {
    // Coalesce a burst into one popup re-render.
    if (pendingBroadcast) clearTimeout(pendingBroadcast);
    pendingBroadcast = setTimeout(() => {
      pendingBroadcast = null;
      // Mark dirty for popups that aren't open yet.
      chrome.storage.session
        .set({ vault_dirty_at: new Date().toISOString() })
        .catch(() => {});
      // Best-effort fanout to any open popup. If none are listening,
      // sendMessage rejects with `Could not establish connection` —
      // swallow it.
      chrome.runtime.sendMessage({ type: MSG_VAULT_CHANGED }).catch(() => {});
    }, 250);
  };

  (async () => {
    try {
      while (!controller.signal.aborted) {
        try {
          const resp = await fetch(`${session.server_url}/push/v1/stream`, {
            headers: {
              authorization: `Bearer ${token}`,
              accept: "text/event-stream",
            },
            signal: controller.signal,
          });
          if (resp.status === 401 && rt) {
            const refreshed = await tryRefresh(session.server_url, rt);
            if (!refreshed) return;
            token = refreshed.access_token;
            rt = refreshed.refresh_token;
            await chrome.storage.session.set({
              access_token: token,
              refresh_token: rt,
            });
            continue;
          }
          if (!resp.ok || !resp.body) {
            await sleep(backoff);
            backoff = Math.min(backoff * 2, 30000);
            continue;
          }
          backoff = 1000;
          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          let buf = "";
          while (!controller.signal.aborted) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            let idx;
            while ((idx = buf.indexOf("\n\n")) !== -1) {
              const chunk = buf.slice(0, idx);
              buf = buf.slice(idx + 2);
              const ev = parseSseChunk(chunk);
              if (!ev || ev.event === "heartbeat") continue;
              broadcast();
            }
          }
        } catch (_) {
          if (controller.signal.aborted) return;
          await sleep(backoff);
          backoff = Math.min(backoff * 2, 30000);
        }
      }
    } finally {
      _sseRunning = false;
    }
  })();
}

function stopSse() {
  if (_sseAbort) {
    _sseAbort.abort();
    _sseAbort = null;
  }
  _sseRunning = false;
}

async function tryRefresh(serverUrl, refreshToken) {
  try {
    const r = await fetch(`${serverUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }).toString(),
    });
    if (!r.ok) return null;
    const body = await r.json();
    return { access_token: body.access_token, refresh_token: body.refresh_token };
  } catch (_) {
    return null;
  }
}

function parseSseChunk(chunk) {
  const ev = {};
  for (const line of chunk.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const field = i === -1 ? line : line.slice(0, i);
    const value = i === -1 ? "" : line.slice(i + 1).replace(/^ /, "");
    if (field === "event") ev.event = value;
    else if (field === "data") ev.data = (ev.data ? ev.data + "\n" : "") + value;
    else if (field === "id") ev.id = value;
  }
  return ev.event || ev.data ? ev : null;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ===========================================================================
// GH #1 — webAuthenticationProxy provider (lifecycle + dispatch skeleton)
// ===========================================================================
//
// Chrome dispatches three event types to a registered provider:
//   * onCreateRequest   — site called navigator.credentials.create()
//   * onGetRequest      — site called navigator.credentials.get()
//   * onIsUvpaaRequest  — site polled isUserVerifyingPlatformAuthenticatorAvailable()
//
// We only attach when the API is present (Chrome 115+ in the stable
// channel; Firefox is ironing out an equivalent). isUvpaa always
// answers true (the popup is always "available" — user verification
// happens via the master-password unlock the popup already requires).

async function attachPasskeyProxy() {
  if (_passkeyAttached) return;
  if (!chrome.webAuthenticationProxy || typeof chrome.webAuthenticationProxy.attach !== "function") {
    return; // browser doesn't support it (Firefox + older Chrome)
  }
  // User opt-in gate. Until the popup's Settings flips this to true,
  // we stay detached so every site's normal passkey flow (OS sheet,
  // hardware key, other extensions) keeps working. The toggle flips
  // it once the user has unlocked Hekate at least once and explicitly
  // chosen us as their provider.
  const { passkey_provider_enabled } = await chrome.storage.local
    .get("passkey_provider_enabled")
    .catch(() => ({}));
  if (!passkey_provider_enabled) return;

  try {
    await chrome.webAuthenticationProxy.attach();
    _passkeyAttached = true;
  } catch (e) {
    // attach() rejects in two main cases:
    //   1. Another extension owns the proxy slot. We can't recover
    //      without user intervention (chrome://settings → Passkeys).
    //   2. We're already attached — usually because the previous SW
    //      lifetime's attachment outlived our `_passkeyAttached`
    //      module flag. In that case we ARE attached; just flip the
    //      flag so callers don't keep retrying.
    const msg = String(e && e.message ? e.message : e);
    if (/already attached/i.test(msg)) {
      _passkeyAttached = true;
    }
    return;
  }
}

// MV3 lifecycle invariant: webAuthenticationProxy event listeners must
// be registered SYNCHRONOUSLY at the top level of the service worker
// so Chrome can wake the SW to dispatch them. Registering them inside
// attachPasskeyProxy() (after several awaits) was the bug that caused
// auto-attach to lose the dispatch path on every SW eviction. The
// listeners only fire when we're actually attached, so they're a
// no-op until then.
if (chrome.webAuthenticationProxy && typeof chrome.webAuthenticationProxy.attach === "function") {
  chrome.webAuthenticationProxy.onCreateRequest.addListener((req) => {
    dispatchToPopup("create", req).then((reply) => {
      if (reply && reply.responseJson) {
        chrome.webAuthenticationProxy.completeCreateRequest({
          requestId: req.requestId,
          responseJson: reply.responseJson,
        });
      } else {
        chrome.webAuthenticationProxy.completeCreateRequest({
          requestId: req.requestId,
          error: reply?.error || { name: "NotAllowedError", message: "Hekate denied the request" },
        });
      }
    });
  });

  chrome.webAuthenticationProxy.onGetRequest.addListener((req) => {
    dispatchToPopup("get", req).then((reply) => {
      if (reply && reply.responseJson) {
        chrome.webAuthenticationProxy.completeGetRequest({
          requestId: req.requestId,
          responseJson: reply.responseJson,
        });
      } else {
        chrome.webAuthenticationProxy.completeGetRequest({
          requestId: req.requestId,
          error: reply?.error || { name: "NotAllowedError", message: "Hekate denied the request" },
        });
      }
    });
  });

  chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((req) => {
    // Hekate is always "available" — user verification rides the
    // popup unlock flow. RPs use this answer to decide whether to
    // even show platform-authenticator UI; lying false would make
    // sites hide the option entirely.
    chrome.webAuthenticationProxy.completeIsUvpaaRequest({
      requestId: req.requestId,
      isUvpaa: true,
    });
  });

  if (chrome.webAuthenticationProxy.onRemoteSessionStateChange) {
    chrome.webAuthenticationProxy.onRemoteSessionStateChange.addListener(() => {
      // Reattach on resume from sleep / network change.
      attachPasskeyProxy().catch(() => {});
    });
  }
}

// Re-run attach on every SW startup. MV3 SWs evict after ~30s idle;
// when Chrome wakes us back up to dispatch an event, this top-level
// statement runs and ensures the proxy attachment is reapplied
// (idempotent — `_passkeyAttached` gates against double attaches).
// This is the primary auto-attach hook; onInstalled / onStartup below
// stay as belt-and-braces for the cold-launch case.
attachPasskeyProxy().catch(() => {});

// Forward a ceremony to the popup. Returns the popup's reply, or a
// rejection envelope if the popup isn't reachable / the user takes
// too long. We use chrome.runtime.sendMessage for the dispatch and a
// per-request resolver in `_passkeyPending` for the reply (popup
// posts back an MSG_PASSKEY_REPLY with the matching requestId).
function dispatchToPopup(kind, req) {
  return new Promise((resolve) => {
    const requestId = req.requestId;
    const timeoutId = setTimeout(() => {
      _passkeyPending.delete(requestId);
      // Drain the matching queue entry — otherwise the popup would
      // re-process this timed-out ceremony on its next open and might
      // write a cipher / sign with a stale challenge for a request the
      // RP has already given up on.
      chrome.storage.session
        .get(["passkey_queue"])
        .then((s) => {
          const queue = Array.isArray(s.passkey_queue) ? s.passkey_queue : [];
          const next = queue.filter((q) => q.requestId !== requestId);
          return chrome.storage.session.set({ passkey_queue: next });
        })
        .catch(() => {});
      resolve({
        error: {
          name: "NotAllowedError",
          message: "Hekate approval timed out",
        },
      });
    }, PASSKEY_REQUEST_TIMEOUT_MS);
    _passkeyPending.set(requestId, { resolve, timeoutId });

    // Best-effort dispatch — popup may be closed. The popup, on next
    // open, drains chrome.storage.session["passkey_queue"] and handles
    // every queued request before timing out.
    chrome.storage.session
      .get(["passkey_queue"])
      .then((s) => {
        const queue = Array.isArray(s.passkey_queue) ? s.passkey_queue : [];
        queue.push({ requestId, kind, req, queuedAt: new Date().toISOString() });
        return chrome.storage.session.set({ passkey_queue: queue });
      })
      .catch(() => {});

    chrome.runtime
      .sendMessage({ type: MSG_PASSKEY_REQUEST, requestId, kind, req })
      .catch(() => {
        // Popup closed; reply will arrive when user opens it and the
        // popup drains the queue.
      });

    // Auto-open the popup so the user doesn't have to know to click
    // the extension icon in the toolbar. The webAuthenticationProxy
    // event is treated by Chrome as user-gesture-derived (the user
    // clicked Register / Authenticate on the RP), so action.openPopup
    // is allowed from this context. If for any reason it isn't —
    // Chrome version, focus loss, an existing popup — fall back to
    // a standalone popup-typed window so the user still sees the
    // approval UI without hunting for the toolbar icon.
    openApprovalUi().catch(() => {});
  });
}

async function detachPasskeyProxy() {
  if (!_passkeyAttached) return;
  try {
    await chrome.webAuthenticationProxy.detach();
  } catch (_) {
    /* already gone */
  }
  _passkeyAttached = false;
}

// Surface the approval UI without forcing the user to remember they
// have to click the toolbar icon. Tries the toolbar popup first
// (cheaper, matches user expectation when an extension provides
// passkeys); falls back to a standalone popup-typed window if Chrome
// refuses (no focused window, no permission, or the popup is already
// up). Both routes load popup.html which drains
// chrome.storage.session.passkey_queue and renders the approval
// modal.
async function openApprovalUi() {
  // Avoid stacking windows for repeated ceremonies. If we've already
  // opened a passkey-approval window in this SW lifetime and it's
  // still alive, focus it instead of creating a new one.
  if (_passkeyApprovalWindowId !== null) {
    try {
      await chrome.windows.update(_passkeyApprovalWindowId, { focused: true });
      return;
    } catch (_) {
      // Window was closed; fall through to recreate.
      _passkeyApprovalWindowId = null;
    }
  }

  // 1. Try the toolbar popup. Requires a focused window in the
  //    current Chrome profile and is gated on user-gesture context;
  //    the webAuthenticationProxy event handler IS such a context,
  //    so this should work in the common case.
  if (chrome.action && typeof chrome.action.openPopup === "function") {
    try {
      await chrome.action.openPopup();
      return;
    } catch (_) {
      // Fall through to the standalone-window fallback. Common
      // failure: no focused window in the profile (the RP tab might
      // be in a different window the popup can't attach to).
    }
  }

  // 2. Fallback: open popup.html as its own popup-typed window. Sized
  //    to match the toolbar popup so the modal renders cleanly.
  try {
    const win = await chrome.windows.create({
      url: chrome.runtime.getURL("popup/popup.html"),
      type: "popup",
      width: 380,
      height: 600,
      focused: true,
    });
    if (win && typeof win.id === "number") {
      _passkeyApprovalWindowId = win.id;
      // Forget the id when the window is closed so the next ceremony
      // gets a fresh one.
      const onRemoved = (closedId) => {
        if (closedId === _passkeyApprovalWindowId) {
          _passkeyApprovalWindowId = null;
          chrome.windows.onRemoved.removeListener(onRemoved);
        }
      };
      chrome.windows.onRemoved.addListener(onRemoved);
    }
  } catch (_) {
    // Last-resort: nothing we can do. The user will have to click
    // the extension icon manually within the 60s SW timeout.
  }
}

// Audit X-M4 (2026-05-07): Service workers can be evicted by Chrome
// at almost any point — network change, ~30s idle if no fetch
// activity, resource pressure. If eviction lands between
// dispatchToPopup() and the popup reply, the in-memory _passkeyPending
// map is gone, the original chrome.webAuthenticationProxy request is
// abandoned (Chrome times it out RP-side), and the popup's queue
// entry would otherwise sit there until the user opens the popup —
// at which point we'd present a stale modal for a ceremony the RP
// already gave up on.
//
// Mitigation: on every SW startup, drop queue entries older than
// PASSKEY_REQUEST_TIMEOUT_MS. This is best-effort cleanup — we can't
// reanimate the original request from a fresh SW instance — but it
// keeps the popup from showing approval prompts that can't usefully
// land anywhere.
async function prunePasskeyQueue() {
  try {
    const stored = await chrome.storage.session.get(["passkey_queue"]);
    const queue = Array.isArray(stored.passkey_queue) ? stored.passkey_queue : [];
    if (queue.length === 0) return;
    const now = Date.now();
    const fresh = queue.filter((e) => {
      const queuedAt = e.queuedAt ? Date.parse(e.queuedAt) : NaN;
      return Number.isFinite(queuedAt) && now - queuedAt < PASSKEY_REQUEST_TIMEOUT_MS;
    });
    if (fresh.length !== queue.length) {
      await chrome.storage.session.set({ passkey_queue: fresh });
    }
  } catch (_) {
    /* nothing actionable on failure */
  }
}

// Live-toggle from the popup's Settings without requiring an SW restart.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !("passkey_provider_enabled" in changes)) return;
  const next = changes.passkey_provider_enabled.newValue;
  if (next) {
    attachPasskeyProxy().catch(() => {});
  } else {
    detachPasskeyProxy().catch(() => {});
  }
});

function resolvePasskeyRequest(msg) {
  const pending = _passkeyPending.get(msg.requestId);
  if (!pending) return;
  clearTimeout(pending.timeoutId);
  _passkeyPending.delete(msg.requestId);
  // Drain the matching queue entry so the popup doesn't re-show it
  // on next open.
  chrome.storage.session
    .get(["passkey_queue"])
    .then((s) => {
      const queue = Array.isArray(s.passkey_queue) ? s.passkey_queue : [];
      const next = queue.filter((q) => q.requestId !== msg.requestId);
      return chrome.storage.session.set({ passkey_queue: next });
    })
    .catch(() => {});
  pending.resolve({
    responseJson: msg.payload?.responseJson,
    error: msg.error,
  });
}
