/**
 * hekate browser extension — popup logic.
 *
 * Screens (rendered into #app):
 *   login        — server / email / master-password form
 *   vault        — list of items with copy / fill / edit / trash
 *   trash        — trashed items with restore / purge
 *   typePicker   — choose a cipher type to add
 *   addEdit      — single form for both new and edit, type-aware
 *
 * Session state lives in `chrome.storage.session` (RAM-only, cleared on
 * browser close). `localStorage` only holds the non-secret last-used
 * server URL and email.
 *
 * All authenticated calls go through `authedFetch`, which transparently
 * exchanges the saved refresh token for a new access token on 401 and
 * retries — once. If that refresh also fails, callers see a 401 and
 * push the user back to the login screen.
 */

import init, * as hekate from "../wasm/hekate_core.js";

const AAD_PROTECTED_ACCOUNT_KEY = "pmgr-account-key";

// ===========================================================================
// Icon set — Lucide-derived SVG strings (24x24 viewBox, stroke-width 2).
// Inlining avoids a separate fetch + lets CSS color them via `currentColor`.
// All icons should set `stroke="currentColor"` and use `fill="none"` unless
// the design calls for a filled glyph.
// ===========================================================================
const ICON = {
  vault:    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  send:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7"/><path d="m16 6-4-4-4 4"/><path d="M12 2v14"/></svg>`,
  org:      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 21V9h6v12"/><path d="M3 9h18"/></svg>`,
  settings: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/><circle cx="12" cy="12" r="3"/></svg>`,
  search:   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
  plus:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>`,
  copy:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  edit:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4Z"/></svg>`,
  trash:    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>`,
  fill:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 6H3"/><path d="M10 12H3"/><path d="M10 18H3"/><path d="m14 12 7 0-3-3"/><path d="m18 15 3-3"/></svg>`,
  back:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>`,
  lock:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  // Per-cipher type glyphs (rendered inside a 32x32 tinted square).
  typeLogin:    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="13" r="6"/><path d="m17 13 4-4"/><path d="m21 9-2-2"/></svg>`,
  typeNote:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2"/></svg>`,
  typeCard:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>`,
  typeIdent:    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  typeSsh:      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2 11 12"/><path d="m18 5 3 3"/><circle cx="6" cy="18" r="4"/></svg>`,
  typeApi:      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12h6"/><path d="M16 12h6"/><circle cx="12" cy="12" r="4"/></svg>`,
  typeTotp:     `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>`,
};

// Render an icon by name. `cls` is appended as className so icons can be
// styled (color, size) per use-site.
function icon(name, cls) {
  const svg = ICON[name] || "";
  if (!cls) return svg;
  return svg.replace("<svg ", `<svg class="${cls}" `);
}

// Map cipher type → icon name (for the row-icon avatar).
function iconForCipherType(t) {
  return (
    {
      1: "typeLogin",
      2: "typeNote",
      3: "typeCard",
      4: "typeIdent",
      5: "typeSsh",
      6: "typeTotp",
      7: "typeApi",
    }[t] || "typeNote"
  );
}

// ===========================================================================
// Layout shells
// ===========================================================================
//
// `topShell` produces the standard top-level view: brand-colored header,
// scrollable content, bottom tab bar. Used by Vault / Sends / Orgs /
// Settings.
//
// `subShell` is the sub-flow shell: brand-colored header with a back
// arrow, scrollable content, no tab bar. Used by Add/Edit, Create Send,
// Invite Peer, Pin Peer, Collections inside an org, Rotate Keys, etc.
//
// Both expose the same content-mounting protocol: callers pass an HTML
// string for `content`, and bind event handlers AFTER the shell is
// mounted via `app.innerHTML = ...` (DOM nodes don't exist yet during
// the template construction).

const TABS = [
  { id: "vault",    icon: "vault",    label: "Vault",    onClick: () => renderVault() },
  { id: "send",     icon: "send",     label: "Share",    onClick: () => renderSendsList() },
  { id: "org",      icon: "org",      label: "Orgs",     onClick: () => renderOrgsList() },
  { id: "settings", icon: "settings", label: "Settings", onClick: () => renderSettings() },
];

// `opts.title` (string)
// `opts.content` (HTML string for the scroll area)
// `opts.headerAction` (optional `{ icon, ariaLabel, onClick }` for the right side of the header)
// `opts.activeTab` (id from TABS)
// `opts.fab` (optional `{ icon, ariaLabel, onClick }`)
// Returns the HTML; caller assigns to `app.innerHTML` then runs `wireTopShell(opts)`
// to bind handlers.
function topShellHtml(opts) {
  const { title, content, headerAction, activeTab, fab } = opts;
  const headerActionHtml = headerAction
    ? `<button class="header-action" id="headerAction" aria-label="${escapeAttr(headerAction.ariaLabel || "")}" title="${escapeAttr(headerAction.ariaLabel || "")}">${icon(headerAction.icon)}</button>`
    : "";
  const fabHtml = fab
    ? `<button class="fab" id="fabBtn" aria-label="${escapeAttr(fab.ariaLabel || "")}" title="${escapeAttr(fab.ariaLabel || "")}">${icon(fab.icon)}</button>`
    : "";
  const tabsHtml = TABS.map(
    (t) =>
      `<button class="tab ${t.id === activeTab ? "active" : ""}" data-tab="${t.id}" aria-label="${escapeAttr(t.label)}">${icon(t.icon)}<span>${escapeHtml(t.label)}</span></button>`,
  ).join("");
  return `
    <div class="shell">
      <div class="shell-header">
        <div class="header-title">${escapeHtml(title)}</div>
        ${headerActionHtml}
      </div>
      <div class="shell-content" id="shellContent">
        ${content}
      </div>
      ${fabHtml}
      <div class="shell-tabbar">${tabsHtml}</div>
    </div>`;
}

function wireTopShell(opts) {
  document.querySelectorAll(".shell-tabbar .tab").forEach((btn) => {
    const id = btn.dataset.tab;
    const t = TABS.find((tt) => tt.id === id);
    if (t && id !== opts.activeTab) {
      btn.addEventListener("click", t.onClick);
    }
  });
  if (opts.headerAction) {
    document.getElementById("headerAction").addEventListener("click", opts.headerAction.onClick);
  }
  if (opts.fab) {
    document.getElementById("fabBtn").addEventListener("click", opts.fab.onClick);
  }
}

// `opts.title`, `opts.content`, `opts.onBack`, optional
// `opts.headerAction` / `opts.fab` like topShell.
function subShellHtml(opts) {
  const { title, content, headerAction, fab } = opts;
  const headerActionHtml = headerAction
    ? `<button class="header-action" id="headerAction" aria-label="${escapeAttr(headerAction.ariaLabel || "")}" title="${escapeAttr(headerAction.ariaLabel || "")}">${icon(headerAction.icon)}</button>`
    : "";
  const fabHtml = fab
    ? `<button class="fab" id="fabBtn" aria-label="${escapeAttr(fab.ariaLabel || "")}" title="${escapeAttr(fab.ariaLabel || "")}">${icon(fab.icon)}</button>`
    : "";
  return `
    <div class="shell">
      <div class="shell-header">
        <button class="header-back" id="backBtn" aria-label="Back">${icon("back")}<span>Back</span></button>
        <div class="header-title">${escapeHtml(title)}</div>
        ${headerActionHtml}
      </div>
      <div class="shell-content" id="shellContent">
        ${content}
      </div>
      ${fabHtml}
    </div>`;
}

function wireSubShell(opts) {
  document.getElementById("backBtn").addEventListener("click", opts.onBack);
  if (opts.headerAction) {
    document.getElementById("headerAction").addEventListener("click", opts.headerAction.onClick);
  }
  if (opts.fab) {
    document.getElementById("fabBtn").addEventListener("click", opts.fab.onClick);
  }
}

// AAD-binding helpers (BW04/LP06 mitigation): every per-cipher ciphertext
// commits to the cipher's id (and where applicable, type) so the server
// cannot substitute one cipher's row for another's, swap the wrap key
// across rows, or flip the cipher_type to make a card render as a login.
// Mirrors `hekate-cli/src/crypto.rs::aad_*`.
function aadProtectedCipherKey(cipherId) {
  return enc.encode(`pmgr-cipher-key-v2:${cipherId}`);
}
function aadCipherName(cipherId, cipherType) {
  return enc.encode(`pmgr-cipher-name-v2:${cipherId}:${cipherType}`);
}
function aadCipherNotes(cipherId, cipherType) {
  return enc.encode(`pmgr-cipher-notes-v2:${cipherId}:${cipherType}`);
}
function aadCipherData(cipherId, cipherType) {
  return enc.encode(`pmgr-cipher-data-v2:${cipherId}:${cipherType}`);
}

// Generate a fresh UUIDv4 for new cipher ids. The server only validates
// "is a UUID", so v4 from crypto.randomUUID() is sufficient — UUIDv7's
// time-ordering benefit is for B-tree friendliness on the server, not a
// security requirement on the client.
function newCipherId() {
  return crypto.randomUUID();
}

const app = document.getElementById("app");
const enc = new TextEncoder();
const dec = new TextDecoder();

// ===========================================================================
// Cipher type config
// ===========================================================================
//
// Each entry maps a wire `type` integer to:
//   - label      shown in the UI ("Login", "Card", …)
//   - addLabel   shown in the type picker on + Add
//   - fields[]   form/data spec; each field's `name` is also the JSON key
//                stored in the encrypted data blob (matches the CLI's
//                serde structures in crates/hekate-cli/src/commands/add.rs)
//   - summarize  function that takes the decrypted data object and returns
//                the secondary text shown under the cipher's name in the
//                vault list
//
// JSON-key conventions match the CLI exactly so a cipher created in one
// can be edited in the other:
//   login:    { username, password, uri }                            (lowercase)
//   note:     {} — body lives in the notes field
//   card:     { cardholderName, brand, number, expMonth, expYear, code }
//   identity: { title, firstName, middleName, lastName, company, email,
//               phone, address1, address2, city, state, postalCode, country,
//               ssn, passportNumber, licenseNumber }
//   ssh-key:  { publicKey, privateKey, keyFingerprint }
//   totp:     { secret, issuer, accountName }

const CIPHER_TYPES = {
  1: {
    id: 1,
    label: "Login",
    addLabel: "Login",
    fields: [
      { name: "username", label: "Username", type: "text" },
      { name: "password", label: "Password", type: "password", reveal: true, generator: true },
      { name: "uri", label: "URI", type: "url", placeholder: "https://example.com" },
    ],
    summarize: (d) => d.username || d.uri || null,
  },
  2: {
    id: 2,
    label: "Secure note",
    addLabel: "Note",
    fields: [],
    summarize: () => "secure note",
  },
  3: {
    id: 3,
    label: "Card",
    addLabel: "Card",
    fields: [
      { name: "cardholderName", label: "Cardholder", type: "text" },
      { name: "brand", label: "Brand", type: "text", placeholder: "Visa / Mastercard / …" },
      { name: "number", label: "Number", type: "password", reveal: true, autocomplete: "off" },
      { name: "expMonth", label: "Exp month", type: "text", placeholder: "12", maxlength: 2 },
      { name: "expYear", label: "Exp year", type: "text", placeholder: "2030", maxlength: 4 },
      { name: "code", label: "CVV", type: "password", reveal: true, autocomplete: "off", maxlength: 4 },
    ],
    summarize: (d) => {
      const digits = (d.number || "").replace(/\D/g, "");
      const last4 = digits.length >= 4 ? `•••• ${digits.slice(-4)}` : "";
      return [d.brand, last4].filter(Boolean).join(" ") || "card";
    },
  },
  4: {
    id: 4,
    label: "Identity",
    addLabel: "Identity",
    fields: [
      { name: "title", label: "Title", type: "text" },
      { name: "firstName", label: "First name", type: "text" },
      { name: "middleName", label: "Middle name", type: "text" },
      { name: "lastName", label: "Last name", type: "text" },
      { name: "company", label: "Company", type: "text" },
      { name: "email", label: "Email", type: "email" },
      { name: "phone", label: "Phone", type: "tel" },
      { name: "address1", label: "Address line 1", type: "text" },
      { name: "address2", label: "Address line 2", type: "text" },
      { name: "city", label: "City", type: "text" },
      { name: "state", label: "State", type: "text" },
      { name: "postalCode", label: "Postal code", type: "text" },
      { name: "country", label: "Country", type: "text" },
      { name: "ssn", label: "SSN", type: "password", reveal: true, autocomplete: "off" },
      { name: "passportNumber", label: "Passport", type: "password", reveal: true, autocomplete: "off" },
      { name: "licenseNumber", label: "License", type: "password", reveal: true, autocomplete: "off" },
    ],
    summarize: (d) => {
      const full = [d.firstName, d.lastName].filter(Boolean).join(" ");
      return full || d.email || d.company || "identity";
    },
  },
  5: {
    id: 5,
    label: "SSH key",
    addLabel: "SSH key",
    fields: [
      {
        name: "publicKey",
        label: "Public key",
        type: "textarea",
        rows: 3,
        placeholder: "ssh-ed25519 AAAA… user@host",
      },
      {
        name: "privateKey",
        label: "Private key",
        type: "textarea",
        rows: 5,
        reveal: true,
        placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----",
      },
      { name: "keyFingerprint", label: "Fingerprint", type: "text", placeholder: "SHA256:…" },
    ],
    summarize: (d) => {
      if (d.keyFingerprint) return d.keyFingerprint;
      if (d.publicKey) {
        const parts = d.publicKey.trim().split(/\s+/);
        return parts.slice(0, 1).concat(parts.slice(-1)).join(" ");
      }
      return "ssh key";
    },
  },
  6: {
    id: 6,
    label: "TOTP",
    addLabel: "TOTP",
    fields: [
      {
        name: "secret",
        label: "Secret",
        type: "password",
        reveal: true,
        autocomplete: "off",
        placeholder: "otpauth://totp/… or BASE32",
      },
      { name: "issuer", label: "Issuer", type: "text", placeholder: "GitHub" },
      { name: "accountName", label: "Account", type: "text" },
    ],
    summarize: (d) => {
      const parts = [d.issuer, d.accountName].filter(Boolean);
      return parts.length ? parts.join(" / ") : "totp";
    },
  },
};

const ADD_PICKER_ORDER = [1, 2, 3, 4, 5, 6];

// ===========================================================================
// base64 helpers
// ===========================================================================

function b64encode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
}
function b64decode(s) {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlEncode(bytes) {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlDecode(s) {
  return b64decode(s.replace(/-/g, "+").replace(/_/g, "/"));
}

// ===========================================================================
// JWT helpers
// ===========================================================================
//
// The popup never validates JWT signatures (the server does that on every
// request); we only ever decode `sub` so we know our own user_id without
// adding a /whoami round-trip.

function decodeJwtClaims(accessToken) {
  const parts = (accessToken || "").split(".");
  if (parts.length !== 3) throw new Error("malformed access_token");
  const json = new TextDecoder().decode(b64urlDecode(parts[1]));
  return JSON.parse(json);
}

async function currentUserId() {
  const s = await loadSession();
  if (s.user_id) return s.user_id;
  if (!s.access_token) throw new Error("not logged in");
  const sub = decodeJwtClaims(s.access_token).sub;
  if (!sub) throw new Error("access_token has no sub claim");
  await saveSession({ user_id: sub });
  return sub;
}

// ===========================================================================
// pin storage (org_pins, peer_pins)
// ===========================================================================
//
// Pins are TOFU integrity anchors — non-secret, but must survive popup
// closes and login/logout cycles. Stored in chrome.storage.local under a
// per-user key so a different user logging in on the same browser
// doesn't inherit the previous user's trust set.

function pinsKey(userId) {
  return `hekate_pins:${userId}`;
}

async function loadPins(userId) {
  const k = pinsKey(userId);
  const obj = await chrome.storage.local.get(k);
  return obj[k] || { org_pins: {}, peer_pins: {} };
}

async function savePins(userId, pins) {
  await chrome.storage.local.set({ [pinsKey(userId)]: pins });
}

async function pinOrg(userId, orgId, pin) {
  const pins = await loadPins(userId);
  pins.org_pins[orgId] = pin;
  await savePins(userId, pins);
}

// ===========================================================================
// session storage
// ===========================================================================

async function loadSession() {
  return await chrome.storage.session.get([
    "server_url",
    "email",
    "access_token",
    "refresh_token",
    "account_key_b64",
    "signing_seed_b64",
    "user_id",
    "protected_account_private_key",
  ]);
}
async function saveSession(s) {
  await chrome.storage.session.set(s);
}
async function clearSession() {
  await chrome.storage.session.clear();
}

// ===========================================================================
// Settings + clipboard auto-clear
// ===========================================================================
//
// Settings live in localStorage (non-secret, per-browser-profile). The only
// setting today is `clearSecs` — how long after a Copy click the popup
// should overwrite the clipboard with an empty string. Default 30s.
//
// Limitation: the timer runs in this popup window. When the popup closes
// (user clicks elsewhere) the setTimeout dies. We document that explicitly
// in docs/browser-extension.md. A future iteration can hand the timer
// off to the service worker via chrome.alarms + an offscreen document
// for reliable cross-popup clearing.

// `strictManifest` (M2.5 follow-up): when true, BW04 personal-manifest
// mismatches block rendering of the vault until the user disables
// strict mode or the warnings clear. Defaults to false so an upgrade
// can never lock a user out of their own data — same conservative
// default as the CLI's `hekate config strict-manifest` knob.
const SETTINGS_DEFAULTS = { clearSecs: 30, strictManifest: false };

function loadSettings() {
  try {
    const raw = localStorage.getItem("hekate.settings");
    return { ...SETTINGS_DEFAULTS, ...(raw ? JSON.parse(raw) : {}) };
  } catch (_) {
    return { ...SETTINGS_DEFAULTS };
  }
}
function saveSettings(s) {
  localStorage.setItem("hekate.settings", JSON.stringify(s));
}

async function copyWithAutoClear(value, label) {
  await navigator.clipboard.writeText(value);
  const settings = loadSettings();
  const secs = parseInt(settings.clearSecs, 10);
  if (!secs || secs <= 0) {
    // Cancel any pending alarm too, in case the user just disabled.
    chrome.runtime
      .sendMessage({ type: "hekate:cancel_clipboard_clear" })
      .catch(() => {});
    toast(`${label} copied — clipboard auto-clear is OFF (Settings to change).`);
    return;
  }
  // Hand off to the service worker. This survives popup close: when the
  // alarm fires the SW spins up an offscreen document with CLIPBOARD
  // reason, instructs it to writeText(""), and tears it down.
  // chrome.alarms minimum granularity is 30s; smaller values get quietly
  // clamped by Chromium. Document the floor in the Settings UI.
  await chrome.runtime
    .sendMessage({ type: "hekate:schedule_clipboard_clear", secs })
    .catch(() => {
      /* SW unreachable — clipboard stays */
    });
  toast(`${label} copied — clears in ${secs}s (background timer).`);
}

// ===========================================================================
// HTTP
// ===========================================================================

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return await checkResponse(r);
}

async function postForm(url, params) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  return await checkResponse(r);
}

/// Like `postForm` but returns `{ status, body }` without throwing on
/// 401 — used by the password grant so we can recognize the
/// `two_factor_required` 401 body and prompt the user instead of
/// surfacing it as a login error.
async function postFormRaw(url, params) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  let body = null;
  try {
    body = await r.json();
  } catch (_) {
    /* empty body or non-JSON */
  }
  return { status: r.status, body };
}

async function checkResponse(r) {
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const body = await r.json();
      if (body && body.error) msg = body.error;
    } catch (_) {
      /* ignore */
    }
    throw new Error(msg);
  }
  // Empty-body successes happen on more than just 204: the org-invite
  // POST returns 201 with no body, attachment delete returns 200 with
  // no body, etc. Read text first; only parse JSON if there's content.
  // Without this guard `r.json()` on an empty 201 throws
  // "Unexpected end of JSON input" which surfaces as a confusing UI
  // error even though the operation succeeded server-side.
  if (r.status === 204) return null;
  const text = await r.text();
  if (!text) return null;
  return JSON.parse(text);
}

async function authedFetch(method, path, body, extraHeaders) {
  let session = await loadSession();
  const url = `${session.server_url}${path}`;
  const baseHeaders = { ...(extraHeaders || {}) };
  if (body !== undefined && body !== null && !baseHeaders["content-type"]) {
    baseHeaders["content-type"] = "application/json";
  }
  // Body shapes:
  //   - undefined / null  → no body
  //   - string             → sent as-is
  //   - ArrayBuffer / typed array → sent as-is for opaque uploads (tus
  //     file Sends, attachments). Without this branch the bytes get
  //     JSON.stringify'd into `{"0":1,"1":2,…}` and the server's
  //     BLAKE3 finalize check rejects the upload, leaving the row
  //     orphaned ("send body has not been uploaded yet" on access).
  //   - anything else      → JSON.stringify
  const isBinary =
    body instanceof ArrayBuffer || (body && ArrayBuffer.isView(body));
  const buildOpts = (token) => ({
    method,
    headers: { ...baseHeaders, authorization: `Bearer ${token}` },
    body:
      body === undefined || body === null
        ? undefined
        : typeof body === "string"
          ? body
          : isBinary
            ? body
            : JSON.stringify(body),
  });

  let r = await fetch(url, buildOpts(session.access_token));
  if (r.status !== 401 || !session.refresh_token) return r;

  const refreshed = await tryRefresh(session.server_url, session.refresh_token);
  if (!refreshed) return r;

  await saveSession({
    access_token: refreshed.access_token,
    refresh_token: refreshed.refresh_token,
    ...(refreshed.protected_account_private_key
      ? { protected_account_private_key: refreshed.protected_account_private_key }
      : {}),
  });
  return await fetch(url, buildOpts(refreshed.access_token));
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
    return {
      access_token: body.access_token,
      refresh_token: body.refresh_token,
      // Carry the wrapped X25519 priv along on refresh too, since
      // a rotate-keys on another device would change it.
      protected_account_private_key: body.protected_account_private_key || null,
    };
  } catch (_) {
    return null;
  }
}

async function apiGet(path) {
  return checkResponse(await authedFetch("GET", path));
}
async function apiPost(path, body) {
  return checkResponse(await authedFetch("POST", path, body));
}
async function apiPut(path, body, ifMatchRevision) {
  return checkResponse(
    await authedFetch("PUT", path, body, { "if-match": `"${ifMatchRevision}"` }),
  );
}
async function apiDelete(path) {
  const r = await authedFetch("DELETE", path);
  if (r.status === 204) return null;
  return checkResponse(r);
}
async function apiPatch(path, body) {
  return checkResponse(await authedFetch("PATCH", path, body));
}

// ===========================================================================
// WebAuthn (M2.23b) — JSON ↔ browser-API conversions
// ===========================================================================
//
// `webauthn-rs` emits CreationChallengeResponse / RequestChallengeResponse
// JSON where every binary field is base64url-no-pad. The
// `navigator.credentials.{create,get}` Web APIs expect ArrayBuffers in
// those positions. These helpers walk the trees and convert in both
// directions. Mirror of the browser's standard pattern documented at
// https://www.w3.org/TR/webauthn-2/.

function webauthnDecodeCreationOptions(json) {
  // Server returns `{ publicKey: { ... } }` per the WebAuthn spec.
  const pk = JSON.parse(JSON.stringify(json.publicKey)); // deep clone
  pk.challenge = b64urlDecode(pk.challenge);
  pk.user.id = b64urlDecode(pk.user.id);
  if (Array.isArray(pk.excludeCredentials)) {
    pk.excludeCredentials = pk.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlDecode(c.id),
    }));
  }
  return { publicKey: pk };
}

function webauthnDecodeRequestOptions(json) {
  const pk = JSON.parse(JSON.stringify(json.publicKey));
  pk.challenge = b64urlDecode(pk.challenge);
  if (Array.isArray(pk.allowCredentials)) {
    pk.allowCredentials = pk.allowCredentials.map((c) => ({
      ...c,
      id: b64urlDecode(c.id),
    }));
  }
  return { publicKey: pk };
}

function webauthnEncodeCredentialForServer(credential) {
  // Common to both create() and get(). webauthn-rs deserializes from
  // the standard `RegisterPublicKeyCredential` / `PublicKeyCredential`
  // JSON shape, with `rawId`, `clientDataJSON`, `attestationObject`,
  // `authenticatorData`, `signature`, `userHandle` as base64url.
  const out = {
    id: credential.id,
    rawId: b64urlEncode(new Uint8Array(credential.rawId)),
    type: credential.type,
    response: {},
    extensions: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
  };
  const r = credential.response;
  if (r.attestationObject) {
    out.response.attestationObject = b64urlEncode(new Uint8Array(r.attestationObject));
    out.response.clientDataJSON = b64urlEncode(new Uint8Array(r.clientDataJSON));
    if (r.getTransports) {
      out.response.transports = r.getTransports();
    }
  } else {
    // assertion (navigator.credentials.get)
    out.response.authenticatorData = b64urlEncode(new Uint8Array(r.authenticatorData));
    out.response.clientDataJSON = b64urlEncode(new Uint8Array(r.clientDataJSON));
    out.response.signature = b64urlEncode(new Uint8Array(r.signature));
    if (r.userHandle && r.userHandle.byteLength > 0) {
      out.response.userHandle = b64urlEncode(new Uint8Array(r.userHandle));
    }
  }
  return out;
}

// ===========================================================================
// Vault manifest (BW04 set-level integrity)
// ===========================================================================
//
// Mirror of `crates/hekate-cli/src/manifest.rs` for the popup. After every
// successful cipher write we:
//   1. Pull /sync to get the authoritative cipher list.
//   2. Build a manifest from those rows + version = (current+1) | 1.
//   3. Sign with the in-session signing seed via the WASM `hekate-core`.
//   4. POST to /api/v1/vault/manifest.
// On vault render after a full sync we verify the embedded manifest under
// the in-localStorage pubkey and surface mismatches in the UI status bar.

async function syncAndUploadManifest(session) {
  if (!session || !session.signing_seed_b64) {
    // Pre-M3.5 session that predates the seed — silent skip; user can
    // re-login to upgrade.
    return { ok: false, reason: "no signing seed in session" };
  }
  const sync = await apiGet("/api/v1/sync");
  const entries = sync.changes.ciphers.map((c) => ({
    cipherId: c.id,
    revisionDate: c.revision_date,
    deleted: !!c.deleted_date,
  }));
  let nextVersion = 1;
  let parentHash = new Uint8Array(32); // genesis = all zeros
  if (sync.manifest) {
    nextVersion = sync.manifest.version + 1;
    parentHash = await sha256Bytes(b64decode(sync.manifest.canonical_b64));
  }
  const manifestObj = {
    version: nextVersion,
    timestamp: new Date().toISOString(),
    parentCanonicalSha256: parentHash,
    entries,
  };
  const seed = b64urlDecode(session.signing_seed_b64);
  const signed = hekate.signManifestCanonical(seed, manifestObj);
  await apiPost("/api/v1/vault/manifest", {
    version: nextVersion,
    canonical_b64: b64encode(signed.canonicalBytes),
    signature_b64: b64encode(signed.signature),
  });
  return { ok: true, version: nextVersion };
}

async function sha256Bytes(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

/**
 * Verify the embedded /sync manifest against the in-localStorage pubkey
 * and cross-check every cipher in the response.
 *
 * Returns `{ status, warnings }`:
 *   - status="ok"      manifest verified + matches the cipher list
 *   - status="no-data" fresh account: no manifest yet AND no ciphers.
 *                     Benign — the genesis manifest gets created on the
 *                     first cipher write. Caller should NOT alarm.
 *   - status="warn"    real disagreement (sig fails, drift, drops, OR
 *                     manifest absent despite a non-empty cipher list).
 *                     `warnings` carries human-readable strings.
 */
function verifyManifestFromSync(sync) {
  if (!sync || !sync.manifest) {
    const ciphers = (sync && sync.changes && sync.changes.ciphers) || [];
    if (ciphers.length === 0) {
      // Fresh-account / pre-genesis state. The server only signs once
      // the user has at least one cipher; until then there's nothing
      // to verify and the alarm coloring would be misleading.
      return { status: "no-data", warnings: [] };
    }
    return {
      status: "warn",
      warnings: [
        "server returned ciphers but no signed manifest — refusing to trust the cipher list",
      ],
    };
  }
  const pubkeyB64 = localStorage.getItem("hekate.signing_pubkey_b64");
  if (!pubkeyB64) {
    return {
      status: "warn",
      warnings: ["local state has no signing pubkey — re-login to enable"],
    };
  }
  const pubkey = b64urlDecode(pubkeyB64);
  const canonical = b64decode(sync.manifest.canonical_b64);
  const signature = b64decode(sync.manifest.signature_b64);

  let parsed;
  try {
    parsed = hekate.verifyManifestSignature(pubkey, canonical, signature);
  } catch (e) {
    return {
      status: "warn",
      warnings: [`manifest signature did not verify: ${e.message || e}`],
    };
  }
  const byId = new Map();
  for (const e of parsed.entries) byId.set(e.cipherId, e);

  const warnings = [];
  for (const c of sync.changes.ciphers) {
    const ent = byId.get(c.id);
    if (!ent) {
      warnings.push(`cipher ${c.id} returned by server is NOT in the signed manifest`);
      continue;
    }
    if (ent.revisionDate !== c.revision_date) {
      warnings.push(
        `cipher ${c.id}: server revision_date ${c.revision_date} ≠ manifest ${ent.revisionDate}`,
      );
    }
    const serverDeleted = !!c.deleted_date;
    if (ent.deleted !== serverDeleted) {
      warnings.push(
        `cipher ${c.id}: server says deleted=${serverDeleted}, manifest says ${ent.deleted}`,
      );
    }
  }
  const serverIds = new Set(sync.changes.ciphers.map((c) => c.id));
  for (const ent of parsed.entries) {
    if (!serverIds.has(ent.cipherId)) {
      warnings.push(
        `manifest lists cipher ${ent.cipherId} but /sync did not return it — possible server drop`,
      );
    }
  }
  return { status: warnings.length === 0 ? "ok" : "warn", warnings };
}

// ===========================================================================
// SSE: refresh while popup is open
// ===========================================================================
//
// Honest scope: this only runs while the popup is visible. Closing the
// popup tears down the AbortController and ends the connection. A future
// iteration will move SSE into the service worker so the cached vault
// state stays fresh even between popup opens.
//
// EventSource doesn't allow custom headers, so we go through `fetch` with
// `signal` + a streaming reader and parse the SSE wire format ourselves.

/// Ask the service worker to start (or remain) subscribed, and register
/// a one-shot listener that re-renders the vault when the SW signals
/// a remote change. The SW owns the actual SSE connection so it
/// survives popup close.
function startSwSseBridge() {
  // Tell the SW to start (idempotent — it bails if already running).
  // We don't await; if the SW is asleep this kicks it awake.
  chrome.runtime
    .sendMessage({ type: "hekate:start_sse" })
    .catch(() => {
      /* SW unreachable; popup-side render works without live refresh */
    });

  // Listener: install once. clearTickers() removes it on screen change.
  if (_sseAbort) return;
  const handler = (msg, sender) => {
    // Audit X-H2 (2026-05-07): refuse messages that didn't originate
    // from one of our own extension contexts (SW / popup / offscreen).
    // Today no content scripts are declared so this is defense-in-depth,
    // but it costs one line and stops a future content_scripts addition
    // from instantly turning every page into a vault-refresh trigger.
    if (!sender || sender.id !== chrome.runtime.id) return;
    if (msg && msg.type === "hekate:vault_changed") {
      renderVault();
    }
  };
  chrome.runtime.onMessage.addListener(handler);

  // Reuse _sseAbort as a removal hook so clearTickers tears this down too.
  _sseAbort = {
    abort: () => {
      chrome.runtime.onMessage.removeListener(handler);
    },
  };

  // If the SW recorded a vault change while the popup was closed, the
  // sync we just did already reflects it — nothing extra to do here,
  // but clear the dirty flag so the next change is unambiguous.
  chrome.storage.session.remove("vault_dirty_at").catch(() => {});
}

// ===========================================================================
// Entry + login
// ===========================================================================

async function main() {
  await init();
  const s = await loadSession();
  if (s.access_token && s.account_key_b64) {
    await renderVault();
    // Fire-and-forget. Surfacing an approval modal on top of the vault
    // is intentional — the user just unlocked, so any queued ceremony
    // is the most likely reason they opened the popup.
    drainPasskeyQueue().catch((e) => console.error("passkey drain failed:", e));
  } else {
    renderLogin();
  }
}

function renderLogin(error) {
  clearTickers();
  app.innerHTML = `
    <h1>Hekate</h1>
    <form id="login">
      <label><span>Server</span>
        <input name="server" type="url" placeholder="http://hekate.localhost"
               value="${escapeAttr(localStorage.getItem("hekate.server") || "")}" required>
      </label>
      <label><span>Email</span>
        <input name="email" type="email" autocomplete="username"
               value="${escapeAttr(localStorage.getItem("hekate.email") || "")}" required>
      </label>
      <label><span>Master password</span>
        <input name="password" type="password" autocomplete="current-password" required autofocus>
      </label>
      <button type="submit">Unlock</button>
      <p class="error" id="err">${error ? escapeHtml(error) : ""}</p>
    </form>
    <p class="muted">Session is held in memory until you close the browser
       or click "Lock". Master password and master key are never written
       to disk.</p>
  `;
  document.getElementById("login").addEventListener("submit", onLogin);
}

// ===========================================================================
// 2FA challenge handler (M2.22 TOTP / recovery + M2.23b WebAuthn)
// ===========================================================================
//
// `onLogin()` calls this when the password grant comes back as 401 +
// `{error: "two_factor_required", two_factor_providers, two_factor_token,
//   webauthn_challenge?}`. We render a sub-screen that lets the user
// pick a factor, drive the appropriate ceremony, then replay the
// password grant with `two_factor_token` + provider + value. Returns
// the eventual TokenResponse JSON or rejects with an Error.
//
// WebAuthn note: as of Chrome 116 (Aug 2023), `navigator.credentials.{
// create, get}` works in extension contexts when the RP ID is covered
// by the extension's host_permissions. Our manifest grants
// `http(s)://*/*`, so any RP ID the user's server uses is allowed.
// If the call fails (older Chrome / Firefox / unusual platform) the
// user gets the error and can fall back to TOTP or recovery.
function complete2faChallenge(server, email, mphB64, challenge) {
  return new Promise((resolve, reject) => {
    const providers = Array.isArray(challenge.two_factor_providers)
      ? challenge.two_factor_providers
      : [];
    const hasWebauthn = providers.includes("webauthn") && !!challenge.webauthn_challenge;
    const hasTotp = providers.includes("totp");
    const hasRecovery = providers.includes("recovery");

    app.innerHTML = `
      <h1>Two-factor required</h1>
      <p class="muted">${escapeHtml(email)}</p>
      ${
        hasWebauthn
          ? `<p><button id="useWebauthn">🔑 Use security key / passkey</button></p>`
          : ""
      }
      ${
        hasTotp
          ? `
        <form id="totpForm">
          <label><span>Authenticator code</span>
            <input name="code" type="text" inputmode="numeric"
                   autocomplete="one-time-code" required autofocus
                   pattern="[0-9]{6}" maxlength="6">
          </label>
          <button type="submit">Verify</button>
        </form>`
          : ""
      }
      ${
        hasRecovery
          ? `<p><a href="#" id="useRecovery">Use a recovery code instead</a></p>`
          : ""
      }
      <p class="error" id="err2fa"></p>
      <p><button class="secondary" id="cancel2fa">Cancel</button></p>
    `;
    document.getElementById("cancel2fa").addEventListener("click", () => {
      reject(new Error("2FA cancelled"));
    });

    const showErr = (msg) => {
      document.getElementById("err2fa").textContent = msg;
    };

    if (hasWebauthn) {
      const btn = document.getElementById("useWebauthn");
      const trigger = async () => {
        btn.disabled = true;
        btn.textContent = "Touch your authenticator…";
        showErr("");
        try {
          const opts = webauthnDecodeRequestOptions(challenge.webauthn_challenge);
          const credential = await navigator.credentials.get(opts);
          if (!credential) throw new Error("authenticator returned no credential");
          const assertion = webauthnEncodeCredentialForServer(credential);
          const tok = await replay2fa(
            server,
            email,
            mphB64,
            challenge.two_factor_token,
            "webauthn",
            JSON.stringify(assertion),
          );
          resolve(tok);
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "🔑 Use security key / passkey";
          showErr(err.message || String(err));
        }
      };
      btn.addEventListener("click", trigger);
      // If WebAuthn is the only option, auto-trigger so the user
      // doesn't have to click through. The OS sheet pops immediately.
      if (!hasTotp && !hasRecovery) trigger();
    }

    if (hasTotp) {
      document.getElementById("totpForm").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const code = ev.target.code.value.trim();
        showErr("");
        try {
          const tok = await replay2fa(
            server,
            email,
            mphB64,
            challenge.two_factor_token,
            "totp",
            code,
          );
          resolve(tok);
        } catch (err) {
          showErr(err.message || String(err));
        }
      });
    }

    if (hasRecovery) {
      document.getElementById("useRecovery").addEventListener("click", async (ev) => {
        ev.preventDefault();
        // eslint-disable-next-line no-alert
        const code = window.prompt(
          "Enter a recovery code (XXXX-XXXX-XXXX-XXXX). Single-use.",
        );
        if (!code) return;
        showErr("");
        try {
          const tok = await replay2fa(
            server,
            email,
            mphB64,
            challenge.two_factor_token,
            "recovery",
            code,
          );
          resolve(tok);
        } catch (err) {
          showErr(err.message || String(err));
        }
      });
    }
  });
}

async function replay2fa(server, email, mphB64, token, provider, value) {
  const r = await postFormRaw(`${server}/identity/connect/token`, {
    grant_type: "password",
    username: email,
    password: mphB64,
    two_factor_token: token,
    two_factor_provider: provider,
    two_factor_value: value,
  });
  if (r.status >= 200 && r.status < 300) return r.body;
  const msg = (r.body && r.body.error) || `verification failed: ${r.status}`;
  throw new Error(msg);
}

async function onLogin(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const server = fd.get("server").trim().replace(/\/$/, "");
  const email = fd.get("email").trim().toLowerCase();
  const password = fd.get("password");
  const submit = e.target.querySelector("button[type=submit]");
  submit.disabled = true;
  submit.textContent = "Deriving key…";
  document.getElementById("err").textContent = "";

  localStorage.setItem("hekate.server", server);
  localStorage.setItem("hekate.email", email);

  try {
    const pre = await postJSON(`${server}/api/v1/accounts/prelogin`, { email });

    // BW07/LP04 mitigation #1: enforce a hard floor on the params before we
    // even compute Argon2id. A server returning weak params (or fake params
    // for an unknown email) gets rejected here.
    if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
      throw new Error(
        "server returned KDF parameters below the safe floor — refusing " +
          "to derive a master_password_hash that could be brute-forced.",
      );
    }

    const salt = b64decode(pre.kdf_salt);
    const mk = hekate.deriveMasterKey(enc.encode(password), pre.kdf_params, salt);

    // BW07/LP04 mitigation #2: verify the bind MAC the server stored at
    // registration before sending the master_password_hash. If verification
    // fails the server is either tampering with the params/salt or the
    // master password is wrong; either way, do NOT send mph.
    if (!pre.kdf_params_mac) {
      throw new Error("server omitted kdf_params_mac — refusing to log in.");
    }
    const serverMac = b64decode(pre.kdf_params_mac);
    if (!hekate.verifyKdfBindMac(mk, pre.kdf_params, salt, serverMac)) {
      throw new Error(
        "Wrong master password, or the server is attempting to downgrade " +
          "the KDF (BW07/LP04). Did NOT send credentials.",
      );
    }

    const mph = hekate.deriveMasterPasswordHash(mk);
    const mphB64 = b64encode(mph);
    let tok;
    {
      const first = await postFormRaw(`${server}/identity/connect/token`, {
        grant_type: "password",
        username: email,
        password: mphB64,
      });
      if (first.status >= 200 && first.status < 300) {
        tok = first.body;
      } else if (
        first.status === 401 &&
        first.body &&
        first.body.error === "two_factor_required"
      ) {
        tok = await complete2faChallenge(server, email, mphB64, first.body);
      } else if (first.body && first.body.error) {
        throw new Error(first.body.error);
      } else {
        throw new Error(`login failed: ${first.status}`);
      }
    }
    const smk = hekate.deriveStretchedMasterKey(mk);
    const accountKey = hekate.encStringDecryptXc20p(
      tok.protected_account_key,
      smk,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );
    // BW04 set-level integrity: derive the Ed25519 signing seed from the
    // master key BEFORE discarding mk. The seed lives in chrome.storage.session
    // (RAM-only, cleared on browser close); the pubkey is non-secret and lives
    // in localStorage so we can verify signed manifests without re-deriving.
    const signingSeed = hekate.deriveAccountSigningSeed(mk);
    const signingPubkey = hekate.verifyingKeyFromSeed(signingSeed);
    localStorage.setItem("hekate.signing_pubkey_b64", b64urlEncode(signingPubkey));
    await saveSession({
      server_url: server,
      email,
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      account_key_b64: b64urlEncode(accountKey),
      signing_seed_b64: b64urlEncode(signingSeed),
      // Cached for invite-accept (M3.14a): the X25519 private key
      // is needed to verify-decrypt signcryption envelopes. The token
      // grant carries it on every login/refresh, so storing the
      // wrapped blob in session-only storage is harmless and cheaper
      // than a /me round-trip every accept.
      protected_account_private_key: tok.protected_account_private_key || null,
    });
    await renderVault();
    // Same as main() — if a passkey ceremony was queued while the
    // user was locked out (e.g. they clicked Register on an RP, the
    // SW caught it, then they had to unlock the popup), drain the
    // queue now so the approval modal renders. Without this the
    // ceremony sits in chrome.storage.session until SW timeout.
    drainPasskeyQueue().catch((e) => console.error("passkey drain failed:", e));
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Unlock";
    document.getElementById("err").textContent = err.message;
  }
}

// ===========================================================================
// Vault list
// ===========================================================================

// Module-scope vault state for live filter+search re-renders without
// re-running /sync.
let vaultState = {
  showTrash: false,
  ciphers: [],
  matches: [],
  filterType: 0, // 0 = all
  searchTerm: "",
};

async function renderVault(opts) {
  clearTickers();
  opts = opts || {};
  const showTrash = !!opts.showTrash;
  const title = showTrash ? "Trash" : "Vault";

  const content = `
    <div class="search-bar">
      ${icon("search")}
      <input id="searchInput" type="search" placeholder="${showTrash ? "Search trash…" : "Search vault…"}" autocomplete="off">
    </div>
    <div class="filter-chips" id="filterChips">
      <button class="chip active" data-filter="0">All</button>
      <button class="chip" data-filter="1">Logins</button>
      <button class="chip" data-filter="6">TOTP</button>
      <button class="chip" data-filter="3">Cards</button>
      <button class="chip" data-filter="4">Identities</button>
      <button class="chip" data-filter="2">Notes</button>
      <button class="chip" data-filter="5">SSH</button>
      <button class="chip" data-filter="7">API</button>
    </div>
    <div id="matches"></div>
    <div id="status">Loading…</div>
    <div id="rows"></div>`;

  if (showTrash) {
    app.innerHTML = subShellHtml({
      title,
      content,
      onBack: () => renderSettings(),
    });
    wireSubShell({ onBack: () => renderSettings() });
  } else {
    app.innerHTML = topShellHtml({
      title,
      content,
      activeTab: "vault",
      headerAction: {
        icon: "plus",
        ariaLabel: "Add item",
        onClick: () => renderTypePicker(),
      },
    });
    wireTopShell({
      activeTab: "vault",
      headerAction: { onClick: () => renderTypePicker() },
    });
  }

  document.getElementById("searchInput").addEventListener("input", (e) => {
    vaultState.searchTerm = e.target.value.trim().toLowerCase();
    renderVaultRows();
  });
  document.querySelectorAll("#filterChips .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll("#filterChips .chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      vaultState.filterType = parseInt(chip.dataset.filter, 10);
      renderVaultRows();
    });
  });

  let resp;
  try {
    resp = await apiGet("/api/v1/sync");
  } catch (err) {
    if (/401|unauth/i.test(err.message)) {
      await clearSession();
      renderLogin("Session expired; please log in again.");
      return;
    }
    document.getElementById("status").textContent = "Error: " + err.message;
    return;
  }

  const s = await loadSession();
  const accountKey = b64urlDecode(s.account_key_b64);
  const ciphers = resp.changes.ciphers
    .filter((c) => (showTrash ? !!c.deleted_date : !c.deleted_date))
    .map((c) => decryptForList(c, accountKey))
    .sort((a, b) => a.name.localeCompare(b.name));

  let matches = [];
  if (!showTrash) {
    const tab = await getActiveTab();
    const tabHost = tab && tab.url ? safeHost(tab.url) : null;
    matches = tabHost
      ? ciphers.filter((c) => {
          if (c.type === 1 && c.data && c.data.password) {
            return hostMatches(c.data.uri, tabHost);
          }
          if (c.type === 6 && c.data && c.data.secret) {
            return totpMatches(c.data, tabHost);
          }
          return false;
        })
      : [];
    renderMatchesSection(matches, tabHost);
  } else {
    const matchesEl = document.getElementById("matches");
    if (matchesEl) matchesEl.innerHTML = "";
  }

  vaultState = {
    showTrash,
    ciphers,
    matches,
    filterType: 0,
    searchTerm: "",
  };
  renderVaultRows();

  if (!showTrash) {
    const verdict = verifyManifestFromSync(resp);
    const strict = !!loadSettings().strictManifest;
    // Strict mode blocks only on real disagreement. The benign
    // no-data case (fresh account, no ciphers yet) is not a failure
    // — strict-blocking it would make every new user think their
    // vault is corrupted before they've even added an item.
    if (strict && verdict.status === "warn") {
      renderStrictManifestBlock(verdict.warnings);
      return;
    }
    renderManifestStatus(verdict);
    startSwSseBridge();
  }
}

function renderVaultRows() {
  const { showTrash, ciphers, filterType, searchTerm } = vaultState;
  const status = document.getElementById("status");
  const rows = document.getElementById("rows");
  if (!status || !rows) return;

  let filtered = ciphers;
  if (filterType !== 0) filtered = filtered.filter((c) => c.type === filterType);
  if (searchTerm) {
    filtered = filtered.filter((c) => {
      const name = (c.name || "").toLowerCase();
      const sub = summarizeRow(c).toLowerCase();
      return name.includes(searchTerm) || sub.includes(searchTerm);
    });
  }

  if (ciphers.length === 0) {
    status.textContent = "";
    rows.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon(showTrash ? "trash" : "vault")}</div>
        <div class="empty-title">${showTrash ? "Trash is empty" : "Vault is empty"}</div>
        <div class="empty-sub">${showTrash ? "Items you delete show up here." : "Tap + to add your first item."}</div>
      </div>`;
    return;
  }
  if (filtered.length === 0) {
    status.textContent = "no matches";
    rows.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon("search")}</div>
        <div class="empty-title">No matches</div>
        <div class="empty-sub">${searchTerm ? `Nothing matched "${escapeHtml(searchTerm)}"` : "Try a different filter."}</div>
      </div>`;
    return;
  }
  status.textContent = `${filtered.length} of ${ciphers.length} item${ciphers.length === 1 ? "" : "s"}${showTrash ? " in trash" : ""}`;
  rows.innerHTML = filtered.map((c) => renderRow(c, { showTrash })).join("");
  wireRowButtons(rows, { showTrash });
  clearTickers();
  startTickers(rows, filtered);
}

/// Strict mode: replace the entire vault view with a blocking
/// integrity-failure screen. The user must either disable strict mode
/// (Settings) or reach a state where the warnings clear before they
/// can read or write ciphers. Mirrors the CLI's non-zero exit on
/// `hekate sync` under `strict-manifest on`.
function renderStrictManifestBlock(warnings) {
  clearTickers();
  app.innerHTML = `
    <h1 style="color:#b00020">⛔ Vault integrity failure</h1>
    <p>Strict-manifest mode is on, and the server's signed BW04 manifest
       does not match the cipher list it returned. Refusing to render
       the vault.</p>
    <ul>${warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>
    <p class="muted">This is the M2.5 follow-up: when strict mode is on,
       any mismatch is treated as a hard error rather than a warning.
       If you believe the mismatch is legitimate (e.g. a recovery
       scenario), open Settings and turn strict mode off.</p>
    <p>
      <button id="goSettings">Open Settings</button>
      <button class="secondary" id="lockNow">Lock</button>
    </p>
  `;
  document.getElementById("goSettings").addEventListener("click", () =>
    renderSettings(),
  );
  document.getElementById("lockNow").addEventListener("click", async () => {
    await clearSession();
    renderLogin();
  });
}

/// Render a small status strip directly under the toolbar reflecting
/// the manifest verdict.
///   - status="ok":      hide the strip (manifest verified, all clean)
///   - status="no-data": hide the strip too (fresh account, no ciphers
///                       yet — alarm coloring would be misleading)
///   - status="warn":    orange alarm strip listing the disagreements
function renderManifestStatus(verdict) {
  let strip = document.getElementById("manifest-status");
  if (!strip) {
    strip = document.createElement("div");
    strip.id = "manifest-status";
    const matches = document.getElementById("matches");
    matches.parentNode.insertBefore(strip, matches);
  }
  if (!verdict || verdict.status !== "warn") {
    strip.innerHTML = "";
    return;
  }
  const warnings = verdict.warnings || [];
  strip.innerHTML = `
    <div class="manifest-warn">
      <strong>⚠ Vault integrity (${warnings.length})</strong>
      <ul>${warnings
        .slice(0, 4)
        .map((w) => `<li>${escapeHtml(w)}</li>`)
        .join("")}</ul>
      ${
        warnings.length > 4
          ? `<p class="muted">…and ${warnings.length - 4} more</p>`
          : ""
      }
    </div>
  `;
}

function renderRow(c, opts) {
  const showTrash = opts && opts.showTrash;
  const id = escapeAttr(c.id);
  const summary = summarizeRow(c);
  const typeIcon = icon(iconForCipherType(c.type));
  return `
    <div class="row" data-id="${id}">
      <div class="row-icon" data-type="${c.type}">${typeIcon}</div>
      <div class="row-main">
        <div class="row-name">${escapeHtml(c.name)}</div>
        <div class="muted small" data-totp-display="${c.type === 6 ? id : ""}">${escapeHtml(summary)}</div>
      </div>
      <div class="row-actions">
        ${
          showTrash
            ? `<button class="text restore" data-id="${id}" title="Restore">Restore</button>
               <button class="text danger purge" data-id="${id}" title="Delete forever">Delete</button>`
            : rowActions(c)
        }
      </div>
    </div>`;
}

function rowActions(c) {
  const id = escapeAttr(c.id);
  const buttons = [];
  if (c.type === 1 && c.data) {
    const canFill = c.data.username || c.data.password;
    if (canFill) buttons.push(`<button class="fill" data-id="${id}" title="Fill on this page" aria-label="Fill">${icon("fill")}</button>`);
    if (c.data.password) {
      buttons.push(`<button data-copy="${escapeAttr(c.data.password)}" data-copy-label="Password" title="Copy password" aria-label="Copy password">${icon("copy")}</button>`);
    }
  } else if (c.type === 6) {
    buttons.push(`<button class="totp-copy" data-id="${id}" title="Copy TOTP code" aria-label="Copy TOTP code">${icon("copy")}</button>`);
  } else if (c.type === 3 && c.data && c.data.number) {
    buttons.push(`<button data-copy="${escapeAttr(c.data.number)}" data-copy-label="Number" title="Copy card number" aria-label="Copy card number">${icon("copy")}</button>`);
  } else if (c.type === 5 && c.data && c.data.publicKey) {
    buttons.push(`<button data-copy="${escapeAttr(c.data.publicKey)}" data-copy-label="Public key" title="Copy public key" aria-label="Copy public key">${icon("copy")}</button>`);
  } else if (c.type === 4 && c.data && c.data.email) {
    buttons.push(`<button data-copy="${escapeAttr(c.data.email)}" data-copy-label="Email" title="Copy email" aria-label="Copy email">${icon("copy")}</button>`);
  }
  buttons.push(`<button class="edit" data-id="${id}" title="Edit" aria-label="Edit">${icon("edit")}</button>`);
  buttons.push(`<button class="trash danger" data-id="${id}" title="Move to trash" aria-label="Move to trash">${icon("trash")}</button>`);
  return buttons.join("\n");
}

function summarizeRow(c) {
  if (c.name === "<undecryptable>") return "(decrypt failed)";
  const cfg = CIPHER_TYPES[c.type];
  if (!cfg) return typeName(c.type);
  if (c.type === 6 && c.data && c.data.secret) {
    return "loading code…"; // ticker fills in
  }
  try {
    const s = cfg.summarize(c.data || {});
    return s || cfg.label.toLowerCase();
  } catch (_) {
    return cfg.label.toLowerCase();
  }
}

function renderMatchesSection(matches, tabHost) {
  const el = document.getElementById("matches");
  if (!tabHost) {
    el.innerHTML = "";
    return;
  }
  if (matches.length === 0) {
    el.innerHTML = `<p class="muted">No matches for <code>${escapeHtml(tabHost)}</code>.</p>`;
    return;
  }
  el.innerHTML = `
    <h2>Matches for <code>${escapeHtml(tabHost)}</code></h2>
    <div id="match-rows">
      ${matches.map((c) => renderRow(c, { showTrash: false })).join("")}
    </div>
  `;
  const matchRows = document.getElementById("match-rows");
  wireRowButtons(matchRows, { showTrash: false });
  // Start the TOTP tickers for any TOTP entries in the match list so
  // live codes render here too.
  startTickers(matchRows, matches);
}

function wireRowButtons(container, opts) {
  container.querySelectorAll("button[data-copy]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      await copyWithAutoClear(btn.dataset.copy, btn.dataset.copyLabel || "Value");
    }),
  );
  container.querySelectorAll("button.fill").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        await fillActiveTab(btn.dataset.id);
        toast("Filled. Submit the form when ready.");
        window.close();
      } catch (err) {
        toast("Fill failed: " + err.message, 2500);
      }
    }),
  );
  container.querySelectorAll("button.totp-copy").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        const code = await fetchTotpCode(btn.dataset.id);
        await copyWithAutoClear(code, `Code ${code}`);
      } catch (err) {
        toast("Couldn't generate code: " + err.message, 2500);
      }
    }),
  );
  container.querySelectorAll("button.edit").forEach((btn) =>
    btn.addEventListener("click", () => renderAddEdit(btn.dataset.id, null)),
  );
  container.querySelectorAll("button.trash").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        await apiDelete(`/api/v1/ciphers/${encodeURIComponent(btn.dataset.id)}`);
        await uploadManifestQuiet();
        toast("Moved to trash.");
        await renderVault({ showTrash: !!(opts && opts.showTrash) });
      } catch (err) {
        toast("Trash failed: " + err.message, 2500);
      }
    }),
  );
  container.querySelectorAll("button.restore").forEach((btn) =>
    btn.addEventListener("click", async () => {
      try {
        await apiPost(
          `/api/v1/ciphers/${encodeURIComponent(btn.dataset.id)}/restore`,
          null,
        );
        await uploadManifestQuiet();
        toast("Restored.");
        await renderVault({ showTrash: true });
      } catch (err) {
        toast("Restore failed: " + err.message, 2500);
      }
    }),
  );
  container.querySelectorAll("button.purge").forEach((btn) =>
    btn.addEventListener("click", async () => {
      if (!confirm("Permanently delete this item? This cannot be undone.")) return;
      try {
        await apiDelete(
          `/api/v1/ciphers/${encodeURIComponent(btn.dataset.id)}/permanent`,
        );
        await uploadManifestQuiet();
        toast("Deleted.");
        await renderVault({ showTrash: true });
      } catch (err) {
        toast("Delete failed: " + err.message, 2500);
      }
    }),
  );
}

/// Best-effort manifest refresh after a write. Errors surface as a toast
/// rather than blocking the user's action — the cipher write already
/// succeeded, the only consequence is that BW04 set-level integrity
/// for *this* write didn't get sealed. The next successful write retries.
async function uploadManifestQuiet() {
  try {
    const session = await loadSession();
    const result = await syncAndUploadManifest(session);
    if (!result.ok) {
      console.warn("manifest upload skipped:", result.reason);
    }
  } catch (err) {
    console.warn("manifest upload failed:", err);
    toast("warning: signed manifest upload failed", 2200);
  }
}

// ===========================================================================
// GH #1 — Hekate as passkey provider: WebAuthn assembly + approval flow
// ===========================================================================
//
// Owns the popup-side response builder for ceremonies the SW dispatches
// via chrome.webAuthenticationProxy. The SW puts each ceremony into
// chrome.storage.session["passkey_queue"] and broadcasts MSG_PASSKEY_REQUEST.
// We drain the queue on popup open and listen for live broadcasts while
// the popup stays open. Replies go back via MSG_PASSKEY_REPLY.
//
// What we build (WebAuthn level-2, byte-canonical):
//   * clientDataJSON           — JSON byte-string the RP rebuilds
//   * authenticatorData        — sha256(rpId)(32) || flags(1) || signCount(4)
//                                [|| attestedCredentialData] (create only)
//   * attestedCredentialData   — AAGUID(16) || credIdLen(2) || credId(16)
//                                || COSE_Key(77 for ES256) (create only)
//   * attestationObject        — CBOR { fmt:"none", attStmt:{}, authData }
//                                (create only)
//   * For .get(): DER ECDSA over (authData || sha256(clientDataJSON))
//
// All ArrayBuffer-typed fields in the responseJson are base64url-no-pad
// (the encoding `PublicKeyCredential.toJSON()` uses).

// Stable Hekate AAGUID. Source of truth is hekate-core::passkey::HEKATE_AAGUID;
// changing this is a credential-stability decision (RP-side AAGUID
// allowlists stop matching previously-issued Hekate credentials).
const HEKATE_AAGUID = new Uint8Array([
  0x48, 0x65, 0x6b, 0x61, 0x74, 0x65, 0x40, 0x72, 0xa0, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01,
]);

const PASSKEY_FLAG_UP = 0x01; // user present
const PASSKEY_FLAG_UV = 0x04; // user verified — master-password unlock counts
const PASSKEY_FLAG_AT = 0x40; // attested credential data present (create only)

// COSE algorithm identifier (RFC 8152) for ECDSA over P-256 with SHA-256.
// Used in the RegistrationResponseJSON's `publicKeyAlgorithm` field —
// Chrome's webAuthenticationProxy.completeCreateRequest validates this.
const PASSKEY_ALG_ES256 = -7;

// SubjectPublicKeyInfo prefix for P-256 ECDSA (RFC 5480 §2.1.1.1).
//   SEQUENCE {
//     SEQUENCE { OID 1.2.840.10045.2.1 (ecPublicKey),
//                OID 1.2.840.10045.3.1.7 (secp256r1) },
//     BIT STRING { 0x00 + sec1-uncompressed-pubkey } }
// Total = 26-byte fixed prefix + 65 bytes (0x04 || X(32) || Y(32)).
const PASSKEY_P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);
function passkeyP256SpkiFromSec1(sec1Bytes) {
  return passkeyConcat(PASSKEY_P256_SPKI_PREFIX, sec1Bytes);
}

const MSG_PASSKEY_REQUEST = "hekate:passkey_request";
const MSG_PASSKEY_REPLY = "hekate:passkey_reply";

async function passkeySha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

function passkeyConcat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

function passkeyU16BE(n) {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

function passkeyU32BE(n) {
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ]);
}

// Minimal CBOR encoder — enough for attestationObject (3-key map of two
// short text strings + one byte string up to a few hundred bytes). RFC
// 8949 canonical-form rule: smallest-length encoding for each item.
function _cborHeader(majorType, n) {
  if (n < 24) return new Uint8Array([majorType | n]);
  if (n < 256) return new Uint8Array([majorType | 24, n]);
  if (n < 65536)
    return new Uint8Array([majorType | 25, (n >>> 8) & 0xff, n & 0xff]);
  throw new Error("CBOR length too large for popup encoder: " + n);
}
function cborText(s) {
  const bytes = enc.encode(s);
  return passkeyConcat(_cborHeader(0x60, bytes.length), bytes);
}
function cborBytes(b) {
  return passkeyConcat(_cborHeader(0x40, b.length), b);
}
function cborMapHeader(n) {
  return _cborHeader(0xa0, n);
}

function buildClientDataJSON({ type, challenge, origin }) {
  // crossOrigin: false — the SW only dispatches top-level ceremonies (the
  // proxy doesn't fire for cross-origin iframes that lack a permissions
  // policy grant; if it ever does, we should plumb isSameOriginWithAncestors
  // through the request and toggle this).
  return enc.encode(
    JSON.stringify({
      type,
      challenge,
      origin,
      crossOrigin: false,
    }),
  );
}

async function buildAuthenticatorData({
  rpId,
  flags,
  signCount,
  attestedCredentialData,
}) {
  const rpIdHash = await passkeySha256(enc.encode(rpId));
  const flagsByte = new Uint8Array([flags]);
  const counter = passkeyU32BE(signCount | 0);
  return attestedCredentialData
    ? passkeyConcat(rpIdHash, flagsByte, counter, attestedCredentialData)
    : passkeyConcat(rpIdHash, flagsByte, counter);
}

function buildAttestedCredentialData({
  aaguid,
  credentialIdBytes,
  cosePubkeyBytes,
}) {
  if (aaguid.length !== 16) throw new Error("AAGUID must be 16 bytes");
  return passkeyConcat(
    aaguid,
    passkeyU16BE(credentialIdBytes.length),
    credentialIdBytes,
    cosePubkeyBytes,
  );
}

function buildAttestationObject(authData) {
  // Map(3): { "fmt":"none", "attStmt":{}, "authData":<bstr> }. Canonical
  // ordering by encoded key length: fmt(3) < attStmt(7) < authData(8).
  return passkeyConcat(
    cborMapHeader(3),
    cborText("fmt"),
    cborText("none"),
    cborText("attStmt"),
    cborMapHeader(0),
    cborText("authData"),
    cborBytes(authData),
  );
}

// Cipher-side helpers — find/append/create login ciphers carrying
// `fido2Credentials` arrays. Our login schema is flat (no nested `login`
// object the way Bitwarden has); fido2Credentials lives next to
// username/password/uri inside the per-cipher protected_data.

// Audit X-M1 (2026-05-07): cheap rpId shape check. WebAuthn rpId is
// a hostname per spec (https://www.w3.org/TR/webauthn-2/#rp-id), so
// path / port / query / fragment / userinfo / scheme are all wrong.
// We don't try to be a full Public Suffix List check — that's
// browser-policy territory and Chrome already enforces the
// rpId-vs-origin binding before delivering to us — but rejecting
// obvious shape violations here means a buggy or compromised RP
// can't sneak weird rpIds into the cipher row name / uri field.
function isValidRpId(rpId) {
  if (typeof rpId !== "string" || rpId.length === 0 || rpId.length > 253) {
    return false;
  }
  // WebAuthn rpId must be a registrable-domain-shaped hostname:
  // ASCII letters/digits/hyphens, dots between labels, no leading/
  // trailing dot, no path/port/query/etc.
  return /^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*$/.test(rpId);
}

function rpIdMatchesUri(rpId, uri) {
  if (!uri || !rpId) return false;
  let host;
  try {
    host = new URL(uri).hostname;
  } catch (_) {
    return false;
  }
  return host === rpId || host.endsWith("." + rpId);
}

async function listLoginCiphersFull() {
  const sync = await apiGet("/api/v1/sync");
  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);
  const out = [];
  for (const c of sync.changes.ciphers) {
    if (c.type !== 1) continue;
    if (c.deleted_date) continue;
    out.push({ raw: c, decoded: decryptFull(c, accountKey) });
  }
  return { items: out, accountKey };
}

async function findLoginCipherByRpId(rpId) {
  const { items, accountKey } = await listLoginCiphersFull();
  const match = items.find((c) => rpIdMatchesUri(rpId, c.decoded.data?.uri));
  return match ? { ...match, accountKey } : null;
}

async function findFido2CredByCredentialId(credentialIdB64url) {
  const { items, accountKey } = await listLoginCiphersFull();
  for (const c of items) {
    const list = c.decoded.data?.fido2Credentials || [];
    const cred = list.find((f) => f.credentialId === credentialIdB64url);
    if (cred) return { cred, cipher: c, accountKey };
  }
  return null;
}

async function appendFido2CredentialToCipher(cipher, accountKey, fido2cred) {
  const data = { ...(cipher.decoded.data || {}) };
  const list = Array.isArray(data.fido2Credentials)
    ? data.fido2Credentials.slice()
    : [];
  list.push(fido2cred);
  data.fido2Credentials = list;
  const dataJson = JSON.stringify(data);

  const cipherKey = hekate.encStringDecryptXc20p(
    cipher.raw.protected_cipher_key,
    accountKey,
    aadProtectedCipherKey(cipher.raw.id),
  );

  const body = {
    id: cipher.raw.id,
    type: cipher.raw.type,
    folder_id: cipher.raw.folder_id,
    protected_cipher_key: cipher.raw.protected_cipher_key,
    name: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(cipher.decoded.name),
      aadCipherName(cipher.raw.id, cipher.raw.type),
    ),
    notes: cipher.decoded.notes
      ? hekate.encStringEncryptXc20p(
          "ck:1",
          cipherKey,
          enc.encode(cipher.decoded.notes),
          aadCipherNotes(cipher.raw.id, cipher.raw.type),
        )
      : null,
    data: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(dataJson),
      aadCipherData(cipher.raw.id, cipher.raw.type),
    ),
    favorite: !!cipher.raw.favorite,
  };
  await apiPut(
    `/api/v1/ciphers/${encodeURIComponent(cipher.raw.id)}`,
    body,
    cipher.raw.revision_date,
  );
  await uploadManifestQuiet();
}

async function createLoginCipherWithFido2(name, uri, fido2cred, accountKey) {
  const cipherId = newCipherId();
  const cipherKey = hekate.randomKey32();
  const protected_cipher_key = hekate.encStringEncryptXc20p(
    "ak:1",
    accountKey,
    cipherKey,
    aadProtectedCipherKey(cipherId),
  );
  // Surface the passkey's userName as the cipher's top-level username
  // so the vault list / autofill have something human-readable to
  // show. WebAuthn auth itself doesn't need this field — the RP
  // identifies via credentialId + signature — but rendering
  // "WebAuthn.io" with no further context (vs. "WebAuthn.io —
  // hekate-smoke-final") is a poor UX with multiple passkeys.
  const data = { uri, fido2Credentials: [fido2cred] };
  if (fido2cred.userName) data.username = fido2cred.userName;
  const dataJson = JSON.stringify(data);
  const body = {
    id: cipherId,
    type: 1,
    folder_id: null,
    protected_cipher_key,
    name: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(name),
      aadCipherName(cipherId, 1),
    ),
    notes: null,
    data: hekate.encStringEncryptXc20p(
      "ck:1",
      cipherKey,
      enc.encode(dataJson),
      aadCipherData(cipherId, 1),
    ),
    favorite: false,
  };
  await apiPost("/api/v1/ciphers", body);
  await uploadManifestQuiet();
}

// Approval modal — uses the existing .modal-overlay/.modal-card chrome
// already in popup.css. Resolves true on Approve, false on Cancel /
// Escape / backdrop click.
function renderPasskeyApproval({ rpId, rpName, action, kind }) {
  // Audit X-M1 (2026-05-07): show rpName *and* rpId. The RP-supplied
  // rpName goes into the cipher row name later, and an attacker who
  // owns `google.attacker.com` can set rpName="Google" — without
  // displaying the rpId next to it, the user has no signal to spot
  // the mismatch. rpId is the authoritative WebAuthn identifier and
  // what the browser already enforces against the page's origin.
  const showRpName = rpName && rpName !== rpId;
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.innerHTML = `
      <div class="modal-card">
        <h3>${escapeHtml(action)}</h3>
        ${
          showRpName
            ? `<p>Site claims to be: <strong>${escapeHtml(rpName)}</strong></p>`
            : ""
        }
        <p>Verified domain: <strong>${escapeHtml(rpId || "(unknown)")}</strong></p>
        <p class="muted small">${
          kind === "create"
            ? "A new passkey will be saved to your Hekate vault."
            : "Hekate will sign in to this site with a saved passkey."
        } Approve only if the verified domain matches the site you're using.</p>
        <div class="modal-buttons">
          <button type="button" class="secondary" id="pkCancel">Cancel</button>
          <button type="button" class="primary" id="pkApprove">Approve</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    let resolved = false;
    const finish = (ok) => {
      if (resolved) return;
      resolved = true;
      overlay.remove();
      resolve(ok);
    };
    overlay.querySelector("#pkApprove").addEventListener("click", () => finish(true));
    overlay.querySelector("#pkCancel").addEventListener("click", () => finish(false));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(false);
    });
    document.addEventListener("keydown", function onKey(e) {
      if (e.key === "Escape") {
        document.removeEventListener("keydown", onKey);
        finish(false);
      }
    });
    setTimeout(() => overlay.querySelector("#pkApprove").focus(), 0);
  });
}

async function buildPasskeyCreateResponse(parsed, kp) {
  // Flat options shape — see handlePasskeyEntry for the rationale.
  const rpId = parsed.rp?.id;
  const challenge = parsed.challenge; // base64url-no-pad already
  // Chrome stuffs the page's actual origin into
  // `extensions.remoteDesktopClientOverride.origin` (reuse of an
  // existing WebAuthn extension that was originally for Remote
  // Desktop). Fall back to a top-level `origin` field on the off
  // chance Chrome's serialization changes again.
  const origin =
    parsed.origin ||
    parsed.extensions?.remoteDesktopClientOverride?.origin;

  const clientDataJSON = buildClientDataJSON({
    type: "webauthn.create",
    challenge,
    origin,
  });

  const credIdBytes = b64urlDecode(kp.credentialIdB64url);
  const sec1 = b64decode(kp.publicSec1B64);
  const cosePubkey = hekate.passkeyCoseEs256(sec1);

  const attestedCredentialData = buildAttestedCredentialData({
    aaguid: HEKATE_AAGUID,
    credentialIdBytes: credIdBytes,
    cosePubkeyBytes: cosePubkey,
  });

  const authData = await buildAuthenticatorData({
    rpId,
    flags: PASSKEY_FLAG_UP | PASSKEY_FLAG_UV | PASSKEY_FLAG_AT,
    signCount: 0,
    attestedCredentialData,
  });

  const attestationObject = buildAttestationObject(authData);

  return {
    id: kp.credentialIdB64url,
    rawId: kp.credentialIdB64url,
    type: "public-key",
    response: {
      clientDataJSON: b64urlEncode(clientDataJSON),
      attestationObject: b64urlEncode(attestationObject),
      // WebAuthn L3 / RegistrationResponseJSON fields. Chrome's
      // webAuthenticationProxy.completeCreateRequest validates these
      // and rejects the whole response with
      // "Invalid responseJson: field missing or invalid:
      //  publicKeyAlgorithm" if any are absent. Without this, every
      // ceremony silently fails — the cipher gets written
      // (we hit that code earlier in doPasskeyCreate) but the RP
      // never receives a valid credential.
      authenticatorData: b64urlEncode(authData),
      publicKey: b64urlEncode(passkeyP256SpkiFromSec1(sec1)),
      publicKeyAlgorithm: PASSKEY_ALG_ES256,
      transports: ["internal"],
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
  };
}

async function buildPasskeyGetResponse(parsed, cred) {
  // Flat options shape — see handlePasskeyEntry for the rationale.
  const rpId = parsed.rpId || cred.rpId;
  const challenge = parsed.challenge;
  const origin =
    parsed.origin ||
    parsed.extensions?.remoteDesktopClientOverride?.origin;

  const clientDataJSON = buildClientDataJSON({
    type: "webauthn.get",
    challenge,
    origin,
  });

  // Audit M-3 (2026-05-07): cross the WASM boundary with the rpId as a
  // string. hekate-core builds authenticatorData (sha256(rpId) || flags
  // || signCount) and signs (authData || sha256(clientDataJSON))
  // atomically, so a bug in this file's authData assembly can't drift
  // the signed rpId off what the popup-side approval modal showed the
  // user.
  const clientDataHash = await passkeySha256(clientDataJSON);
  const { authenticatorData, signature } = hekate.passkeySignAssertion(
    cred.keyValue,
    rpId,
    PASSKEY_FLAG_UP | PASSKEY_FLAG_UV,
    0,
    clientDataHash,
  );
  const authData = new Uint8Array(authenticatorData);
  const sigDer = new Uint8Array(signature);

  return {
    id: cred.credentialId,
    rawId: cred.credentialId,
    type: "public-key",
    response: {
      clientDataJSON: b64urlEncode(clientDataJSON),
      authenticatorData: b64urlEncode(authData),
      signature: b64urlEncode(sigDer),
      userHandle: cred.userHandle,
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
  };
}

async function doPasskeyCreate(parsed, requestId) {
  // Flat options shape — see handlePasskeyEntry for the rationale.
  const rpId = parsed.rp?.id;
  if (!rpId) throw new Error("create request missing rp.id");
  const userHandle = parsed.user?.id || ""; // base64url already
  const userName = parsed.user?.name || "";
  const userDisplayName = parsed.user?.displayName || "";
  const rpName = parsed.rp?.name || rpId;

  const kp = hekate.passkeyGenerate();

  const fido2cred = {
    credentialId: kp.credentialIdB64url,
    keyType: "public-key",
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: kp.privatePkcs8B64,
    rpId,
    userHandle,
    userName,
    counter: "0",
    rpName,
    userDisplayName,
    discoverable: "true",
    creationDate: new Date().toISOString(),
  };

  // Audit X-H3 (2026-05-07): build the response object FIRST (pure
  // in-memory crypto, fast) so we have it ready before the slow
  // cipher-write round trip. Then re-check that the SW still has
  // this ceremony pending — its 60s timeout path drains the queue
  // entry, so a missing entry means the RP has already given up on
  // us. Writing a cipher anyway would let a malicious site
  // DoS-pollute the vault by opening ceremonies and timing them
  // out (free vault entries with no live RP to claim them).
  const responseObj = await buildPasskeyCreateResponse(parsed, kp);
  const responseJson = JSON.stringify(responseObj);

  if (!(await isPasskeyEntryStillPending(requestId))) {
    throw new Error(
      "ceremony timed out before approval was processed; not writing cipher",
    );
  }

  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);

  const existing = await findLoginCipherByRpId(rpId);
  if (existing) {
    await appendFido2CredentialToCipher(existing, accountKey, fido2cred);
  } else {
    await createLoginCipherWithFido2(
      rpName,
      `https://${rpId}`,
      fido2cred,
      accountKey,
    );
  }

  return responseJson;
}

async function isPasskeyEntryStillPending(requestId) {
  // Truthy if the SW's timeout path hasn't already drained this
  // entry. There's still a small race (the SW can time out between
  // this check and the eventual cipher write), but that window is
  // bounded by the cipher-write round trip and the worst case is one
  // junk vault entry — not the unbounded vault-pollution surface the
  // pre-fix code had.
  try {
    const stored = await chrome.storage.session.get(["passkey_queue"]);
    const queue = Array.isArray(stored.passkey_queue) ? stored.passkey_queue : [];
    return queue.some((e) => e.requestId === requestId);
  } catch (_) {
    return false;
  }
}

async function doPasskeyGet(parsed) {
  // Flat options shape — see handlePasskeyEntry for the rationale.
  const rpId = parsed.rpId;
  if (!rpId) throw new Error("get request missing rpId");
  const allowList = Array.isArray(parsed.allowCredentials)
    ? parsed.allowCredentials
    : [];

  let chosen = null;
  if (allowList.length > 0) {
    for (const a of allowList) {
      const found = await findFido2CredByCredentialId(a.id);
      if (found && found.cred.rpId === rpId) {
        chosen = found.cred;
        break;
      }
    }
  } else {
    // Discoverable-credential / usernameless — pick the first matching rpId.
    const { items } = await listLoginCiphersFull();
    outer: for (const c of items) {
      const list = c.decoded.data?.fido2Credentials || [];
      for (const f of list) {
        if (f.rpId === rpId) {
          chosen = f;
          break outer;
        }
      }
    }
  }
  if (!chosen) throw new Error(`no passkey for ${rpId}`);

  const responseObj = await buildPasskeyGetResponse(parsed, chosen);
  return JSON.stringify(responseObj);
}

async function sendPasskeyReply(requestId, responseJson, error) {
  // Drain the queue entry so we don't re-fire on the next popup open.
  try {
    const stored = await chrome.storage.session.get(["passkey_queue"]);
    const queue = Array.isArray(stored.passkey_queue) ? stored.passkey_queue : [];
    await chrome.storage.session.set({
      passkey_queue: queue.filter((e) => e.requestId !== requestId),
    });
  } catch (_) {
    /* nothing actionable */
  }
  await chrome.runtime
    .sendMessage({
      type: MSG_PASSKEY_REPLY,
      requestId,
      payload: responseJson ? { responseJson } : undefined,
      error: error || undefined,
    })
    .catch(() => {});
}

async function handlePasskeyEntry({ requestId, kind, req }) {
  let parsed;
  try {
    parsed = JSON.parse(req.requestDetailsJson);
  } catch (e) {
    await sendPasskeyReply(requestId, null, {
      name: "NotAllowedError",
      message: "malformed requestDetailsJson",
    });
    return;
  }
  // Chrome's `requestDetailsJson` is the FLAT options
  // (PublicKeyCredentialCreationOptionsJSON for create,
  // PublicKeyCredentialRequestOptionsJSON for get) — no `publicKey`
  // wrapper. For create, rpId lives at `rp.id`; for get, at `rpId`.
  const rpId = kind === "create" ? parsed.rp?.id : parsed.rpId;
  const rpName = kind === "create" ? parsed.rp?.name : undefined;

  // Audit X-M1 (2026-05-07): refuse rpIds that don't look like a
  // valid WebAuthn identifier. The spec says rpId is a hostname, so
  // it can't contain a path / port / query / fragment / userinfo.
  // This won't catch a registered evil-domain typosquat (no public
  // suffix list), but it does block obviously-malformed inputs that
  // a legit caller would never send.
  if (!isValidRpId(rpId)) {
    await sendPasskeyReply(requestId, null, {
      name: "NotAllowedError",
      message: `rpId rejected by policy: ${rpId || "(missing)"}`,
    });
    return;
  }

  const action =
    kind === "create"
      ? "Create passkey for this site?"
      : "Sign in with your saved passkey?";

  const approved = await renderPasskeyApproval({ rpId, rpName, action, kind });
  if (!approved) {
    await sendPasskeyReply(requestId, null, {
      name: "NotAllowedError",
      message: "user declined",
    });
    return;
  }

  try {
    const responseJson =
      kind === "create"
        ? await doPasskeyCreate(parsed, requestId)
        : await doPasskeyGet(parsed);
    await sendPasskeyReply(requestId, responseJson, null);
    toast(kind === "create" ? "Passkey created." : "Signed in.", 1800);
  } catch (e) {
    console.error("passkey ceremony failed:", e);
    await sendPasskeyReply(requestId, null, {
      name: "NotAllowedError",
      message: String(e?.message || e),
    });
    toast(`Passkey failed: ${e?.message || e}`, 2400);
  }
}

let _passkeyDraining = false;
async function drainPasskeyQueue() {
  if (_passkeyDraining) return;
  _passkeyDraining = true;
  try {
    // Vault must be unlocked — we need account_key for cipher I/O.
    const session = await loadSession();
    if (!session.access_token || !session.account_key_b64) return;

    // Snapshot the queue once; entries we process will remove themselves
    // via sendPasskeyReply. New entries that arrive mid-drain are
    // picked up by the runtime onMessage listener below.
    const stored = await chrome.storage.session.get(["passkey_queue"]);
    const queue = Array.isArray(stored.passkey_queue) ? stored.passkey_queue : [];
    for (const entry of queue) {
      // Re-check on each iteration — a previous handler might have replied
      // to this id already (race with the SW timeout path).
      const cur = await chrome.storage.session.get(["passkey_queue"]);
      const still = Array.isArray(cur.passkey_queue)
        ? cur.passkey_queue.some((e) => e.requestId === entry.requestId)
        : false;
      if (!still) continue;
      // Audit X-M4 (2026-05-07): belt-and-braces age check. The SW's
      // 60s timeout drains the queue entry on its own, but if the SW
      // was evicted before the timeout fired, the entry could outlive
      // the original ceremony. Skip + drop anything older than the
      // SW timeout window so we never present an approval modal for
      // a request the RP has already given up on.
      const queuedAt = entry.queuedAt ? Date.parse(entry.queuedAt) : NaN;
      if (Number.isFinite(queuedAt) && Date.now() - queuedAt > 60_000) {
        await sendPasskeyReply(entry.requestId, null, {
          name: "NotAllowedError",
          message: "ceremony expired before approval",
        });
        continue;
      }
      try {
        await handlePasskeyEntry(entry);
      } catch (e) {
        await sendPasskeyReply(entry.requestId, null, {
          name: "NotAllowedError",
          message: String(e?.message || e),
        });
      }
    }
  } finally {
    _passkeyDraining = false;
  }
}

// Live broadcasts: SW posts MSG_PASSKEY_REQUEST when a ceremony arrives
// while the popup is open. Drain whenever we hear it (idempotent).
chrome.runtime.onMessage.addListener((msg, sender) => {
  // Audit X-H2 (2026-05-07): only accept messages from this exact
  // extension. A spoofed MSG_PASSKEY_REQUEST from a content script
  // could otherwise force the popup to drain and surface a fake
  // approval modal at an attacker-chosen rpId.
  if (!sender || sender.id !== chrome.runtime.id) return;
  if (msg && msg.type === MSG_PASSKEY_REQUEST) {
    drainPasskeyQueue().catch(() => {});
  }
});

// ===========================================================================
// Settings
// ===========================================================================

async function renderSettings() {
  clearTickers();
  const settings = loadSettings();
  const session = await loadSession();
  // Passkey-provider toggle lives in chrome.storage.local (NOT the
  // localStorage settings blob) because the service worker subscribes
  // to chrome.storage.onChanged on it — that's how flipping the
  // toggle here takes effect without an SW restart.
  const passkeyState = await chrome.storage.local
    .get("passkey_provider_enabled")
    .catch(() => ({}));
  const passkeyEnabled = !!passkeyState.passkey_provider_enabled;
  const passkeySupported =
    typeof chrome !== "undefined" &&
    !!chrome.webAuthenticationProxy &&
    typeof chrome.webAuthenticationProxy.attach === "function";
  const content = `
    <h2>Account</h2>
    <div class="setting-group">
      <div class="setting-row">
        <div>
          <div class="setting-label">${escapeHtml(session.email || "")}</div>
          <div class="setting-sub">${escapeHtml(session.server_url || "")}</div>
        </div>
      </div>
      <div class="setting-row clickable" id="lockBtn">
        <div>
          <div class="setting-label">Sign out</div>
          <div class="setting-sub">Clear keys + tokens from memory; next launch requires email + master password.</div>
        </div>
      </div>
      <div class="setting-row clickable" id="trashBtn">
        <div>
          <div class="setting-label">Trash</div>
          <div class="setting-sub">View and restore deleted items.</div>
        </div>
      </div>
    </div>

    <h2>Security</h2>
    <div class="setting-group">
      <div class="setting-row clickable" id="manage2faBtn">
        <div>
          <div class="setting-label">Two-factor authentication</div>
          <div class="setting-sub">TOTP + WebAuthn passkeys + recovery codes.</div>
        </div>
      </div>
      <div class="setting-row clickable" id="rotateKeysBtn">
        <div>
          <div class="setting-label">Rotate account key</div>
          <div class="setting-sub">Re-wrap every cipher, share, and org membership.</div>
        </div>
      </div>
    </div>

    <form id="settingsForm">
      <h2>Preferences</h2>
      <label><span>Clipboard auto-clear (seconds)</span>
        <input name="clearSecs" type="number" min="0" max="600" step="5"
               value="${escapeAttr(String(settings.clearSecs))}">
      </label>
      <p class="muted small">
        Set to <code>0</code> to disable. The clipboard is wiped this many
        seconds after a Copy. The timer runs in the service worker via
        <code>chrome.alarms</code> + an offscreen document so it fires
        even after the popup closes; Chromium clamps the minimum to ~30s.
      </p>
      <label class="checkbox">
        <input type="checkbox" name="strictManifest" ${
          settings.strictManifest ? "checked" : ""
        }>
        <span>Strict manifest verification (BW04)</span>
      </label>
      <p class="muted small">
        When on, any signed-manifest mismatch on /sync replaces the vault
        view with a blocking integrity-failure screen instead of a
        warnings strip.
      </p>
      <button type="submit" class="primary-block">Save preferences</button>
    </form>

    <h2>Passkey provider <span class="muted small">(experimental — GH #1)</span></h2>
    <div class="setting-group">
      <div class="setting-row">
        <div>
          <div class="setting-label">Use Hekate as my passkey provider</div>
          <div class="setting-sub">${
            passkeySupported
              ? `When enabled, sites that ask for a WebAuthn passkey
                 (<code>navigator.credentials.create()</code> /
                 <code>.get()</code>) get routed through Hekate
                 instead of the OS authenticator. Passkeys you
                 create are stored in the matching login cipher and
                 sync across your devices.`
              : `Your browser doesn't expose
                 <code>chrome.webAuthenticationProxy</code>. Requires
                 Chromium 115+ (Firefox tracking).`
          }</div>
          <p class="muted small" style="margin-top: 0.5em;">
            ${
              passkeyEnabled
                ? `<strong>Status:</strong> enabled. WebAuthn ceremonies
                   are intercepted and an approval modal opens in this
                   popup. Open the popup within 60s to approve;
                   otherwise the request is rejected with
                   <code>NotAllowedError</code>.`
                : `<strong>Status:</strong> disabled. Sites use whatever
                   provider Chrome currently has selected (OS, hardware
                   key, other extension).`
            }
          </p>
          ${
            passkeySupported
              ? `<label class="checkbox" style="margin-top: 0.5em;">
                   <input type="checkbox" id="passkeyProviderToggle" ${
                     passkeyEnabled ? "checked" : ""
                   }>
                   <span>Enabled</span>
                 </label>`
              : ""
          }
        </div>
      </div>
    </div>`;
  app.innerHTML = topShellHtml({ title: "Settings", content, activeTab: "settings" });
  wireTopShell({ activeTab: "settings" });

  document.getElementById("lockBtn").addEventListener("click", async () => {
    await clearSession();
    renderLogin();
  });
  document.getElementById("trashBtn").addEventListener("click", () =>
    renderVault({ showTrash: true }),
  );
  document.getElementById("manage2faBtn").addEventListener("click", () => render2faPanel());
  document.getElementById("rotateKeysBtn").addEventListener("click", () => renderRotateKeys());
  document.getElementById("settingsForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const secs = parseInt(fd.get("clearSecs") || "0", 10) || 0;
    const strictManifest = fd.get("strictManifest") === "on";
    saveSettings({
      ...settings,
      clearSecs: Math.max(0, Math.min(600, secs)),
      strictManifest,
    });
    toast(`Saved. Auto-clear: ${secs > 0 ? `${secs}s` : "OFF"}.`);
  });

  const passkeyToggle = document.getElementById("passkeyProviderToggle");
  if (passkeyToggle) {
    passkeyToggle.addEventListener("change", async (e) => {
      const enabled = e.target.checked;
      try {
        // Audit X-M3 (2026-05-07): when the user first enables the
        // passkey provider, surface a one-time consent dialog. The
        // toggle has system-wide blast radius — every WebAuthn
        // ceremony on every tab routes through Hekate while it's on,
        // and ceremonies that fire while the popup is closed return
        // NotAllowedError after a 60s timeout. The browser's own
        // webAuthenticationProxy permission warning is cryptic, so
        // we restate the cost explicitly the first time.
        if (enabled) {
          const consent = await loadPasskeyProviderConsent();
          if (!consent) {
            const ok = await renderPasskeyProviderConsent();
            if (!ok) {
              e.target.checked = false;
              return;
            }
            await chrome.storage.local.set({
              passkey_provider_consent_seen: true,
            });
          }
        }
        await chrome.storage.local.set({ passkey_provider_enabled: enabled });
        toast(
          enabled
            ? "Passkey provider enabled. Sites now route through Hekate."
            : "Passkey provider disabled.",
        );
        // Re-render so the status line updates without requiring a tab change.
        renderSettings();
      } catch (err) {
        toast(`Failed to save: ${err.message}`);
        e.target.checked = !enabled;
      }
    });
  }
}

async function loadPasskeyProviderConsent() {
  try {
    const v = await chrome.storage.local.get("passkey_provider_consent_seen");
    return !!v.passkey_provider_consent_seen;
  } catch (_) {
    return false;
  }
}

function renderPasskeyProviderConsent() {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.innerHTML = `
      <div class="modal-card">
        <h3>Use Hekate as your passkey provider?</h3>
        <p>While this is on:</p>
        <ul style="margin: 0 0 12px; padding-left: 1.25em; font-size: 12.5px; color: var(--fg-secondary);">
          <li>Every WebAuthn passkey ceremony in this browser routes
              through Hekate — including sites you've never used the
              extension with.</li>
          <li>If a site asks for a passkey while this popup is closed,
              you'll need to open the popup within ~60 seconds to
              approve. Otherwise the site sees a generic
              <code>NotAllowedError</code> and falls back to its other
              sign-in methods.</li>
          <li>Other passkey providers (the OS authenticator, hardware
              keys, another extension) won't be reachable until you
              turn this off.</li>
        </ul>
        <p class="muted small">You can disable this any time from
           Settings.</p>
        <div class="modal-buttons">
          <button type="button" class="secondary" id="ppCancel">Cancel</button>
          <button type="button" class="primary" id="ppApprove">Enable</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    let resolved = false;
    const finish = (ok) => {
      if (resolved) return;
      resolved = true;
      overlay.remove();
      resolve(ok);
    };
    overlay.querySelector("#ppApprove").addEventListener("click", () => finish(true));
    overlay.querySelector("#ppCancel").addEventListener("click", () => finish(false));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(false);
    });
    document.addEventListener("keydown", function onKey(e) {
      if (e.key === "Escape") {
        document.removeEventListener("keydown", onKey);
        finish(false);
      }
    });
    setTimeout(() => overlay.querySelector("#ppApprove").focus(), 0);
  });
}

// ===========================================================================
// 2FA management panel (M2.23b)
// ===========================================================================

async function render2faPanel(opts) {
  clearTickers();
  opts = opts || {};
  const content = `
    <p class="error" id="err2fa"></p>
    <div id="status2fa">Loading…</div>`;
  app.innerHTML = subShellHtml({ title: "Two-factor authentication", content });
  wireSubShell({ onBack: () => renderSettings() });

  let status, creds;
  try {
    [status, creds] = await Promise.all([
      apiGet("/api/v1/account/2fa/status"),
      apiGet("/api/v1/account/2fa/webauthn/credentials"),
    ]);
  } catch (err) {
    document.getElementById("err2fa").textContent = err.message;
    return;
  }

  document.getElementById("status2fa").innerHTML = `
    <h2>TOTP (authenticator app)</h2>
    <p>${
      status.enabled
        ? `Enabled. Recovery codes remaining: <strong>${status.recovery_codes_remaining}</strong>${
            status.recovery_codes_remaining <= 3
              ? ' <span class="muted">(consider regenerating)</span>'
              : ""
          }`
        : "Not enabled."
    }</p>
    <p>${
      status.enabled
        ? `<button class="secondary" id="totpDisable">Disable TOTP</button>
           <button class="secondary" id="recoveryRegen">Regenerate recovery codes</button>`
        : `<button id="totpEnable">Enable TOTP…</button>`
    }</p>

    <h2>Security keys / passkeys (WebAuthn)</h2>
    ${
      creds.length === 0
        ? `<p class="muted">No security keys enrolled.</p>`
        : `<ul id="webauthnList">${creds
            .map(
              (c) => `
              <li data-id="${escapeAttr(c.id)}">
                <strong class="cred-name">${escapeHtml(c.name)}</strong>
                <span class="muted">
                  added ${escapeHtml((c.created_at || "").slice(0, 10))}${
                    c.last_used_at
                      ? ` · last used ${escapeHtml(c.last_used_at.slice(0, 10))}`
                      : ""
                  }
                </span>
                <span class="cred-actions">
                  <button class="secondary cred-rename" data-id="${escapeAttr(c.id)}">Rename</button>
                  <button class="secondary cred-delete" data-id="${escapeAttr(c.id)}">Delete</button>
                </span>
              </li>`,
            )
            .join("")}</ul>`
    }
    <p><button id="webauthnEnroll">Add security key / passkey…</button></p>
  `;

  if (status.enabled) {
    document.getElementById("totpDisable").addEventListener("click", () =>
      onTotpDisable(),
    );
    document.getElementById("recoveryRegen").addEventListener("click", () =>
      onRecoveryRegenerate(),
    );
  } else {
    document.getElementById("totpEnable").addEventListener("click", () =>
      renderTotpEnroll(),
    );
  }
  document
    .getElementById("webauthnEnroll")
    .addEventListener("click", () => onWebauthnEnroll());
  document.querySelectorAll(".cred-rename").forEach((btn) =>
    btn.addEventListener("click", () => onWebauthnRename(btn.dataset.id)),
  );
  document.querySelectorAll(".cred-delete").forEach((btn) =>
    btn.addEventListener("click", () => onWebauthnDelete(btn.dataset.id)),
  );
}

async function onWebauthnEnroll() {
  const name = window.prompt(
    'Name this credential (e.g. "YubiKey 5C", "MacBook TouchID"):',
  );
  if (!name) return;
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 64) {
    toast("Name must be 1..64 characters.", 2500);
    return;
  }
  // Re-auth with master password — same shape as TOTP enrollment.
  const pw = await promptMasterPassword();
  if (pw == null) return;
  let mphB64;
  try {
    mphB64 = await deriveMphB64(pw);
  } catch (err) {
    toast(err.message, 2500);
    return;
  }
  let setup;
  try {
    setup = await apiPost("/api/v1/account/2fa/webauthn/register/start", {
      master_password_hash: mphB64,
      name: trimmed,
    });
  } catch (err) {
    toast("Couldn't start enrollment: " + err.message, 3000);
    return;
  }
  toast("Touch your authenticator to enroll…", 1500);
  let credential;
  try {
    const opts = webauthnDecodeCreationOptions(setup.creation_options);
    credential = await navigator.credentials.create(opts);
  } catch (err) {
    toast("Authenticator declined: " + (err.message || err.name), 3000);
    return;
  }
  if (!credential) {
    toast("No credential produced.", 2500);
    return;
  }
  try {
    const wire = webauthnEncodeCredentialForServer(credential);
    await apiPost("/api/v1/account/2fa/webauthn/register/finish", {
      credential: wire,
    });
  } catch (err) {
    toast("Server rejected the credential: " + err.message, 3000);
    return;
  }
  toast(`✓ Enrolled "${trimmed}".`);
  await render2faPanel();
}

async function onWebauthnRename(id) {
  const newName = window.prompt("New name:");
  if (!newName) return;
  try {
    await apiPatch(`/api/v1/account/2fa/webauthn/credentials/${encodeURIComponent(id)}`, {
      name: newName.trim(),
    });
  } catch (err) {
    toast("Rename failed: " + err.message, 2500);
    return;
  }
  await render2faPanel();
}

async function onWebauthnDelete(id) {
  if (!window.confirm("Delete this credential? This cannot be undone.")) return;
  try {
    await apiDelete(`/api/v1/account/2fa/webauthn/credentials/${encodeURIComponent(id)}`);
  } catch (err) {
    toast("Delete failed: " + err.message, 2500);
    return;
  }
  await render2faPanel();
}

async function onTotpDisable() {
  if (
    !window.confirm(
      "Disable TOTP and wipe all recovery codes? Other sessions will be invalidated.",
    )
  )
    return;
  const pw = await promptMasterPassword();
  if (pw == null) return;
  try {
    const mphB64 = await deriveMphB64(pw);
    await apiPost("/api/v1/account/2fa/totp/disable", {
      master_password_hash: mphB64,
    });
  } catch (err) {
    toast("Disable failed: " + err.message, 2500);
    return;
  }
  toast("✓ TOTP disabled.");
  await render2faPanel();
}

async function onRecoveryRegenerate() {
  if (
    !window.confirm(
      "Regenerate recovery codes? All existing codes (consumed and unconsumed) will be invalidated.",
    )
  )
    return;
  const pw = await promptMasterPassword();
  if (pw == null) return;
  let resp;
  try {
    const mphB64 = await deriveMphB64(pw);
    resp = await apiPost("/api/v1/account/2fa/recovery-codes/regenerate", {
      master_password_hash: mphB64,
    });
  } catch (err) {
    toast("Regenerate failed: " + err.message, 2500);
    return;
  }
  showRecoveryCodesOnce(resp.recovery_codes);
}

async function renderTotpEnroll() {
  const pw = await promptMasterPassword();
  if (pw == null) return render2faPanel();
  let mphB64;
  try {
    mphB64 = await deriveMphB64(pw);
  } catch (err) {
    toast(err.message, 2500);
    return render2faPanel();
  }
  const session = await loadSession();
  let setup;
  try {
    setup = await apiPost("/api/v1/account/2fa/totp/setup", {
      master_password_hash: mphB64,
      account_label: session.email,
    });
  } catch (err) {
    toast("Setup failed: " + err.message, 2500);
    return render2faPanel();
  }
  // Render the otpauth:// URI as a scannable QR via the WASM
  // qrcode binding. Most authenticator apps require a scan; falling
  // back to the URL text alone strands users without a copy/paste
  // path between devices.
  let qrSvg = "";
  try {
    qrSvg = hekate.qrCodeSvg(setup.otpauth_url);
  } catch (err) {
    console.warn("totp QR render failed:", err);
  }
  // Two-step UX:
  //   1. Scan the QR (or fall back to manual entry via a collapsible
  //      <details> block) and confirm the 6-digit code your authenticator
  //      now shows.
  //   2. After successful confirm, jump to a dedicated screen showing
  //      the recovery codes — they only become useful once 2FA is
  //      actually enabled, so showing them mid-enrollment was confusing
  //      and forced a long scroll.
  const content = `
    <p>Scan this QR with your authenticator (1Password, Aegis, Google
       Authenticator, etc.):</p>
    ${qrSvg
      ? `<div class="totp-qr">${qrSvg}</div>`
      : `<p class="muted">(QR rendering failed — use the secret below.)</p>`}
    <details class="totp-fallback">
      <summary>Trouble scanning? Enter the secret manually</summary>
      <p class="muted small">Most authenticators take either form.</p>
      <p><strong>Secret:</strong>
        <code id="totpSecret">${escapeHtml(setup.secret_b32)}</code>
        <button class="secondary" id="copySecret">Copy</button></p>
      <p class="muted small">Or paste this <code>otpauth://</code> URL into the app:</p>
      <p><code id="otpUrl">${escapeHtml(setup.otpauth_url)}</code>
        <button class="secondary" id="copyUrl">Copy URL</button></p>
    </details>
    <form id="totpConfirm">
      <label><span>Enter the 6-digit code your app shows</span>
        <input name="code" type="text" inputmode="numeric"
               autocomplete="one-time-code" required autofocus
               pattern="[0-9]{6}" maxlength="6">
      </label>
      <button type="submit">Confirm + enable</button>
    </form>
    <p class="error" id="err2fa"></p>`;
  app.innerHTML = subShellHtml({ title: "Enable TOTP", content });
  wireSubShell({ onBack: () => render2faPanel() });
  document.getElementById("copySecret").addEventListener("click", () =>
    navigator.clipboard.writeText(setup.secret_b32).then(() => toast("Secret copied.")),
  );
  document.getElementById("copyUrl").addEventListener("click", () =>
    navigator.clipboard.writeText(setup.otpauth_url).then(() => toast("URL copied.")),
  );
  document.getElementById("totpConfirm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const code = ev.target.code.value.trim();
    let resp;
    try {
      resp = await apiPost("/api/v1/account/2fa/totp/confirm", { totp_code: code });
    } catch (err) {
      document.getElementById("err2fa").textContent = err.message;
      return;
    }
    // The server rotated security_stamp + revoked refresh tokens; refresh
    // the locally-stored access + refresh pair so subsequent calls don't
    // 401 us out of session.
    await saveSession({
      access_token: resp.access_token,
      refresh_token: resp.refresh_token,
    });
    // Hand the user the recovery codes on their own screen — these only
    // matter now that 2FA is actually enabled, and a fresh-screen
    // "save these now" prompt is much less likely to be missed than
    // codes buried mid-scroll on the enrollment page.
    showRecoveryCodesOnce(setup.recovery_codes);
  });
}

function showRecoveryCodesOnce(codes) {
  const content = `
    <p><strong>Save these now — they're shown once.</strong> Each code works
       once. They authenticate when your authenticator is gone; they do
       NOT decrypt the vault.</p>
    <pre>${codes.map((c) => escapeHtml(c)).join("\n")}</pre>
    <div style="display:flex; gap:8px; margin-top: 12px;">
      <button id="copy">Copy all</button>
      <button id="done" class="secondary">I've saved them — done</button>
    </div>`;
  app.innerHTML = subShellHtml({ title: "New recovery codes", content });
  wireSubShell({ onBack: () => render2faPanel() });
  document.getElementById("copy").addEventListener("click", () =>
    navigator.clipboard
      .writeText(codes.join("\n"))
      .then(() => toast("Codes copied.")),
  );
  document.getElementById("done").addEventListener("click", () => render2faPanel());
}

// ===========================================================================
// M3.11 — Sends UI (text Sends only; file Sends are M3.12+)
// ===========================================================================
//
// The popup shows owned Sends, lets the user create new text Sends,
// and walks through the anonymous public-access flow for a pasted
// share URL. All crypto runs client-side via WASM:
//
// - send_key (32 random bytes) → URL fragment, never sent to the server
// - content_key = HKDF(send_key, salt=send_id) encrypts the payload
// - send_key wrapped under the user's account_key for sender-side
//   list/edit (so the popup can decrypt the sender's own name field)
//
// Server stores (data, protected_send_key, name, deletion_date,
// max_access_count, password_phc, ...). The owner's display "name"
// is encrypted under the account_key with `hekate.sendNameAad(send_id)`
// — bound to the send_id so two Sends' name ciphertexts can't be
// swapped. Recipients never see this field; they only get the payload
// derived from the URL-fragment send_key.

async function renderSendsList() {
  clearTickers();
  const s = await loadSession();
  const content = `
    <p class="muted">
      Ephemeral encrypted shares with anonymous recipients. The
      recipient URL carries a 32-byte key in its fragment; the
      server can revoke (delete / disable / expire / max-access) but
      cannot decrypt.
    </p>
    <div style="display:flex; gap:8px; margin-bottom:12px; flex-wrap: wrap;">
      <button id="newSend">+ New text share</button>
      <button id="newFileSend">+ New file share</button>
      <button class="secondary" id="openSend">Open shared link…</button>
    </div>
    <div id="sendsStatus">Loading…</div>
    <div id="sendsRows"></div>`;
  app.innerHTML = topShellHtml({
    title: "Share",
    content,
    activeTab: "send",
  });
  wireTopShell({ activeTab: "send" });
  document.getElementById("newSend").addEventListener("click", () => renderNewSend());
  document.getElementById("newFileSend").addEventListener("click", () => renderNewFileSend());
  document.getElementById("openSend").addEventListener("click", () => renderOpenSend());

  let sends;
  try {
    sends = await apiGet("/api/v1/sends");
  } catch (err) {
    document.getElementById("sendsStatus").textContent = "Error: " + err.message;
    return;
  }
  const accountKey = b64urlDecode(s.account_key_b64);
  const status = document.getElementById("sendsStatus");
  const rows = document.getElementById("sendsRows");
  if (!sends || sends.length === 0) {
    status.textContent = "";
    rows.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon("send")}</div>
        <div class="empty-title">No shares yet</div>
        <div class="empty-sub">Tap + New text share or + New file share to create one.</div>
      </div>`;
    return;
  }
  status.textContent = `${sends.length} share${sends.length === 1 ? "" : "s"}`;

  const decoded = sends.map((sd) => {
    let name = "<undecryptable>";
    try {
      const pt = hekate.encStringDecryptXc20p(sd.name, accountKey, hekate.sendNameAad(sd.id));
      name = dec.decode(pt);
    } catch (_) {
      /* leave placeholder */
    }
    return { ...sd, _name: name };
  });

  rows.innerHTML = decoded
    .map((sd) => {
      const max = sd.max_access_count ? `/ ${sd.max_access_count}` : "/ ∞";
      const flags = [
        sd.disabled ? "disabled" : null,
        sd.has_password ? "password" : null,
      ]
        .filter((x) => x)
        .join(", ");
      return `
        <div class="row send-row" data-id="${escapeAttr(sd.id)}">
          <div class="row-main">
            <div class="row-name">${escapeHtml(sd._name)}${
              flags ? ` <span class="muted">[${escapeHtml(flags)}]</span>` : ""
            }</div>
            <div class="muted small">
              access ${sd.access_count} ${escapeHtml(max)} ·
              expires ${escapeHtml(sd.deletion_date)}
            </div>
          </div>
          <div class="row-actions">
            <button class="secondary" data-act="copy">Copy URL</button>
            <button class="secondary" data-act="${
              sd.disabled ? "enable" : "disable"
            }">${sd.disabled ? "Enable" : "Disable"}</button>
            <button class="secondary danger" data-act="delete">Delete</button>
          </div>
        </div>`;
    })
    .join("");

  rows.querySelectorAll(".send-row").forEach((row) => {
    const id = row.dataset.id;
    row.querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", () => onSendRowAction(id, btn.dataset.act));
    });
  });
}

async function onSendRowAction(id, act) {
  const s = await loadSession();
  if (act === "copy") {
    // Re-derive the share URL from the wrapped send_key.
    const sd = await apiGet(`/api/v1/sends/${encodeURIComponent(id)}`);
    const accountKey = b64urlDecode(s.account_key_b64);
    const aad = hekate.sendKeyWrapAad(id);
    let sendKey;
    try {
      sendKey = hekate.encStringDecryptXc20p(sd.protected_send_key, accountKey, aad);
    } catch (_) {
      toast("Could not unwrap send_key — vault state may be stale.");
      return;
    }
    const url = `${s.server_url.replace(/\/$/, "")}/send/#/${id}/${hekate.sendEncodeKey(sendKey)}`;
    await copyWithAutoClear(url, "share URL");
    return;
  }
  if (act === "disable" || act === "enable") {
    try {
      await apiPost(`/api/v1/sends/${encodeURIComponent(id)}/${act}`, {});
      toast(`Share ${act}d.`);
      renderSendsList();
    } catch (err) {
      toast("Error: " + err.message, 3000);
    }
    return;
  }
  if (act === "delete") {
    if (!window.confirm("Permanently delete this share? Recipients will get 410 Gone.")) {
      return;
    }
    try {
      await apiDelete(`/api/v1/sends/${encodeURIComponent(id)}`);
      toast("Share deleted.");
      renderSendsList();
    } catch (err) {
      toast("Error: " + err.message, 3000);
    }
  }
}

function renderNewSend() {
  const content = `
    <form id="newSendForm">
      <label><span>Display name (sender-side; recipients won't see this)</span>
        <input name="name" required placeholder="e.g. Wifi for Alice">
      </label>
      <label><span>Body (text)</span>
        <textarea name="body" rows="6" required></textarea>
      </label>
      <label><span>Access password (optional gate)</span>
        <input name="password" type="password" autocomplete="new-password">
      </label>
      <label><span>Max accesses (blank = unlimited)</span>
        <input name="maxAccess" type="number" min="1" placeholder="e.g. 3">
      </label>
      <label><span>TTL — auto-delete after</span>
        <select name="ttl">
          <option value="1h">1 hour</option>
          <option value="1d">1 day</option>
          <option value="7d" selected>7 days</option>
          <option value="30d">30 days</option>
        </select>
      </label>
      <button type="submit" class="primary-block">Create + copy share URL</button>
    </form>`;
  app.innerHTML = subShellHtml({ title: "New text share", content });
  wireSubShell({ onBack: () => renderSendsList() });
  document.getElementById("newSendForm").addEventListener("submit", onCreateTextSend);
}

async function onCreateTextSend(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const name = (fd.get("name") || "").toString().trim();
  const body = (fd.get("body") || "").toString();
  const password = (fd.get("password") || "").toString();
  const maxAccess = parseInt((fd.get("maxAccess") || "").toString(), 10);
  const ttl = (fd.get("ttl") || "7d").toString();

  if (!name || !body) {
    toast("Name and body are required.");
    return;
  }
  const ttlMs = parseTtlMs(ttl);
  const deletionDate = new Date(Date.now() + ttlMs).toISOString();

  // Generate IDs + keys (all client-side; the server never sees the
  // send_key or the plaintext).
  const sendId = hekate.newCipherIdFromUuidV7
    ? hekate.newCipherIdFromUuidV7()
    : crypto.randomUUID(); // any UUID is fine — the server validates UUID shape only
  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);
  const sendKey = hekate.sendGenerateKey();

  let dataWire, protectedSendKey, nameWire;
  try {
    dataWire = hekate.sendEncryptText(sendKey, sendId, enc.encode(body));
    protectedSendKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      sendKey,
      hekate.sendKeyWrapAad(sendId),
    );
    nameWire = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      enc.encode(name),
      hekate.sendNameAad(sendId),
    );
  } catch (err) {
    toast("Encrypt failed: " + err.message, 3000);
    return;
  }

  const requestBody = {
    id: sendId,
    send_type: 1,
    name: nameWire,
    protected_send_key: protectedSendKey,
    data: dataWire,
    deletion_date: deletionDate,
    disabled: false,
  };
  if (password) requestBody.password = password;
  if (Number.isFinite(maxAccess) && maxAccess > 0) {
    requestBody.max_access_count = maxAccess;
  }

  try {
    await apiPost("/api/v1/sends", requestBody);
  } catch (err) {
    toast("Server rejected: " + err.message, 4000);
    return;
  }

  const url = `${session.server_url.replace(/\/$/, "")}/send/#/${sendId}/${hekate.sendEncodeKey(sendKey)}`;
  const content = `
    <p>The recipient URL is below. <strong>Anyone with this URL can read the
       share</strong> until it expires, hits its access limit, or you disable
       / delete it. The fragment (after the <code>#</code>) is the
       decryption key — your browser does not transmit it to the server.</p>
    <textarea id="shareUrl" rows="3" readonly>${escapeHtml(url)}</textarea>
    <div style="display:flex; gap:8px;">
      <button id="copy">Copy URL</button>
      <button class="secondary" id="done">Done</button>
    </div>`;
  app.innerHTML = subShellHtml({ title: "Share created", content });
  wireSubShell({ onBack: () => renderSendsList() });
  document.getElementById("done").addEventListener("click", () => renderSendsList());
  document.getElementById("copy").addEventListener("click", () =>
    copyWithAutoClear(url, "share URL"),
  );
}

function parseTtlMs(s) {
  const m = /^(\d+)([smhd])$/.exec(String(s).trim());
  if (!m) return 7 * 86400 * 1000;
  const n = parseInt(m[1], 10);
  const mul = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2]];
  return n * mul;
}

// ---- M3.13: file Sends ---------------------------------------------------

function renderNewFileSend() {
  const content = `
    <form id="newFileSendForm">
      <label><span>File</span>
        <input name="file" type="file" required>
      </label>
      <label><span>Display name (sender-side; recipients won't see this)</span>
        <input name="name" placeholder="Defaults to the file's basename">
      </label>
      <label><span>Access password (optional gate)</span>
        <input name="password" type="password" autocomplete="new-password">
      </label>
      <label><span>Max accesses (blank = unlimited)</span>
        <input name="maxAccess" type="number" min="1" placeholder="e.g. 3">
      </label>
      <label><span>TTL — auto-delete after</span>
        <select name="ttl">
          <option value="1h">1 hour</option>
          <option value="1d">1 day</option>
          <option value="7d" selected>7 days</option>
          <option value="30d">30 days</option>
        </select>
      </label>
      <p class="muted small">
        File body is encrypted client-side with a fresh per-file
        AEAD key (separate from the URL-fragment send_key). Server
        gets opaque ciphertext + a tus upload; recipients fetch via
        a 5-minute download token granted by /access.
      </p>
      <button type="submit" class="primary-block">Create + copy share URL</button>
    </form>`;
  app.innerHTML = subShellHtml({ title: "New file share", content });
  wireSubShell({ onBack: () => renderSendsList() });
  document.getElementById("newFileSendForm").addEventListener("submit", onCreateFileSend);
}

async function onCreateFileSend(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const file = fd.get("file");
  if (!file || !file.name) {
    toast("Pick a file first.");
    return;
  }
  if (file.size === 0) {
    toast("Empty files can't be uploaded.");
    return;
  }
  const name = (fd.get("name") || "").toString().trim() || file.name;
  const password = (fd.get("password") || "").toString();
  const maxAccess = parseInt((fd.get("maxAccess") || "").toString(), 10);
  const ttl = (fd.get("ttl") || "7d").toString();

  const ttlMs = parseTtlMs(ttl);
  const deletionDate = new Date(Date.now() + ttlMs).toISOString();

  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);

  // Read the file fully into memory. Single-shot upload like
  // attachments — chunked PATCH stays in the CLI for very large
  // files.
  let plaintext;
  try {
    plaintext = new Uint8Array(await file.arrayBuffer());
  } catch (err) {
    toast("Couldn't read file: " + err.message, 4000);
    return;
  }

  const sendId = crypto.randomUUID();
  const sendKey = hekate.sendGenerateKey();

  // Per-file AEAD key (separate from send_key). The recipient
  // extracts this from the encrypted metadata after decoding the
  // URL fragment.
  const fileAeadKey = hekate.randomKey32();

  let ciphertext;
  try {
    ciphertext = hekate.attachmentEncrypt(fileAeadKey, sendId, plaintext);
  } catch (err) {
    toast("Encrypt failed: " + err.message, 4000);
    return;
  }
  const hashB64 = hekate.blake3HashB64(ciphertext);

  // Encrypted metadata payload — JSON with filename + size_pt +
  // file_aead_key_b64, encrypted under content_key (HKDF of
  // send_key + send_id). The recipient HKDFs the URL-fragment
  // send_key and decrypts to extract `file_aead_key`.
  const metadataJson = JSON.stringify({
    filename: file.name,
    size_pt: plaintext.length,
    // Standard base64-no-pad to match the CLI's output (and what
    // `hekate send open` will decode on the recipient side).
    file_aead_key_b64: b64encode(fileAeadKey),
  });
  let dataWire, protectedSendKey, nameWire;
  try {
    dataWire = hekate.sendEncryptText(sendKey, sendId, enc.encode(metadataJson));
    protectedSendKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      sendKey,
      hekate.sendKeyWrapAad(sendId),
    );
    nameWire = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      enc.encode(name),
      hekate.sendNameAad(sendId),
    );
  } catch (err) {
    toast("Wrap failed: " + err.message, 4000);
    return;
  }

  const requestBody = {
    id: sendId,
    send_type: 2,
    name: nameWire,
    protected_send_key: protectedSendKey,
    data: dataWire,
    deletion_date: deletionDate,
    disabled: false,
  };
  if (password) requestBody.password = password;
  if (Number.isFinite(maxAccess) && maxAccess > 0) {
    requestBody.max_access_count = maxAccess;
  }

  toast(`Creating share + uploading ${file.name}…`, 1500);
  try {
    await apiPost("/api/v1/sends", requestBody);
  } catch (err) {
    toast("Server rejected create: " + err.message, 4000);
    return;
  }

  // Body upload via tus single-shot. Server enforces the BLAKE3
  // hash + size_pt match on finalize.
  const meta = buildTusMetadata([
    ["content_hash_b3", hashB64],
    ["size_pt", String(plaintext.length)],
  ]);
  const r = await authedFetch(
    "POST",
    `/api/v1/sends/${encodeURIComponent(sendId)}/upload`,
    ciphertext,
    {
      "tus-resumable": "1.0.0",
      "upload-length": String(ciphertext.length),
      "upload-metadata": meta,
      "content-type": "application/offset+octet-stream",
    },
  );
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    // Body upload failed but the row exists — best-effort cleanup
    // so the user doesn't see a permanently broken Send.
    apiDelete(`/api/v1/sends/${encodeURIComponent(sendId)}`).catch(() => {});
    toast(`Server: ${r.status} ${body}`, 5000);
    return;
  }

  const url = `${session.server_url.replace(/\/$/, "")}/send/#/${sendId}/${hekate.sendEncodeKey(sendKey)}`;
  const content = `
    <p>The recipient URL is below. <strong>Anyone with this URL can
       download the file</strong> until it expires, hits its access
       limit, or you disable / delete it. The fragment (after the
       <code>#</code>) is the decryption key — your browser does not
       transmit it to the server.</p>
    <textarea id="shareUrl" rows="3" readonly>${escapeHtml(url)}</textarea>
    <div style="display:flex; gap:8px;">
      <button id="copy">Copy URL</button>
      <button class="secondary" id="done">Done</button>
    </div>`;
  app.innerHTML = subShellHtml({ title: "File share created", content });
  wireSubShell({ onBack: () => renderSendsList() });
  document.getElementById("done").addEventListener("click", () => renderSendsList());
  document.getElementById("copy").addEventListener("click", () =>
    copyWithAutoClear(url, "share URL"),
  );
}

function renderOpenSend() {
  const content = `
    <form id="openSendForm">
      <label><span>Share URL</span>
        <input name="url" required placeholder="https://hekate.example/send/#/...">
      </label>
      <label><span>Access password (if the sender set one)</span>
        <input name="password" type="password" autocomplete="off">
      </label>
      <button type="submit" class="primary-block">Fetch + decrypt</button>
    </form>
    <pre id="openSendOut" class="muted" hidden></pre>`;
  app.innerHTML = subShellHtml({ title: "Open shared link", content });
  wireSubShell({ onBack: () => renderSendsList() });
  document.getElementById("openSendForm").addEventListener("submit", onOpenSend);
}

async function onOpenSend(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const rawUrl = (fd.get("url") || "").toString().trim();
  const password = (fd.get("password") || "").toString();
  let parsed;
  try {
    parsed = parseShareUrl(rawUrl);
  } catch (err) {
    toast("Bad URL: " + err.message, 3000);
    return;
  }
  // Public-access endpoint: no auth, no Authorization header.
  let resp;
  try {
    resp = await postJSON(
      `${parsed.serverBase}/api/v1/public/sends/${encodeURIComponent(parsed.sendId)}/access`,
      password ? { password } : {},
    );
  } catch (err) {
    toast("Server: " + err.message, 4000);
    return;
  }
  let sendKey;
  try {
    sendKey = hekate.sendDecodeKey(parsed.sendKeyB64);
  } catch (err) {
    toast("Bad URL fragment: " + err.message, 4000);
    return;
  }

  if (resp.send_type === 1) {
    let plaintext;
    try {
      const ptBytes = hekate.sendDecryptText(sendKey, parsed.sendId, resp.data);
      plaintext = dec.decode(ptBytes);
    } catch (err) {
      toast("Decrypt failed: " + err.message, 4000);
      return;
    }
    const out = document.getElementById("openSendOut");
    out.hidden = false;
    out.textContent = plaintext;
    return;
  }

  if (resp.send_type === 2) {
    // File Send: decrypt the metadata blob, fetch the body via the
    // download token, BLAKE3-verify, decrypt with file_aead_key,
    // trigger browser save.
    if (!resp.download_token) {
      toast("Server didn't return a download_token (body still uploading?).", 4000);
      return;
    }
    let metaBytes;
    try {
      metaBytes = hekate.sendDecryptText(sendKey, parsed.sendId, resp.data);
    } catch (err) {
      toast("Decrypt metadata failed: " + err.message, 4000);
      return;
    }
    let meta;
    try {
      meta = JSON.parse(dec.decode(metaBytes));
    } catch (err) {
      toast("Share metadata is not JSON: " + err.message, 4000);
      return;
    }
    if (!meta.file_aead_key_b64 || !meta.filename) {
      toast("Share metadata is missing fields.", 4000);
      return;
    }
    const fileAeadKey = b64decode(meta.file_aead_key_b64);
    const blobUrl = `${parsed.serverBase}/api/v1/public/sends/${encodeURIComponent(
      parsed.sendId,
    )}/blob/${encodeURIComponent(resp.download_token)}`;
    let blobResp;
    try {
      blobResp = await fetch(blobUrl);
    } catch (err) {
      toast("Network error: " + err.message, 4000);
      return;
    }
    if (!blobResp.ok) {
      toast(`Server: ${blobResp.status} ${blobResp.statusText}`, 4000);
      return;
    }
    const ciphertext = new Uint8Array(await blobResp.arrayBuffer());
    if (Number.isFinite(resp.size_ct) && ciphertext.length !== resp.size_ct) {
      toast(
        `Downloaded ${ciphertext.length} bytes; server claimed ${resp.size_ct}.`,
        5000,
      );
      return;
    }
    let plaintextBytes;
    try {
      plaintextBytes = hekate.attachmentDecrypt(fileAeadKey, parsed.sendId, ciphertext);
    } catch (err) {
      toast("Decrypt body failed: " + err.message, 5000);
      return;
    }
    if (Number.isFinite(meta.size_pt) && plaintextBytes.length !== meta.size_pt) {
      console.warn(
        `plaintext is ${plaintextBytes.length} bytes; metadata claimed ${meta.size_pt}`,
      );
    }
    // Trigger the browser's save dialog.
    const blob = new Blob([plaintextBytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = meta.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60_000);

    const out = document.getElementById("openSendOut");
    out.hidden = false;
    out.textContent = `Downloaded ${meta.filename} (${plaintextBytes.length} bytes).`;
    return;
  }

  toast(`Unknown send_type ${resp.send_type}.`, 4000);
}

function parseShareUrl(url) {
  const hashIdx = url.indexOf("#");
  if (hashIdx < 0) throw new Error("URL is missing the #fragment with the recipient key");
  const before = url.slice(0, hashIdx);
  const frag = url.slice(hashIdx + 1).replace(/^\//, "");
  const slash = frag.indexOf("/");
  if (slash < 0) throw new Error("fragment must be #/<send_id>/<send_key>");
  const sendId = frag.slice(0, slash);
  const sendKeyB64 = frag.slice(slash + 1);
  if (!sendId || !sendKeyB64) {
    throw new Error("fragment must be #/<send_id>/<send_key>");
  }
  // Strip trailing /send/ if present so we end up with a clean base.
  const serverBase = before.replace(/\/?send\/?$/, "").replace(/\/$/, "");
  if (!/^https?:\/\//.test(serverBase)) {
    throw new Error("URL must include the server scheme + host");
  }
  return { serverBase, sendId, sendKeyB64 };
}

// ===========================================================================
// M3.12 — Attachments UI (file picker → tus upload → list / download / delete)
// ===========================================================================
//
// Renders inside the cipher edit view (`renderAddEdit` for personal
// ciphers). All crypto runs client-side via WASM:
//
// - att_key (32 random bytes)  → wrapped under cipher_key as
//   `content_key` EncString with AAD `<att_id>|key|<cipher_id>`
// - body                       → PMGRA1 chunked-AEAD with att_key
//                                (1 MiB plaintext chunks, AAD bound
//                                to attachment_id + chunk_index)
// - filename                   → EncString under cipher_key with AAD
//                                `pmgr-attachment-filename-v1:<att_id>:<cipher_id>`
// - BLAKE3 of ciphertext       → server's tus-finalize integrity check
//
// The popup uses single-shot upload (entire ciphertext in the
// creation-with-upload POST body); resumable PATCH chunking would
// only matter for very large files / flaky networks, where the CLI
// already has the cleaner UX.

async function renderAttachmentsSection(cipherId) {
  const container = document.getElementById("attachmentsSection");
  if (!container) return;
  container.innerHTML = `
    <hr>
    <div id="attachmentsHeader" class="row">
      <h3 style="margin:0">Attachments</h3>
      <input id="attachmentFile" type="file" style="display:none">
      <button class="secondary" id="attachmentUpload">+ Add file</button>
    </div>
    <div id="attachmentsList" class="muted small">Loading…</div>
  `;
  document.getElementById("attachmentUpload").addEventListener("click", () => {
    document.getElementById("attachmentFile").click();
  });
  document.getElementById("attachmentFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    onUploadAttachment(file, cipherId).catch((err) => {
      toast("Upload failed: " + err.message, 4000);
    });
  });
  await refreshAttachmentsList(cipherId);
}

async function refreshAttachmentsList(cipherId) {
  const listEl = document.getElementById("attachmentsList");
  if (!listEl) return;
  let sync;
  try {
    sync = await apiGet("/api/v1/sync");
  } catch (err) {
    listEl.textContent = "Error: " + err.message;
    return;
  }
  const mine = (sync.changes.attachments || []).filter((a) => a.cipher_id === cipherId);
  if (mine.length === 0) {
    listEl.innerHTML = `<p class="muted">No attachments yet.</p>`;
    return;
  }

  // Need the cipher's per-cipher key to decrypt filenames.
  const cipher = sync.changes.ciphers.find((c) => c.id === cipherId);
  if (!cipher) {
    listEl.textContent = "Cipher not found in sync (refresh and try again)";
    return;
  }
  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);
  let cipherKey;
  try {
    cipherKey = hekate.encStringDecryptXc20p(
      cipher.protected_cipher_key,
      accountKey,
      enc.encode(`pmgr-cipher-key-v2:${cipherId}`),
    );
  } catch (_) {
    listEl.textContent =
      "Couldn't unwrap the cipher key — attachments are unreadable on this device.";
    return;
  }

  listEl.innerHTML = mine
    .map((a) => {
      let filename = "<undecryptable>";
      try {
        const aad = enc.encode(`pmgr-attachment-filename-v1:${a.id}:${cipherId}`);
        filename = dec.decode(hekate.encStringDecryptXc20p(a.filename, cipherKey, aad));
      } catch (_) {
        /* keep placeholder */
      }
      const size = humanBytes(a.size_pt);
      return `
        <div class="row attachment-row" data-id="${escapeAttr(a.id)}">
          <div class="row-main">
            <div class="row-name">${escapeHtml(filename)}</div>
            <div class="muted small">${escapeHtml(size)} · ${escapeHtml(a.revision_date)}</div>
          </div>
          <div class="row-actions">
            <button class="secondary" data-act="download">Download</button>
            <button class="secondary danger" data-act="delete">Delete</button>
          </div>
        </div>`;
    })
    .join("");

  listEl.querySelectorAll(".attachment-row").forEach((row) => {
    const id = row.dataset.id;
    row.querySelector('button[data-act="download"]').addEventListener("click", () => {
      onDownloadAttachment(id, cipherId, cipherKey).catch((err) =>
        toast("Download failed: " + err.message, 4000),
      );
    });
    row.querySelector('button[data-act="delete"]').addEventListener("click", () => {
      onDeleteAttachment(id, cipherId).catch((err) =>
        toast("Delete failed: " + err.message, 4000),
      );
    });
  });
}

async function onUploadAttachment(file, cipherId) {
  if (file.size === 0) {
    toast("Empty files can't be uploaded.");
    return;
  }
  // Read the whole file. For the M2.24 100 MiB cap this is fine on the
  // popup side; very large files should go through the CLI's
  // chunked-PATCH path.
  const plaintext = new Uint8Array(await file.arrayBuffer());

  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);
  const cipher = await apiGet(`/api/v1/ciphers/${encodeURIComponent(cipherId)}`);

  let cipherKey;
  try {
    cipherKey = hekate.encStringDecryptXc20p(
      cipher.protected_cipher_key,
      accountKey,
      enc.encode(`pmgr-cipher-key-v2:${cipherId}`),
    );
  } catch (err) {
    throw new Error("could not unwrap cipher key: " + err.message);
  }

  const attId = crypto.randomUUID();
  const attKey = hekate.randomKey32();

  // Encrypt the body with the per-attachment AEAD key. The result
  // includes the PMGRA1 header + per-chunk Poly1305 tags.
  const ciphertext = hekate.attachmentEncrypt(attKey, attId, plaintext);
  const hashB64 = hekate.blake3HashB64(ciphertext);

  // Wrap the att_key under the cipher key with location-bound AAD.
  const wrapAad = hekate.attachmentKeyWrapAad(attId, cipherId);
  const contentKeyWire = hekate.encStringEncryptXc20p("ak:1", cipherKey, attKey, wrapAad);

  // Encrypt the filename under the cipher key (NOT the att_key) so
  // the owner's list view can decrypt it without unwrapping each
  // attachment's key.
  const filenameAad = enc.encode(`pmgr-attachment-filename-v1:${attId}:${cipherId}`);
  const filenameWire = hekate.encStringEncryptXc20p(
    "ak:1",
    cipherKey,
    enc.encode(file.name),
    filenameAad,
  );

  const meta = buildTusMetadata([
    ["attachment_id", attId],
    ["cipher_id", cipherId],
    ["filename", filenameWire],
    ["content_key", contentKeyWire],
    ["content_hash_b3", hashB64],
    ["size_pt", String(plaintext.length)],
  ]);

  toast(`Uploading ${file.name}…`, 1200);
  const r = await authedFetch("POST", "/api/v1/attachments", ciphertext, {
    "tus-resumable": "1.0.0",
    "upload-length": String(ciphertext.length),
    "upload-metadata": meta,
    "content-type": "application/offset+octet-stream",
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`server: ${r.status} ${body}`);
  }
  toast(`Uploaded ${file.name}.`);
  // Re-sign the BW04 manifest so the new attachment is bound into
  // the per-cipher attachments_root. Don't block the UI on it.
  syncAndUploadManifest(session).catch((e) =>
    console.warn("manifest re-sign after attachment upload failed:", e),
  );
  await refreshAttachmentsList(cipherId);
}

async function onDownloadAttachment(attId, cipherId, cipherKey) {
  const session = await loadSession();

  const view = await apiGet(`/api/v1/attachments/${encodeURIComponent(attId)}`);

  // Unwrap the per-attachment key.
  const wrapAad = hekate.attachmentKeyWrapAad(attId, cipherId);
  let attKey;
  try {
    attKey = hekate.encStringDecryptXc20p(view.content_key, cipherKey, wrapAad);
  } catch (err) {
    throw new Error("could not unwrap attachment key: " + err.message);
  }

  // Pull the body bytes.
  const r = await authedFetch("GET", `/api/v1/attachments/${encodeURIComponent(attId)}/blob`);
  if (!r.ok) {
    throw new Error(`server: ${r.status} ${r.statusText}`);
  }
  const ciphertext = new Uint8Array(await r.arrayBuffer());

  // Verify integrity against the server-reported BLAKE3 hash before decrypting.
  const observed = hekate.blake3HashB64(ciphertext);
  if (observed !== view.content_hash_b3) {
    throw new Error("BLAKE3 mismatch — body may have been tampered in transit");
  }

  const plaintext = hekate.attachmentDecrypt(attKey, attId, ciphertext);

  // Decrypt the filename for the download prompt.
  let filename = `attachment-${attId.slice(0, 8)}.bin`;
  try {
    const aad = enc.encode(`pmgr-attachment-filename-v1:${attId}:${cipherId}`);
    filename = dec.decode(hekate.encStringDecryptXc20p(view.filename, cipherKey, aad));
  } catch (_) {
    /* fall back to the synthesized name */
  }

  // Trigger the browser's Save dialog via an object URL.
  const blob = new Blob([plaintext], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke after a tick so the browser has time to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  void session;
}

async function onDeleteAttachment(attId, cipherId) {
  if (!window.confirm("Permanently delete this attachment?")) return;
  await apiDelete(`/api/v1/attachments/${encodeURIComponent(attId)}`);
  toast("Attachment deleted.");
  const session = await loadSession();
  syncAndUploadManifest(session).catch((e) =>
    console.warn("manifest re-sign after attachment delete failed:", e),
  );
  await refreshAttachmentsList(cipherId);
}

/// Build the canonical tus `Upload-Metadata` header value:
/// comma-separated `key value` pairs where each value is base64-encoded.
function buildTusMetadata(pairs) {
  return pairs
    .map(([k, v]) => {
      const bytes = enc.encode(v);
      const b64 = btoa(String.fromCharCode(...bytes));
      return `${k} ${b64}`;
    })
    .join(", ");
}

function humanBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

// ---- helpers shared by the 2FA panel -----------------------------------

// Re-auth prompt for sensitive 2FA-setup flows. Chromium's native
// `window.prompt()` can't mask input, so we render a custom overlay
// with a real `<input type="password">`. Resolves to the typed
// string on submit, or `null` on Cancel / Escape — same contract as
// the previous `prompt()`-based helper, so callers stay unchanged.
function promptMasterPassword(reason) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.innerHTML = `
      <div class="modal-card">
        <h3>Re-enter master password</h3>
        <p>${escapeHtml(reason || "Required to confirm a sensitive change to your account.")}</p>
        <input type="password" autocomplete="current-password" id="mpwInput">
        <div class="modal-buttons">
          <button type="button" class="secondary" id="mpwCancel">Cancel</button>
          <button type="button" class="primary" id="mpwOk">OK</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const input = overlay.querySelector("#mpwInput");
    const okBtn = overlay.querySelector("#mpwOk");
    const cancelBtn = overlay.querySelector("#mpwCancel");
    let resolved = false;

    const finish = (value) => {
      if (resolved) return;
      resolved = true;
      // Stomp the input value before tearing down so the password
      // doesn't linger in detached DOM.
      input.value = "";
      overlay.remove();
      resolve(value);
    };

    okBtn.addEventListener("click", () => finish(input.value));
    cancelBtn.addEventListener("click", () => finish(null));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(null); // backdrop click cancels
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        finish(input.value);
      } else if (e.key === "Escape") {
        e.preventDefault();
        finish(null);
      }
    });
    // setTimeout so the modal is in the DOM before focus.
    setTimeout(() => input.focus(), 0);
  });
}

async function deriveMphB64(password) {
  const session = await loadSession();
  const pre = await postJSON(`${session.server_url}/api/v1/accounts/prelogin`, {
    email: session.email,
  });
  if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
    throw new Error("server returned KDF parameters below the safe floor.");
  }
  const salt = b64decode(pre.kdf_salt);
  const mk = hekate.deriveMasterKey(enc.encode(password), pre.kdf_params, salt);
  if (pre.kdf_params_mac) {
    const serverMac = b64decode(pre.kdf_params_mac);
    if (!hekate.verifyKdfBindMac(mk, pre.kdf_params, salt, serverMac)) {
      throw new Error("KDF bind MAC mismatch — wrong password or server tamper.");
    }
  }
  return b64encode(hekate.deriveMasterPasswordHash(mk));
}

// ===========================================================================
// Add: type picker, then form
// ===========================================================================

function renderTypePicker() {
  clearTickers();
  const content = `
    <div id="picker" class="type-picker">
      ${ADD_PICKER_ORDER.map((id) => {
        const cfg = CIPHER_TYPES[id];
        return `<button class="picker-btn" data-type="${id}">
                  <span class="picker-icon" data-type="${id}">${typeIcon(id)}</span>
                  <span class="picker-label">${escapeHtml(cfg.addLabel)}</span>
                </button>`;
      }).join("")}
    </div>`;
  app.innerHTML = subShellHtml({ title: "New item", content });
  wireSubShell({ onBack: () => renderVault() });
  document.querySelectorAll(".picker-btn").forEach((btn) =>
    btn.addEventListener("click", () => {
      const t = parseInt(btn.dataset.type, 10);
      renderAddEdit(null, t);
    }),
  );
}

// SVG glyph for each cipher type — same set the row-icon avatars use.
function typeIcon(t) {
  return icon(iconForCipherType(t));
}

// ===========================================================================
// Add / Edit form
// ===========================================================================

async function renderAddEdit(idOrNull, typeForCreate) {
  clearTickers();
  const isEdit = !!idOrNull;
  let cipherType = typeForCreate || 1;
  let initialData = {};
  let initialName = "";
  let initialNotes = "";
  let revision = null;

  if (isEdit) {
    try {
      const c = await apiGet(`/api/v1/ciphers/${encodeURIComponent(idOrNull)}`);
      const s = await loadSession();
      const accountKey = b64urlDecode(s.account_key_b64);
      const decoded = decryptFull(c, accountKey);
      cipherType = c.type;
      initialName = decoded.name;
      initialData = decoded.data || {};
      initialNotes = decoded.notes || "";
      revision = c.revision_date;
    } catch (err) {
      toast("Couldn't load item: " + err.message, 2500);
      return renderVault();
    }
  }

  const cfg = CIPHER_TYPES[cipherType];
  if (!cfg) {
    toast(`Unsupported cipher type ${cipherType}.`, 2500);
    return renderVault();
  }

  const fieldsHtml = cfg.fields.map((f) => fieldHtml(f, initialData[f.name])).join("");
  const notesHtml = `
    <label><span>Notes</span>
      <textarea name="__notes" rows="${cipherType === 2 ? 8 : 3}">${escapeHtml(initialNotes)}</textarea>
    </label>`;

  const title = isEdit ? `Edit ${cfg.label.toLowerCase()}` : `New ${cfg.label.toLowerCase()}`;
  const content = `
    <form id="cipherForm">
      <label><span>Name</span>
        <input name="__name" type="text" required autofocus
               value="${escapeAttr(initialName)}">
      </label>
      ${fieldsHtml}
      ${notesHtml}
      <button type="submit" class="primary-block">${isEdit ? "Save" : "Create"}</button>
      <p class="error" id="err"></p>
    </form>
    ${isEdit ? `<div id="attachmentsSection"></div>` : ""}`;
  app.innerHTML = subShellHtml({ title, content });
  wireSubShell({ onBack: () => renderVault() });
  // Wire reveal + generator buttons
  document.querySelectorAll("button.reveal-btn").forEach((btn) =>
    btn.addEventListener("click", () => {
      const target = document.querySelector(`[name="${CSS.escape(btn.dataset.target)}"]`);
      if (!target) return;
      if (target.tagName === "TEXTAREA") {
        target.classList.toggle("masked");
      } else {
        target.type = target.type === "password" ? "text" : "password";
      }
    }),
  );
  document.querySelectorAll("button.generate-btn").forEach((btn) =>
    btn.addEventListener("click", () => {
      const target = document.querySelector(`[name="${CSS.escape(btn.dataset.target)}"]`);
      if (!target) return;
      target.value = generatePassword(20);
      target.type = "text";
    }),
  );

  document
    .getElementById("cipherForm")
    .addEventListener("submit", (e) => onSaveCipher(e, idOrNull, cipherType, revision));

  // M2.24 — attachments. Personal ciphers only on the popup side
  // today (mirrors the CLI's `hekate attach upload` capability surface).
  if (isEdit) {
    renderAttachmentsSection(idOrNull).catch((err) =>
      console.error("attachments render failed", err),
    );
  }
}

function fieldHtml(f, value) {
  const v = value == null ? "" : String(value);
  const placeholder = f.placeholder ? `placeholder="${escapeAttr(f.placeholder)}"` : "";
  const maxlength = f.maxlength ? `maxlength="${f.maxlength}"` : "";
  const autocomplete = f.autocomplete ? `autocomplete="${escapeAttr(f.autocomplete)}"` : "autocomplete=\"off\"";
  if (f.type === "textarea") {
    const rows = f.rows || 3;
    const masked = f.reveal ? "masked" : "";
    return `
      <label><span>${escapeHtml(f.label)}</span>
        ${
          f.reveal
            ? `<div class="row-input">
                 <textarea name="${escapeAttr(f.name)}" rows="${rows}" ${placeholder} class="${masked}">${escapeHtml(v)}</textarea>
                 <button type="button" class="secondary reveal-btn" data-target="${escapeAttr(f.name)}" title="Show / hide">👁</button>
               </div>`
            : `<textarea name="${escapeAttr(f.name)}" rows="${rows}" ${placeholder}>${escapeHtml(v)}</textarea>`
        }
      </label>`;
  }
  const inputType = f.type === "password" ? "password" : f.type;
  const needsRow = f.reveal || f.generator;
  const inputHtml = `<input name="${escapeAttr(f.name)}" type="${inputType}" value="${escapeAttr(v)}" ${placeholder} ${maxlength} ${autocomplete}>`;
  if (!needsRow) {
    return `<label><span>${escapeHtml(f.label)}</span>${inputHtml}</label>`;
  }
  const reveal = f.reveal
    ? `<button type="button" class="secondary reveal-btn" data-target="${escapeAttr(f.name)}" title="Show / hide">👁</button>`
    : "";
  const generator = f.generator
    ? `<button type="button" class="secondary generate-btn" data-target="${escapeAttr(f.name)}" title="Generate">⚄</button>`
    : "";
  return `
    <label><span>${escapeHtml(f.label)}</span>
      <div class="row-input">${inputHtml}${reveal}${generator}</div>
    </label>`;
}

async function onSaveCipher(e, idOrNull, cipherType, revision) {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  const name = (fd.get("__name") || "").trim();
  if (!name) {
    document.getElementById("err").textContent = "Name is required.";
    return;
  }
  const cfg = CIPHER_TYPES[cipherType];
  const data = {};
  for (const f of cfg.fields) {
    const v = nullIfBlank(fd.get(f.name));
    if (v !== null) data[f.name] = v;
  }
  const notes = nullIfBlank(fd.get("__notes"));
  // Secure notes require a body
  if (cipherType === 2 && !notes) {
    document.getElementById("err").textContent = "Note body is required.";
    return;
  }

  const submit = form.querySelector("button[type=submit]");
  submit.disabled = true;
  submit.textContent = "Saving…";

  try {
    const s = await loadSession();
    const accountKey = b64urlDecode(s.account_key_b64);

    let cipherKey, protected_cipher_key, cipherId;
    if (idOrNull) {
      const c = await apiGet(`/api/v1/ciphers/${encodeURIComponent(idOrNull)}`);
      revision = c.revision_date;
      protected_cipher_key = c.protected_cipher_key;
      cipherId = c.id;
      cipherKey = hekate.encStringDecryptXc20p(
        c.protected_cipher_key,
        accountKey,
        aadProtectedCipherKey(cipherId),
      );
    } else {
      // BW04/LP06 mitigation: client picks the id BEFORE encrypting any
      // field so every ciphertext can commit to it via AAD.
      cipherId = newCipherId();
      cipherKey = hekate.randomKey32();
      protected_cipher_key = hekate.encStringEncryptXc20p(
        "ak:1",
        accountKey,
        cipherKey,
        aadProtectedCipherKey(cipherId),
      );
    }

    const dataJson = JSON.stringify(data);
    const body = {
      id: cipherId,
      type: cipherType,
      folder_id: null,
      protected_cipher_key,
      name: hekate.encStringEncryptXc20p(
        "ck:1",
        cipherKey,
        enc.encode(name),
        aadCipherName(cipherId, cipherType),
      ),
      notes: notes
        ? hekate.encStringEncryptXc20p(
            "ck:1",
            cipherKey,
            enc.encode(notes),
            aadCipherNotes(cipherId, cipherType),
          )
        : null,
      data: hekate.encStringEncryptXc20p(
        "ck:1",
        cipherKey,
        enc.encode(dataJson),
        aadCipherData(cipherId, cipherType),
      ),
      favorite: false,
    };

    if (idOrNull) {
      await apiPut(`/api/v1/ciphers/${encodeURIComponent(idOrNull)}`, body, revision);
      toast("Saved.");
    } else {
      await apiPost("/api/v1/ciphers", body);
      toast("Created.");
    }
    await uploadManifestQuiet();
    await renderVault();
  } catch (err) {
    submit.disabled = false;
    submit.textContent = idOrNull ? "Save" : "Create";
    document.getElementById("err").textContent = err.message;
  }
}

function nullIfBlank(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s === "" ? null : s;
}

// ===========================================================================
// Cipher decoding (for list + detail)
// ===========================================================================

function decryptForList(c, accountKey) {
  let name = "<undecryptable>";
  let data = null;
  try {
    const cipherKey = hekate.encStringDecryptXc20p(
      c.protected_cipher_key,
      accountKey,
      aadProtectedCipherKey(c.id),
    );
    name = dec.decode(
      hekate.encStringDecryptXc20p(c.name, cipherKey, aadCipherName(c.id, c.type)),
    );
    if (c.data) {
      const dataJson = dec.decode(
        hekate.encStringDecryptXc20p(c.data, cipherKey, aadCipherData(c.id, c.type)),
      );
      data = JSON.parse(dataJson || "{}");
    }
  } catch (_) {
    /* leave name as <undecryptable> — typically means server returned a
       row with the wrong id/type or the user has stale pre-v2 ciphers */
  }
  return { id: c.id, type: c.type, name, data };
}

function decryptFull(c, accountKey) {
  const result = decryptForList(c, accountKey);
  let notes = "";
  try {
    if (c.notes) {
      const cipherKey = hekate.encStringDecryptXc20p(
        c.protected_cipher_key,
        accountKey,
        aadProtectedCipherKey(c.id),
      );
      notes = dec.decode(
        hekate.encStringDecryptXc20p(c.notes, cipherKey, aadCipherNotes(c.id, c.type)),
      );
    }
  } catch (_) {
    /* ignore */
  }
  return { ...result, notes };
}

// ===========================================================================
// TOTP
// ===========================================================================

const _tickers = [];
let _sseAbort = null;

function clearTickers() {
  while (_tickers.length) clearInterval(_tickers.pop());
  if (_sseAbort) {
    _sseAbort.abort();
    _sseAbort = null;
  }
}

function startTickers(rowsContainer, ciphers) {
  const totps = ciphers.filter((c) => c.type === 6 && c.data && c.data.secret);
  if (totps.length === 0) return;
  const refresh = async () => {
    for (const c of totps) {
      const cell = rowsContainer.querySelector(`[data-totp-display="${cssEscape(c.id)}"]`);
      if (!cell) continue;
      try {
        const { code, remaining } = await totpCode(c.data.secret);
        const issuer = c.data.issuer || "";
        const acct = c.data.accountName || "";
        const prefix = [issuer, acct].filter(Boolean).join(" / ");
        cell.textContent = `${prefix ? prefix + "  " : ""}${code}  (${remaining}s)`;
      } catch (_) {
        cell.textContent = "(invalid TOTP secret)";
      }
    }
  };
  refresh();
  _tickers.push(setInterval(refresh, 1000));
}

async function fetchTotpCode(cipherId) {
  const c = await apiGet(`/api/v1/ciphers/${encodeURIComponent(cipherId)}`);
  const s = await loadSession();
  const accountKey = b64urlDecode(s.account_key_b64);
  const decoded = decryptFull(c, accountKey);
  if (!(decoded.data && decoded.data.secret)) throw new Error("missing secret");
  const { code } = await totpCode(decoded.data.secret);
  return code;
}

async function totpCode(secretOrUrl) {
  let secret = secretOrUrl.trim();
  let period = 30;
  let digits = 6;
  let algo = "SHA-1";
  if (secret.startsWith("otpauth://")) {
    const url = new URL(secret);
    const params = url.searchParams;
    secret = params.get("secret") || "";
    if (params.get("period")) period = parseInt(params.get("period"), 10) || 30;
    if (params.get("digits")) digits = parseInt(params.get("digits"), 10) || 6;
    const a = (params.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
    if (a === "SHA1") algo = "SHA-1";
    else if (a === "SHA256") algo = "SHA-256";
    else if (a === "SHA512") algo = "SHA-512";
    else throw new Error(`unsupported algorithm: ${params.get("algorithm")}`);
  }
  if (!secret) throw new Error("no secret");
  const keyBytes = base32Decode(secret.replace(/\s+/g, "").toUpperCase());
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: algo },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));
  const offset = sig[sig.length - 1] & 0x0f;
  const truncated =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const code = (truncated % 10 ** digits).toString().padStart(digits, "0");
  return { code, remaining: period - (now % period), period };
}

function base32Decode(s) {
  const ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.replace(/=+$/, "").toUpperCase();
  const out = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    const v = ALPH.indexOf(c);
    if (v < 0) throw new Error(`bad base32 char: ${c}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ===========================================================================
// Password generator
// ===========================================================================

function generatePassword(length = 20) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.<>?/";
  const all = lower + upper + digits + symbols;
  const out = [pickChar(lower), pickChar(upper), pickChar(digits), pickChar(symbols)];
  while (out.length < length) out.push(pickChar(all));
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}
function pickChar(s) {
  return s[randomBelow(s.length)];
}
function randomBelow(n) {
  const buf = new Uint32Array(1);
  // Rejection sampling avoids the modulo bias that `% n` introduces.
  const limit = Math.floor(0x100000000 / n) * n;
  while (true) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

// ===========================================================================
// Autofill (M3.2)
// ===========================================================================

async function fillActiveTab(cipherId) {
  const c = await apiGet(`/api/v1/ciphers/${encodeURIComponent(cipherId)}`);
  const s = await loadSession();
  const accountKey = b64urlDecode(s.account_key_b64);
  const decoded = decryptFull(c, accountKey);
  const data = decoded.data || {};
  if (!(data.username || data.password)) {
    throw new Error("nothing to fill");
  }
  const tab = await getActiveTab();
  if (!tab) throw new Error("no active tab");
  // Audit C2 (2026-05-07) — verify the active tab actually matches
  // this cipher's URI before injecting credentials. Without this
  // check, a user who clicks "Fill" on a cipher while the active tab
  // is unrelated (or has been swapped under them) injects the
  // password into the wrong site. The "Matches for <host>" UI in the
  // vault list is informational only; this is the authoritative gate.
  const tabHost = safeHost(tab.url);
  if (!tabHost) {
    throw new Error("active tab is not a fillable URL");
  }
  if (!hostMatches(data.uri, tabHost)) {
    throw new Error(
      `active tab (${tabHost}) does not match this cipher's URI`,
    );
  }
  // Audit C2 — `allFrames: true` would also inject into every
  // sub-iframe (including third-party ad / embed frames living on
  // the matched site). Restrict to the top frame; the user-visible
  // login form is almost always there, and the rare exceptions are
  // not worth the password-into-third-party-iframe blast radius.
  await chrome.scripting.executeScript({
    target: { tabId: tab.id, frameIds: [0] },
    func: pageFill,
    args: [{ username: data.username || "", password: data.password || "" }],
  });
}

function pageFill({ username, password }) {
  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0")
      return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }
  function setValue(el, value) {
    const proto =
      el instanceof HTMLInputElement
        ? HTMLInputElement.prototype
        : HTMLTextAreaElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  const pwInputs = Array.from(document.querySelectorAll("input[type=password]")).filter(
    visible,
  );
  const pwInput = pwInputs[0] || null;
  let userInput = null;
  const userSelector =
    "input[type=email], input[type=text], input[type=tel], input:not([type])";
  if (pwInput) {
    const form = pwInput.form;
    const candidates = (
      form
        ? Array.from(form.querySelectorAll(userSelector))
        : Array.from(document.querySelectorAll(userSelector))
    ).filter(visible);
    const before = candidates.filter(
      (el) => el.compareDocumentPosition(pwInput) & Node.DOCUMENT_POSITION_FOLLOWING,
    );
    userInput = before[before.length - 1] || candidates[0] || null;
  } else {
    userInput =
      Array.from(document.querySelectorAll(userSelector)).filter(visible)[0] || null;
  }
  let filled = 0;
  if (userInput && username) {
    setValue(userInput, username);
    filled++;
  }
  if (pwInput && password) {
    setValue(pwInput, password);
    filled++;
  }
  return filled;
}

// ===========================================================================
// Helpers
// ===========================================================================

async function getActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  } catch (_) {
    return null;
  }
}

function safeHost(url) {
  try {
    const u = new URL(url);
    if (
      u.protocol === "chrome:" ||
      u.protocol === "edge:" ||
      u.protocol === "about:" ||
      u.protocol === "chrome-extension:" ||
      u.protocol === "moz-extension:" ||
      u.protocol === "view-source:" ||
      u.protocol === "file:"
    ) {
      return null;
    }
    return u.host.toLowerCase() || null;
  } catch (_) {
    return null;
  }
}

function hostMatches(uri, tabHost) {
  if (!uri || !tabHost) return false;
  const cipherHost = safeHost(uri);
  if (!cipherHost) return false;
  if (cipherHost === tabHost) return true;
  return tabHost.endsWith("." + cipherHost);
}

/// Heuristic match for a TOTP cipher against the active tab's host.
/// Match if any of the issuer / accountName fields contains the
/// registrable suffix of the host (or vice versa). Optimized for the
/// common case where users type the issuer as "GitHub" against
/// `github.com`. Conservative: when neither field has any text, we
/// don't match — we'd rather miss than show stale codes for unrelated
/// sites.
function totpMatches(data, tabHost) {
  if (!data || !tabHost) return false;
  const fields = [data.issuer, data.accountName].filter(Boolean).map((s) => String(s).toLowerCase());
  if (fields.length === 0) return false;
  // Strip everything but the second-level domain — `mail.github.com` → `github`.
  const parts = tabHost.split(".");
  const hostLabel = parts.length >= 2 ? parts[parts.length - 2] : tabHost;
  if (hostLabel.length < 3) return false; // too short to match meaningfully
  return fields.some((f) => f.includes(hostLabel) || hostLabel.includes(f));
}

function typeName(t) {
  return CIPHER_TYPES[t] ? CIPHER_TYPES[t].label.toLowerCase() : "item";
}

function toast(msg, ms = 1500) {
  const existing = document.querySelector(".toast");
  if (existing) existing.remove();
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
function escapeAttr(s) {
  return escapeHtml(s).replace(/"/g, "&quot;");
}
function cssEscape(s) {
  return CSS && CSS.escape ? CSS.escape(s) : String(s).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}

// ===========================================================================
// M3.15 — Rotate account_key (mirrors `hekate account rotate-keys`)
// ===========================================================================
//
// Rotates the symmetric account_key + all dependent wraps in one
// atomic server call. Master password (and therefore the BW04
// manifest signing key) stays the same.
//
// 2FA NOTE: this flow does a fresh password grant against
// /identity/connect/token to capture the up-to-date
// `protected_account_private_key` (which isn't cached in session
// today). If the user has 2FA enabled the grant returns 401 with
// `two_factor_required` and we surface a clear "use the CLI"
// message — wiring the popup's existing 2FA challenge dispatcher
// into this flow is a follow-up.

function renderRotateKeys() {
  const content = `
    <p>You're about to:</p>
    <ul>
      <li>Generate a fresh 32-byte <code>account_key</code> client-side.</li>
      <li>Re-wrap every personal-cipher PCK, every share key, and every
          org-membership key under it (one atomic server call).</li>
      <li>Re-wrap your X25519 private key (the keypair stays the
          same — peer pins won't break).</li>
      <li>Revoke every other device's refresh token (they'll need to
          re-login).</li>
    </ul>
    <p class="muted small">
      Master password is unchanged. The BW04 manifest signing key
      is derived from the master password (HKDF), so the manifest
      keeps verifying without re-upload.
    </p>
    <form id="rotateKeysForm">
      <label><span>Confirm master password</span>
        <input name="password" type="password" required autofocus
               autocomplete="current-password">
      </label>
      <button type="submit" class="danger primary-block">Rotate</button>
      <p class="error" id="rotateErr"></p>
    </form>`;
  app.innerHTML = subShellHtml({ title: "Rotate account key", content });
  wireSubShell({ onBack: () => renderSettings() });
  document.getElementById("rotateKeysForm").addEventListener("submit", onRotateKeys);
}

async function onRotateKeys(e) {
  e.preventDefault();
  const errEl = document.getElementById("rotateErr");
  const submit = e.target.querySelector('button[type="submit"]');
  errEl.textContent = "";
  submit.disabled = true;
  submit.textContent = "Working…";

  try {
    const fd = new FormData(e.target);
    const password = (fd.get("password") || "").toString();
    if (!password) throw new Error("master password required");

    const session = await loadSession();
    // 1. Re-prelogin to get current KDF params + bind MAC.
    const pre = await postJSON(
      `${session.server_url}/api/v1/accounts/prelogin`,
      { email: session.email },
    );
    if (!hekate.kdfParamsAreSafe(pre.kdf_params)) {
      throw new Error(
        "server returned KDF params below the client safety floor — refusing to derive",
      );
    }
    const salt = b64decode(pre.kdf_salt);
    const mk = hekate.deriveMasterKey(enc.encode(password), pre.kdf_params, salt);
    const macTag = b64decode(pre.kdf_params_mac);
    if (!hekate.verifyKdfBindMac(mk, pre.kdf_params, salt, macTag)) {
      throw new Error(
        "wrong master password, or the server is attempting to downgrade the KDF (BW07/LP04). Did NOT send credentials.",
      );
    }
    const mph = hekate.deriveMasterPasswordHash(mk);
    const mphB64 = b64encode(mph);

    // 2. Fresh password grant to (a) re-auth and (b) capture the
    //    protected_account_private_key blob the popup doesn't cache
    //    in session today.
    const grant = await postFormRaw(
      `${session.server_url}/identity/connect/token`,
      {
        grant_type: "password",
        username: session.email,
        password: mphB64,
      },
    );
    if (grant.status === 401 && grant.body && grant.body.error === "two_factor_required") {
      throw new Error(
        "this account has 2FA enabled — popup rotate-keys can't drive the second-factor challenge yet. Use `hekate account rotate-keys` from the CLI.",
      );
    }
    if (grant.status < 200 || grant.status >= 300) {
      throw new Error(
        grant.body && grant.body.error ? grant.body.error : `login failed: ${grant.status}`,
      );
    }
    const tok = grant.body;
    if (!tok.protected_account_private_key) {
      throw new Error(
        "server didn't return protected_account_private_key on grant — server may be older than M2.26",
      );
    }

    // 3. Generate the new account_key + re-wrap the X25519 private
    //    key under it. Old account_key still lives in the session.
    const oldAccountKey = b64urlDecode(session.account_key_b64);
    const newAccountKey = hekate.randomKey32();

    const oldPrivBytes = hekate.encStringDecryptXc20p(
      tok.protected_account_private_key,
      oldAccountKey,
      enc.encode("pmgr-account-x25519-priv"),
    );
    const newProtectedPriv = hekate.encStringEncryptXc20p(
      "ak:1",
      newAccountKey,
      oldPrivBytes,
      enc.encode("pmgr-account-x25519-priv"),
    );
    const newProtectedAccountKey = hekate.encStringEncryptXc20p(
      "smk:1",
      hekate.deriveStretchedMasterKey(mk),
      newAccountKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    // 4. /sync to enumerate ciphers/sends/orgs. Use the freshly
    //    issued access token from the grant above.
    await saveSession({
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
    });
    const sync = await apiGet("/api/v1/sync");

    // 5. Build per-row rewraps. Personal ciphers only; org ciphers
    //    wrap their PCK under the org sym key (handled via the org
    //    member rewrap below).
    const cipherRewraps = [];
    for (const c of sync.changes.ciphers || []) {
      if (c.org_id) continue;
      const aad = enc.encode(`pmgr-cipher-key-v2:${c.id}`);
      let pck;
      try {
        pck = hekate.encStringDecryptXc20p(c.protected_cipher_key, oldAccountKey, aad);
      } catch (err) {
        throw new Error(`could not unwrap PCK for cipher ${c.id}: ${err.message}`);
      }
      cipherRewraps.push({
        cipher_id: c.id,
        new_protected_cipher_key: hekate.encStringEncryptXc20p(
          "ak:1",
          newAccountKey,
          pck,
          aad,
        ),
      });
    }

    // Per-send rewrap: protected_send_key + name both wrap under the
    // account_key. If either decrypt fails (e.g. a Send was orphaned by
    // an earlier broken rotation, or the AAD format predates the
    // current scheme), skip that Send and continue — refusing to
    // rotate because of one corrupt row would strand the user.
    const sendRewraps = [];
    const skippedSends = [];
    for (const sd of sync.changes.sends || []) {
      try {
        const keyAad = hekate.sendKeyWrapAad(sd.id);
        const sendKey = hekate.encStringDecryptXc20p(
          sd.protected_send_key,
          oldAccountKey,
          keyAad,
        );
        const nameAad = hekate.sendNameAad(sd.id);
        const namePt = hekate.encStringDecryptXc20p(sd.name, oldAccountKey, nameAad);
        sendRewraps.push({
          send_id: sd.id,
          new_protected_send_key: hekate.encStringEncryptXc20p(
            "ak:1",
            newAccountKey,
            sendKey,
            keyAad,
          ),
          new_name: hekate.encStringEncryptXc20p("ak:1", newAccountKey, namePt, nameAad),
        });
      } catch (err) {
        console.warn(`rotate: skipping orphaned send ${sd.id} (${err.message})`);
        skippedSends.push(sd.id);
      }
    }
    if (skippedSends.length) {
      toast(
        `Skipped ${skippedSends.length} orphaned share(s) — delete them and retry.`,
        4000,
      );
    }

    // Org rewraps need each membership's `my_protected_org_key`,
    // which lives on `GET /api/v1/orgs/{id}` — /sync doesn't carry it.
    const orgMemberRewraps = [];
    for (const o of sync.orgs || []) {
      const orgFull = await apiGet(`/api/v1/orgs/${encodeURIComponent(o.org_id)}`);
      if (!orgFull.my_protected_org_key) continue;
      const aad = enc.encode(AAD_PROTECTED_ACCOUNT_KEY);
      const symKey = hekate.encStringDecryptXc20p(
        orgFull.my_protected_org_key,
        oldAccountKey,
        aad,
      );
      orgMemberRewraps.push({
        org_id: o.org_id,
        new_protected_org_key: hekate.encStringEncryptXc20p(
          "ak:1",
          newAccountKey,
          symKey,
          aad,
        ),
      });
    }

    // 6. POST the rotation. Atomic on the server side.
    const resp = await apiPost("/api/v1/account/rotate-keys", {
      master_password_hash: mphB64,
      new_protected_account_key: newProtectedAccountKey,
      new_protected_account_private_key: newProtectedPriv,
      cipher_rewraps: cipherRewraps,
      send_rewraps: sendRewraps,
      org_member_rewraps: orgMemberRewraps,
    });

    // 7. Persist the new account_key + new tokens.
    await saveSession({
      access_token: resp.access_token,
      refresh_token: resp.refresh_token,
      account_key_b64: b64urlEncode(newAccountKey),
    });

    // 8. Re-sign the BW04 manifest. The server bumped every personal
    //    cipher's revision_date when it re-wrapped the PCKs; the
    //    previous signed manifest still has the old timestamps, so
    //    /sync verification would otherwise warn about drift.
    //    Re-pull the freshly-bumped sync state and sign over it.
    try {
      const finalSession = await loadSession();
      await syncAndUploadManifest(finalSession);
    } catch (err) {
      console.warn("manifest re-sign after rotate-keys failed:", err);
    }

    toast(
      `Rotated. Re-wrote ${resp.rewrote_ciphers} cipher${
        resp.rewrote_ciphers === 1 ? "" : "s"
      }, ${resp.rewrote_sends} share${resp.rewrote_sends === 1 ? "" : "s"}, ${
        resp.rewrote_org_memberships
      } org membership${resp.rewrote_org_memberships === 1 ? "" : "s"}.`,
      4000,
    );
    renderVault();
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Rotate";
    errEl.textContent = err.message;
  }
}

// ===========================================================================
// M3.14 — Orgs UI (read-only list)
// ===========================================================================
//
// First-cut popup org surface. Lists the orgs the caller belongs to
// (decrypts no fields — org names are server-plaintext, roster
// metadata is signed but not encrypted). Write operations
// (create / invite / accept / collection management) require
// signcryption-envelope + roster-canonical-bytes WASM bindings that
// haven't been added to wasm.rs yet, plus byte-exact roster
// construction; users do those flows from the CLI today. The popup
// only verifies the BW08 roster signature against the locally
// pinned org signing pubkey when one is available, surfacing
// mismatches as warnings.

async function renderOrgsList() {
  clearTickers();
  const content = `
    <p class="muted">
      Orgs you own or belong to. Owner-only buttons let you create
      collections and invite peers; non-owners see read-only roster
      info. Pending invites land in the bell icon at the top.
    </p>
    <div style="display:flex; gap:8px; margin-bottom: 12px; flex-wrap: wrap;">
      <button id="createOrgBtn">+ Create organization</button>
      <button class="secondary" id="invitesBtn">Pending invites…</button>
    </div>
    <div id="orgsStatus">Loading…</div>
    <div id="orgsRows"></div>`;
  app.innerHTML = topShellHtml({ title: "Organizations", content, activeTab: "org" });
  wireTopShell({ activeTab: "org" });
  document
    .getElementById("createOrgBtn")
    .addEventListener("click", () => renderCreateOrg());
  document
    .getElementById("invitesBtn")
    .addEventListener("click", () => renderInvitesList());

  let resp;
  try {
    resp = await apiGet("/api/v1/sync");
  } catch (err) {
    document.getElementById("orgsStatus").textContent = "Error: " + err.message;
    return;
  }

  const orgs = resp.orgs || [];
  const status = document.getElementById("orgsStatus");
  const rows = document.getElementById("orgsRows");

  if (orgs.length === 0) {
    status.textContent = "";
    rows.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon("org")}</div>
        <div class="empty-title">No organizations</div>
        <div class="empty-sub">Tap + Create organization or accept a pending invite.</div>
      </div>`;
    return;
  }
  status.textContent = `Member of ${orgs.length} org${orgs.length === 1 ? "" : "s"}`;

  rows.innerHTML = orgs
    .map((o) => {
      const memberCount = countRosterMembers(o.roster);
      const policiesEnabled = (o.policies || []).filter((p) => p.enabled).length;
      const policyTag =
        policiesEnabled > 0
          ? ` <span class="muted">[${policiesEnabled} polic${
              policiesEnabled === 1 ? "y" : "ies"
            }]</span>`
          : "";
      const pendingTag = o.pending_envelope
        ? ` <span class="muted">[rotation pending]</span>`
        : "";
      const confirmBtn = o.pending_envelope
        ? `<button class="text" data-act="confirm-rotation" data-org="${escapeAttr(o.org_id)}" title="Confirm pending org-key rotation">Confirm rotation</button>`
        : "";
      const ownerBtns =
        o.role === "owner"
          ? `<div class="row-actions">
               ${confirmBtn}
               <button class="text" data-act="collections" data-org="${escapeAttr(o.org_id)}" title="Collections">Folders</button>
               <button class="text" data-act="members" data-org="${escapeAttr(o.org_id)}" title="Members">Members</button>
               <button class="text" data-act="policies" data-org="${escapeAttr(o.org_id)}" title="Policies">Policies</button>
               <button class="text" data-act="invite" data-org="${escapeAttr(o.org_id)}" title="Invite peer">Invite</button>
             </div>`
          : `<div class="row-actions">
               ${confirmBtn}
               <button class="text" data-act="collections" data-org="${escapeAttr(o.org_id)}" title="Collections">Folders</button>
               <button class="text" data-act="members" data-org="${escapeAttr(o.org_id)}" title="Members">Members</button>
             </div>`;
      return `
        <div class="row org-row">
          <div class="row-icon">${icon("org")}</div>
          <div class="row-main">
            <div class="row-name">${escapeHtml(o.name)}${policyTag}${pendingTag}</div>
            <div class="muted small">
              ${escapeHtml(o.role)} · ${memberCount} member${memberCount === 1 ? "" : "s"} · roster v${escapeHtml(String(o.roster_version))}
            </div>
          </div>
          ${ownerBtns}
        </div>`;
    })
    .join("");

  rows.querySelectorAll("button[data-act='invite']").forEach((btn) => {
    btn.addEventListener("click", () => renderInvitePeer(btn.dataset.org));
  });
  rows.querySelectorAll("button[data-act='collections']").forEach((btn) => {
    btn.addEventListener("click", () => renderCollectionsList(btn.dataset.org));
  });
  rows.querySelectorAll("button[data-act='members']").forEach((btn) => {
    btn.addEventListener("click", () => renderMembersList(btn.dataset.org));
  });
  rows.querySelectorAll("button[data-act='policies']").forEach((btn) => {
    btn.addEventListener("click", () => renderPoliciesList(btn.dataset.org));
  });
  rows.querySelectorAll("button[data-act='confirm-rotation']").forEach((btn) => {
    btn.addEventListener("click", () => {
      const orgId = btn.dataset.org;
      const entry = (resp.orgs || []).find((o) => o.org_id === orgId);
      if (!entry) {
        toast("org no longer in /sync — refresh", 3000);
        return;
      }
      onConfirmRotation(entry);
    });
  });
}

// ===========================================================================
// M3.14b — create organization (popup port of `hekate org create`)
// ===========================================================================
//
// Generates an Ed25519 org signing keypair, signs the org bundle with the
// owner's account signing seed, wraps the org sym key + signing seed under
// the owner's account_key, builds + signs the v1 genesis roster, POSTs to
// the server, and pins the result locally so M4.2 /sync verification has
// a trust anchor on first read.

function renderCreateOrg() {
  clearTickers();
  const content = `
    <form id="createOrgForm">
      <label>
        <span>Display name</span>
        <input name="name" required autofocus maxlength="120"
               placeholder="e.g. Acme Co">
      </label>
      <p class="muted small">
        You become the owner. The popup generates the org's signing key
        + symmetric key, signs the genesis roster, and pins the org
        locally.
      </p>
      <p class="error" id="createOrgErr" hidden></p>
      <div style="display:flex; gap:8px;">
        <button type="submit" id="createOrgSubmit">Create</button>
        <button type="button" class="secondary" id="cancelBtn">Cancel</button>
      </div>
    </form>`;
  app.innerHTML = subShellHtml({ title: "New organization", content });
  wireSubShell({ onBack: () => renderOrgsList() });
  document.getElementById("cancelBtn").addEventListener("click", () => renderOrgsList());
  document.getElementById("createOrgForm").addEventListener("submit", onCreateOrg);
}

async function onCreateOrg(e) {
  e.preventDefault();
  const errEl = document.getElementById("createOrgErr");
  errEl.hidden = true;
  const submit = document.getElementById("createOrgSubmit");
  submit.disabled = true;
  submit.textContent = "Creating…";

  try {
    const fd = new FormData(e.target);
    const name = (fd.get("name") || "").trim();
    if (!name) throw new Error("name is required");

    const session = await loadSession();
    if (!session.account_key_b64 || !session.signing_seed_b64) {
      throw new Error("session is missing keys — log out and back in");
    }
    const accountKey = b64urlDecode(session.account_key_b64);
    const ownerSigningSeed = b64urlDecode(session.signing_seed_b64);
    const ownerUserId = await currentUserId();

    // 1. Org Ed25519 signing keypair (32-byte seed → derive verifying key).
    const orgSigningSeed = hekate.randomKey32();
    const orgSigningPubkey = hekate.verifyingKeyFromSeed(orgSigningSeed);

    // 2. IDs.
    const orgId = crypto.randomUUID();
    const orgSymKeyId = crypto.randomUUID();

    // 3. Owner signs the org bundle (binds owner identity to org_id,
    //    name, org signing pubkey).
    const bundleSig = hekate.signOrgBundle(
      ownerSigningSeed,
      orgId,
      name,
      orgSigningPubkey,
      ownerUserId,
    );

    // 4. Wrap the org signing seed under the owner's account_key.
    const protectedSigningSeed = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      orgSigningSeed,
      enc.encode("pmgr-org-signing-seed"),
    );

    // 5. Generate the org symmetric key + wrap under account_key.
    const orgSymKey = hekate.randomKey32();
    const ownerProtectedOrgKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      orgSymKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    // 6. Genesis roster (version=1, NO_PARENT_HASH zeros).
    const noParent = new Uint8Array(32);
    const roster = {
      orgId,
      version: 1,
      parentCanonicalSha256: noParent,
      timestamp: new Date().toISOString(),
      entries: [{ userId: ownerUserId, role: "owner" }],
      orgSymKeyId,
    };
    const signedRoster = hekate.signOrgRoster(orgSigningSeed, roster);

    // 7. POST.
    const view = await apiPost("/api/v1/orgs", {
      id: orgId,
      name,
      signing_pubkey: b64encode(orgSigningPubkey),
      bundle_sig: b64encode(bundleSig),
      protected_signing_seed: protectedSigningSeed,
      org_sym_key_id: orgSymKeyId,
      owner_protected_org_key: ownerProtectedOrgKey,
      roster: {
        canonical_b64: signedRoster.canonicalB64,
        signature_b64: signedRoster.signatureB64,
      },
    });

    // 8. Pin our own org locally so /sync verification has an anchor.
    //    Fingerprint is SHA-256 over the bundle canonical bytes —
    //    same shape `hekate peer fingerprint` uses for accounts.
    const bundleCanonical = hekate.orgBundleCanonicalBytes(
      orgId,
      name,
      orgSigningPubkey,
      ownerUserId,
    );
    const fingerprint = "SHA256:" + b64encode(hekate.sha256(bundleCanonical));
    await pinOrg(ownerUserId, orgId, {
      org_id: orgId,
      signing_pubkey_b64: b64encode(orgSigningPubkey),
      fingerprint,
      first_seen_at: new Date().toISOString(),
      last_roster_version: 1,
      last_roster_canonical_b64: signedRoster.canonicalB64,
    });

    toast(`Created org "${view.name}"`);
    renderOrgsList();
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Create";
    errEl.textContent = err.message || String(err);
    errEl.hidden = false;
  }
}

// ===========================================================================
// M3.14c — invite peer (popup port of `hekate org invite`)
// ===========================================================================
//
// Two-step UX inside one panel:
//   1. Caller types the peer's user_id. Popup fetches their pubkey
//      bundle, verifies the self-signature, and shows the fingerprint.
//      If we already have a pin, we cross-check; mismatch aborts.
//      If we don't have a pin, the user must explicitly confirm + pin.
//   2. With the peer pinned, choose a role and submit. Popup unwraps
//      the org sym key + signing seed, builds + signs the next roster
//      version, signcrypts the invite payload to the peer, and POSTs.

async function renderInvitePeer(orgId) {
  clearTickers();
  const content = `
    <p class="muted small">org: <code>${escapeHtml(orgId)}</code></p>
    <div id="currentMembers" class="muted small">Loading current members…</div>
    <form id="invitePeerForm">
      <label>
        <span>Peer email or user_id</span>
        <input name="peer_id" required autofocus
               placeholder="alice@example.com or 0192e0a0-…">
      </label>
      <label>
        <span>Role</span>
        <select name="role">
          <option value="user">user</option>
          <option value="admin">admin</option>
        </select>
      </label>
      <p class="muted small">
        On submit, the popup fetches the peer's pubkey bundle, verifies
        its self-signature, and shows you the fingerprint. Confirm the
        fingerprint matches what the peer reads to you out of band
        before the invite goes out.
      </p>
      <p class="error" id="inviteErr" hidden></p>
      <div style="display:flex; gap:8px;">
        <button type="submit" id="inviteSubmit">Continue</button>
        <button type="button" class="secondary" id="cancelBtn">Cancel</button>
      </div>
    </form>`;
  app.innerHTML = subShellHtml({ title: "Invite peer", content });
  wireSubShell({ onBack: () => renderOrgsList() });
  document.getElementById("cancelBtn").addEventListener("click", () => renderOrgsList());
  document.getElementById("invitePeerForm").addEventListener("submit", (e) =>
    onInvitePeer(e, orgId),
  );

  // Best-effort fetch of the current member list, rendered above the
  // form so the inviter sees who's already in the org (helps avoid
  // duplicate invites and shows real emails alongside the user_ids).
  // GH #3: pending invitees come back in their own field so the
  // sidebar can flag "(invite pending)" entries without lying about
  // membership. Failures are non-fatal — the form still works.
  try {
    const org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
    const decoded = hekate.decodeOrgRosterCanonical(b64decode(org.roster.canonical_b64));
    const emails = org.member_emails || {};
    const memberLines = decoded.entries
      .map((entry) => {
        const email = emails[entry.userId];
        const ident = email
          ? `<strong>${escapeHtml(email)}</strong> <code class="muted">${escapeHtml(entry.userId)}</code>`
          : `<code>${escapeHtml(entry.userId)}</code>`;
        return `<li>${ident} <span class="muted">— ${escapeHtml(entry.role)}</span></li>`;
      })
      .join("");
    const pending = org.pending_invitees || {};
    const pendingEntries = Object.entries(pending);
    const pendingLines = pendingEntries
      .map(([userId, info]) => {
        const ident = info.email
          ? `<strong>${escapeHtml(info.email)}</strong> <code class="muted">${escapeHtml(userId)}</code>`
          : `<code>${escapeHtml(userId)}</code>`;
        return `<li>${ident} <span class="muted">— ${escapeHtml(info.role)} · invite pending</span></li>`;
      })
      .join("");
    const el = document.getElementById("currentMembers");
    if (el) {
      let html = `
        <p class="muted small" style="margin: 0 0 4px;">
          Already in this org (${decoded.entries.length}):
        </p>
        <ul style="margin: 0 0 12px; padding-left: 20px;">${memberLines}</ul>`;
      if (pendingEntries.length > 0) {
        html += `
        <p class="muted small" style="margin: 0 0 4px;">
          Pending invites (${pendingEntries.length}):
        </p>
        <ul style="margin: 0 0 12px; padding-left: 20px;">${pendingLines}</ul>`;
      }
      el.innerHTML = html;
    }
  } catch (err) {
    const el = document.getElementById("currentMembers");
    if (el) el.textContent = "Couldn't load member list: " + err.message;
  }
}

async function onInvitePeer(e, orgId) {
  e.preventDefault();
  const errEl = document.getElementById("inviteErr");
  errEl.hidden = true;
  const submit = document.getElementById("inviteSubmit");
  submit.disabled = true;
  submit.textContent = "Working…";

  try {
    const fd = new FormData(e.target);
    const peerInput = (fd.get("peer_id") || "").trim();
    const role = (fd.get("role") || "user").trim();
    if (!peerInput) throw new Error("peer email or user_id is required");
    if (role !== "admin" && role !== "user") {
      throw new Error("role must be admin or user");
    }

    const session = await loadSession();
    if (!session.account_key_b64 || !session.signing_seed_b64) {
      throw new Error("session is missing keys — log out and back in");
    }
    const accountKey = b64urlDecode(session.account_key_b64);
    const ownerSigningSeed = b64urlDecode(session.signing_seed_b64);
    const ownerUserId = await currentUserId();

    // Step 1 — fetch + verify peer bundle, pin (or cross-check pin).
    // Detect email vs UUID by the presence of `@`. The server's
    // `/users/lookup?email=…` endpoint resolves email → bundle (auth
    // required to avoid an enumeration oracle); the UUID endpoint
    // stays unauthenticated as before.
    const bundleUrl = peerInput.includes("@")
      ? `/api/v1/users/lookup?email=${encodeURIComponent(peerInput)}`
      : `/api/v1/users/${encodeURIComponent(peerInput)}/pubkeys`;
    let bundle;
    try {
      bundle = await apiGet(bundleUrl);
    } catch (err) {
      if (peerInput.includes("@") && /404/.test(err.message || "")) {
        throw new Error(
          `no user found for "${peerInput}" on this server — confirm the address with the peer.`,
        );
      }
      throw err;
    }
    const peerId = bundle.user_id;
    const peerSigningPk = b64decode(bundle.account_signing_pubkey);
    const peerX25519Pk = b64decode(bundle.account_public_key);
    const bundleSigBytes = b64decode(bundle.account_pubkey_bundle_sig);
    if (peerSigningPk.length !== 32) throw new Error("peer signing pubkey wrong length");
    if (peerX25519Pk.length !== 32) throw new Error("peer x25519 pubkey wrong length");
    if (bundleSigBytes.length !== 64) throw new Error("peer bundle sig wrong length");
    const ok = hekate.verifyPubkeyBundle(
      bundle.user_id,
      peerSigningPk,
      peerX25519Pk,
      bundleSigBytes,
    );
    if (!ok) {
      throw new Error(
        "peer bundle self-sig did not verify — server may be attempting substitution",
      );
    }
    const canonical = hekate.pubkeyBundleCanonicalBytes(
      bundle.user_id,
      peerSigningPk,
      peerX25519Pk,
    );
    const fingerprint = "SHA256:" + b64encode(hekate.sha256(canonical));

    const pins = await loadPins(ownerUserId);
    const existing = pins.peer_pins[peerId];
    if (existing) {
      if (
        existing.account_signing_pubkey_b64 !== bundle.account_signing_pubkey ||
        existing.account_public_key_b64 !== bundle.account_public_key ||
        existing.account_pubkey_bundle_sig_b64 !== bundle.account_pubkey_bundle_sig
      ) {
        throw new Error(
          `pin mismatch for ${peerId} — first seen ${existing.first_seen_at} ` +
            `with fingerprint ${existing.fingerprint}, server now claims ` +
            `${fingerprint}. Refusing to overwrite.`,
        );
      }
    } else {
      const confirmed = window.confirm(
        `Pin new peer ${bundle.user_id}?\n\nFingerprint:\n  ${fingerprint}\n\n` +
          `Verify this matches what the peer reads to you out of band before clicking OK.`,
      );
      if (!confirmed) throw new Error("pin not confirmed — aborted");
      pins.peer_pins[peerId] = {
        user_id: bundle.user_id,
        account_signing_pubkey_b64: bundle.account_signing_pubkey,
        account_public_key_b64: bundle.account_public_key,
        account_pubkey_bundle_sig_b64: bundle.account_pubkey_bundle_sig,
        fingerprint,
        first_seen_at: new Date().toISOString(),
      };
      await savePins(ownerUserId, pins);
    }

    // Step 2 — fetch the org (gives us my_protected_org_key +
    // owner_protected_signing_seed + the current signed roster).
    submit.textContent = "Building invite…";
    const org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
    if (org.owner_user_id !== ownerUserId) {
      throw new Error("only the org owner can invite members");
    }
    if (!org.owner_protected_signing_seed) {
      throw new Error("server omitted owner_protected_signing_seed");
    }

    // Unwrap org symmetric key + signing seed.
    const orgSymKey = hekate.encStringDecryptXc20p(
      org.my_protected_org_key,
      accountKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );
    const orgSigningSeed = hekate.encStringDecryptXc20p(
      org.owner_protected_signing_seed,
      accountKey,
      enc.encode("pmgr-org-signing-seed"),
    );

    // Decode current roster, build next.
    const currentCanonical = b64decode(org.roster.canonical_b64);
    const current = hekate.decodeOrgRosterCanonical(currentCanonical);
    if (current.entries.some((entry) => entry.userId === peerId)) {
      throw new Error("peer is already in the roster");
    }
    const nextEntries = current.entries.concat([{ userId: peerId, role }]);
    const nextRoster = {
      orgId: org.id,
      version: current.version + 1,
      parentCanonicalSha256: hekate.sha256(currentCanonical),
      timestamp: new Date().toISOString(),
      entries: nextEntries,
      orgSymKeyId: org.org_sym_key_id,
    };
    const signedNext = hekate.signOrgRoster(orgSigningSeed, nextRoster);

    // Build the invite payload (matches CLI exactly).
    const payload = JSON.stringify({
      org_id: org.id,
      org_signing_pubkey_b64: org.signing_pubkey,
      org_bundle_sig_b64: org.bundle_sig,
      org_name: org.name,
      org_sym_key_id: org.org_sym_key_id,
      org_sym_key_b64: b64encode(orgSymKey),
      role,
    });
    const envelope = hekate.signcryptSealEnvelope(
      ownerSigningSeed,
      ownerUserId,
      peerId,
      peerX25519Pk,
      enc.encode(payload),
    );

    // POST.
    await apiPost(`/api/v1/orgs/${encodeURIComponent(orgId)}/invites`, {
      invitee_user_id: peerId,
      role,
      envelope,
      next_roster: {
        canonical_b64: signedNext.canonicalB64,
        signature_b64: signedNext.signatureB64,
      },
    });

    toast(`Invited ${peerId} to "${org.name}" as ${role}.`);
    renderOrgsList();
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Continue";
    errEl.textContent = err.message || String(err);
    errEl.hidden = false;
  }
}

// ===========================================================================
// M3.14a — accept invite (popup port of `hekate org accept`)
// ===========================================================================
//
// The accept flow is the densest of M3.14: it must verify three
// signatures before storing anything (envelope, org bundle, roster),
// AND require that the inviter is already pinned out-of-band. The
// popup refuses to accept invites from un-pinned inviters; user has
// to pin them first via M3.14c (Invite peer also pins on first sight,
// but the inviter flow is reversed here — we're the *invitee*. Pin
// the inviter via the "Pin peer" entry below before accepting).

async function renderInvitesList() {
  clearTickers();
  const content = `
    <p class="muted small">
      You can only accept invites from peers you've pinned out of band.
      If a row says "inviter not pinned", click <em>Pin inviter</em>
      first — verify their fingerprint matches what they read aloud
      before continuing.
    </p>
    <div style="display:flex; gap:8px; margin-bottom: 12px;">
      <button class="secondary" id="pinPeerBtn">Pin peer…</button>
    </div>
    <div id="invitesStatus">Loading…</div>
    <div id="invitesRows"></div>`;
  app.innerHTML = subShellHtml({ title: "Pending invites", content });
  wireSubShell({ onBack: () => renderOrgsList() });
  document
    .getElementById("pinPeerBtn")
    .addEventListener("click", () => renderPinPeer(() => renderInvitesList()));

  let invites;
  try {
    invites = await apiGet("/api/v1/account/invites");
  } catch (err) {
    document.getElementById("invitesStatus").textContent = "Error: " + err.message;
    return;
  }
  const status = document.getElementById("invitesStatus");
  const rows = document.getElementById("invitesRows");
  if (!invites || invites.length === 0) {
    status.textContent = "No pending invites.";
    rows.innerHTML = "";
    return;
  }
  status.textContent = `${invites.length} pending invite${invites.length === 1 ? "" : "s"}`;

  const ownerUserId = await currentUserId();
  const pins = await loadPins(ownerUserId);
  rows.innerHTML = invites
    .map((inv) => {
      const pinned = !!pins.peer_pins[inv.inviter_user_id];
      const acceptDisabled = pinned ? "" : "disabled";
      const note = pinned
        ? `<span class="muted">inviter pinned ✓</span>`
        : `<span class="muted">inviter not pinned</span>`;
      return `
        <div class="row" data-org="${escapeAttr(inv.org_id)}">
          <div class="row-main">
            <div class="row-name">${escapeHtml(inv.org_name)} <span class="muted">[${escapeHtml(inv.role)}]</span></div>
            <div class="muted small">
              from <code>${escapeHtml(inv.inviter_user_id)}</code> · ${note}
              · invited ${escapeHtml(inv.invited_at)} · roster v${escapeHtml(String(inv.roster_version))}
            </div>
          </div>
          <div class="row-actions">
            <button data-act="accept" ${acceptDisabled}>Accept</button>
            <button class="secondary" data-act="pin">Pin inviter</button>
          </div>
        </div>`;
    })
    .join("");

  rows.querySelectorAll(".row").forEach((row) => {
    const orgId = row.dataset.org;
    row.querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.dataset.act === "pin") {
          const inv = invites.find((i) => i.org_id === orgId);
          if (inv) renderPinPeer(() => renderInvitesList(), inv.inviter_user_id);
        } else if (btn.dataset.act === "accept") {
          onAcceptInvite(orgId);
        }
      });
    });
  });
}

// "Pin peer" — TOFU peer pinning UI. `onDone` is called after a
// successful pin (or cancel). Optional `prefill` puts a user_id in
// the input on entry.
function renderPinPeer(onDone, prefill) {
  clearTickers();
  const content = `
    <form id="pinPeerForm">
      <label>
        <span>Peer user_id</span>
        <input name="peer_id" required autofocus
               value="${escapeAttr(prefill || "")}"
               placeholder="0192e0a0-…">
      </label>
      <p class="muted small">
        Pinning fetches the peer's pubkey bundle, verifies the
        self-signature, and shows the SHA-256 fingerprint. Confirm the
        fingerprint matches what the peer reads to you out of band
        before clicking OK on the prompt.
      </p>
      <p class="error" id="pinErr" hidden></p>
      <div style="display:flex; gap:8px;">
        <button type="submit" id="pinSubmit">Fetch + pin</button>
        <button type="button" class="secondary" id="cancelBtn">Cancel</button>
      </div>
    </form>`;
  const back = () => onDone();
  app.innerHTML = subShellHtml({ title: "Pin peer", content });
  wireSubShell({ onBack: back });
  document.getElementById("cancelBtn").addEventListener("click", back);
  document.getElementById("pinPeerForm").addEventListener("submit", (e) =>
    onPinPeer(e, onDone),
  );
}

async function onPinPeer(e, onDone) {
  e.preventDefault();
  const errEl = document.getElementById("pinErr");
  errEl.hidden = true;
  const submit = document.getElementById("pinSubmit");
  submit.disabled = true;
  submit.textContent = "Fetching…";
  try {
    const fd = new FormData(e.target);
    const peerId = (fd.get("peer_id") || "").trim();
    if (!peerId) throw new Error("peer user_id is required");

    const ownerUserId = await currentUserId();
    const bundle = await apiGet(`/api/v1/users/${encodeURIComponent(peerId)}/pubkeys`);
    const peerSigningPk = b64decode(bundle.account_signing_pubkey);
    const peerX25519Pk = b64decode(bundle.account_public_key);
    const sigBytes = b64decode(bundle.account_pubkey_bundle_sig);
    if (peerSigningPk.length !== 32) throw new Error("peer signing pubkey wrong length");
    if (peerX25519Pk.length !== 32) throw new Error("peer x25519 pubkey wrong length");
    if (sigBytes.length !== 64) throw new Error("peer bundle sig wrong length");
    if (!hekate.verifyPubkeyBundle(bundle.user_id, peerSigningPk, peerX25519Pk, sigBytes)) {
      throw new Error("peer bundle self-sig did not verify — server may be substituting");
    }
    const fingerprint =
      "SHA256:" +
      b64encode(
        hekate.sha256(
          hekate.pubkeyBundleCanonicalBytes(bundle.user_id, peerSigningPk, peerX25519Pk),
        ),
      );

    const pins = await loadPins(ownerUserId);
    const existing = pins.peer_pins[peerId];
    if (existing) {
      if (
        existing.account_signing_pubkey_b64 !== bundle.account_signing_pubkey ||
        existing.account_public_key_b64 !== bundle.account_public_key
      ) {
        throw new Error(
          `pin mismatch — first seen ${existing.first_seen_at} with fingerprint ` +
            `${existing.fingerprint}, server now claims ${fingerprint}. ` +
            `Refusing to overwrite.`,
        );
      }
      toast(`Pin already on file (${fingerprint}).`);
      onDone();
      return;
    }
    const confirmed = window.confirm(
      `Pin new peer ${bundle.user_id}?\n\nFingerprint:\n  ${fingerprint}\n\n` +
        `Verify this matches what the peer reads to you out of band before clicking OK.`,
    );
    if (!confirmed) {
      submit.disabled = false;
      submit.textContent = "Fetch + pin";
      return;
    }
    pins.peer_pins[peerId] = {
      user_id: bundle.user_id,
      account_signing_pubkey_b64: bundle.account_signing_pubkey,
      account_public_key_b64: bundle.account_public_key,
      account_pubkey_bundle_sig_b64: bundle.account_pubkey_bundle_sig,
      fingerprint,
      first_seen_at: new Date().toISOString(),
    };
    await savePins(ownerUserId, pins);
    toast(`Pinned ${peerId}.`);
    onDone();
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Fetch + pin";
    errEl.textContent = err.message || String(err);
    errEl.hidden = false;
  }
}

async function onAcceptInvite(orgId) {
  try {
    const session = await loadSession();
    if (!session.account_key_b64) throw new Error("session missing keys — log out and back in");
    if (!session.protected_account_private_key) {
      throw new Error(
        "session missing protected_account_private_key — log out + back in to refresh",
      );
    }
    const accountKey = b64urlDecode(session.account_key_b64);
    const ownerUserId = await currentUserId();

    const invites = await apiGet("/api/v1/account/invites");
    const invite = invites.find((i) => i.org_id === orgId);
    if (!invite) throw new Error("no pending invite for this org");

    const pins = await loadPins(ownerUserId);
    const inviterPin = pins.peer_pins[invite.inviter_user_id];
    if (!inviterPin) {
      throw new Error(
        `inviter ${invite.inviter_user_id} is not pinned — pin them first`,
      );
    }
    const inviterSigningPk = b64decode(inviterPin.account_signing_pubkey_b64);
    if (inviterSigningPk.length !== 32) throw new Error("pinned signing key wrong length");

    // Decrypt our X25519 private key.
    const myX25519Priv = hekate.encStringDecryptXc20p(
      session.protected_account_private_key,
      accountKey,
      enc.encode("pmgr-account-x25519-priv"),
    );

    // Verify-decrypt envelope.
    const plaintext = hekate.signcryptOpenEnvelope(
      invite.envelope,
      inviterSigningPk,
      ownerUserId,
      myX25519Priv,
    );
    const payload = JSON.parse(dec.decode(plaintext));

    if (payload.org_id !== orgId) {
      throw new Error("envelope org_id != invite org_id — server tampering?");
    }
    if (payload.role !== invite.role) {
      throw new Error("envelope role != invite role — server tampering?");
    }
    const orgSigningPk = b64decode(payload.org_signing_pubkey_b64);
    const orgBundleSig = b64decode(payload.org_bundle_sig_b64);
    if (orgSigningPk.length !== 32) throw new Error("org signing key wrong length");
    if (orgBundleSig.length !== 64) throw new Error("org bundle sig wrong length");

    // Verify org bundle under inviter's PINNED signing key.
    if (
      !hekate.verifyOrgBundle(
        inviterSigningPk,
        orgId,
        payload.org_name,
        orgSigningPk,
        invite.inviter_user_id,
        orgBundleSig,
      )
    ) {
      throw new Error("org bundle sig did not verify under inviter's pinned key");
    }

    // Verify roster under (now-trusted) org signing key + we're listed
    // with the claimed role.
    const roster = hekate.verifyOrgRoster(
      orgSigningPk,
      invite.roster.canonical_b64,
      invite.roster.signature_b64,
    );
    const me = roster.entries.find((entry) => entry.userId === ownerUserId);
    if (!me) throw new Error("roster does not list us — server tampering?");
    if (me.role !== invite.role) {
      throw new Error("roster role != claimed invite role — server tampering?");
    }

    // Re-wrap the org sym key under our account_key.
    const orgSymKeyBytes = b64decode(payload.org_sym_key_b64);
    if (orgSymKeyBytes.length !== 32) throw new Error("org sym key wrong length");
    const protectedOrgKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      orgSymKeyBytes,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    await apiPost(`/api/v1/orgs/${encodeURIComponent(orgId)}/accept`, {
      protected_org_key: protectedOrgKey,
      org_sym_key_id: payload.org_sym_key_id,
    });

    // TOFU-pin the org for /sync verification.
    const bundleCanonical = hekate.orgBundleCanonicalBytes(
      orgId,
      payload.org_name,
      orgSigningPk,
      invite.inviter_user_id,
    );
    const orgFingerprint = "SHA256:" + b64encode(hekate.sha256(bundleCanonical));
    await pinOrg(ownerUserId, orgId, {
      org_id: orgId,
      signing_pubkey_b64: payload.org_signing_pubkey_b64,
      fingerprint: orgFingerprint,
      first_seen_at: new Date().toISOString(),
      last_roster_version: roster.version,
      last_roster_canonical_b64: invite.roster.canonical_b64,
    });

    toast(`Joined "${payload.org_name}" as ${invite.role}.`);
    renderOrgsList();
  } catch (err) {
    toast("Accept failed: " + (err.message || String(err)), 4500);
  }
}

// ===========================================================================
// M4.5b — members list + remove member (rotates org sym key)
// ===========================================================================
//
// Owner-only. Mirrors `hekate org remove-member` (CLI) and the web
// vault's `lib/orgWrite.ts::revokeMember`. The remove operation is
// destructive — it rotates the org symmetric key, signcrypts the
// new key to every remaining non-owner (TOFU pin verified against
// live), and re-wraps every org-owned cipher's PCK under the new
// key. All-or-nothing on the server side.

async function renderMembersList(orgId) {
  clearTickers();
  const content = `
    <p class="muted small">org: <code>${escapeHtml(orgId)}</code></p>
    <p class="error" id="membersErr" hidden></p>
    <div id="orphanBanner"></div>
    <div id="membersStatus">Loading…</div>
    <div id="membersRows"></div>
    <h3 style="margin-top: 16px; font-size: 14px;">Pending invites</h3>
    <div id="pendingRows" class="muted small">None.</div>`;
  app.innerHTML = subShellHtml({ title: "Members", content });
  wireSubShell({ onBack: () => renderOrgsList() });

  let org;
  try {
    org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  } catch (err) {
    document.getElementById("membersStatus").textContent = "Error: " + err.message;
    return;
  }

  const session = await loadSession();
  const myUserId = await currentUserId();
  const isOwner = org.owner_user_id === myUserId;
  const decoded = hekate.decodeOrgRosterCanonical(b64decode(org.roster.canonical_b64));
  const emails = org.member_emails || {};
  const status = document.getElementById("membersStatus");
  const rows = document.getElementById("membersRows");
  status.textContent = `${decoded.entries.length} member${decoded.entries.length === 1 ? "" : "s"}`;

  // Detect roster orphans — entries in the signed roster with no
  // membership row server-side. Pre-GH#2 invites that never accepted
  // are the typical source. Owner-only banner with a Prune action;
  // mirrors the web vault's flow.
  const orphans = isOwner
    ? decoded.entries
        .map((e) => e.userId)
        .filter((uid) => uid !== org.owner_user_id && !emails[uid])
    : [];
  const orphanBanner = document.getElementById("orphanBanner");
  if (orphans.length > 0) {
    orphanBanner.innerHTML = `
      <div class="manifest-warn">
        <strong>⚠ Roster needs cleanup</strong>
        <p>${orphans.length} ${orphans.length === 1 ? "user_id is" : "user_ids are"} in this org's signed roster but ${orphans.length === 1 ? "has" : "have"} no membership row server-side. They can't access any data — most likely a pre-GH#2 invite that was never accepted. Prune re-signs the roster dropping them. The org symmetric key is not rotated.</p>
        <ul>${orphans.map((u) => `<li><code>${escapeHtml(u)}</code></li>`).join("")}</ul>
        <p><button class="text" id="pruneOrphansBtn">Prune ${orphans.length} orphan ${orphans.length === 1 ? "entry" : "entries"}</button></p>
      </div>`;
    document
      .getElementById("pruneOrphansBtn")
      .addEventListener("click", () => onPruneOrphans(orgId, orphans));
  } else {
    orphanBanner.innerHTML = "";
  }

  rows.innerHTML = decoded.entries
    .map((entry) => {
      const email = emails[entry.userId];
      const ident = email
        ? `<strong>${escapeHtml(email)}</strong> <code class="muted small">${escapeHtml(entry.userId)}</code>`
        : `<code>${escapeHtml(entry.userId)}</code>`;
      const canRemove =
        isOwner && entry.role !== "owner" && entry.userId !== myUserId;
      const action = canRemove
        ? `<button class="text danger" data-act="remove" data-user="${escapeAttr(entry.userId)}" data-label="${escapeAttr(email || entry.userId)}">Remove</button>`
        : "";
      return `
        <div class="row">
          <div class="row-main">
            <div class="row-name">${ident}</div>
            <div class="muted small">${escapeHtml(entry.role)}</div>
          </div>
          <div class="row-actions">${action}</div>
        </div>`;
    })
    .join("");

  rows.querySelectorAll("button[data-act='remove']").forEach((btn) => {
    btn.addEventListener("click", () =>
      onRemoveMember(orgId, btn.dataset.user, btn.dataset.label),
    );
  });

  // Pending invitees (owner sees them; non-owners get an empty map).
  const pending = org.pending_invitees || {};
  const pendingEntries = Object.entries(pending);
  const pendingEl = document.getElementById("pendingRows");
  if (pendingEntries.length > 0) {
    pendingEl.innerHTML = pendingEntries
      .map(([userId, info]) => {
        const ident = info.email
          ? `<strong>${escapeHtml(info.email)}</strong> <code class="muted small">${escapeHtml(userId)}</code>`
          : `<code>${escapeHtml(userId)}</code>`;
        const cancelBtn = isOwner
          ? `<button class="text danger" data-act="cancel-invite" data-user="${escapeAttr(userId)}" data-label="${escapeAttr(info.email || userId)}">Cancel</button>`
          : "";
        return `<div class="row"><div class="row-main"><div class="row-name">${ident}</div><div class="muted small">${escapeHtml(info.role)} · invited</div></div><div class="row-actions">${cancelBtn}</div></div>`;
      })
      .join("");
    pendingEl
      .querySelectorAll("button[data-act='cancel-invite']")
      .forEach((btn) => {
        btn.addEventListener("click", () =>
          onCancelInvite(orgId, btn.dataset.user, btn.dataset.label),
        );
      });
  }
  void session;
}

async function onPruneOrphans(orgId, orphanUserIds) {
  if (
    !window.confirm(
      `Prune ${orphanUserIds.length} orphan ${orphanUserIds.length === 1 ? "entry" : "entries"} from the signed roster?\n\n` +
        "These user_ids are in the cryptographic roster but have no " +
        "membership row server-side — they were never able to access " +
        "this org's data. Pruning re-signs the roster without them. " +
        "The org symmetric key is NOT rotated.",
    )
  ) {
    return;
  }
  const errEl = document.getElementById("membersErr");
  if (errEl) errEl.hidden = true;
  toast("Pruning roster…", 1500);
  try {
    const session = await loadSession();
    const accountKey = b64urlDecode(session.account_key_b64);
    const myUserId = await currentUserId();

    const org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
    if (org.owner_user_id !== myUserId) {
      throw new Error("only the org owner can prune the roster");
    }
    if (!org.owner_protected_signing_seed) {
      throw new Error("server omitted owner_protected_signing_seed");
    }
    const orgSigningSeed = hekate.encStringDecryptXc20p(
      org.owner_protected_signing_seed,
      accountKey,
      enc.encode("pmgr-org-signing-seed"),
    );

    const currentCanonical = b64decode(org.roster.canonical_b64);
    const current = hekate.decodeOrgRosterCanonical(currentCanonical);
    const orphanSet = new Set(orphanUserIds);
    const nextEntries = current.entries.filter((e) => !orphanSet.has(e.userId));
    if (nextEntries.length === current.entries.length) {
      throw new Error(
        "no entries match the supplied user_ids — roster may have been pruned by another client",
      );
    }
    if (!nextEntries.some((e) => e.userId === myUserId && e.role === "owner")) {
      throw new Error("refusing to prune the owner from the roster");
    }
    const next = {
      orgId: org.id,
      version: current.version + 1,
      parentCanonicalSha256: hekate.sha256(currentCanonical),
      timestamp: new Date().toISOString(),
      entries: nextEntries,
      orgSymKeyId: org.org_sym_key_id,
    };
    const signedNext = hekate.signOrgRoster(orgSigningSeed, next);

    await apiPost(`/api/v1/orgs/${encodeURIComponent(orgId)}/prune-roster`, {
      next_roster: {
        canonical_b64: signedNext.canonicalB64,
        signature_b64: signedNext.signatureB64,
      },
    });

    // Refresh local pin so /sync verification tracks the new roster.
    const pins = await loadPins(myUserId);
    const existingPin = pins.org_pins[orgId];
    if (existingPin) {
      await pinOrg(myUserId, orgId, {
        ...existingPin,
        last_roster_version: next.version,
        last_roster_canonical_b64: signedNext.canonicalB64,
      });
    }

    toast(`Pruned ${orphanUserIds.length} orphan ${orphanUserIds.length === 1 ? "entry" : "entries"}.`);
    renderMembersList(orgId);
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message || String(err);
      errEl.hidden = false;
    } else {
      toast("Prune failed: " + (err.message || String(err)), 4500);
    }
  }
}

async function onCancelInvite(orgId, inviteeUserId, label) {
  if (
    !window.confirm(
      `Cancel the invitation to "${label}"?\n\n` +
        "They lose the pending invite. The org's signed roster is " +
        "unaffected since the invite never advanced it. You can " +
        "re-invite later.",
    )
  ) {
    return;
  }
  const errEl = document.getElementById("membersErr");
  if (errEl) errEl.hidden = true;
  toast("Cancelling invite…", 1200);
  try {
    // Server endpoint: DELETE /api/v1/orgs/{org_id}/invites/{invitee_user_id}
    // Body is optional (legacy `next_roster` field is dropped server-side).
    const r = await authedFetch(
      "DELETE",
      `/api/v1/orgs/${encodeURIComponent(orgId)}/invites/${encodeURIComponent(inviteeUserId)}`,
      {},
    );
    if (r.status !== 204 && !r.ok) await checkResponse(r);
    toast(`Cancelled invite to "${label}".`);
    renderMembersList(orgId);
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message || String(err);
      errEl.hidden = false;
    } else {
      toast("Cancel failed: " + (err.message || String(err)), 4500);
    }
  }
}

async function onRemoveMember(orgId, targetUserId, label) {
  if (
    !window.confirm(
      `Remove "${label}" from this org?\n\n` +
        "This rotates the org symmetric key, re-wraps every org-owned " +
        "cipher under the new key, and signcrypts the new key to every " +
        "remaining member. They'll auto-confirm on next sync. The " +
        "removed member loses access immediately.\n\n" +
        "All remaining members must already be peer-pinned with " +
        "fingerprints verified out of band.",
    )
  ) {
    return;
  }
  const errEl = document.getElementById("membersErr");
  if (errEl) errEl.hidden = true;
  toast("Rotating org key…", 1500);

  try {
    const session = await loadSession();
    const accountKey = b64urlDecode(session.account_key_b64);
    const ownerSigningSeed = b64urlDecode(session.signing_seed_b64);
    const myUserId = await currentUserId();
    if (targetUserId === myUserId) {
      throw new Error(
        "the owner cannot revoke themselves; transfer ownership first (M4 v2)",
      );
    }

    // 1. Org + signing seed + old sym key.
    const org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
    if (org.owner_user_id !== myUserId) {
      throw new Error("only the org owner can remove members");
    }
    if (!org.owner_protected_signing_seed) {
      throw new Error("server omitted owner_protected_signing_seed");
    }
    const orgSigningSeed = hekate.encStringDecryptXc20p(
      org.owner_protected_signing_seed,
      accountKey,
      enc.encode("pmgr-org-signing-seed"),
    );
    const oldOrgSymKey = hekate.encStringDecryptXc20p(
      org.my_protected_org_key,
      accountKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    // 2. Parse current roster + verify target is removable.
    const currentCanonical = b64decode(org.roster.canonical_b64);
    const current = hekate.decodeOrgRosterCanonical(currentCanonical);
    const targetEntry = current.entries.find((e) => e.userId === targetUserId);
    if (!targetEntry) throw new Error(`${targetUserId} is not in the roster`);
    if (targetEntry.role === "owner") throw new Error("cannot revoke the org owner");

    // 3. Build next roster (drop target, version+1, parent_hash, NEW key_id).
    const nextEntries = current.entries.filter((e) => e.userId !== targetUserId);
    const newOrgSymKeyId = crypto.randomUUID();
    const next = {
      orgId: org.id,
      version: current.version + 1,
      parentCanonicalSha256: hekate.sha256(currentCanonical),
      timestamp: new Date().toISOString(),
      entries: nextEntries,
      orgSymKeyId: newOrgSymKeyId,
    };
    const signedNext = hekate.signOrgRoster(orgSigningSeed, next);

    // 4. New sym key + owner wrap.
    const newOrgSymKey = hekate.randomKey32();
    const ownerProtectedOrgKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      newOrgSymKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    // 5. Signcrypt to every remaining non-owner. Verify TOFU pin
    //    matches the live pubkey bundle — refuses the rotation if
    //    the server has diverged.
    const pins = await loadPins(myUserId);
    const rewrapEnvelopes = [];
    for (const entry of nextEntries) {
      if (entry.userId === myUserId) continue;
      const pin = pins.peer_pins[entry.userId];
      if (!pin) {
        throw new Error(
          `remaining member ${entry.userId} is not pinned — pin them first ` +
            `(via Invite peer or hekate peer fetch) and verify the fingerprint ` +
            `out of band before rotating, otherwise they cannot be re-wrapped to.`,
        );
      }
      const live = await apiGet(`/api/v1/users/${encodeURIComponent(entry.userId)}/pubkeys`);
      if (
        live.account_signing_pubkey !== pin.account_signing_pubkey_b64 ||
        live.account_public_key !== pin.account_public_key_b64 ||
        live.account_pubkey_bundle_sig !== pin.account_pubkey_bundle_sig_b64
      ) {
        throw new Error(
          `server-returned pubkey bundle for ${entry.userId} does not match ` +
            `TOFU pin — refusing to wrap the new org key. Investigate before retrying.`,
        );
      }
      const peerX25519Pk = b64decode(pin.account_public_key_b64);
      const payload = JSON.stringify({
        kind: "pmgr-org-key-rotation-v1",
        org_id: org.id,
        org_sym_key_id: newOrgSymKeyId,
        org_sym_key_b64: b64encode(newOrgSymKey),
      });
      const envelope = hekate.signcryptSealEnvelope(
        ownerSigningSeed,
        myUserId,
        entry.userId,
        peerX25519Pk,
        enc.encode(payload),
      );
      rewrapEnvelopes.push({ user_id: entry.userId, envelope });
    }

    // 6. Re-wrap every org-owned cipher PCK under the new sym key.
    const sync = await apiGet("/api/v1/sync");
    const cipherRewraps = [];
    for (const c of sync.changes.ciphers) {
      if (c.org_id !== orgId) continue;
      const aad = enc.encode("pmgr-cipher-key-v2:" + c.id);
      let cipherKeyBytes;
      try {
        cipherKeyBytes = hekate.encStringDecryptXc20p(
          c.protected_cipher_key,
          oldOrgSymKey,
          aad,
        );
      } catch (err) {
        throw new Error(
          `failed to unwrap cipher ${c.id} under the old org sym key — ` +
            `refusing to rotate. ${err.message || err}`,
        );
      }
      const newProtected = hekate.encStringEncryptXc20p(
        "ok:1",
        newOrgSymKey,
        cipherKeyBytes,
        aad,
      );
      cipherRewraps.push({ cipher_id: c.id, protected_cipher_key: newProtected });
    }

    // 7. Re-encrypt every collection name under the new sym key. Same
    //    1:1 enumeration contract as cipher_rewraps; without it the
    //    server (correctly) rejects the revoke. Collection names use
    //    collectionNameAad which is independent of the sym key, so we
    //    decrypt under old + re-encrypt under new with the same AAD.
    const collections = await apiGet(
      `/api/v1/orgs/${encodeURIComponent(orgId)}/collections`,
    );
    const collectionRewraps = [];
    for (const c of collections) {
      const aad = hekate.collectionNameAad(c.id, c.org_id);
      let nameBytes;
      try {
        nameBytes = hekate.encStringDecryptXc20p(c.name, oldOrgSymKey, aad);
      } catch (err) {
        throw new Error(
          `failed to decrypt collection ${c.id} name under the old org sym key — ` +
            `refusing to rotate. ${err.message || err}`,
        );
      }
      const newName = hekate.encStringEncryptXc20p(
        "ok:1",
        newOrgSymKey,
        nameBytes,
        aad,
      );
      collectionRewraps.push({ collection_id: c.id, name: newName });
    }

    // 8. POST.
    await apiPost(
      `/api/v1/orgs/${encodeURIComponent(orgId)}/members/${encodeURIComponent(targetUserId)}/revoke`,
      {
        next_roster: {
          canonical_b64: signedNext.canonicalB64,
          signature_b64: signedNext.signatureB64,
        },
        next_org_sym_key_id: newOrgSymKeyId,
        owner_protected_org_key: ownerProtectedOrgKey,
        rewrap_envelopes: rewrapEnvelopes,
        cipher_rewraps: cipherRewraps,
        collection_rewraps: collectionRewraps,
      },
    );

    // 8. Refresh local org pin to track the new roster version.
    //    Signing pubkey is unchanged by member-removal rotation, so
    //    the fingerprint stays the same.
    const existingPin = pins.org_pins[orgId];
    await pinOrg(myUserId, orgId, {
      org_id: orgId,
      signing_pubkey_b64: org.signing_pubkey,
      fingerprint:
        existingPin?.fingerprint ??
        "SHA256:" +
          b64encode(
            hekate.sha256(
              hekate.orgBundleCanonicalBytes(
                orgId,
                org.name,
                b64decode(org.signing_pubkey),
                org.owner_user_id,
              ),
            ),
          ),
      first_seen_at: existingPin?.first_seen_at ?? new Date().toISOString(),
      last_roster_version: next.version,
      last_roster_canonical_b64: signedNext.canonicalB64,
    });

    toast(`Removed "${label}" + rotated org key.`);
    renderMembersList(orgId);
  } catch (err) {
    const errEl = document.getElementById("membersErr");
    if (errEl) {
      errEl.textContent = err.message || String(err);
      errEl.hidden = false;
    } else {
      toast("Remove failed: " + (err.message || String(err)), 4500);
    }
  }
}

// ===========================================================================
// M4.6 — owner-only policies list + enable/disable toggles
// ===========================================================================
//
// Mirrors the web vault's `lib/orgWrite.ts::{listPolicies, setPolicy}`
// + `OrgDetail.tsx` policies card. Shows the five known policy types
// regardless of whether the server has a row yet, so an owner can
// enable any of them with a single click. Server enforces `single_org`
// on /accept; the rest are reserved for client-side enforcement and
// surface unchanged via /sync.

const POLICY_TYPES = [
  "master_password_complexity",
  "vault_timeout",
  "password_generator_rules",
  "single_org",
  "restrict_send",
];

const POLICY_LABELS = {
  master_password_complexity: "Master password complexity",
  vault_timeout: "Vault timeout",
  password_generator_rules: "Password generator rules",
  single_org: "Single organization",
  restrict_send: "Restrict Send",
};

const POLICY_DESCRIPTIONS = {
  master_password_complexity:
    "Client-enforced rules on master-password length / complexity at register / change-password.",
  vault_timeout:
    "Client-enforced max idle before the vault re-locks or logs out.",
  password_generator_rules:
    "Client-enforced floors for `hekate generate` (length, character classes).",
  single_org:
    "Server-enforced. Members of this org cannot accept invites to a second org.",
  restrict_send:
    "Reserved. Send subsystem will honor this once enforcement lands.",
};

async function renderPoliciesList(orgId) {
  clearTickers();
  const content = `
    <p class="muted small">org: <code>${escapeHtml(orgId)}</code></p>
    <p class="muted small">
      Toggle policies on or off for this org. Server enforces
      <code>single_org</code> at /accept; the rest are delivered via
      /sync and applied client-side at max strictness.
    </p>
    <p class="error" id="policiesErr" hidden></p>
    <div id="policiesStatus">Loading…</div>
    <div id="policiesRows"></div>`;
  app.innerHTML = subShellHtml({ title: "Policies", content });
  wireSubShell({ onBack: () => renderOrgsList() });

  let org;
  try {
    org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  } catch (err) {
    document.getElementById("policiesStatus").textContent =
      "Error: " + err.message;
    return;
  }
  const myUserId = await currentUserId();
  if (org.owner_user_id !== myUserId) {
    document.getElementById("policiesStatus").textContent =
      "Only the org owner can manage policies.";
    return;
  }

  let rows;
  try {
    rows = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}/policies`);
  } catch (err) {
    document.getElementById("policiesStatus").textContent =
      "Error: " + err.message;
    return;
  }
  const byType = {};
  for (const p of rows) byType[p.policy_type] = p;
  paintPoliciesRows(orgId, byType);
}

function paintPoliciesRows(orgId, byType) {
  const status = document.getElementById("policiesStatus");
  if (status) status.textContent = "";
  const container = document.getElementById("policiesRows");
  container.innerHTML = POLICY_TYPES.map((type) => {
    const p = byType[type];
    const enabled = !!(p && p.enabled);
    const label = POLICY_LABELS[type] || type;
    const desc = POLICY_DESCRIPTIONS[type] || "";
    const action = enabled ? "disable" : "enable";
    return `
      <div class="row">
        <div class="row-main">
          <div class="row-name">${escapeHtml(label)}</div>
          <div class="muted small">${escapeHtml(desc)}</div>
          <code class="muted small">${escapeHtml(type)}</code>
        </div>
        <div class="row-actions">
          <span class="muted small">${enabled ? "enabled" : "disabled"}</span>
          <button class="text" data-act="toggle-policy" data-type="${escapeAttr(type)}" data-action="${action}">
            ${enabled ? "Disable" : "Enable"}
          </button>
        </div>
      </div>`;
  }).join("");
  container
    .querySelectorAll("button[data-act='toggle-policy']")
    .forEach((btn) => {
      btn.addEventListener("click", () =>
        onTogglePolicy(orgId, btn.dataset.type, byType, btn),
      );
    });
}

async function onTogglePolicy(orgId, policyType, byType, btn) {
  const errEl = document.getElementById("policiesErr");
  if (errEl) errEl.hidden = true;
  const existing = byType[policyType];
  const nextEnabled = !(existing && existing.enabled);
  const originalLabel = btn.textContent;
  btn.textContent = "Saving…";
  btn.disabled = true;
  try {
    const r = await checkResponse(
      await authedFetch(
        "PUT",
        `/api/v1/orgs/${encodeURIComponent(orgId)}/policies/${encodeURIComponent(policyType)}`,
        { enabled: nextEnabled, config: existing?.config ?? {} },
      ),
    );
    byType[policyType] = r;
    paintPoliciesRows(orgId, byType);
    toast(`${POLICY_LABELS[policyType] || policyType}: ${nextEnabled ? "enabled" : "disabled"}`);
  } catch (err) {
    btn.textContent = originalLabel;
    btn.disabled = false;
    if (errEl) {
      errEl.textContent = err.message || String(err);
      errEl.hidden = false;
    } else {
      toast("Toggle failed: " + (err.message || String(err)), 4500);
    }
  }
}

// ===========================================================================
// M4.5b — rotate-confirm consumer (member side of org-key rotation)
// ===========================================================================
//
// When the owner removes a member, every remaining non-owner member
// gets a signcryption envelope on /sync containing the new org sym
// key. This function decrypts it under the caller's X25519 priv,
// verifies under the owner's pinned signing key, re-wraps the new
// sym key under the caller's account_key, and POSTs /rotate-confirm
// to swap the membership row's protected_org_key + clear pending.
// Mirror of CLI's `consume_pending_envelope` and the web vault's
// `lib/orgWrite.ts::confirmRotation`.

async function onConfirmRotation(orgEntry) {
  if (!orgEntry || !orgEntry.pending_envelope) {
    toast("no pending envelope on this org", 3000);
    return;
  }
  toast("Confirming rotation…", 1500);

  try {
    const session = await loadSession();
    if (!session.protected_account_private_key) {
      throw new Error(
        "session is missing protected_account_private_key — log out and back in",
      );
    }
    const accountKey = b64urlDecode(session.account_key_b64);
    const myUserId = await currentUserId();

    // Cross-check sender_id against server-reported owner.
    const fullOrg = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgEntry.org_id)}`);
    if (orgEntry.pending_envelope.sender_id !== fullOrg.owner_user_id) {
      throw new Error(
        `envelope sender ${orgEntry.pending_envelope.sender_id} does not match the ` +
          `org owner ${fullOrg.owner_user_id} — possible rotation injection`,
      );
    }

    // Owner must be in our peer pins.
    const pins = await loadPins(myUserId);
    const ownerPin = pins.peer_pins[fullOrg.owner_user_id];
    if (!ownerPin) {
      throw new Error(
        `org owner ${fullOrg.owner_user_id} is not in peer pins — pin them ` +
          `(via Invite peer or hekate peer fetch) and verify the fingerprint ` +
          `out of band before consuming the rotation.`,
      );
    }
    const ownerSigningPk = b64decode(ownerPin.account_signing_pubkey_b64);

    // Decrypt our X25519 priv (wrapped under account_key).
    const myX25519Priv = hekate.encStringDecryptXc20p(
      session.protected_account_private_key,
      accountKey,
      enc.encode("pmgr-account-x25519-priv"),
    );

    const plaintext = hekate.signcryptOpenEnvelope(
      orgEntry.pending_envelope,
      ownerSigningPk,
      myUserId,
      myX25519Priv,
    );
    const payload = JSON.parse(dec.decode(plaintext));
    if (payload.kind !== "pmgr-org-key-rotation-v1") {
      throw new Error("envelope payload kind is not pmgr-org-key-rotation-v1");
    }
    if (payload.org_id !== orgEntry.org_id) {
      throw new Error(
        "envelope org_id does not match the org being rotated — refusing",
      );
    }

    // Cross-check the claimed key_id against the verified roster.
    const roster = hekate.decodeOrgRosterCanonical(b64decode(orgEntry.roster.canonical_b64));
    if (payload.org_sym_key_id !== roster.orgSymKeyId) {
      throw new Error(
        `envelope org_sym_key_id (${payload.org_sym_key_id}) does not match ` +
          `the current org_sym_key_id (${roster.orgSymKeyId}) bound into the ` +
          `verified roster — refusing to consume`,
      );
    }
    const newSymKey = b64decode(payload.org_sym_key_b64);
    if (newSymKey.length !== 32) {
      throw new Error("new org sym key has wrong length");
    }

    // Re-wrap under our account_key.
    const protectedOrgKey = hekate.encStringEncryptXc20p(
      "ak:1",
      accountKey,
      newSymKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    await apiPost(
      `/api/v1/orgs/${encodeURIComponent(orgEntry.org_id)}/rotate-confirm`,
      {
        protected_org_key: protectedOrgKey,
        org_sym_key_id: payload.org_sym_key_id,
      },
    );

    // Refresh local org pin to track the new roster (signing pubkey
    // unchanged by member-removal rotation).
    const existingPin = pins.org_pins[orgEntry.org_id];
    if (existingPin) {
      await pinOrg(myUserId, orgEntry.org_id, {
        ...existingPin,
        last_roster_version: roster.version,
        last_roster_canonical_b64: orgEntry.roster.canonical_b64,
      });
    }

    toast(`Confirmed rotation for "${fullOrg.name}".`);
    renderOrgsList();
  } catch (err) {
    toast("Confirm failed: " + (err.message || String(err)), 4500);
  }
}

// ===========================================================================
// M3.14d — collection management (list / create / delete)
// ===========================================================================
//
// Collection NAMES are encrypted under the org symmetric key with an
// AAD bound to (collection_id, org_id). Membership management
// (grant/revoke/list) is server-side ACL — those endpoints don't
// need crypto, but we leave them on the CLI for now since they're
// less commonly used than create/list/delete.

async function renderCollectionsList(orgId) {
  clearTickers();
  const content = `
    <p class="muted small">org: <code>${escapeHtml(orgId)}</code></p>
    <div style="display:flex; gap:8px; margin-bottom: 12px;">
      <button id="newCollectionBtn">+ New collection</button>
    </div>
    <div id="collectionsStatus">Loading…</div>
    <div id="collectionsRows"></div>`;
  app.innerHTML = subShellHtml({ title: "Collections", content });
  wireSubShell({ onBack: () => renderOrgsList() });
  document
    .getElementById("newCollectionBtn")
    .addEventListener("click", () => renderCreateCollection(orgId));

  let org;
  try {
    org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
  } catch (err) {
    document.getElementById("collectionsStatus").textContent = "Error: " + err.message;
    return;
  }
  let cols;
  try {
    cols = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}/collections`);
  } catch (err) {
    document.getElementById("collectionsStatus").textContent = "Error: " + err.message;
    return;
  }

  const session = await loadSession();
  const accountKey = b64urlDecode(session.account_key_b64);
  let orgSymKey;
  try {
    orgSymKey = hekate.encStringDecryptXc20p(
      org.my_protected_org_key,
      accountKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );
  } catch (_) {
    document.getElementById("collectionsStatus").textContent =
      "Could not unwrap org sym key — collection names unreadable.";
    return;
  }

  const status = document.getElementById("collectionsStatus");
  const rows = document.getElementById("collectionsRows");
  if (!cols || cols.length === 0) {
    status.textContent = "No collections yet.";
    rows.innerHTML = "";
    return;
  }
  status.textContent = `${cols.length} collection${cols.length === 1 ? "" : "s"}`;

  const decoded = cols.map((c) => {
    let name = "<undecryptable>";
    try {
      const aad = hekate.collectionNameAad(c.id, c.org_id);
      name = dec.decode(hekate.encStringDecryptXc20p(c.name, orgSymKey, aad));
    } catch (_) {
      /* keep placeholder */
    }
    return { ...c, _name: name };
  });

  const isOwner = org.owner_user_id === session.user_id;
  rows.innerHTML = decoded
    .map((c) => {
      const del = isOwner
        ? `<button class="secondary danger" data-act="delete">Delete</button>`
        : "";
      return `
        <div class="row" data-id="${escapeAttr(c.id)}">
          <div class="row-main">
            <div class="row-name">${escapeHtml(c._name)}</div>
            <div class="muted small"><code>${escapeHtml(c.id)}</code></div>
          </div>
          <div class="row-actions">${del}</div>
        </div>`;
    })
    .join("");

  rows.querySelectorAll("button[data-act='delete']").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.closest(".row").dataset.id;
      onDeleteCollection(orgId, id);
    });
  });
}

function renderCreateCollection(orgId) {
  clearTickers();
  const content = `
    <form id="newCollectionForm">
      <label>
        <span>Name</span>
        <input name="name" required autofocus maxlength="120"
               placeholder="e.g. Engineering">
      </label>
      <p class="muted small">
        The name is encrypted under the org symmetric key before
        upload. The server only sees ciphertext.
      </p>
      <p class="error" id="newCollectionErr" hidden></p>
      <div style="display:flex; gap:8px;">
        <button type="submit" id="newCollectionSubmit">Create</button>
        <button type="button" class="secondary" id="cancelBtn">Cancel</button>
      </div>
    </form>`;
  const back = () => renderCollectionsList(orgId);
  app.innerHTML = subShellHtml({ title: "New collection", content });
  wireSubShell({ onBack: back });
  document.getElementById("cancelBtn").addEventListener("click", back);
  document
    .getElementById("newCollectionForm")
    .addEventListener("submit", (e) => onCreateCollection(e, orgId));
}

async function onCreateCollection(e, orgId) {
  e.preventDefault();
  const errEl = document.getElementById("newCollectionErr");
  errEl.hidden = true;
  const submit = document.getElementById("newCollectionSubmit");
  submit.disabled = true;
  submit.textContent = "Creating…";

  try {
    const fd = new FormData(e.target);
    const name = (fd.get("name") || "").trim();
    if (!name) throw new Error("name is required");

    const session = await loadSession();
    const accountKey = b64urlDecode(session.account_key_b64);

    const org = await apiGet(`/api/v1/orgs/${encodeURIComponent(orgId)}`);
    const orgSymKey = hekate.encStringDecryptXc20p(
      org.my_protected_org_key,
      accountKey,
      enc.encode(AAD_PROTECTED_ACCOUNT_KEY),
    );

    const collectionId = crypto.randomUUID();
    const aad = hekate.collectionNameAad(collectionId, orgId);
    const nameWire = hekate.encStringEncryptXc20p(
      "ok:1",
      orgSymKey,
      enc.encode(name),
      aad,
    );

    await apiPost(`/api/v1/orgs/${encodeURIComponent(orgId)}/collections`, {
      id: collectionId,
      name: nameWire,
    });
    toast(`Created collection "${name}"`);
    renderCollectionsList(orgId);
  } catch (err) {
    submit.disabled = false;
    submit.textContent = "Create";
    errEl.textContent = err.message || String(err);
    errEl.hidden = false;
  }
}

async function onDeleteCollection(orgId, collectionId) {
  if (
    !window.confirm(
      "Delete this collection? Ciphers in it will lose the org-side membership.",
    )
  ) {
    return;
  }
  try {
    await apiDelete(
      `/api/v1/orgs/${encodeURIComponent(orgId)}/collections/${encodeURIComponent(collectionId)}`,
    );
    toast("Collection deleted.");
    renderCollectionsList(orgId);
  } catch (err) {
    toast("Delete failed: " + (err.message || String(err)), 4000);
  }
}

/// Cheap member-count from the canonical roster bytes. We don't
/// fully decode the canonical encoding here (that lives on the
/// Rust side as `hekate-core::org_roster::decode_canonical`); we
/// instead read the entry-count u32 at the well-known offset.
/// Returns -1 on parse failure so the UI shows a `?`.
function countRosterMembers(roster) {
  try {
    const canonical = b64decode(roster.canonical_b64);
    // Canonical layout from `hekate-core::org_roster::canonical_bytes`:
    //   DST                       "pmgr-org-roster-v1\x00"  (19 bytes)
    //   version                   u64 LE        (8 bytes)
    //   parent_canonical_sha256   [u8; 32]
    //   org_id                    u32 len + bytes
    //   timestamp                 u32 len + bytes
    //   entries                   u32 count   ← what we want
    //   entries × { user_id u32+bytes, role u32+bytes }
    //   org_sym_key_id            u32 len + bytes  (trailer)
    let p = 0;
    const dst = new TextEncoder().encode("pmgr-org-roster-v1\x00");
    if (canonical.length < dst.length) return -1;
    for (let i = 0; i < dst.length; i++) {
      if (canonical[p + i] !== dst[i]) return -1;
    }
    p += dst.length;
    const u32 = (off) =>
      canonical[off] |
      (canonical[off + 1] << 8) |
      (canonical[off + 2] << 16) |
      (canonical[off + 3] << 24);
    p += 8; // version u64
    p += 32; // parent_canonical_sha256
    const orgIdLen = u32(p);
    p += 4 + orgIdLen;
    const tsLen = u32(p);
    p += 4 + tsLen;
    return u32(p) >>> 0; // entries u32
  } catch (_) {
    return -1;
  }
}

// ===========================================================================
// Entry
// ===========================================================================

main().catch((e) => {
  app.textContent = "Error: " + e.message;
});
