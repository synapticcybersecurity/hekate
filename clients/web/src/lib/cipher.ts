/* Cipher decryption helpers, ported from
 * clients/extension/popup/popup.js:189-199 + 3227-3270.
 *
 * Every per-cipher field commits to the cipher's id (and where
 * relevant, type) via AAD, mitigating the BW04/LP06 server-side row
 * substitution attack: the server cannot move a `protected_cipher_key`
 * onto another row, swap a card's name onto a login, or flip
 * `cipher_type` to make a card render as a login.
 *
 * The AAD constants are protocol-frozen (`pmgr-cipher-key-v2:`,
 * `pmgr-cipher-name-v2:…`, `…-notes-v2:…`, `…-data-v2:…`) — see
 * `project_rename_hekate.md` memory.
 */
import type { HekateCore } from "../wasm-types";

const enc = new TextEncoder();
const dec = new TextDecoder();

export function aadProtectedCipherKey(cipherId: string): Uint8Array {
  return enc.encode(`pmgr-cipher-key-v2:${cipherId}`);
}

export function aadCipherName(cipherId: string, cipherType: number): Uint8Array {
  return enc.encode(`pmgr-cipher-name-v2:${cipherId}:${cipherType}`);
}

export function aadCipherNotes(cipherId: string, cipherType: number): Uint8Array {
  return enc.encode(`pmgr-cipher-notes-v2:${cipherId}:${cipherType}`);
}

export function aadCipherData(cipherId: string, cipherType: number): Uint8Array {
  return enc.encode(`pmgr-cipher-data-v2:${cipherId}:${cipherType}`);
}

/* Cipher-type IDs (mirror hekate-core::cipher::CipherType + popup.js
 * iconForCipherType). The CLI/server use numeric ids on the wire. */
export const CipherType = {
  Login: 1,
  Note: 2,
  Card: 3,
  Identity: 4,
  SshKey: 5,
  Totp: 6,
  Api: 7,
} as const;
export type CipherTypeId = (typeof CipherType)[keyof typeof CipherType];

/* Per-type field metadata. Single source of truth for both the EditCipher
 * form (C.3b) and the CipherDetail render (C.3a). Field NAMES are
 * protocol-frozen — they're keys inside the encrypted `data` JSON blob
 * and changing one would orphan existing ciphers. Mirrors popup.js's
 * CIPHER_TYPES exactly so a cipher created in one client decrypts
 * cleanly in the other.
 */
export type FieldKind = "text" | "email" | "url" | "tel" | "password" | "textarea";
export interface FieldDef {
  name: string;
  label: string;
  kind: FieldKind;
  /** Show a reveal/mask toggle (and obscure the value in list views). */
  reveal?: boolean;
  /** Show a "Generate" button (Login password only). */
  generate?: boolean;
  /** textarea row count. */
  rows?: number;
  placeholder?: string;
  maxLength?: number;
  /** When set, omit this field's `<input autocomplete>` for browsers
   *  that overzealously offer to autofill credentials into them. */
  autocompleteOff?: boolean;
}

export interface CipherTypeDef {
  id: number;
  label: string;
  fields: FieldDef[];
}

export const CIPHER_TYPE_DEFS: Record<number, CipherTypeDef> = {
  [CipherType.Login]: {
    id: CipherType.Login,
    label: "Login",
    fields: [
      { name: "username", label: "Username", kind: "text" },
      {
        name: "password",
        label: "Password",
        kind: "password",
        reveal: true,
        generate: true,
      },
      {
        name: "uri",
        label: "URI",
        kind: "url",
        placeholder: "https://example.com",
      },
    ],
  },
  [CipherType.Note]: {
    id: CipherType.Note,
    label: "Secure note",
    fields: [],
  },
  [CipherType.Card]: {
    id: CipherType.Card,
    label: "Card",
    fields: [
      { name: "cardholderName", label: "Cardholder", kind: "text" },
      {
        name: "brand",
        label: "Brand",
        kind: "text",
        placeholder: "Visa / Mastercard / …",
      },
      {
        name: "number",
        label: "Number",
        kind: "password",
        reveal: true,
        autocompleteOff: true,
      },
      {
        name: "expMonth",
        label: "Exp month",
        kind: "text",
        placeholder: "12",
        maxLength: 2,
      },
      {
        name: "expYear",
        label: "Exp year",
        kind: "text",
        placeholder: "2030",
        maxLength: 4,
      },
      {
        name: "code",
        label: "CVV",
        kind: "password",
        reveal: true,
        autocompleteOff: true,
        maxLength: 4,
      },
    ],
  },
  [CipherType.Identity]: {
    id: CipherType.Identity,
    label: "Identity",
    fields: [
      { name: "title", label: "Title", kind: "text" },
      { name: "firstName", label: "First name", kind: "text" },
      { name: "middleName", label: "Middle name", kind: "text" },
      { name: "lastName", label: "Last name", kind: "text" },
      { name: "company", label: "Company", kind: "text" },
      { name: "email", label: "Email", kind: "email" },
      { name: "phone", label: "Phone", kind: "tel" },
      { name: "address1", label: "Address line 1", kind: "text" },
      { name: "address2", label: "Address line 2", kind: "text" },
      { name: "city", label: "City", kind: "text" },
      { name: "state", label: "State", kind: "text" },
      { name: "postalCode", label: "Postal code", kind: "text" },
      { name: "country", label: "Country", kind: "text" },
      { name: "ssn", label: "SSN", kind: "password", reveal: true, autocompleteOff: true },
      {
        name: "passportNumber",
        label: "Passport",
        kind: "password",
        reveal: true,
        autocompleteOff: true,
      },
      {
        name: "licenseNumber",
        label: "License",
        kind: "password",
        reveal: true,
        autocompleteOff: true,
      },
    ],
  },
  [CipherType.SshKey]: {
    id: CipherType.SshKey,
    label: "SSH key",
    fields: [
      {
        name: "publicKey",
        label: "Public key",
        kind: "textarea",
        rows: 3,
        placeholder: "ssh-ed25519 AAAA… user@host",
      },
      {
        name: "privateKey",
        label: "Private key",
        kind: "textarea",
        rows: 5,
        reveal: true,
        placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----",
      },
      {
        name: "keyFingerprint",
        label: "Fingerprint",
        kind: "text",
        placeholder: "SHA256:…",
      },
    ],
  },
  [CipherType.Totp]: {
    id: CipherType.Totp,
    label: "TOTP",
    fields: [
      {
        name: "secret",
        label: "Secret",
        kind: "password",
        reveal: true,
        autocompleteOff: true,
        placeholder: "otpauth://totp/… or BASE32",
      },
      { name: "issuer", label: "Issuer", kind: "text", placeholder: "GitHub" },
      { name: "accountName", label: "Account", kind: "text" },
    ],
  },
};

/** Order shown in the type picker (matches popup ADD_PICKER_ORDER —
 *  API type 7 isn't pickable; you can view existing API ciphers but
 *  not create new ones from the UI). */
export const ADD_PICKER_ORDER: number[] = [
  CipherType.Login,
  CipherType.Note,
  CipherType.Card,
  CipherType.Identity,
  CipherType.SshKey,
  CipherType.Totp,
];

/* Wire shape from `/api/v1/sync` (changes.ciphers[]). Only the fields
 * we actually consume; the server may add more. */
export interface CipherView {
  id: string;
  type: number;
  folder_id: string | null;
  protected_cipher_key: string;
  name: string;
  notes: string | null;
  data: string;
  favorite: boolean;
  revision_date: string;
  creation_date: string;
  deleted_date: string | null;
  org_id?: string | null;
  collection_ids?: string[];
  permissions?: "manage" | "read" | "read_hide_passwords";
}

export interface DecryptedListItem {
  id: string;
  type: number;
  name: string;
  data: Record<string, unknown> | null;
  favorite: boolean;
  folderId: string | null;
  orgId: string | null;
  permissions: "manage" | "read" | "read_hide_passwords";
  revisionDate: string;
  deletedDate: string | null;
}

export interface DecryptedFullItem extends DecryptedListItem {
  notes: string;
}

/** List-view decrypt: name + data only. notes is excluded so the
 *  cheap-path doesn't pay the extra AEAD on every row render. Returns
 *  `name = "<undecryptable>"` on failure rather than throwing — the
 *  list keeps rendering even if one row is broken (typically pre-v2
 *  legacy AAD or org-key-rotation pickup not yet confirmed). */
export function decryptForList(
  hekate: HekateCore,
  c: CipherView,
  accountKey: Uint8Array,
): DecryptedListItem {
  let name = "<undecryptable>";
  let data: Record<string, unknown> | null = null;
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
      data = JSON.parse(dataJson || "{}") as Record<string, unknown>;
    }
  } catch {
    /* leave name as <undecryptable> */
  }
  return {
    id: c.id,
    type: c.type,
    name,
    data,
    favorite: c.favorite,
    folderId: c.folder_id,
    orgId: c.org_id ?? null,
    permissions: c.permissions ?? "manage",
    revisionDate: c.revision_date,
    deletedDate: c.deleted_date,
  };
}

/** Full decrypt: list-view + notes. Used by CipherDetail. */
export function decryptFull(
  hekate: HekateCore,
  c: CipherView,
  accountKey: Uint8Array,
): DecryptedFullItem {
  const list = decryptForList(hekate, c, accountKey);
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
  } catch {
    /* ignore */
  }
  return { ...list, notes };
}
