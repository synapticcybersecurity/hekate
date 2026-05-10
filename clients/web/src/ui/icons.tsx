/* Lucide-derived inline SVG icons. Lifted from
 * clients/extension/popup/popup.js's ICON dict so the web vault matches
 * the popup's exact glyph set. All icons set `stroke="currentColor"` +
 * `fill="none"` (per-cipher tints come from CSS color via parent class).
 */
import type { JSX } from "solid-js";

interface IconProps {
  class?: string;
  size?: number;
}

function svg(path: JSX.Element, p: IconProps): JSX.Element {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={p.size ?? 24}
      height={p.size ?? 24}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width={2}
      stroke-linecap="round"
      stroke-linejoin="round"
      class={p.class}
    >
      {path}
    </svg>
  );
}

export const IconVault = (p: IconProps) =>
  svg(
    <>
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </>,
    p,
  );

export const IconSend = (p: IconProps) =>
  svg(
    <>
      <path d="M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7" />
      <path d="m16 6-4-4-4 4" />
      <path d="M12 2v14" />
    </>,
    p,
  );

export const IconOrg = (p: IconProps) =>
  svg(
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M9 21V9h6v12" />
      <path d="M3 9h18" />
    </>,
    p,
  );

export const IconSettings = (p: IconProps) =>
  svg(
    <>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      <circle cx="12" cy="12" r="3" />
    </>,
    p,
  );

export const IconSearch = (p: IconProps) =>
  svg(
    <>
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </>,
    p,
  );

export const IconPlus = (p: IconProps) =>
  svg(
    <>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </>,
    p,
  );

export const IconCopy = (p: IconProps) =>
  svg(
    <>
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </>,
    p,
  );

export const IconBack = (p: IconProps) =>
  svg(<path d="m15 18-6-6 6-6" />, p);

export const IconEdit = (p: IconProps) =>
  svg(
    <>
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4Z" />
    </>,
    p,
  );

export const IconEye = (p: IconProps) =>
  svg(
    <>
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </>,
    p,
  );

export const IconEyeOff = (p: IconProps) =>
  svg(
    <>
      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
      <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
      <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
      <line x1="2" y1="2" x2="22" y2="22" />
    </>,
    p,
  );

// Per-cipher-type glyphs (rendered inside a tinted square avatar).
export const IconLogin = (p: IconProps) =>
  svg(
    <>
      <circle cx="11" cy="13" r="6" />
      <path d="m17 13 4-4" />
      <path d="m21 9-2-2" />
    </>,
    p,
  );

export const IconNote = (p: IconProps) =>
  svg(
    <>
      <path d="M14 3v4a1 1 0 0 0 1 1h4" />
      <path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2" />
    </>,
    p,
  );

export const IconCard = (p: IconProps) =>
  svg(
    <>
      <rect x="2" y="5" width="20" height="14" rx="2" />
      <path d="M2 10h20" />
    </>,
    p,
  );

export const IconIdentity = (p: IconProps) =>
  svg(
    <>
      <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </>,
    p,
  );

export const IconSsh = (p: IconProps) =>
  svg(
    <>
      <path d="M21 2 11 12" />
      <path d="m18 5 3 3" />
      <circle cx="6" cy="18" r="4" />
    </>,
    p,
  );

export const IconApi = (p: IconProps) =>
  svg(
    <>
      <path d="M2 12h6" />
      <path d="M16 12h6" />
      <circle cx="12" cy="12" r="4" />
    </>,
    p,
  );

export const IconTotp = (p: IconProps) =>
  svg(
    <>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </>,
    p,
  );

export function iconForCipherType(type: number) {
  return (
    {
      1: IconLogin,
      2: IconNote,
      3: IconCard,
      4: IconIdentity,
      5: IconSsh,
      6: IconTotp,
      7: IconApi,
    }[type] ?? IconNote
  );
}
