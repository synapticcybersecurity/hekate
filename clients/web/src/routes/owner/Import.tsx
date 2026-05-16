/* Vault import (D.1 — Bitwarden JSON).
 *
 * Three phases (signal-driven):
 *   upload    → pick a Bitwarden JSON export
 *   preview   → dry-run summary (folder/cipher counts + warnings)
 *   committing → folder loop + cipher loop + manifest re-sign
 *   done      → success summary with succeeded/failed/skipped counts
 *
 * Mirrors the CLI orchestration at
 * `crates/hekate-cli/src/commands/import.rs:121-203`. Parsing is done
 * client-side via the `parseBitwardenJson` WASM binding — the export
 * blob never leaves the browser. Per-cipher failures are non-fatal
 * (collected for display); the manifest is re-signed once at the end.
 */
import { createSignal, For, Match, Show, Switch } from "solid-js";

import { ApiError, authedFetch } from "../../lib/api";
import { aadFolderName, CipherType } from "../../lib/cipher";
import { saveCipher, type CipherDraft } from "../../lib/cipherWrite";
import { uploadManifest } from "../../lib/manifest";
import { getSession } from "../../lib/session";
import { loadHekateCore } from "../../wasm";
import type { ProjectedImport } from "../../wasm-types";
import { SubShell } from "../../ui/Shell";

/* Server rate-limit posture (per crates/hekate-server/src/rate_limit.rs):
 *   600 req/min, burst 50 — so a bulk import naturally trips 429s once
 *   the burst is spent. The server replies with `Retry-After: <secs>`
 *   and `{retry_after: <secs>}` in the body; we honor whichever is
 *   present, falling back to exponential backoff capped at 30s. */
const MAX_429_RETRIES = 8;

async function withRetryOn429<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (
        !(err instanceof ApiError) ||
        err.status !== 429 ||
        attempt >= MAX_429_RETRIES
      ) {
        throw err;
      }
      const wait = retryAfterMs(err) ?? Math.min(2 ** attempt, 30) * 1000;
      await sleep(wait);
    }
  }
}

function retryAfterMs(err: ApiError): number | null {
  const body = err.body as { retry_after?: unknown } | null;
  if (body && typeof body.retry_after === "number") {
    return Math.max(1, body.retry_after) * 1000;
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const enc = new TextEncoder();

export interface ImportProps {
  onBack: () => void;
  /** Bump the vault reload key so the freshly-imported items appear
   *  when the user navigates back. */
  onImported: () => void;
}

type Phase =
  | { kind: "upload" }
  | {
      kind: "preview";
      projected: ProjectedImport;
      fileName: string;
    }
  | {
      kind: "committing";
      progress: { current: number; total: number };
      message: string;
    }
  | {
      kind: "done";
      succeeded: number;
      failed: Array<{ name: string; reason: string }>;
      warnings: string[];
    };

export function Import(props: ImportProps) {
  const [phase, setPhase] = createSignal<Phase>({ kind: "upload" });
  const [error, setError] = createSignal<string | null>(null);

  async function onFileSelected(file: File) {
    setError(null);
    try {
      const text = await file.text();
      const hekate = await loadHekateCore();
      const projected = hekate.parseBitwardenJson(text);
      setPhase({ kind: "preview", projected, fileName: file.name });
    } catch (err) {
      setError(messageOf(err));
    }
  }

  async function commit(projected: ProjectedImport) {
    const session = getSession();
    if (!session) {
      setError("Session expired — log in again to import.");
      return;
    }
    const hekate = await loadHekateCore();
    const accountKey = session.accountKey;

    setPhase({
      kind: "committing",
      progress: { current: 0, total: projected.folders.length + projected.ciphers.length },
      message: "Creating folders…",
    });

    // 1. Materialize folders. Map the parser's `bitwardenFolderId`
    //    field (rewritten to a folder *name* during projection) to
    //    the server-allocated folder id, so we can thread it onto
    //    each cipher below.
    const folderMap = new Map<string, string>();
    let step = 0;
    for (const name of projected.folders) {
      try {
        const nameEnc = hekate.encStringEncryptXc20p(
          "ak:1",
          accountKey,
          enc.encode(name),
          aadFolderName(),
        );
        const view = await withRetryOn429(async () => {
          const r = await authedFetch("POST", "/api/v1/folders", {
            body: { name: nameEnc },
          });
          if (!r.ok) {
            let body: unknown = null;
            try {
              body = await r.json();
            } catch {
              /* empty / non-JSON */
            }
            throw new ApiError(r.status, `${r.status} ${r.statusText}`, body);
          }
          return (await r.json()) as { id: string };
        });
        folderMap.set(name, view.id);
      } catch (err) {
        // Folder creation failure is fatal for the folder loop only —
        // we still try ciphers (they'll just land at the vault root).
        // Surface it as a warning so the user sees the partial state.
        projected.warnings.push(
          `failed to create folder ${JSON.stringify(name)}: ${messageOf(err)}`,
        );
      }
      step += 1;
      setPhase({
        kind: "committing",
        progress: { current: step, total: projected.folders.length + projected.ciphers.length },
        message: `Folder ${step}/${projected.folders.length}: ${name}`,
      });
    }

    // 2. Materialize ciphers. Per-item failures accumulate in
    //    `failed`; the manifest re-sign at the end covers everything
    //    that did succeed.
    const failed: Array<{ name: string; reason: string }> = [];
    let succeeded = 0;
    const cipherTotal = projected.ciphers.length;
    for (let i = 0; i < cipherTotal; i++) {
      const c = projected.ciphers[i];
      const folderId = c.bitwardenFolderId
        ? (folderMap.get(c.bitwardenFolderId) ?? null)
        : null;
      try {
        const data = JSON.parse(c.dataJson) as Record<string, string>;
        const draft: CipherDraft = {
          id: null,
          type: c.cipherType,
          name: c.name,
          notes: c.notes,
          data,
          favorite: c.favorite,
          folderId,
        };
        await withRetryOn429(() => saveCipher(draft, accountKey));
        succeeded += 1;
      } catch (err) {
        failed.push({ name: c.name, reason: messageOf(err) });
      }
      step += 1;
      setPhase({
        kind: "committing",
        progress: { current: step, total: projected.folders.length + projected.ciphers.length },
        message: `Cipher ${i + 1}/${cipherTotal}: ${c.name}`,
      });
    }

    // 3. Re-sign the BW04 manifest once at the end (CLI parity:
    //    `manifest::sync_and_upload(...)`). Retries on 429 — a
    //    silent failure here is bad UX (vault refuses to render
    //    until the next write re-signs), and the manifest endpoint
    //    is on the general bucket too.
    if (succeeded > 0) {
      setPhase({
        kind: "committing",
        progress: { current: step, total: step },
        message: "Re-signing vault manifest…",
      });
      try {
        await withRetryOn429(() => uploadManifest());
      } catch (err) {
        projected.warnings.push(
          `manifest re-sign failed (${messageOf(err)}) — vault may refuse to render until the next write triggers a fresh sign`,
        );
      }
    }

    setPhase({
      kind: "done",
      succeeded,
      failed,
      warnings: projected.warnings,
    });
    if (succeeded > 0) props.onImported();
  }

  return (
    <SubShell title="Import items" onBack={props.onBack}>
      <Switch>
        <Match when={phase().kind === "upload"}>
          <UploadPhase
            onFile={onFileSelected}
            error={error()}
            onBack={props.onBack}
          />
        </Match>
        <Match when={phase().kind === "preview"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "preview" }>;
            return (
              <PreviewPhase
                projected={p.projected}
                fileName={p.fileName}
                error={error()}
                onCancel={() => {
                  setError(null);
                  setPhase({ kind: "upload" });
                }}
                onConfirm={() => commit(p.projected)}
              />
            );
          })()}
        </Match>
        <Match when={phase().kind === "committing"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "committing" }>;
            return <CommittingPhase progress={p.progress} message={p.message} />;
          })()}
        </Match>
        <Match when={phase().kind === "done"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "done" }>;
            return (
              <DonePhase
                succeeded={p.succeeded}
                failed={p.failed}
                warnings={p.warnings}
                onDone={props.onBack}
              />
            );
          })()}
        </Match>
      </Switch>
    </SubShell>
  );
}

function UploadPhase(props: {
  onFile: (f: File) => void;
  error: string | null;
  onBack: () => void;
}) {
  return (
    <>
      <p class="muted" style="margin: 0 0 0.85rem;">
        Import items from another password manager. Parsing happens
        entirely in your browser — the export file never leaves this
        device. Items land in your personal vault; org-owned items in
        the export are skipped.
      </p>
      <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
        Bitwarden JSON only in this release. CSV, 1Password, and
        KeePass imports are queued; until then, use{" "}
        <code>hekate import</code> on the CLI for those formats.
      </p>

      <form class="card" onSubmit={(e) => e.preventDefault()}>
        <div class="field">
          <label for="import-file">
            Bitwarden export <span class="muted">(unencrypted JSON)</span>
          </label>
          <input
            id="import-file"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              const f = e.currentTarget.files?.[0];
              if (f) props.onFile(f);
            }}
          />
          <p class="muted" style="margin-top: 0.4rem; font-size: 0.8rem;">
            Bitwarden web vault → Tools → Export Vault → File format
            "JSON (unencrypted)". Encrypted JSON exports aren't
            supported yet.
          </p>
        </div>
        <Show when={props.error}>
          <div class="banner banner-error">{props.error}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary" type="button" onClick={props.onBack}>
            Cancel
          </button>
        </div>
      </form>
    </>
  );
}

function PreviewPhase(props: {
  projected: ProjectedImport;
  fileName: string;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const counts = () => countByType(props.projected.ciphers);
  return (
    <>
      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Ready to import.</strong>
        </p>
        <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.85rem;">
          From <code>{props.fileName}</code>:
        </p>
        <ul style="margin: 0 0 0.85rem 1.1rem; font-size: 0.9rem;">
          <li>
            <strong>{props.projected.folders.length}</strong> folder
            {props.projected.folders.length === 1 ? "" : "s"}
          </li>
          <li>
            <strong>{props.projected.ciphers.length}</strong> cipher
            {props.projected.ciphers.length === 1 ? "" : "s"}
            <span class="muted"> — {countSummary(counts())}</span>
          </li>
          <Show when={props.projected.warnings.length > 0}>
            <li>
              <strong>{props.projected.warnings.length}</strong> skipped
              <span class="muted"> (see below)</span>
            </li>
          </Show>
        </ul>
        <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
          New items will land in your personal vault. There's no bulk
          undo — to back out, delete the imported items individually
          from the trash.
        </p>
        <Show when={props.error}>
          <div class="banner banner-error">{props.error}</div>
        </Show>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="button" onClick={props.onConfirm}>
            Import {props.projected.ciphers.length} item
            {props.projected.ciphers.length === 1 ? "" : "s"}
          </button>
          <button class="btn btn-secondary" type="button" onClick={props.onCancel}>
            Cancel
          </button>
        </div>
      </div>
      <Show when={props.projected.warnings.length > 0}>
        <WarningsCard warnings={props.projected.warnings} />
      </Show>
    </>
  );
}

function CommittingPhase(props: {
  progress: { current: number; total: number };
  message: string;
}) {
  const pct = () => {
    if (props.progress.total === 0) return 100;
    return Math.round((props.progress.current / props.progress.total) * 100);
  };
  return (
    <div class="card">
      <p style="margin: 0 0 0.5rem;">
        <strong>Importing…</strong>
      </p>
      <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.85rem;">
        {props.message}
      </p>
      <div
        role="progressbar"
        aria-valuenow={props.progress.current}
        aria-valuemin={0}
        aria-valuemax={props.progress.total}
        style="height: 0.5rem; background: var(--border, #2a2a2a); border-radius: 0.25rem; overflow: hidden;"
      >
        <div
          style={`height: 100%; background: var(--accent, #4ea1ff); width: ${pct()}%; transition: width 120ms ease;`}
        />
      </div>
      <p class="muted" style="margin: 0.4rem 0 0; font-size: 0.8rem;">
        {props.progress.current} / {props.progress.total}
      </p>
    </div>
  );
}

function DonePhase(props: {
  succeeded: number;
  failed: Array<{ name: string; reason: string }>;
  warnings: string[];
  onDone: () => void;
}) {
  return (
    <>
      <div class="card">
        <p style="margin: 0 0 0.5rem;">
          <strong>Import complete.</strong>
        </p>
        <ul style="margin: 0 0 0.85rem 1.1rem; font-size: 0.9rem;">
          <li>
            Imported <strong>{props.succeeded}</strong> cipher
            {props.succeeded === 1 ? "" : "s"}.
          </li>
          <Show when={props.failed.length > 0}>
            <li>
              Failed <strong>{props.failed.length}</strong>{" "}
              <span class="muted">(see below)</span>.
            </li>
          </Show>
          <Show when={props.warnings.length > 0}>
            <li>
              Skipped <strong>{props.warnings.length}</strong>{" "}
              <span class="muted">(see below)</span>.
            </li>
          </Show>
        </ul>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" type="button" onClick={props.onDone}>
            Done
          </button>
        </div>
      </div>
      <Show when={props.failed.length > 0}>
        <div class="card">
          <p style="margin: 0 0 0.4rem;">
            <strong>Failed items</strong>
          </p>
          <ul style="margin: 0; padding-left: 1.1rem; font-size: 0.85rem;">
            <For each={props.failed}>
              {(f) => (
                <li>
                  <code>{f.name}</code> <span class="muted">— {f.reason}</span>
                </li>
              )}
            </For>
          </ul>
        </div>
      </Show>
      <Show when={props.warnings.length > 0}>
        <WarningsCard warnings={props.warnings} />
      </Show>
    </>
  );
}

function WarningsCard(props: { warnings: string[] }) {
  return (
    <div class="card">
      <p style="margin: 0 0 0.4rem;">
        <strong>Skipped items</strong>
      </p>
      <ul style="margin: 0; padding-left: 1.1rem; font-size: 0.85rem;">
        <For each={props.warnings}>
          {(w) => <li class="muted">{w}</li>}
        </For>
      </ul>
    </div>
  );
}

function countByType(ciphers: ProjectedImport["ciphers"]): Record<number, number> {
  const out: Record<number, number> = {};
  for (const c of ciphers) {
    out[c.cipherType] = (out[c.cipherType] ?? 0) + 1;
  }
  return out;
}

function countSummary(counts: Record<number, number>): string {
  const parts: string[] = [];
  const label: Record<number, string> = {
    [CipherType.Login]: "login",
    [CipherType.Note]: "note",
    [CipherType.Card]: "card",
    [CipherType.Identity]: "identity",
  };
  for (const t of [CipherType.Login, CipherType.Note, CipherType.Card, CipherType.Identity]) {
    const n = counts[t];
    if (n) parts.push(`${n} ${label[t]}${n === 1 ? "" : "s"}`);
  }
  return parts.length ? parts.join(", ") : "no items";
}

function messageOf(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
