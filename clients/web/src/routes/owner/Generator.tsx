/* Standalone password / passphrase generator (#41).
 *
 * A top-level tab (alongside Vault / Share / Orgs / Settings) — distinct from
 * the inline "Generate" button on the password field in EditCipher. Both call
 * the same hekate-core generation (CSPRNG + EFF wordlist) through wasm.
 *
 * Rendered as a tab body inside TopShell, so it returns its content directly
 * (no shell/back button of its own). The output regenerates reactively on any
 * option change; a `nonce` signal lets the manual ↻ button force a fresh value
 * even when no option changed.
 */
import { createEffect, createSignal, Match, Show, Switch } from "solid-js";

import { copy } from "../../lib/clipboard";
import { generatePassphrase, generatePassword } from "../../lib/generate";

type Mode = "password" | "passphrase";

export function Generator() {
  const [mode, setMode] = createSignal<Mode>("password");

  // Password options.
  const [length, setLength] = createSignal(20);
  const [lowercase, setLowercase] = createSignal(true);
  const [uppercase, setUppercase] = createSignal(true);
  const [numbers, setNumbers] = createSignal(true);
  const [symbols, setSymbols] = createSignal(true);
  const [avoidAmbiguous, setAvoidAmbiguous] = createSignal(false);

  // Passphrase options.
  const [words, setWords] = createSignal(5);
  const [separator, setSeparator] = createSignal("-");
  const [capitalize, setCapitalize] = createSignal(false);

  const [value, setValue] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);
  // Bumped by the ↻ button to force a regenerate with unchanged options.
  const [nonce, setNonce] = createSignal(0);

  async function run(fn: () => Promise<string>) {
    try {
      const v = await fn();
      setError(null);
      setValue(v);
    } catch (e) {
      setValue("");
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Read every option synchronously so Solid tracks them, then hand the
  // snapshot to the async generator. Re-runs on any option / mode / nonce
  // change.
  createEffect(() => {
    nonce();
    if (mode() === "password") {
      const opts = {
        length: length(),
        lowercase: lowercase(),
        uppercase: uppercase(),
        numbers: numbers(),
        symbols: symbols(),
        avoidAmbiguous: avoidAmbiguous(),
      };
      void run(() => generatePassword(opts));
    } else {
      const opts = {
        words: words(),
        separator: separator(),
        capitalize: capitalize(),
      };
      void run(() => generatePassphrase(opts));
    }
  });

  async function onCopy() {
    if (!value()) return;
    await copy(value());
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      <div class="card">
        <div style="display: flex; gap: 0.5rem; margin: 0 0 0.75rem;">
          <button
            type="button"
            class={`btn ${mode() === "password" ? "" : "btn-secondary"}`}
            onClick={() => setMode("password")}
          >
            Password
          </button>
          <button
            type="button"
            class={`btn ${mode() === "passphrase" ? "" : "btn-secondary"}`}
            onClick={() => setMode("passphrase")}
          >
            Passphrase
          </button>
        </div>

        <div
          style="display: flex; align-items: stretch; gap: 0.5rem; margin: 0 0 0.5rem;"
        >
          <output
            aria-label="Generated value"
            style="flex: 1; font-family: var(--font-mono, monospace); word-break: break-all; padding: 0.6rem 0.75rem; border: 1px solid var(--border, #ccc); border-radius: 6px; min-height: 1.4rem; background: var(--bg-subtle, #f6f6f6);"
          >
            {value()}
          </output>
          <button
            type="button"
            class="btn btn-secondary"
            title="Regenerate"
            aria-label="Regenerate"
            onClick={() => setNonce(nonce() + 1)}
          >
            ↻
          </button>
          <button
            type="button"
            class="btn btn-secondary"
            style="white-space: nowrap;"
            disabled={!value()}
            onClick={() => void onCopy()}
          >
            {copied() ? "Copied" : "Copy"}
          </button>
        </div>

        <Show when={error()}>
          <p class="muted" style="margin: 0 0 0.75rem; color: var(--danger, #c0392b); font-size: 0.85rem;">
            {error()}
          </p>
        </Show>

        <Switch>
          <Match when={mode() === "password"}>
            <div class="field">
              <label>
                Length: <strong>{length()}</strong>
              </label>
              <input
                type="range"
                min="4"
                max="128"
                value={length()}
                onInput={(e) => setLength(Number(e.currentTarget.value))}
                style="width: 100%;"
              />
            </div>
            <Toggle
              label="Lowercase (a–z)"
              checked={lowercase()}
              onChange={setLowercase}
            />
            <Toggle
              label="Uppercase (A–Z)"
              checked={uppercase()}
              onChange={setUppercase}
            />
            <Toggle
              label="Numbers (0–9)"
              checked={numbers()}
              onChange={setNumbers}
            />
            <Toggle
              label="Symbols (!@#…)"
              checked={symbols()}
              onChange={setSymbols}
            />
            <Toggle
              label="Avoid ambiguous (O 0 I l 1)"
              checked={avoidAmbiguous()}
              onChange={setAvoidAmbiguous}
            />
          </Match>

          <Match when={mode() === "passphrase"}>
            <div class="field">
              <label>
                Words: <strong>{words()}</strong>
              </label>
              <input
                type="range"
                min="3"
                max="12"
                value={words()}
                onInput={(e) => setWords(Number(e.currentTarget.value))}
                style="width: 100%;"
              />
            </div>
            <div class="field">
              <label>Separator</label>
              <input
                class="input"
                type="text"
                value={separator()}
                maxlength="8"
                onInput={(e) => setSeparator(e.currentTarget.value)}
              />
            </div>
            <Toggle
              label="Capitalize each word"
              checked={capitalize()}
              onChange={setCapitalize}
            />
          </Match>
        </Switch>
      </div>
    </>
  );
}

function Toggle(props: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label style="display: flex; align-items: center; gap: 0.5rem; margin: 0 0 0.5rem;">
      <input
        type="checkbox"
        checked={props.checked}
        onChange={(e) => props.onChange(e.currentTarget.checked)}
      />
      <span>{props.label}</span>
    </label>
  );
}
