/* Password & passphrase generation.
 *
 * The CSPRNG, options, and EFF wordlist live in hekate-core (Rust, unit-tested)
 * and are reached through the wasm bindings — the web vault no longer hand-rolls
 * generation. Single source of truth shared with the CLI and the browser
 * extension.
 */
import { loadHekateCore } from "../wasm";

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  numbers: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  numbers: true,
  symbols: true,
  avoidAmbiguous: false,
};

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  words: 5,
  separator: "-",
  capitalize: false,
};

export async function generatePassword(
  opts: Partial<PasswordOptions> = {},
): Promise<string> {
  const core = await loadHekateCore();
  return core.generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, ...opts });
}

export async function generatePassphrase(
  opts: Partial<PassphraseOptions> = {},
): Promise<string> {
  const core = await loadHekateCore();
  return core.generatePassphrase({ ...DEFAULT_PASSPHRASE_OPTIONS, ...opts });
}
