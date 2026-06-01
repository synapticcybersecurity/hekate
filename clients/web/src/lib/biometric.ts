/* Touch ID unlock — desktop IPC wrapper.
 *
 * Bridges to the Tauri commands implemented in
 * `clients/desktop/src-tauri/src/biometric.rs` (backed by the Swift Keychain
 * helper). Everything here is gated on `isDesktop()` and no-ops in the
 * browser build. The master key crosses the IPC boundary as base64; the
 * unlock key + biometric gate live entirely in the native layer.
 *
 * Uses the global Tauri bridge (`withGlobalTauri` in tauri.conf.json) so the
 * SPA needs no `@tauri-apps/api` dependency.
 */
import { isDesktop } from "./config";

type InvokeFn = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

function invoker(): InvokeFn | null {
  if (typeof window === "undefined") return null;
  const w = window as unknown as {
    __TAURI__?: { core?: { invoke?: InvokeFn } };
  };
  return w.__TAURI__?.core?.invoke ?? null;
}

/** Whether this device can offer Touch ID (desktop + biometrics enrolled). */
export async function biometricAvailable(): Promise<boolean> {
  if (!isDesktop()) return false;
  const invoke = invoker();
  if (!invoke) return false;
  try {
    return await invoke<boolean>("biometric_available");
  } catch {
    return false;
  }
}

/** Whether Touch ID is currently enrolled for `account` on this device. */
export async function biometricEnrolled(account: string): Promise<boolean> {
  if (!isDesktop()) return false;
  const invoke = invoker();
  if (!invoke) return false;
  try {
    return await invoke<boolean>("biometric_enrolled", { account });
  } catch {
    return false;
  }
}

/** Enroll Touch ID: store the master key behind the biometric gate. */
export async function biometricEnable(
  account: string,
  masterKeyB64: string,
): Promise<void> {
  const invoke = invoker();
  if (!invoke) throw new Error("Touch ID is unavailable");
  await invoke<void>("biometric_enable", { account, masterKeyB64 });
}

/** Prompt Touch ID and return the master key (base64) on success. Throws if
 *  cancelled / failed / not enrolled. */
export async function biometricUnlock(account: string): Promise<string> {
  const invoke = invoker();
  if (!invoke) throw new Error("Touch ID is unavailable");
  return invoke<string>("biometric_unlock", { account });
}

/** Remove the stored Touch ID material for `account` (best-effort). */
export async function biometricDisable(account: string): Promise<void> {
  if (!isDesktop()) return;
  const invoke = invoker();
  if (!invoke) return;
  try {
    await invoke<void>("biometric_disable", { account });
  } catch {
    /* already gone / unavailable — nothing to do */
  }
}
