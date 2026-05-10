/* Peer pins (C.7d-4).
 *
 * One SubShell with three regions:
 *   - "Your fingerprint" — pinned at top so the user can read it
 *     aloud / Signal it to a peer who wants to pin them.
 *   - "Pin a new peer" — inline form (email or user_id), TOFU confirm
 *     screen showing the fingerprint, commit button.
 *   - "Pinned peers" — list with fingerprint + first_seen + Unpin.
 *
 * Phase machine handles the TOFU confirm screen + the "match" /
 * "mismatch" / "fresh-pin" outcomes from `resolvePeer`.
 */
import { createSignal, For, Match, onMount, Show, Switch } from "solid-js";

import { ApiError } from "../../lib/api";
import {
  commitPin,
  loadPeerPins,
  myFingerprint,
  resolvePeer,
  unpinPeer,
  type PeerPin,
  type PubkeyBundle,
} from "../../lib/peerPins";
import { SubShell } from "../../ui/Shell";

export interface PeerPinsProps {
  onBack: () => void;
}

interface MyId {
  userId: string;
  fingerprint: string;
}

type Phase =
  | { kind: "list" }
  | { kind: "resolving" }
  | {
      kind: "confirm-fresh";
      bundle: PubkeyBundle;
      fingerprint: string;
      email?: string;
    };

export function PeerPins(props: PeerPinsProps) {
  const [pins, setPins] = createSignal<PeerPin[]>(loadPeerPins());
  const [me, setMe] = createSignal<MyId | null>(null);
  const [meError, setMeError] = createSignal<string | null>(null);
  const [phase, setPhase] = createSignal<Phase>({ kind: "list" });
  const [peerInput, setPeerInput] = createSignal("");
  const [resolveError, setResolveError] = createSignal<string | null>(null);
  const [fpCopied, setFpCopied] = createSignal(false);

  onMount(() => {
    void (async () => {
      try {
        const m = await myFingerprint();
        setMe(m);
      } catch (err) {
        setMeError(errMsg(err));
      }
    })();
  });

  function refreshList() {
    setPins(loadPeerPins());
  }

  async function onResolve(e: Event) {
    e.preventDefault();
    const input = peerInput().trim();
    if (!input) {
      setResolveError("Email or user_id required.");
      return;
    }
    setResolveError(null);
    setPhase({ kind: "resolving" });
    try {
      const result = await resolvePeer(input);
      if (result.kind === "match") {
        setPeerInput("");
        setPhase({ kind: "list" });
        // resolvePeer may have backfilled email on the stored pin;
        // pull a fresh list so the row updates immediately.
        refreshList();
        window.alert(
          `Already pinned — fingerprint matches.\n\n${result.pin.fingerprint}\n\nFirst seen: ${result.pin.first_seen_at}`,
        );
        return;
      }
      setPhase({
        kind: "confirm-fresh",
        bundle: result.bundle,
        fingerprint: result.fingerprint,
        email: result.email,
      });
    } catch (err) {
      setResolveError(errMsg(err));
      setPhase({ kind: "list" });
    }
  }

  function onConfirmCommit() {
    const p = phase();
    if (p.kind !== "confirm-fresh") return;
    commitPin(p.bundle, p.fingerprint, p.email);
    refreshList();
    setPeerInput("");
    setPhase({ kind: "list" });
  }

  function onUnpin(userId: string) {
    if (
      !window.confirm(
        `Unpin ${userId}?\n\nThis is a security-relevant action — you should only unpin after verifying out-of-band that the peer rotated their keys legitimately, OR if you're sure you want to drop this trust anchor.`,
      )
    ) {
      return;
    }
    unpinPeer(userId);
    refreshList();
  }

  async function copyFingerprint() {
    const m = me();
    if (!m) return;
    try {
      await navigator.clipboard.writeText(m.fingerprint);
      setFpCopied(true);
      setTimeout(() => setFpCopied(false), 1500);
    } catch {
      /* clipboard refusal */
    }
  }

  return (
    <SubShell title="Peer pins" onBack={props.onBack}>
      <Switch>
        <Match when={phase().kind === "confirm-fresh"}>
          {(() => {
            const p = phase() as Extract<Phase, { kind: "confirm-fresh" }>;
            return (
              <div class="card">
                <p style="margin: 0 0 0.5rem;">
                  <strong>Pin new peer?</strong>
                </p>
                <Show when={p.email}>
                  <p style="margin: 0 0 0.4rem;">
                    <strong>{p.email}</strong>
                  </p>
                </Show>
                <p class="muted" style="margin: 0 0 0.5rem; font-size: 0.9rem;">
                  user_id:{" "}
                  <code style="word-break: break-all;">{p.bundle.user_id}</code>
                </p>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.9rem;">
                  Fingerprint:
                </p>
                <pre class="recovery-codes" style="margin: 0 0 0.85rem;">
                  {p.fingerprint}
                </pre>
                <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
                  Verify this matches what the peer reads to you out of
                  band (Signal, voice call, in person) before clicking
                  Pin. The server's word alone is not enough — TOFU only
                  works if the first encounter is honest.
                </p>
                <div style="display: flex; gap: 0.5rem;">
                  <button class="btn" type="button" onClick={onConfirmCommit}>
                    Pin this peer
                  </button>
                  <button
                    class="btn btn-secondary"
                    type="button"
                    onClick={() => setPhase({ kind: "list" })}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            );
          })()}
        </Match>

        <Match when={phase().kind !== "confirm-fresh"}>
          <div class="card">
            <p style="margin: 0 0 0.5rem;">
              <strong>Your fingerprint</strong>
            </p>
            <p class="muted" style="margin: 0 0 0.75rem; font-size: 0.85rem;">
              Read this to peers (Signal, voice, in person) so they can
              pin you.
            </p>
            <Show when={me()} fallback={<MeFallback error={meError()} />}>
              {(m) => (
                <>
                  <p class="muted" style="margin: 0 0 0.4rem; font-size: 0.85rem;">
                    user_id:{" "}
                    <code style="word-break: break-all;">{m().userId}</code>
                  </p>
                  <pre class="recovery-codes" style="margin: 0 0 0.5rem;">
                    {m().fingerprint}
                  </pre>
                  <button
                    class="btn btn-secondary"
                    type="button"
                    onClick={() => void copyFingerprint()}
                  >
                    {fpCopied() ? "Copied" : "Copy fingerprint"}
                  </button>
                </>
              )}
            </Show>
          </div>

          <div class="card">
            <p style="margin: 0 0 0.5rem;">
              <strong>Pin a new peer</strong>
            </p>
            <p class="muted" style="margin: 0 0 0.85rem; font-size: 0.85rem;">
              Fetches the peer's pubkey bundle, verifies the
              self-signature, then asks you to confirm the fingerprint
              out-of-band before committing the pin.
            </p>
            <form onSubmit={onResolve}>
              <div class="field">
                <label for="peer-input">Peer email or user_id</label>
                <input
                  id="peer-input"
                  type="text"
                  required
                  placeholder="alice@example.com or 0192e0a0-…"
                  value={peerInput()}
                  onInput={(e) => setPeerInput(e.currentTarget.value)}
                />
              </div>
              <Show when={resolveError()}>
                <div class="banner banner-error">{resolveError()}</div>
              </Show>
              <button
                class="btn"
                type="submit"
                disabled={phase().kind === "resolving"}
              >
                {phase().kind === "resolving" ? "Looking up…" : "Look up peer"}
              </button>
            </form>
          </div>

          <div class="card">
            <p style="margin: 0 0 0.5rem;">
              <strong>Pinned peers ({pins().length})</strong>
            </p>
            <Show
              when={pins().length > 0}
              fallback={
                <p class="muted" style="margin: 0; font-size: 0.85rem;">
                  No peers pinned in this browser yet. Pins set via the
                  popup or the CLI live in their own stores — this list
                  is web-vault-local.
                </p>
              }
            >
              <ul style="list-style: none; margin: 0; padding: 0;">
                <For each={pins()}>
                  {(pin) => (
                    <li style="border-top: 1px solid var(--border); padding: 0.6rem 0;">
                      <Show when={pin.email}>
                        <p style="margin: 0 0 0.2rem; font-weight: 500;">
                          {pin.email}
                        </p>
                      </Show>
                      <p
                        class="muted"
                        style="margin: 0 0 0.2rem; font-size: 0.85rem;"
                      >
                        user_id:{" "}
                        <code style="word-break: break-all;">{pin.user_id}</code>
                      </p>
                      <p style="margin: 0 0 0.2rem; font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: 0.85rem; word-break: break-all;">
                        {pin.fingerprint}
                      </p>
                      <p
                        class="muted"
                        style="margin: 0 0 0.4rem; font-size: 0.8rem;"
                      >
                        first seen: {pin.first_seen_at}
                      </p>
                      <button
                        class="btn btn-secondary"
                        type="button"
                        style="padding: 0.3rem 0.75rem; font-size: 0.85rem;"
                        onClick={() => onUnpin(pin.user_id)}
                      >
                        Unpin
                      </button>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </div>
        </Match>
      </Switch>
    </SubShell>
  );
}

function MeFallback(props: { error: string | null }) {
  return (
    <Show
      when={props.error}
      fallback={<p class="muted" style="margin: 0; font-size: 0.85rem;">Loading…</p>}
    >
      <div class="banner banner-error">{props.error}</div>
    </Show>
  );
}

function errMsg(err: unknown): string {
  if (err instanceof ApiError) return `${err.status}: ${err.message}`;
  if (err instanceof Error) return err.message;
  return String(err);
}
