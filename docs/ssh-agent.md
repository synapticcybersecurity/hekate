# pmgr — SSH agent

`hekate ssh-agent` is a local SSH agent backed by the user's stored
ssh-key ciphers. It speaks OpenSSH's agent protocol verbatim, so any
program that already knows how to talk to `ssh-agent` (i.e. `ssh`,
`ssh-add`, `git`, `rsync -e ssh`, `ssh-keygen -Y sign`, IDE plugins,
…) works against it transparently once `SSH_AUTH_SOCK` points at
the agent's Unix socket.

> **Status (M2.17 / M2.17a):** Ed25519 only. RSA / ECDSA support is
> tracked as a follow-up. Per-use approval is opt-in via
> `--approve-cmd`; without it the agent signs without prompting.

---

## Quickstart

1. **Add your private key to the vault**, encrypted client-side like
   any other cipher:

   ```bash
   hekate add ssh-key \
     --name "Work laptop" \
     --public-key="$(cat ~/.ssh/id_ed25519.pub)" \
     --private-key="$(cat ~/.ssh/id_ed25519)"
   ```

   The private key is an OpenSSH PEM blob (`-----BEGIN OPENSSH
   PRIVATE KEY-----` … `-----END OPENSSH PRIVATE KEY-----`). pmgr
   parses it client-side, throws away the plaintext, and stores
   only the EncString-wrapped ciphertext under your account key.

2. **Start the agent.** It forks to the background:

   ```bash
   hekate ssh-agent start
   # ✓ hekate ssh-agent started (pid 1234, 1 identity).
   #   socket: /run/user/1000/hekate-ssh-1000.sock
   ```

3. **Point your shell at it:**

   ```bash
   export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/hekate-ssh-$(id -u).sock
   ```

4. **Use it like any other agent:**

   ```bash
   ssh-add -l                   # → SHA256:… smoke@hekate (ED25519)
   ssh-add -L                   # full public key in OpenSSH format
   ssh user@host                # signs the auth challenge via hekate
   git push                     # via SSH transport, also signs via hekate
   ssh-keygen -Y sign -f key.pub -n test message.txt
   ```

5. **Stop it when you're done:**

   ```bash
   hekate ssh-agent stop
   ```

`hekate ssh-agent status` reports running / not running and the socket
path.

---

## Per-use approval (`--approve-cmd`)

By default the agent will sign anything its keys are asked to sign,
without prompting. That matches the trust model of OpenSSH's own
agent: the kernel's filesystem permission on the 0600 socket is the
access barrier.

To prompt the user on every sign — useful on a shared workstation, or
just as a defense against rogue processes that share your UID — pass
`--approve-cmd "<shell command>"`:

```bash
hekate ssh-agent start --approve-cmd 'osascript -e \
  "display dialog \"hekate: sign with $HEKATE_SSH_KEY_COMMENT?\" \
   buttons {\"No\",\"Yes\"} default button \"Yes\" giving up after 30"'
```

The agent forks `sh -c "<cmd>"` for every `SSH_AGENTC_SIGN_REQUEST`
with two environment variables set:

| Variable | Example value |
|---|---|
| `HEKATE_SSH_KEY_COMMENT` | `alice@laptop` (the comment on the OpenSSH key, or `hekate:<cipher_id>` if blank) |
| `HEKATE_SSH_KEY_FP` | `SHA256:M4GWx3en1gK3z3obn6ly6QeYMR2kW6P9LyWr/BPJewI` |

A **zero exit** approves; **any non-zero exit** denies. The denial
surfaces to the SSH client as `agent refused operation`. There's a
hard 60-second ceiling on the approval command so a stuck dialog
doesn't hang an ssh session indefinitely.

### Example approval commands

**macOS — native dialog with timeout:**

```bash
hekate ssh-agent start --approve-cmd 'osascript -e \
  "display dialog \"hekate: sign with $HEKATE_SSH_KEY_COMMENT?\nFingerprint: $HEKATE_SSH_KEY_FP\" \
   buttons {\"Deny\",\"Approve\"} default button \"Approve\" \
   cancel button \"Deny\" giving up after 30" >/dev/null'
```

**Linux — zenity question dialog:**

```bash
hekate ssh-agent start --approve-cmd \
  'zenity --question --no-wrap --timeout=30 \
    --title="hekate ssh-agent" \
    --text="Sign with <b>$HEKATE_SSH_KEY_COMMENT</b>?\n\n<tt>$HEKATE_SSH_KEY_FP</tt>"'
```

**Linux — notify-send + a touch file (auto-deny if you don't actively allow):**

```bash
# In ~/.config/hekate/ssh-approve.sh:
#!/usr/bin/env bash
set -e
TOKEN=$(mktemp -u /tmp/hekate-approve-XXXXXX)
notify-send -u critical -t 30000 \
  "hekate ssh-agent" \
  "Sign with $HEKATE_SSH_KEY_COMMENT?\nTouch $TOKEN within 30 s to approve."
for _ in $(seq 1 30); do
  [ -e "$TOKEN" ] && { rm -f "$TOKEN"; exit 0; }
  sleep 1
done
exit 1
```

Then:

```bash
hekate ssh-agent start --approve-cmd "$HOME/.config/hekate/ssh-approve.sh"
```

**CI / scripted environments:** simply omit `--approve-cmd`. The agent
signs without prompt, which is the right behaviour for an
unattended automation host.

---

## Trust model

The hekate SSH agent occupies the same trust position as OpenSSH's own
`ssh-agent`:

- **Socket access ≡ key access.** Anything with read/write on the
  socket can sign. The socket is mode `0600` so ordinary kernel
  filesystem permissions enforce that only your own UID can talk to
  it.
- **Memory residency.** Decrypted private keys live in the agent
  process's heap as `ed25519-dalek::SigningKey` values for the
  agent's full lifetime. Stop the agent (`hekate ssh-agent stop`) to
  wipe them.
- **Live identity reload (M2.17b).** The agent subscribes to the
  server's `/push/v1/stream` channel and re-pulls `/sync` on every
  cipher change, so adding a new Ed25519 ssh-key cipher in the
  vault makes it appear in the agent within a fraction of a second
  — no `stop && start` needed. As a consequence, the agent holds
  the unwrapped account key for its full lifetime (it needs it to
  decrypt newly-arrived ciphers). That's a real trust trade-off:
  killing the agent process wipes those keys, but until you do,
  any process with `/proc/<pid>/mem` access on your UID can read
  them. Same exposure as OpenSSH's own agent.
- **No network access** after `start`. The agent does not
  re-contact the server. (The vault is loaded once at start; the
  rest of the agent's lifetime is local-only.)

---

## What's not yet implemented

| Gap | Tracked under |
|---|---|
| **RSA / ECDSA / ECDSA-SK / Ed25519-SK** identities | M2.17b |
| ~~**Hot reload** of identities when the vault changes~~ | shipped — M2.17b |
| **Locked / unlocked** state (`ssh-add -x`, `ssh-add -X`) | low priority |
| **`ssh-add -K` "remove all"** equivalent | low priority |
| **Confirm-on-add** flag (the OpenSSH `-c` mode) | superseded by `--approve-cmd` |
| **Built-in approval UI** (no shell-out) | unlikely; `--approve-cmd` covers the surface area cheaply |

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `hekate ssh-agent start` exits with `no Ed25519 ssh-key ciphers in the vault` | You haven't stored an Ed25519 key yet, or all your stored keys are RSA/ECDSA (not yet supported). Add one with `hekate add ssh-key --name … --private-key="$(cat ~/.ssh/id_ed25519)"`. |
| `hekate ssh-agent start` says `an ssh-agent is already running` | Either a previous `start` is still alive (good — use it!), or the PID file is stale and pointing at a different process. Run `hekate ssh-agent stop` to clean up. |
| `ssh-add -l` shows no keys despite `start` reporting `1 identity` | `SSH_AUTH_SOCK` is unset or pointing at the wrong socket. Echo the path that `start` printed and `export SSH_AUTH_SOCK=…` in the same shell. |
| `ssh: connect to host …: agent refused operation` on every key | Your `--approve-cmd` is exiting non-zero. Test it standalone with the env vars exported manually: `HEKATE_SSH_KEY_COMMENT=test HEKATE_SSH_KEY_FP=SHA256:abc sh -c "<your cmd>"; echo $?`. |
| `Could not load private key from /tmp/…/openssh.priv` at start | The `privateKey` field in your stored cipher isn't a valid OpenSSH PEM. Re-add the key making sure you pass `$(cat ~/.ssh/id_ed25519)` (the private file, not the `.pub` file). |
| The agent silently dies after a while | It does NOT timeout on its own. If the process is gone, something else killed it (OOM, session logout, manual `pkill`). The agent does not currently survive a logout — start it again from your shell init or a systemd-user unit. |

To see what the agent is doing, start it in the foreground for
debugging by adding a no-op `--approve-cmd` that logs:

```bash
hekate ssh-agent start --approve-cmd \
  'echo "[$(date)] sign $HEKATE_SSH_KEY_COMMENT $HEKATE_SSH_KEY_FP" >> ~/hekate-ssh.log; true'
```

Tail `~/hekate-ssh.log` to see every sign attempt.
