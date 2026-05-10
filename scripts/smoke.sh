#!/usr/bin/env bash
#
# End-to-end smoke for the hekate CLI against a real Postgres-backed server.
# Walks register → add → edit → trash → restore → purge → change-password →
# sync at every step, and asserts the BW04 signed manifest stays ✓ verified
# across rotations.
#
# Self-contained: brings the server up, runs the flow, tears down. Wipes
# the dev DB and CLI state volumes on every run so "test pollution" can
# never silently mask a regression.
#
# Run: `make smoke` (preferred) or `bash scripts/smoke.sh` directly.

set -euo pipefail

HEKATE_PASS_OLD=oldpassword1
HEKATE_PASS_NEW=newpassword1
HEKATE_EMAIL=smoke@hekate.test
RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; RESET=$'\033[0m'

ok() { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
say() { printf '%s→%s %s\n' "$CYAN" "$RESET" "$1"; }
die() { printf '%sFAIL%s %s\n' "$RED" "$RESET" "$1" >&2; exit 1; }

cleanup() {
  if [ "${SKIP_TEARDOWN:-0}" = "1" ]; then return; fi
  say "Tearing down…"
  docker compose -f docker-compose.yml down >/dev/null 2>&1 || true
}
trap cleanup EXIT

HEKATE=(docker run --rm -i
  -v "$PWD":/workspace
  -v hekate_cli_state:/state
  -v hekate_target:/workspace/target
  -w /workspace
  -e XDG_CONFIG_HOME=/state -e HOME=/state
  --add-host=host.docker.internal:host-gateway
  hekate-dev:latest /workspace/target/release/hekate)

run_hekate() {
  # Pipe a password to stdin; tee its output to /tmp/hekate.last so callers
  # can grep without re-running. Stderr passes through unchanged.
  local input="$1"; shift
  printf '%s\n' "$input" | "${HEKATE[@]}" "$@" 2>&1 | tee /tmp/hekate.last
}

# ---- 1. clean slate -------------------------------------------------------
say "Wiping dev volumes for a hermetic run…"
docker volume rm hekate_pgdata hekate_hekate_data hekate_cli_state >/dev/null 2>&1 || true

# ---- 2. server up ---------------------------------------------------------
say "Bringing up Postgres + hekate-server…"
docker compose -f docker-compose.yml up -d --build >/dev/null
for _ in $(seq 1 60); do
  if curl -sf http://localhost:8088/health/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -sf http://localhost:8088/health/ready >/dev/null || die "server never became ready"
ok "server ready"

# ---- 3. CLI build ---------------------------------------------------------
say "Building the CLI binary…"
make cli >/dev/null
ok "CLI built"

# ---- 4. register ----------------------------------------------------------
say "register"
printf '%s\n%s\n' "$HEKATE_PASS_OLD" "$HEKATE_PASS_OLD" | \
  "${HEKATE[@]}" register --server http://host.docker.internal:8088 --email "$HEKATE_EMAIL" \
    >/tmp/hekate.last 2>&1 || die "register failed: $(cat /tmp/hekate.last)"
grep -q "Registered and logged in" /tmp/hekate.last || die "register did not confirm: $(cat /tmp/hekate.last)"
ok "registered $HEKATE_EMAIL"

# ---- 5. add login + edit + sync ✓ -----------------------------------------
say "add login"
run_hekate "$HEKATE_PASS_OLD" add login --name 'GitHub' --username alice \
  --password 'hunter2' --uri 'https://github.com' >/dev/null
LOGIN_ID=$(grep -oE '019[0-9a-f-]+' /tmp/hekate.last | head -1)
[ -n "$LOGIN_ID" ] || die "add login: no cipher id printed"
ok "login id $LOGIN_ID"

say "edit login --username"
run_hekate "$HEKATE_PASS_OLD" edit login "$LOGIN_ID" --username bob >/dev/null
grep -q "Updated GitHub" /tmp/hekate.last || die "edit did not report Updated"
ok "edited"

say "sync (manifest must verify clean after writes)"
run_hekate "$HEKATE_PASS_OLD" sync >/dev/null
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "sync after edit: manifest not verified: $(cat /tmp/hekate.last)"
ok "sync ✓ verified"

# ---- 6. add totp + sync ---------------------------------------------------
say "add totp"
run_hekate "$HEKATE_PASS_OLD" add totp --name 'GitHub-2FA' \
  --secret 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' --issuer 'GitHub' --account 'alice' >/dev/null
grep -q "Created totp" /tmp/hekate.last || die "add totp: $(cat /tmp/hekate.last)"
ok "totp added"

run_hekate "$HEKATE_PASS_OLD" sync >/dev/null
grep -q "Ciphers:     2" /tmp/hekate.last || die "sync should now show 2 ciphers"
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "sync after totp add: manifest not verified"
ok "sync ✓ verified (2 entries)"

# ---- 7. trash + restore + purge ------------------------------------------
say "trash login → sync → restore → sync → purge → sync"
run_hekate "$HEKATE_PASS_OLD" delete "$LOGIN_ID" >/dev/null
run_hekate "$HEKATE_PASS_OLD" sync >/dev/null
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "sync after trash: manifest not verified"

run_hekate "$HEKATE_PASS_OLD" restore "$LOGIN_ID" >/dev/null
run_hekate "$HEKATE_PASS_OLD" sync >/dev/null
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "sync after restore: manifest not verified"

# Purge needs `--yes` to skip the prompt.
run_hekate "$HEKATE_PASS_OLD" delete "$LOGIN_ID" >/dev/null
run_hekate "$HEKATE_PASS_OLD" purge "$LOGIN_ID" --yes >/dev/null
run_hekate "$HEKATE_PASS_OLD" sync >/dev/null
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "sync after purge: manifest not verified"
ok "trash/restore/purge cycle clean"

# ---- 8. change-password rotates the signing pubkey + wipes manifest ------
say "change-password (rotates Ed25519 pubkey, wipes manifest)"
printf '%s\n%s\n%s\ny\n' "$HEKATE_PASS_OLD" "$HEKATE_PASS_NEW" "$HEKATE_PASS_NEW" | \
  "${HEKATE[@]}" account change-password >/tmp/hekate.last 2>&1 \
    || die "change-password: $(cat /tmp/hekate.last)"
grep -q "Master password changed" /tmp/hekate.last || die "change-password did not confirm"
ok "password rotated"

# Server should have wiped the manifest row.
MANIFEST_ROWS=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT count(*) FROM vault_manifests")
[ "$MANIFEST_ROWS" = "0" ] || die "expected 0 manifest rows after change-password, got $MANIFEST_ROWS"
ok "vault_manifests row cleared (0 rows)"

# ---- 9. add under new password → fresh genesis manifest -------------------
say "add login under NEW password (uploads fresh v1 genesis)"
run_hekate "$HEKATE_PASS_NEW" add login --name 'After-rotate' \
  --username carol --password 'newpw' --uri 'https://example.com' >/dev/null
grep -q "Created login" /tmp/hekate.last || die "post-rotate add: $(cat /tmp/hekate.last)"

run_hekate "$HEKATE_PASS_NEW" sync >/dev/null
grep -q "Manifest:.*✓ verified" /tmp/hekate.last || die "post-rotate sync: manifest not verified"
ok "sync ✓ verified under new key"

VERSION=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT version FROM vault_manifests")
[ "$VERSION" = "1" ] || die "expected manifest v1 (genesis) post-rotate, got v$VERSION"
ok "manifest is v1 (genesis under new pubkey)"

# ---- 10. report -----------------------------------------------------------
echo
ok "ALL SMOKE CHECKS PASSED"
