#!/usr/bin/env bash
#
# M4.1 end-to-end smoke: two-user invite + accept flow against a real
# Postgres-backed server.
#
#   alice register
#   bob   register
#   alice peer-fetch bob   (TOFU pin)
#   alice org create "Acme"
#   alice org invite bob
#   bob   peer-fetch alice (TOFU pin — required to verify envelope)
#   bob   org invites      (sees pending invitation)
#   bob   org accept
#   alice org list         (member_count = 2)
#   bob   org list         (role = user)
#
# Each user has their own CLI state in a distinct named volume, so the
# hekate binary genuinely runs as two separate clients.

set -euo pipefail

HEKATE_PASS=secretpassword1
ALICE_EMAIL=alice@hekate.test
BOB_EMAIL=bob@hekate.test
CAROL_EMAIL=carol@hekate.test
RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; RESET=$'\033[0m'

ok()  { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
say() { printf '%s→%s %s\n' "$CYAN" "$RESET" "$1"; }
die() { printf '%sFAIL%s %s\n' "$RED" "$RESET" "$1" >&2; exit 1; }

cleanup() {
  if [ "${SKIP_TEARDOWN:-0}" = "1" ]; then return; fi
  say "Tearing down…"
  docker compose -f docker-compose.yml down >/dev/null 2>&1 || true
}
trap cleanup EXIT

# One named volume per simulated user.
ALICE_VOL=hekate_cli_state_alice
BOB_VOL=hekate_cli_state_bob
CAROL_VOL=hekate_cli_state_carol

hekate_for() {
  local vol=$1; shift
  docker run --rm -i \
    -v "$PWD":/workspace \
    -v "$vol":/state \
    -v hekate_target:/workspace/target \
    -w /workspace \
    -e XDG_CONFIG_HOME=/state -e HOME=/state \
    --add-host=host.docker.internal:host-gateway \
    hekate-dev:latest /workspace/target/release/hekate "$@"
}

run_for() {
  local vol=$1 input=$2; shift 2
  printf '%s\n' "$input" | hekate_for "$vol" "$@" 2>&1 | tee /tmp/hekate.last
}

# ---- 1. clean slate ------------------------------------------------------
say "Wiping dev volumes for a hermetic run…"
docker volume rm hekate_pgdata hekate_hekate_data "$ALICE_VOL" "$BOB_VOL" "$CAROL_VOL" >/dev/null 2>&1 || true

# ---- 2. server up --------------------------------------------------------
say "Bringing up Postgres + hekate-server…"
docker compose -f docker-compose.yml up -d --build >/dev/null
for _ in $(seq 1 60); do
  if curl -sf http://localhost:8088/health/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -sf http://localhost:8088/health/ready >/dev/null || die "server never became ready"
ok "server ready"

# ---- 3. CLI build --------------------------------------------------------
say "Building the CLI binary…"
make cli >/dev/null
ok "CLI built"

# ---- 4. register both users ---------------------------------------------
say "register alice"
printf '%s\n%s\n' "$HEKATE_PASS" "$HEKATE_PASS" | \
  hekate_for "$ALICE_VOL" register --server http://host.docker.internal:8088 \
    --email "$ALICE_EMAIL" >/tmp/hekate.last 2>&1 \
  || die "register alice: $(cat /tmp/hekate.last)"
grep -q "Registered and logged in" /tmp/hekate.last || die "alice register did not confirm"
ok "alice registered"

say "register bob"
printf '%s\n%s\n' "$HEKATE_PASS" "$HEKATE_PASS" | \
  hekate_for "$BOB_VOL" register --server http://host.docker.internal:8088 \
    --email "$BOB_EMAIL" >/tmp/hekate.last 2>&1 \
  || die "register bob: $(cat /tmp/hekate.last)"
grep -q "Registered and logged in" /tmp/hekate.last || die "bob register did not confirm"
ok "bob registered"

# ---- 5. extract user_ids via `hekate peer fingerprint` --------------------
ALICE_UID=$(hekate_for "$ALICE_VOL" peer fingerprint 2>&1 \
  | awk '/^user_id:/{print $2}')
BOB_UID=$(hekate_for "$BOB_VOL" peer fingerprint 2>&1 \
  | awk '/^user_id:/{print $2}')
[ -n "$ALICE_UID" ] || die "could not read alice user_id"
[ -n "$BOB_UID" ]   || die "could not read bob user_id"
ok "alice = $ALICE_UID"
ok "bob   = $BOB_UID"

# ---- 6. alice peer-fetches bob (TOFU pin) -------------------------------
say "alice → peer fetch bob"
hekate_for "$ALICE_VOL" peer fetch "$BOB_UID" >/tmp/hekate.last 2>&1 \
  || die "alice peer fetch bob: $(cat /tmp/hekate.last)"
grep -q "pinned new peer" /tmp/hekate.last || die "alice did not pin bob"
ok "alice pinned bob"

# ---- 7. alice creates Acme org ------------------------------------------
say "alice → org create Acme"
run_for "$ALICE_VOL" "$HEKATE_PASS" org create --name 'Acme' >/dev/null
grep -q "Created org" /tmp/hekate.last || die "alice create org: $(cat /tmp/hekate.last)"
ORG_ID=$(grep -oE '019[0-9a-f-]+' /tmp/hekate.last | head -1)
[ -n "$ORG_ID" ] || die "could not extract org id"
ok "org $ORG_ID created (alice = owner, roster v1)"

# ---- 8. alice invites bob -----------------------------------------------
say "alice → org invite bob (signcryption envelope)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org invite "$ORG_ID" "$BOB_UID" --role user >/dev/null
grep -q "Invited" /tmp/hekate.last || die "invite failed: $(cat /tmp/hekate.last)"
grep -q "Roster bumped to v2" /tmp/hekate.last || die "invite did not bump roster: $(cat /tmp/hekate.last)"
ok "alice invited bob; roster v2 signed"

# ---- 9. bob peer-fetches alice (required to verify envelope) -----------
say "bob → peer fetch alice (needed for envelope sender verification)"
hekate_for "$BOB_VOL" peer fetch "$ALICE_UID" >/tmp/hekate.last 2>&1 \
  || die "bob peer fetch alice: $(cat /tmp/hekate.last)"
grep -q "pinned new peer" /tmp/hekate.last || die "bob did not pin alice"
ok "bob pinned alice"

# ---- 10. bob lists invites ---------------------------------------------
say "bob → org invites"
hekate_for "$BOB_VOL" org invites >/tmp/hekate.last 2>&1 \
  || die "bob list invites: $(cat /tmp/hekate.last)"
grep -q "$ORG_ID" /tmp/hekate.last || die "bob did not see invitation for $ORG_ID"
grep -q "Acme" /tmp/hekate.last || die "invitation missing org name"
ok "bob sees pending invitation"

# ---- 11. bob accepts ---------------------------------------------------
say "bob → org accept"
run_for "$BOB_VOL" "$HEKATE_PASS" org accept "$ORG_ID" >/dev/null
grep -q "Joined org" /tmp/hekate.last || die "bob accept: $(cat /tmp/hekate.last)"
grep -q "org signing pubkey pinned" /tmp/hekate.last || die "bob did not TOFU-pin org signing key"
ok "bob accepted; org signing pubkey TOFU-pinned"

# ---- 12. both list orgs ------------------------------------------------
say "alice → org list (expect member_count = 2)"
hekate_for "$ALICE_VOL" org list >/tmp/hekate.last 2>&1 \
  || die "alice list: $(cat /tmp/hekate.last)"
grep -q "Acme" /tmp/hekate.last || die "alice does not see Acme"
grep -E "Acme.*owner.*[[:space:]]2$" /tmp/hekate.last >/dev/null \
  || die "alice does not see member_count=2: $(cat /tmp/hekate.last)"
ok "alice sees Acme owner, 2 members"

say "bob → org list (expect role=user)"
hekate_for "$BOB_VOL" org list >/tmp/hekate.last 2>&1 \
  || die "bob list: $(cat /tmp/hekate.last)"
grep -q "Acme" /tmp/hekate.last || die "bob does not see Acme"
grep -E "Acme.*user" /tmp/hekate.last >/dev/null \
  || die "bob role is not 'user': $(cat /tmp/hekate.last)"
ok "bob sees Acme as user"

# ---- 12.4. M4.3 collections + org-owned cipher -------------------------
say "alice → org collection create Engineering"
run_for "$ALICE_VOL" "$HEKATE_PASS" org collection create "$ORG_ID" --name 'Engineering' >/dev/null
grep -q "Created collection" /tmp/hekate.last \
  || die "alice create collection: $(cat /tmp/hekate.last)"
COLL_ID=$(grep -oE '019[0-9a-f-]+' /tmp/hekate.last | head -1)
[ -n "$COLL_ID" ] || die "could not extract collection id"
ok "collection $COLL_ID created"

say "bob → org collection list (decrypts the name)"
run_for "$BOB_VOL" "$HEKATE_PASS" org collection list "$ORG_ID" >/dev/null
grep -q "Engineering" /tmp/hekate.last \
  || die "bob did not see the decrypted collection name: $(cat /tmp/hekate.last)"
ok "bob sees 'Engineering'"

say "alice → add login --org --collection (org-owned cipher)"
run_for "$ALICE_VOL" "$HEKATE_PASS" add login --name 'Acme-Wifi' \
  --username 'guest' --password 'shared123' \
  --org "$ORG_ID" --collection "$COLL_ID" >/dev/null
grep -q "Created login" /tmp/hekate.last \
  || die "alice create org cipher: $(cat /tmp/hekate.last)"
ok "org cipher created"
CIPHER_ID=$(grep -oE '019[0-9a-f-]+' /tmp/hekate.last | tail -1)
[ -n "$CIPHER_ID" ] || die "could not extract cipher id"

# ---- 12.4a. M4.4 permissions: bob has no perms → can't see -------------
say "bob → list (M4.4: no permission row → no visibility)"
run_for "$BOB_VOL" "$HEKATE_PASS" list >/dev/null
grep -q "Acme-Wifi" /tmp/hekate.last \
  && die "bob saw the cipher without a collection_members row"
ok "bob correctly sees no org cipher (no permission)"

say "alice → org collection grant bob read_hide_passwords"
run_for "$ALICE_VOL" "$HEKATE_PASS" org collection grant "$ORG_ID" "$COLL_ID" "$BOB_UID" \
  --permission read_hide_passwords >/dev/null
grep -q "Granted read_hide_passwords" /tmp/hekate.last \
  || die "alice grant: $(cat /tmp/hekate.last)"
ok "alice granted bob read_hide_passwords"

say "bob → show (password must be masked under read_hide_passwords)"
run_for "$BOB_VOL" "$HEKATE_PASS" show "$CIPHER_ID" --reveal >/dev/null
grep -q "Acme-Wifi" /tmp/hekate.last \
  || die "bob did not see the cipher after grant"
grep -q "<hidden by collection permission>" /tmp/hekate.last \
  || die "bob's password was not masked under read_hide_passwords: $(cat /tmp/hekate.last)"
grep -qv "shared123" /tmp/hekate.last \
  || die "bob saw the password despite read_hide_passwords"
ok "bob's password is masked"

say "bob → tries to delete (must be 403)"
run_for "$BOB_VOL" "$HEKATE_PASS" delete "$CIPHER_ID" >/dev/null 2>&1 \
  && die "bob's delete should have failed with permission denied"
grep -qE "permission denied|403|requires \`manage\`" /tmp/hekate.last \
  || die "bob's delete didn't fail with the expected permission error: $(cat /tmp/hekate.last)"
ok "bob's write blocked (read_hide_passwords)"

say "alice → upgrade bob to manage"
run_for "$ALICE_VOL" "$HEKATE_PASS" org collection grant "$ORG_ID" "$COLL_ID" "$BOB_UID" \
  --permission manage >/dev/null
grep -q "Granted manage" /tmp/hekate.last \
  || die "alice upgrade: $(cat /tmp/hekate.last)"
ok "alice upgraded bob to manage"

say "bob → show --reveal (now sees password)"
run_for "$BOB_VOL" "$HEKATE_PASS" show "$CIPHER_ID" --reveal >/dev/null
grep -q "shared123" /tmp/hekate.last \
  || die "bob did not see the password under manage: $(cat /tmp/hekate.last)"
ok "bob sees password under manage"

say "alice → revoke bob"
run_for "$ALICE_VOL" "$HEKATE_PASS" org collection revoke "$ORG_ID" "$COLL_ID" "$BOB_UID" >/dev/null
grep -q "Revoked" /tmp/hekate.last \
  || die "alice revoke: $(cat /tmp/hekate.last)"
ok "alice revoked bob"

say "bob → list (must NOT see the cipher anymore)"
run_for "$BOB_VOL" "$HEKATE_PASS" list >/dev/null
grep -q "Acme-Wifi" /tmp/hekate.last \
  && die "bob still sees the cipher after revoke"
ok "bob lost visibility after revoke"

# ---- 12.4b. M4.5a cipher org-move (round trip) -------------------------
say "alice → add personal login (will move into the org)"
run_for "$ALICE_VOL" "$HEKATE_PASS" add login --name 'Personal-Spy' \
  --username 'spy' --password 'sneak' >/dev/null
grep -q "Created login" /tmp/hekate.last \
  || die "alice add personal: $(cat /tmp/hekate.last)"
PERSONAL_ID=$(grep -oE '019[0-9a-f-]+' /tmp/hekate.last | tail -1)
[ -n "$PERSONAL_ID" ] || die "could not extract personal cipher id"
ok "personal cipher $PERSONAL_ID created"

say "alice → move-to-org (re-keys under org sym key)"
run_for "$ALICE_VOL" "$HEKATE_PASS" move-to-org "$PERSONAL_ID" \
  --org "$ORG_ID" --collection "$COLL_ID" >/dev/null
grep -qE "Moved .* into org" /tmp/hekate.last \
  || die "move-to-org failed: $(cat /tmp/hekate.last)"
ok "alice moved cipher into org"

say "alice → show (still readable after move)"
run_for "$ALICE_VOL" "$HEKATE_PASS" show "$PERSONAL_ID" --reveal >/dev/null
grep -q "sneak" /tmp/hekate.last \
  || die "alice can't decrypt the moved cipher"
ok "alice still reads the cipher under org sym key"

say "alice → move-to-personal (re-keys under account_key)"
run_for "$ALICE_VOL" "$HEKATE_PASS" move-to-personal "$PERSONAL_ID" >/dev/null
grep -qE "Moved .* into your personal vault" /tmp/hekate.last \
  || die "move-to-personal failed: $(cat /tmp/hekate.last)"
ok "alice moved cipher back to personal"

say "alice → show (still readable after move-back)"
run_for "$ALICE_VOL" "$HEKATE_PASS" show "$PERSONAL_ID" --reveal >/dev/null
grep -q "sneak" /tmp/hekate.last \
  || die "alice can't decrypt after move-to-personal"
ok "alice still reads the cipher under account_key"

# ---- 12.5. M4.2 roster verification on /sync ---------------------------
say "alice → sync (must verify org roster against pinned signing key)"
run_for "$ALICE_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Orgs:.*✓ verified" /tmp/hekate.last \
  || die "alice sync did not verify org roster: $(cat /tmp/hekate.last)"
ok "alice sync ✓ org roster verified"

say "bob → sync (must verify org roster against pinned signing key)"
run_for "$BOB_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Orgs:.*✓ verified" /tmp/hekate.last \
  || die "bob sync did not verify org roster: $(cat /tmp/hekate.last)"
ok "bob sync ✓ org roster verified"

# ---- 12.6. M4.5b — member removal + org key rotation -----------------
# Bring carol on board, then alice revokes bob from the org. The
# rotation is the load-bearing check: every remaining non-owner member
# (carol) must observe the new sym key via a pending signcryption
# envelope on /sync, and bob must lose org membership entirely.

say "register carol"
printf '%s\n%s\n' "$HEKATE_PASS" "$HEKATE_PASS" | \
  hekate_for "$CAROL_VOL" register --server http://host.docker.internal:8088 \
    --email "$CAROL_EMAIL" >/tmp/hekate.last 2>&1 \
  || die "register carol: $(cat /tmp/hekate.last)"
grep -q "Registered and logged in" /tmp/hekate.last || die "carol register did not confirm"
ok "carol registered"

CAROL_UID=$(hekate_for "$CAROL_VOL" peer fingerprint 2>&1 \
  | awk '/^user_id:/{print $2}')
[ -n "$CAROL_UID" ] || die "could not read carol user_id"
ok "carol = $CAROL_UID"

say "alice → peer fetch carol"
hekate_for "$ALICE_VOL" peer fetch "$CAROL_UID" >/tmp/hekate.last 2>&1 \
  || die "alice peer fetch carol: $(cat /tmp/hekate.last)"
grep -q "pinned new peer" /tmp/hekate.last || die "alice did not pin carol"
ok "alice pinned carol"

say "alice → org invite carol"
run_for "$ALICE_VOL" "$HEKATE_PASS" org invite "$ORG_ID" "$CAROL_UID" --role user >/dev/null
grep -q "Invited" /tmp/hekate.last || die "invite carol failed: $(cat /tmp/hekate.last)"
grep -q "Roster bumped to v3" /tmp/hekate.last || die "carol invite did not bump to v3"
ok "alice invited carol; roster v3 signed"

say "carol → peer fetch alice"
hekate_for "$CAROL_VOL" peer fetch "$ALICE_UID" >/tmp/hekate.last 2>&1 \
  || die "carol peer fetch alice: $(cat /tmp/hekate.last)"
grep -q "pinned new peer" /tmp/hekate.last || die "carol did not pin alice"
ok "carol pinned alice"

say "carol → org accept"
run_for "$CAROL_VOL" "$HEKATE_PASS" org accept "$ORG_ID" >/dev/null
grep -q "Joined org" /tmp/hekate.last || die "carol accept: $(cat /tmp/hekate.last)"
ok "carol accepted; org signing pubkey TOFU-pinned"

say "alice → org collection grant carol read"
run_for "$ALICE_VOL" "$HEKATE_PASS" org collection grant "$ORG_ID" "$COLL_ID" "$CAROL_UID" \
  --permission read >/dev/null
grep -q "Granted read" /tmp/hekate.last || die "alice grant carol: $(cat /tmp/hekate.last)"
ok "carol can read the Engineering collection"

# Capture pre-rotation key_id so we can prove the rotation actually
# rotated.
OLD_KEY_ID=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT org_sym_key_id FROM organizations WHERE id = '$ORG_ID'" | tr -d '[:space:]')
[ -n "$OLD_KEY_ID" ] || die "could not read org_sym_key_id pre-rotation"

say "alice → org remove-member bob (rotates org sym key + re-wraps ciphers)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org remove-member "$ORG_ID" "$BOB_UID" >/dev/null
grep -qE "Removed .* Rotated org sym key" /tmp/hekate.last \
  || die "alice remove-member: $(cat /tmp/hekate.last)"
grep -q "Roster bumped to v4" /tmp/hekate.last \
  || die "remove-member did not bump roster to v4: $(cat /tmp/hekate.last)"
ok "alice removed bob and rotated key"

say "Postgres: org_sym_key_id changed after rotation"
NEW_KEY_ID=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT org_sym_key_id FROM organizations WHERE id = '$ORG_ID'" | tr -d '[:space:]')
[ -n "$NEW_KEY_ID" ] || die "could not read post-rotation key_id"
[ "$NEW_KEY_ID" != "$OLD_KEY_ID" ] || die "org_sym_key_id did not change"
ok "org_sym_key_id rotated ($OLD_KEY_ID → $NEW_KEY_ID)"

say "bob → org list (must NOT include Acme)"
hekate_for "$BOB_VOL" org list >/tmp/hekate.last 2>&1 \
  || die "bob org list: $(cat /tmp/hekate.last)"
grep -q "Acme" /tmp/hekate.last && die "bob still sees Acme after revoke"
ok "bob lost org membership"

say "bob → sync (no org rosters, the revoke removed his row)"
run_for "$BOB_VOL" "$HEKATE_PASS" sync >/dev/null
# When bob has no orgs at all, the M4.2 verifier doesn't print Orgs:
# at all; just confirm bob doesn't see "✓ verified" for any org now
# AND the cipher count is zero.
grep -q "Ciphers:     0" /tmp/hekate.last \
  || die "bob's /sync still surfaces ciphers after revoke: $(cat /tmp/hekate.last)"
ok "bob's /sync shows no ciphers after revoke"

say "carol → sync (consumes pending org-key envelope, then ✓ verifies)"
run_for "$CAROL_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Consumed pending org-key rotation" /tmp/hekate.last \
  || die "carol did not consume the pending envelope: $(cat /tmp/hekate.last)"
grep -q "Orgs:.*✓ verified" /tmp/hekate.last \
  || die "carol sync did not verify post-rotation roster: $(cat /tmp/hekate.last)"
ok "carol consumed envelope and verified rotated roster"

say "carol → sync again (no more pending envelope this time)"
run_for "$CAROL_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Consumed pending org-key rotation" /tmp/hekate.last \
  && die "carol's pending envelope should have been cleared"
ok "carol's pending envelope was cleared after first consume"

say "carol → show $CIPHER_ID --reveal (decrypts under new sym key)"
run_for "$CAROL_VOL" "$HEKATE_PASS" show "$CIPHER_ID" --reveal >/dev/null
grep -q "Acme-Wifi" /tmp/hekate.last \
  || die "carol can't see the cipher after rotation: $(cat /tmp/hekate.last)"
grep -q "shared123" /tmp/hekate.last \
  || die "carol could not decrypt the password under the new sym key: $(cat /tmp/hekate.last)"
ok "carol decrypts the cipher under the rotated sym key"

# ---- 12.7. M4.6 — policies (set + propagate + enforce) ----------------
# alice (owner) sets master_password_complexity + single_org on Acme.
# Carol's /sync surfaces them; her `hekate generate` honors the rules and
# alice's attempt to create a second org is blocked by single_org.

say "alice → org policy set master_password_complexity"
run_for "$ALICE_VOL" "$HEKATE_PASS" org policy set "$ORG_ID" master_password_complexity \
  --enabled true \
  --config '{"min_length":16,"require_upper":true,"require_lower":true,"require_digit":true}' \
  >/dev/null
grep -q "Set policy master_password_complexity" /tmp/hekate.last \
  || die "alice set complexity: $(cat /tmp/hekate.last)"
ok "alice set master_password_complexity"

say "alice → org policy list (sees it)"
hekate_for "$ALICE_VOL" org policy list "$ORG_ID" >/tmp/hekate.last 2>&1 \
  || die "alice list policies: $(cat /tmp/hekate.last)"
grep -q "master_password_complexity" /tmp/hekate.last \
  || die "alice does not see policy in list: $(cat /tmp/hekate.last)"
ok "alice's list shows master_password_complexity"

say "alice → org policy set password_generator_rules (min_length 24, all classes)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org policy set "$ORG_ID" password_generator_rules \
  --enabled true \
  --config '{"min_length":24,"character_classes":["lower","upper","digit","symbol"]}' \
  >/dev/null
grep -q "Set policy password_generator_rules" /tmp/hekate.last \
  || die "alice set generator rules: $(cat /tmp/hekate.last)"
ok "alice set password_generator_rules"

say "carol → sync (must surface the policies via OrgSyncEntry.policies)"
run_for "$CAROL_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Orgs:.*✓ verified" /tmp/hekate.last \
  || die "carol's sync did not pass after policy set: $(cat /tmp/hekate.last)"
ok "carol's sync verified (policies in payload)"

say "carol → generate --length 8 (must be blocked by min_length=24 policy)"
run_for "$CAROL_VOL" "$HEKATE_PASS" generate --length 8 >/dev/null 2>&1 \
  && die "carol's generate --length 8 should have been rejected by policy"
grep -qE "below the 24-character minimum|password_generator_rules" /tmp/hekate.last \
  || die "carol's policy rejection message looks wrong: $(cat /tmp/hekate.last)"
ok "carol's --length 8 rejected by policy"

say "carol → generate --length 32 (compliant, must succeed)"
run_for "$CAROL_VOL" "$HEKATE_PASS" generate --length 32 >/dev/null \
  || die "carol's compliant generate failed: $(cat /tmp/hekate.last)"
ok "carol's --length 32 produced a password"

say "carol → generate --no-symbols (must be blocked: policy requires symbol class)"
run_for "$CAROL_VOL" "$HEKATE_PASS" generate --length 32 --no-symbols >/dev/null 2>&1 \
  && die "carol's --no-symbols should have been rejected by policy"
grep -qE "requires symbol|--no-symbols" /tmp/hekate.last \
  || die "carol's symbol-class rejection message looks wrong: $(cat /tmp/hekate.last)"
ok "carol's --no-symbols rejected by policy"

say "alice → org policy set single_org"
run_for "$ALICE_VOL" "$HEKATE_PASS" org policy set "$ORG_ID" single_org \
  --enabled true --config '{}' >/dev/null
grep -q "Set policy single_org" /tmp/hekate.last \
  || die "alice set single_org: $(cat /tmp/hekate.last)"
ok "alice set single_org"

say "alice → org create Bogus (must be blocked by single_org on Acme)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org create --name 'Bogus' >/dev/null 2>&1 \
  && die "alice's second-org create should have been blocked by single_org"
grep -qE "single_org|forbidden|403" /tmp/hekate.last \
  || die "alice's second-org block message looks wrong: $(cat /tmp/hekate.last)"
ok "alice's second-org create blocked by single_org"

say "alice → org policy unset single_org (cleanup)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org policy unset "$ORG_ID" single_org >/dev/null
grep -q "Unset policy single_org" /tmp/hekate.last \
  || die "alice unset single_org: $(cat /tmp/hekate.last)"
ok "alice unset single_org"

# ---- 12.8. M2.21 — per-org signed cipher manifest --------------------
# Owner writes auto-upload the manifest; members verify on /sync under
# their TOFU-pinned org signing pubkey. Plus the explicit refresh
# command for the case where non-owner writes have left the manifest
# stale.

say "alice → sync (cipher manifest was auto-signed after each add)"
run_for "$ALICE_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Org ciphers:.*✓ verified" /tmp/hekate.last \
  || die "alice's sync did not verify org cipher manifest: $(cat /tmp/hekate.last)"
ok "alice's /sync verifies signed cipher manifest"

say "carol → sync (verifies manifest under pinned org signing key)"
run_for "$CAROL_VOL" "$HEKATE_PASS" sync >/dev/null
grep -q "Org ciphers:.*✓ verified" /tmp/hekate.last \
  || die "carol's sync did not verify org cipher manifest: $(cat /tmp/hekate.last)"
ok "carol's /sync verifies signed cipher manifest"

say "alice → org cipher-manifest refresh (explicit owner-driven rebuild)"
run_for "$ALICE_VOL" "$HEKATE_PASS" org cipher-manifest refresh "$ORG_ID" >/dev/null
grep -q "Refreshed signed cipher manifest" /tmp/hekate.last \
  || die "alice's explicit refresh failed: $(cat /tmp/hekate.last)"
ok "alice's explicit cipher-manifest refresh succeeded"

say "Postgres: org_cipher_manifests row present + version >= 2"
ROWS=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT count(*) FROM org_cipher_manifests WHERE org_id = '$ORG_ID'")
[ "$ROWS" = "1" ] || die "expected 1 cipher manifest row, got $ROWS"
VERSION=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT version FROM org_cipher_manifests WHERE org_id = '$ORG_ID'")
[ "$VERSION" -ge 2 ] || die "expected manifest version >= 2 after multiple writes, got $VERSION"
ok "DB shows org_cipher_manifests row at v$VERSION"

# ---- 13. server-side roster check --------------------------------------
say "Postgres: organization_members count for $ORG_ID"
ROWS=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT count(*) FROM organization_members WHERE org_id = '$ORG_ID'")
[ "$ROWS" = "2" ] || die "expected 2 accepted members (alice+carol), got $ROWS"
ok "DB shows 2 accepted members (alice + carol)"

VERSION=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT roster_version FROM organizations WHERE id = '$ORG_ID'")
[ "$VERSION" = "4" ] || die "expected roster v4 after revoke, got v$VERSION"
ok "DB shows latest roster v4 (genesis → invite_bob → invite_carol → revoke_bob)"

INVITES=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT count(*) FROM organization_invites WHERE org_id = '$ORG_ID'")
[ "$INVITES" = "0" ] || die "expected 0 pending invites, got $INVITES"
ok "DB shows no pending invites"

PENDING=$(docker exec hekate-postgres-1 psql -U hekate -d hekate -tAc \
  "SELECT count(*) FROM organization_members
     WHERE org_id = '$ORG_ID' AND pending_org_key_envelope_json IS NOT NULL")
[ "$PENDING" = "0" ] || die "expected 0 pending rotation envelopes, got $PENDING"
ok "DB shows all pending rotation envelopes consumed"

# ---- 14. report --------------------------------------------------------
echo
ok "ALL M4.1 + M4.5b + M4.6 + M2.21 SMOKE CHECKS PASSED"
