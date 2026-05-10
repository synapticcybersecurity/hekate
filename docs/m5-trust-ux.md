# M5 — Trust UX (kickoff plan)

Per the open follow-up "Trust UX — pinning friction" surfaced during
the 2026-05-09 M4.5b smoke. This document captures the design
discussion that locked the architecture for M5 v1, with reasoning
preserved so the doc doubles as audit-facing reference for the
threat model going forward.

All identifiers below use the current `hekate-*` naming.
Protocol-frozen byte literals (AAD strings, signature DSTs,
token prefixes, magic numbers) retain their original `pmgr-`
form because they're baked into ciphertexts on disk; the table
in `threat-model-gaps.md` enumerates the protected literals.

> **Vendor entity (for audit / legal clarity).** The
> Hekate-managed-recovery commercial offering described in this
> doc is operated by **Synaptic Cybersecurity Alliance, Inc.**
> (operating brand: **Synapticcyber**, primary domain
> `synapticcyber.com`). The managed Hekate SaaS is at
> `hekate.synapticcyber.com`. References to "Synapticcyber"
> below mean Synaptic Cybersecurity Alliance, Inc. as the
> operating entity. The product itself, **Hekate**, is
> independent of the vendor — self-host customers running
> Hekate are not using a Synapticcyber service.

## Why this milestone exists

During the M4.5b smoke (member-removal + key-rotation), org owners
hit "remaining member is not pinned" walls during routine
member-removal because the rotation flow requires every remaining
non-owner to be TOFU-pinned client-side, with out-of-band
fingerprint verification for each. The same friction surfaces on
invite (owner pins invitee), on accept (invitee pins owner), and
on every device a member signs in from. For non-technical users
this is an availability cliff, not a security feature.

The M5 design replaces "every member TOFU-pins every other member"
with "every member TOFU-pins the org owner-set, and the owner-set
endorses every member's fingerprint in a signed roster." The org
owner-set becomes the single trust root per org; per-peer pinning
becomes opt-in for high-stakes orgs (strong mode).

## Decisions locked

(From the design Q&A on 2026-05-09. See "Reasoning preserved" sections
below for context on each.)

| # | Decision | Choice |
|---|---|---|
| Q1 | Roster binding granularity | **Fingerprint-bound.** Roster entry adds `signingPubkeyFingerprint: BLAKE3(canonical_bundle_bytes)`. Bundle format stays independent of roster schema. |
| Q2 | Authority / quorum model | **Per-owner keypair, pinned co-owner set.** Each owner signs with their own account-level Ed25519 key. Roster signed by *any one* current owner (1-of-N for routine ops). Adding/removing owners requires **2-of-N**. |
| Q3 | Rotation + revocation flows | **Two distinct flows.** Flow A (rotation envelope, voluntary): client signs new bundle under old key (`priorSig`); owners auto-apply on next sync after chain verification. Flow B (owner-driven revocation): existing M4.5b path, owner removes member + triggers org sym-key rotation. |
| Q4 | Migration from v1 rosters | **No migration.** Hekate has no production users; M5 ships v2 as the only schema. v1 never deploys to production clients. |
| Q5 | Strong-mode opt-out | **Single signed bool per org**, default off. New orgs offer it at create time. Flipping in either direction requires 2-of-N quorum. May split into per-policy toggles in v2 if real users want hybrid postures. |
| — | Multi-owner invariant | **Required as soon as the org has any non-owner members.** All-owner orgs and solo orgs are exempt. Recovery-owner identity counts as the second owner for solo / single-human use cases. |
| — | Logging + alerting | **First-class design concern**, not a follow-up. Spec'd inline below; integrates with the future M5 global `events` table referenced in M6's Q4. |
| — | Threshold recovery (M5.x — direction locked, deferred) | **FROST-Ed25519** for cryptographic threshold signing. Default 2-of-4 topology (3 customer shares + 1 optional external). Per-incident customer authorization via FROST nonces. 24h-default time-delay (configurable 1h–72h). Strong-mode disallows external participants. Schema reserves `threshold_share` owner type so future implementation is additive. Synapticcyber managed recovery is one commercial configuration of this primitive, not a privileged protocol path. |

## Schema additions

All non-breaking from the storage perspective; v1 columns and
tables remain readable. Since Q4 ruled out migration, "v1
readability" is academic — we ship v2 directly.

### Pubkey bundle (extends `users` / pubkey storage)

```
PubkeyBundle v2 canonical bytes :=
  user_id || signing_pk || x25519_pk || version (u32 BE) || prior_sig (64 bytes, zeroes for v1)

self_sig    := Ed25519(signing_priv, canonical_bytes)
prior_sig   := Ed25519(prior_signing_priv, canonical_bytes_with_zeroed_prior_sig)
fingerprint := BLAKE3(canonical_bytes || self_sig)
```

`prior_sig` is zero for the first bundle a user ever publishes.
Subsequent bundles (after a master-password change) carry a
`prior_sig` proving continuity from the previous version's
signing key. Server stores the chain; clients can replay it to
verify any bundle traces back through valid prior_sigs.

### Roster (BW08 v2)

```sql
ALTER TABLE roster_entries ADD COLUMN signing_pubkey_fingerprint BYTEA NOT NULL;
ALTER TABLE organizations ADD COLUMN roster_version SMALLINT NOT NULL DEFAULT 2;
```

The roster's signed canonical bytes now include each entry's
fingerprint:

```
RosterEntry := { user_id, role, signing_pubkey_fingerprint }
```

Verification: client fetches the bundle for each member, computes
`BLAKE3(canonical_bundle_bytes || self_sig)`, compares to the
roster's `signing_pubkey_fingerprint`. Mismatch fails closed.

### Co-owner set

New per-org structure, parallel to roster:

```sql
CREATE TABLE org_co_owner_sets (
    org_id        UUID NOT NULL,
    version       INTEGER NOT NULL,
    canonical     BYTEA NOT NULL,    -- canonical-encoded bytes
    signature     BYTEA NOT NULL,    -- Ed25519 sig under previous-version's signer
    parent_hash   BYTEA NOT NULL,    -- BLAKE3 of previous version's canonical bytes
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version)
);
```

Canonical content:

```
CoOwnerSet := {
    org_id,
    version,
    parent_canonical_blake3,
    timestamp,
    entries: [
        { owner_type: "human" | "recovery" | "threshold_share",
          owner_user_id: nullable<uuid>,        // present iff human
          owner_signing_pubkey: ed25519_pk,
          share_set_id: nullable<uuid>,         // present iff threshold_share; groups with other shares
          label: utf8_string }
    ],
    quorum_routine: u8,                          // = 1 (any owner can sign roster)
    quorum_owner_change: u8                      // = 2 (any owner add/remove)
}
```

The `threshold_share` entry type is reserved for the M5.x threshold-recovery
primitive (see "Threshold recovery (M5.x — design direction)" below). Not
implemented in M5 v1; the schema admits it so future versions can extend
without a migration.

```
// future-only, not implemented in M5 v1:
ThresholdShareSet := {
    id: uuid,
    org_id: uuid,
    threshold: u8,                               // T (e.g., 2)
    total_shares: u8,                            // N (e.g., 4)
    aggregated_pubkey: ed25519_pk,               // FROST aggregate verification key
    time_delay_secs: u32,                        // delay before threshold-signed action takes effect
    created_at: timestamp,
}
```

Members TOFU-pin the **initial** co-owner set (version 1) when
they accept an invite to the org. Subsequent updates are signed
by the previous version's signer (1-of-N for routine policy
changes that don't add/remove owners; **2-of-N for adding or
removing co-owners**).

### Org policy block

```sql
ALTER TABLE organizations ADD COLUMN policy_canonical BYTEA NOT NULL;
ALTER TABLE organizations ADD COLUMN policy_signature BYTEA NOT NULL;
ALTER TABLE organizations ADD COLUMN policy_version INTEGER NOT NULL DEFAULT 1;
```

Canonical content:

```
OrgPolicy := {
    org_id,
    version,
    parent_canonical_blake3,
    timestamp,
    strong_mode: bool,
    // Future toggles slot here
}
```

Updates signed by the current co-owner set under 2-of-N quorum
(strong-mode flips are security-relevant; both directions require
quorum).

## Flow specifications

### Flow A — Rotation envelope (voluntary master-password change)

User triggers `hekate account change-password` (or equivalent in
popup / web vault).

1. Client derives new master_key, new signing seed → new signing
   pubkey `P_new`.
2. Client constructs `PubkeyBundle v(N+1)` with new `signing_pk`,
   incremented `version`, and `prior_sig := sign(P_old, canonical_bytes_with_zeroed_prior_sig)`.
3. Client posts new bundle to server. Server stores alongside
   prior version (chain preserved).
4. Server emits a `bundle.rotated` push event for any user whose
   client subscribes (typically: members of orgs the rotating
   user is in).
5. **Default mode:** When an org owner's client receives the
   event, it verifies `prior_sig` (chain continuity) and
   automatically signs a roster update with the new fingerprint.
   No owner UI interaction required.
6. **Strong mode:** The rotation envelope is queued for owner
   review. UI shows old + new fingerprint side-by-side and
   prompts: "Have you confirmed the new fingerprint with the user
   via a separate channel?" Owner explicitly accepts before the
   roster update is signed.

#### Edge cases

- **Compromised old key.** An attacker holding the user's old
  signing key can produce a valid rotation envelope to *their*
  new key. Default-mode owners would auto-apply. **Mitigation
  is out-of-band, not cryptographic** — see the Threat Model
  section below. Strong mode forces human-in-the-loop verification.
- **Rotation while offline.** Client queues the new bundle locally;
  flushes on next sync. No timing assumption needed.
- **Multiple rotations.** Chain `v1 → v2 → v3 → ...` is preserved;
  late-syncing owners verify the full chain back to the bundle
  they last endorsed.
- **Server hides a rotation step.** Chain breaks (`v3.prior_sig`
  is signed by `v2`'s key, not `v1`'s); client refuses.

### Flow B — Owner-driven revocation (compromise / off-boarding)

Existing M4.5b flow with v2 schema:

1. Owner signs roster v(N+1) **omitting** the evicted member.
2. Owner triggers M4.5b: new `org_sym_key` generated; every
   org-owned cipher key re-wrapped under new sym key; the evicted
   member's `protected_org_key` is *not* re-wrapped (they lose
   access).
3. Strong-mode org: M4.5b requires **2-of-N quorum**. Default
   mode: any single owner can trigger.
4. Existing rotation envelopes from the evicted user are
   discarded (not consumed) — their chain doesn't matter once
   they're not in the roster.

### Flow C — Recovery-owner self-rescue

User has lost their master password (personal vault is
unrecoverable by design — see the recovery-codes-are-auth-only
memory).

1. User re-registers on the same Hekate instance, getting a new
   `userId`, new bundle, new fingerprint.
2. User loads recovery-owner key from offline storage (paper
   mnemonic / hardware key / encrypted file).
3. User invokes `hekate org rejoin-with-recovery <org-id>`. The
   client transiently loads the recovery key, signs a co-owner-set
   update adding the new `userId` as a human owner, and posts to
   server. Recovery key is zeroed from memory immediately.
4. Other org owners (or other co-owners with current authority)
   sync, see the new co-owner-set version, verify the recovery
   key's signature against the previously-pinned set, accept.
5. User is back in the org as themselves with a new userId.
   Personal vault is still gone; org membership is restored.

#### Strong-mode restrictions on Flow C

- Default mode: recovery-owner has full equivalence with a human
  owner (can sign roster updates, endorse new fingerprints, evict
  other owners subject to quorum).
- **Strong mode: recovery-owner restricted to self-rescue only.**
  Cannot do routine endorsements, cannot evict other owners.
  Self-rescue itself remains allowed because preventing it would
  defeat the purpose of having the primitive.

## Recovery-owner identity primitive

A recovery owner is a co-owner-set entry that isn't tied to a
Hekate user account. It's a raw Ed25519 keypair the human
generates and stashes offline.

### Personal vs institutional use

The recovery-owner primitive is identity-agnostic — the protocol
doesn't care whether the keypair is held by a single human, a
team, or an institution. The same primitive supports both:

- **Personal use:** a single human stores their recovery key
  (paper / hardware) for self-rescue after master-password loss.
  Already covered in detail in this section.
- **Institutional use:** a company holds a recovery key in a
  corporate safe (HR / legal / IT). The company can use it to
  rejoin / reauthorize org access after employee turnover or
  catastrophic owner loss. The key is structurally identical to
  a personal recovery key; the difference is who controls it
  organizationally.

Institutional use is what handles the routine "employee
terminated / acting maliciously" scenario. Existing flows already
cover this without additional features:

1. **Multi-owner invariant** ensures company orgs always have ≥2
   owners; a single termination doesn't leave the org without
   authority.
2. **Flow B (M4.5b owner-driven revocation)** lets remaining
   owners evict the terminated employee + rotate the org sym
   key, severing their access cryptographically.
3. **Institutional recovery-owner** as belt-and-suspenders: if a
   catastrophic loss leaves the company without active human
   owners, the recovery key in the corporate safe rejoins the
   company's authority.

The "company can recover what the company owns" requirement is
satisfied by these three primitives, *not* by vendor recovery.
Vendor recovery is for a different scenario (the customer has
also lost their institutional recovery keys — see "Threshold
recovery" below).

### Cryptographic shape

- Ed25519 keypair, generated client-side by CSPRNG. **Not derived
  from any master password** — fully independent.
- Private key serialized for offline storage. Three formats:
  - **BIP39-style mnemonic** (24 words, ~256 bits). Print on paper.
  - **Hex / base64 file**, password-protected with a user-chosen
    passphrase. Save to USB stick.
  - **Hardware key** (FIDO2 with HMAC-secret extension, smartcard).
- Public key stored in the org's co-owner-set as
  `{ owner_type: "recovery", owner_user_id: null,
     owner_signing_pubkey: <pk>, label: "Henry's paper key" }`.

### Lifecycle

| Operation | Trigger | Mechanic |
|---|---|---|
| Create | At org creation, or `hekate org add-recovery-owner` | Generate keypair, present seed for offline storage, append to co-owner-set, sign update |
| Rotate | `hekate org rotate-recovery-owner` | Generate new pair, sign co-owner-set update adding new + removing old |
| Revoke | Suspected compromise / loss / `hekate org revoke-recovery-owner` | Other current owners sign co-owner-set update removing the recovery key (2-of-N quorum since this is owner-removal) |
| Use (self-rescue) | User runs `hekate org rejoin-with-recovery` after re-registering | Transiently load offline seed, sign one co-owner-set update, zero from memory |
| Use (routine ops) | Default mode only | Same authority as a human owner |

### Threat model for recovery-owner

| Threat | Defense |
|---|---|
| Recovery key theft | Physical security (safe / safe deposit box). Hardware-key options with PIN/biometric. Compromise containment via standard owner revocation (other owners sign new co-owner-set excluding the compromised key). |
| Recovery key loss | If the user has no other co-owner, they're locked out of the org. **Mitigation:** encourage solo-org users to maintain *two* recovery keys in separate physical locations. The 2-of-N quorum for owner-removal prevents any single recovery-key theft from unilaterally removing the user's other keys. |
| Recovery key + master password compromised simultaneously | Catastrophic — attacker has full org-authority continuity. No cryptographic recovery; out-of-band escalation to other human owners (if any). For solo orgs with no human co-owners, this is unrecoverable. **The argument for not letting solo orgs hold critical secrets without at least one human co-owner.** |

### Industry / academic precedent

The closest analog is the **multi-sig wallet cold-key pattern**
(Bitcoin / Gnosis Safe / Casa). 2-of-3 schemes routinely have one
"cold" key in a safe; the cold key is structurally identical to
Hekate's recovery-owner. Differs from:

- **BIP39 seeds** — those serialize *the* root key, not a
  separate identity. Hekate's recovery-owner is a peer key with
  its own pubkey in the signed co-owner-set.
- **Social recovery wallets** (Argent, EIP-4337 implementations,
  Buterin's 2021 essay [*Why we need wide adoption of social
  recovery wallets*](https://vitalik.eth.limo/general/2021/01/11/recovery.html))
  — those delegate trust to other humans. Hekate's recovery-owner
  is held by the same human, just stored offline.
- **PGP designated revoker** (RFC 4880 §5.2.3.15) — same shape
  (independent key with authority over your identity) but narrow
  scope (only revocation, not full delegation).
- **Threshold signature schemes / FROST / GG18-20 / CGGMP21** —
  cryptographically split a single key across N parties.
  Discrete keys per owner is simpler and gives per-owner
  attribution as a free byproduct.

**Verification pass — completed 2026-05-10.** All citations
above were confirmed against current sources. Findings:

- Buterin essay URL updated to the canonical
  `vitalik.eth.limo` host (the author's site migration; the
  prior `vitalik.ca` URL is no longer reachable).
- All authors / years / venues confirmed for FROST (Komlo &
  Goldberg, SAC 2020), GG18 (Gennaro & Goldfeder, CCS 2018),
  CGGMP21 (Canetti et al., CCS 2020 — note: ePrint 2021/060 but
  presented at CCS 2020), Shamir (CACM 22(11), 1979), and BIP39
  (Palatinus, Rusnak, Voisine, Bowe, 2013).
- RFC 4880 §5.2.3.15 confirmed as the "Revocation Key" subpacket
  (informal name: "designated revoker"). **RFC 4880 has been
  obsoleted by RFC 9580 (2024)**; the designated-revoker
  primitive carries forward unchanged but the canonical reference
  is now RFC 9580.
- Threshold signature literature has moved meaningfully in 2025
  — see the threshold-recovery section's references for the
  current adaptive-security landscape.

Items still recommended for the pre-audit pass:

1. Multi-sig wallet failure-mode literature (lost-quorum
   incidents) — qualitative survey, no specific citation yet.
2. Argent post-mortems — referenced but not deeply audited.
3. Casa / Unchained Capital production multi-sig UX patterns —
   qualitative.

## Threshold recovery (M5.x — design direction)

**Status: deferred from M5 v1, design direction locked.** The
schema (above) reserves the `threshold_share` owner type and the
`ThresholdShareSet` table so the feature ships additively without
a migration when implemented. This section captures the design
intent so the M5 v1 implementation doesn't accidentally close off
the path forward.

### Use case

Higher-resilience recovery than a single recovery-owner key
provides. Customer wants:

- Loss-tolerance against multiple shares being lost simultaneously.
- A "vendor" or third-party share they can call in for catastrophic
  recovery, *without* that party being able to act unilaterally.
- Per-incident customer authorization for any signing event
  involving an external party.

Single-key recovery-owner (M5 v1) gives "1-of-N where any one
recovery key can act with full owner authority." Threshold
recovery gives "T-of-N where T shares must collaborate
cryptographically; no single share — including a vendor share —
can act alone."

### Implementation: FROST-Ed25519

FROST (Komlo & Goldberg, 2020) is the modern Schnorr/Ed25519
threshold signature scheme. Properties relevant to Hekate:

- **The full signing key is never reconstructed.** Each share
  contributes to the signature via the FROST protocol; the
  threshold of shares produces a single Ed25519 signature
  verifiable under one aggregated public key.
- **Per-incident customer authorization is intrinsic.** Each
  signing operation requires fresh nonce contributions from each
  participating share. A vendor cannot replay or pre-compute; if
  the customer's share doesn't participate in a specific signing
  round with fresh nonces, no signature exists for that round.
- **Verification looks like vanilla Ed25519.** Existing roster /
  co-owner-set / policy verification code paths don't change —
  they just verify against the FROST-aggregated pubkey instead of
  a single-party pubkey.

### Topology

Default recommendation: **2-of-4**.

```
Share assignment:
  - Share 1: Primary owner's account-derived signing key
            (online; the per-owner keypair from Q2)
  - Share 2: Customer recovery key A
            (offline, e.g., paper key in CEO's safe)
  - Share 3: Customer recovery key B
            (offline, e.g., hardware token in HR vault)
  - Share 4: External recovery share
            (held by a customer-chosen third party — could be
            Synapticcyber managed recovery, a law firm,
            an insurance carrier, etc.)

Threshold: 2 of 4

Capability matrix:
  - Any 2 customer shares (1+2, 1+3, 2+3) → customer self-recovery
  - External + 1 customer share (4+1, 4+2, 4+3) → externally-assisted
  - External alone (4) → INSUFFICIENT, threshold not met
  - Any single share → INSUFFICIENT
```

Topology is configurable per-org at threshold-recovery enrollment.
Larger customers may want 3-of-7 or higher for distributed
holdings. The protocol is symmetric — every share is equal; no
share has special status in the cryptography.

### Per-incident authorization

FROST signing rounds require fresh participation from at least T
of N shares. Customer authorization is operationalized as:

1. Customer (or external party) initiates a recovery request via
   their Hekate UI. The proposed action — typically "add my new
   userId as an owner of org X" — is fully specified.
2. Hekate routes the request to the other required shareholders
   for participation.
3. Each participating shareholder reviews the proposed action in
   their own client and explicitly opts in to contribute their
   share's nonce + signing contribution.
4. FROST aggregates the contributions into a final signature.
5. Time-delay clock starts (default 24h, configurable 1h–72h).
6. During the delay, any 2 customer shares can revoke the pending
   transaction. After the delay, the action takes effect.
7. Audit log entry signed by the threshold records the event with
   full context (proposed action, participating shares, signing
   timestamp, effective timestamp).

Customer authorization is therefore *cryptographically required*
for every signing round — there's no "standing authorization" the
external party can replay. The participation step itself is the
authorization.

### Strong-mode interaction

Strong-mode orgs **disallow external (non-customer) threshold
participants entirely.** A strong-mode org can still use
threshold recovery, but every share must be controlled by the
customer (no `threshold_share` entries with external labels).
Customers wanting maximum sovereignty run all-customer
thresholds with strong-mode on; the math still gives them
T-of-N resilience without external-party trust.

### Threat model — what threshold defends against

| Threat | Defense |
|---|---|
| External party (e.g., vendor) is compromised | Their share alone is insufficient (T > 1). Attacker holding the external share cannot act without customer participation. |
| External party + server collusion (managed-SaaS scenario) | FROST signing requires customer's fresh nonce contribution. Server controlling the external party cannot synthesize that. **Cryptographically prevents the collusion**, unlike quorum-via-policy. |
| Customer coercion (gunpoint scenario) | Time-delay (24h default) gives other customer shareholders time to detect and revoke. Mandatory active alerting on threshold-signing events prompts other shareholders to investigate. |
| Customer share loss | T-of-N tolerance: with 2-of-4, customer can lose any 2 shares and still recover (potentially with external help). With 2-of-3 customer + 1 external, customer can lose 1 and recover without external help. |
| Replay of past authorization | Per-incident FROST nonces prevent any reuse of previous signing contributions. |

### Threat model — what threshold does *not* defend against

- **Customer + all required external parties simultaneously
  compromised.** If the threshold is met by attacker-controlled
  shares, they can sign. Mitigated by topology choice — make T
  high enough that compromising T parties simultaneously is
  infeasible.
- **Customer revokes external participant after attacker has
  already obtained signature.** Time-delay gives a revocation
  window; after the delay, the signed action stands. Tradeoff
  between recovery latency and revocation responsiveness.

### Synapticcyber managed recovery (commercial layer)

Synapticcyber offers — separately from the protocol —
a paid managed-recovery service: Synapticcyber holds one
threshold share on behalf of the customer, with HSM custody, an
abuse contact, and an SLA on response time.

**Important: this is a commercial layer over the symmetric
protocol, not a Synapticcyber-specific protocol path.**
The wire format treats Synapticcyber's share identically
to any other threshold participant. Customers can run threshold
recovery with no Synapticcyber involvement, with
Synapticcyber as one share, or with Synapticcyber
plus other third parties.

Enrollment flow:

1. Customer (in either self-hosted Hekate or
   Synapticcyber-managed SaaS) opts in via a specific UI:
   "Add Synapticcyber managed recovery to this org."
2. Customer's client fetches Synapticcyber's published
   recovery pubkey, verified against a long-term
   Synapticcyber signing CA included in the binary / SDK
   / extension manifest.
3. Customer's existing co-owner-set authority (2-of-N customer
   shares) signs the addition of the Synapticcyber share
   to the threshold share-set.
4. Synapticcyber is now a threshold participant, treated
   identically to any other.

Customer can revoke Synapticcyber at any time:

1. Customer signs new co-owner-set update removing the
   Synapticcyber share, using 2-of-N customer shares.
2. Takes effect immediately, no Synapticcyber cooperation
   needed.

Synapticcyber-side commitments (key custody, abuse
response, audit log retention, SLA, jurisdictional
considerations) are commercial agreement, not protocol.

The same offering pattern applies to other potential
managed-recovery providers — Hekate doesn't favor or hardcode
Synapticcyber; the binary just happens to ship with
Synapticcyber's CA chain. Any party offering managed
recovery services can publish a CA + pubkey and customers can
enroll them via the same flow.

### Industry / academic precedent

FROST-Ed25519 is well-studied and has multiple production
implementations. Production library: **Zcash Foundation's `frost`
crate** (https://github.com/ZcashFoundation/frost) — at v3.0.0 as
of May 2026, includes `frost-ed25519` alongside other curve
modules. **Partially audited by NCC Group** (audit covers core
protocol; serialization and tooling extensions added in v2/v3 are
not all covered by that audit). The `frost-tools` companion crate
provides `frostd` (signing-coordination server) and a CLI.

- Komlo, C. & Goldberg, I. (2020). *FROST: Flexible Round-Optimized
  Schnorr Threshold Signatures.* SAC 2020. IACR ePrint 2020/852.
- Crites, E., Komlo, C. & Maller, M. (2023). *Fully Adaptive
  Schnorr Threshold Signatures (Sparkle+).* CRYPTO 2023. IACR
  ePrint 2023/445. Proves adaptive security of a three-round
  threshold Schnorr scheme called Sparkle+, distinct from FROST
  itself; weaker but better-than-static security guarantees.
- Crites, E. & Stewart, A. (2025). *A Plausible Attack on the
  Adaptive Security of Threshold Schnorr Signatures.* CRYPTO 2025.
  IACR ePrint 2025/1001. **Important threat-model update.** Shows
  FROST and its variants (and Lindell'22) cannot be proven *fully*
  adaptively secure without modifications, assuming a search
  problem the authors define. Static security is unaffected.
- Companion paper: "On the Adaptive Security of FROST"
  (CRYPTO 2025) and follow-on proposed fixes including
  *Adaptively Secure Partially Non-Interactive Threshold Schnorr*
  (IACR ePrint 2025/1953).
- Bitcoin Improvement Proposal BIP340 (Schnorr signatures).
- Ethereum account-abstraction work on social recovery wallets
  (Buterin's 2021 essay, EIP-4337 implementations).

**Threat-model implication for Hekate:** Hekate's M5.x recovery
scenario operates under static-corruption assumptions
(participants are known in advance; recovery is a low-frequency,
human-coordinated operation, not a high-throughput signing
service). Static security of FROST is well-established and
sufficient for this use case. Adaptive security is an open
research question as of 2026 with active fixes proposed; track
the field through M5.x implementation and re-evaluate before
adopting any non-default FROST variant. The 24h time-delay
specified earlier is itself an additional defense layer that
mitigates several adaptive-corruption scenarios at the protocol
level rather than the cryptographic-proof level.

### Open questions for the M5.x implementation session

These are not load-bearing on the M5 v1 architecture but must be
answered before threshold recovery code lands:

1. **FROST library choice.** Zcash Foundation's `frost-ed25519`
   crate is the current obvious candidate; verify audit status
   and recent updates.
2. **Offline signing UX.** FROST has multi-round protocols;
   offline shares (paper keys, hardware tokens) need to support
   participation without continuous network connectivity. Choose
   between online-only flows (paper keys must be loaded into a
   client temporarily) vs. precomputed-nonce flows (allow truly
   offline signing with nonce commitments published in advance).
3. **Time-delay enforcement layer.** Server enforces (server
   refuses to surface threshold-signed actions until delay
   elapses) vs. client enforces (clients refuse to apply until
   delay) vs. both. Recommend "both" for defense in depth.
4. **External-party pubkey distribution.** For
   Synapticcyber: signed CA chain in the binary. For
   other third parties: customer manually enters / pastes the
   third-party pubkey at enrollment, with explicit fingerprint
   verification prompt.
5. **External-party share rotation cadence.** When
   Synapticcyber (or any external party) rotates their
   share, customer must re-enroll. Define rotation policy +
   deprecation window for old shares.
6. **Per-jurisdiction segregation.** EU customers using
   Synapticcyber managed recovery may need a EU-resident
   Synapticcyber entity holding the share for data-locality
   compliance. Operational, not protocol — but should be
   documented.
7. **Pricing tier interactions.** Synapticcyber managed
   recovery is a paid service. Define pricing model + how it
   composes with managed-SaaS offering vs. self-hosted-with-
   managed-recovery.
8. **Audit log retention.** Threshold-recovery events likely need
   longer retention (e.g., 7 years) for compliance contexts.
   Define retention policy independently of the standard event
   table.

## Strong-mode policy specification

Strong-mode is a single signed boolean in the org's policy block.
When enabled, it tightens behavior across the design:

| Behavior | Default mode | Strong mode |
|---|---|---|
| Rotation envelope (Flow A) | Auto-applied after chain verification | Queued for explicit owner acceptance with OOB-confirmation prompt |
| Recovery-owner authority | Full equivalence with human owner | Restricted to self-rescue only |
| New-member endorsement | Any owner endorses on accept | Owner must confirm fingerprint OOB before signing |
| M4.5b removal+rotation | Any single owner can trigger | 2-of-N quorum required |
| Owner add/remove | 2-of-N (per Q2) | 3-of-N or N-of-N (configurable per org) |
| Threshold recovery — external participants | Allowed (e.g., Synapticcyber managed recovery) | **Disallowed entirely.** All threshold-recovery shares must be customer-controlled. |
| Audit visibility | Log + dashboard | Active alerts on every security event |

### Client-enforced vs server-enforced

Some policy points the server can enforce (signature counts,
quorum thresholds visible in the signed artifacts). Others are
purely client-side (whether OOB verification was actually
performed before signing). The honest framing is:

> **Strong-mode is a posture, not a guarantee.** It commits an
> org's clients to higher rigor and commits the server to
> enforcing whatever signature/quorum requirements are observable
> on signed artifacts. It cannot prove that humans actually
> performed the out-of-band checks they were prompted for. The
> server logs that the prompts were shown (when clients report
> this); compliance with the prompted action is best-effort and
> trust-based.

This framing should be repeated verbatim in any user-facing
documentation of strong-mode and in the threat-model section of
the audit doc.

### Flipping the policy

- **Default → Strong:** 2-of-N quorum.
- **Strong → Default:** 2-of-N quorum.
- **At org creation:** offered as a checkbox; default off.

## Logging + alerting requirements

Per the project rule that audit/alerting are first-class design
concerns, M5 features the following observability commitments:

### Events that must be logged

| Event | Logged where | Visible to |
|---|---|---|
| Rotation envelope received (Flow A) | Server-side audit, signed by submitting client | Affected user, all org owners |
| Rotation envelope auto-applied | Server-side audit + each owner's local audit | All owners |
| Rotation envelope queued (strong mode) | Server-side audit | All owners (alert + queue UI) |
| Rotation envelope explicitly accepted (strong mode) | Server-side audit, signed by accepting owner | All owners |
| Co-owner-set updated | Server-side audit | All current and previous owners |
| Recovery-owner key used (any) | Server-side audit, **alert prominently** | All owners — "Henry's recovery key was used to sign roster v23. If this wasn't you, this is a serious incident." |
| Owner add/remove | Server-side audit, signed by quorum | All owners |
| M4.5b rotation triggered | Server-side audit, includes evicted user_id | All owners + evicted user (last notification before access loss) |
| Strong-mode policy flipped | Server-side audit, signed by quorum | All owners; new state shown prominently in org-detail UI |
| New-member fingerprint endorsement | Server-side audit | All owners + endorsed member |

### Alerting tiers

- **Default mode**: events go to the audit log; owners can review
  via a dashboard. No active alerts.
- **Strong mode**: every event in the table above triggers an
  active alert. Channels:
  - In-app notification (mandatory, all owners).
  - Email (opt-in per owner).
  - SMS / push (opt-in for higher-tier deployments).

The alerting infrastructure is the same primitive across modes;
strong-mode just turns the dial from "log" to "alert" on more
event types. Build the alerting primitive to be configurable
per-event-type per-org regardless of mode.

### Tamper-evidence

- Server-side audit table is append-only at the schema level (no
  UPDATE / DELETE policy); compatible with the future global
  `events` table from M6's Q4.
- Each entry stores the canonical bytes of the action plus the
  signature (where signed actions exist). Owners can independently
  verify any entry.
- For unsigned events (server-internal observations), the entry
  is server-trusted only — useful for ops visibility, not for
  cryptographic audit.

## Threat model

### What M5 v2 defends against

1. **Server-side bundle substitution.** Attacker controlling the
   server returns a different `signing_pk` for a member. Client
   computes BLAKE3 of the substituted bundle, compares to roster
   binding, fails closed.
2. **Roster forgery.** Without owner signing key access, attacker
   cannot produce a signed roster. Multi-owner makes this harder
   proportional to the size of the owner-set.
3. **Roster downgrade replay.** Server replays an older roster.
   Monotonic version + parent-chain defense (existing) catches it.
4. **Co-owner-set forgery.** Same defense as roster — attacker
   needs current owner key to sign updates.
5. **Single owner key compromise.** Other owners sign a new
   co-owner-set excluding the compromised key (2-of-N quorum).
   Members refresh and refuse the compromised owner's signatures
   going forward. **No org-wide signing-seed rotation needed.**
6. **Stale-roster cross-org confusion.** UI surfaces fingerprint
   disagreement between rosters explicitly when present.

### What M5 v2 does *not* defend against

1. **User master-password compromise.** Attacker holding the
   user's master password is cryptographically indistinguishable
   from the user. Can produce valid rotation envelopes; default
   mode will auto-apply. Defense is procedural: detection via
   audit (the legitimate user notices "I never changed my
   password" in the log); response via Flow B owner revocation.
   Strong mode adds human-in-the-loop friction; doesn't close
   the gap.
2. **Multiple owners' keys compromised simultaneously.** Quorum
   defenses degrade gracefully; if the attacker exceeds the
   quorum threshold, they have org-level authority. No
   cryptographic recovery; out-of-band escalation only.
3. **Recovery-owner + master-password both compromised.**
   Catastrophic for solo orgs without human co-owners. Documented
   limitation; argues for ≥1 human co-owner on critical orgs.
4. **Client implementation bugs in client-only policy
   enforcement.** Buggy client could auto-apply against
   strong-mode policy; server can't always detect this.
   Mitigated by client implementation review and audit logging.

### The honest framing

For the audit-facing posture statement:

> Hekate's M5 trust model relies on the soundness of (a) the
> Ed25519 signature primitive, (b) the BLAKE3 hash primitive, (c)
> the multi-owner invariant being maintained operationally, and
> (d) clients faithfully enforcing the strong-mode policy when
> enabled. We are accepting that an attacker who fully
> compromises a user's master password is treated by the system
> as that user; this is the same posture every E2E vault product
> takes. Strong-mode reduces the *blast radius* of such a
> compromise via human-in-the-loop checks but does not eliminate
> the cryptographic indistinguishability.

## Open questions for the implementation session

These were not load-bearing on the architecture but should be
decided before code lands:

1. **Recovery-owner serialization format default.** BIP39
   mnemonic is most user-friendly; hex file is simplest to
   implement; hardware-key support is most secure but most
   integration work. Probably ship BIP39 + hex file in M5 v1;
   hardware-key support post-M5.
2. **Co-owner-set version cap.** Practical upper bound on version
   number; how the chain prunes (or doesn't). Probably
   "unbounded in storage; last N versions in client cache."
3. **Strong-mode owner-add/remove quorum specifics.** I wrote
   "3-of-N or N-of-N (configurable per org)." Does the strong-mode
   bool also control this configurability, or is there a separate
   knob?
4. **Alerting channel implementation.** In-app notifications are
   easy (existing push primitive). Email and SMS need delivery
   infrastructure that doesn't exist yet. Decide what's in M5 v1
   scope.
5. **The "new-member endorsement OOB confirmation prompt" UX.**
   What does the prompt look like? What does "confirmed OOB" let
   the user attest to in a way that's auditable?
6. **Per-policy toggles in v2.** When (if?) we split the bool,
   what's the migration path for orgs that flip on the bool now
   and want fine-grained toggles later?

## Reuse inventory (already shipped)

- **`signing_seed_protected` per-org** — `crates/hekate-server/src/routes/orgs.rs`.
  Today it's the org-wide seed; v2 retires it in favor of
  per-owner keys held in their account-level signing seeds.
  Existing code path becomes the "co-owner-set version 1
  bootstrap" path.
- **BW08 signed-roster pattern** —
  `hekate-core::org_roster::canonical_bytes` + `signOrgRoster` /
  `verifyOrgRoster` in the wasm bindings. v2 extends the canonical
  bytes shape; signing/verification mechanics unchanged.
- **TOFU peer-pin registries (per-client)** — CLI / popup / web
  vault each maintain their own. v2 *deprecates* per-peer pinning
  in favor of TOFU on the org co-owner-set; per-peer pins remain
  available as opt-in strong-mode behavior.
- **M4.5b rotate-on-revoke** —
  `hekate-server/src/routes/orgs.rs::revoke_member` + the three
  client rewrap loops. Unchanged; works as Flow B.
- **Push events** — SSE channel for `cipher.changed`, etc.
  M5 adds `bundle.rotated`, `roster.changed`, `co_owner_set.changed`,
  `policy.changed`, `recovery_owner.used`.
- **Per-org JSONB policies (M4.6)** — extend with `strong_mode`
  policy key (or move to the new dedicated `OrgPolicy` block,
  which is cleaner).

## References

(Pre-audit verification pass needed on all citations.)

- Buterin, V. (2021). *Why we need wide adoption of social
  recovery wallets.* https://vitalik.eth.limo/general/2021/01/11/recovery.html
- Komlo, C. & Goldberg, I. (2020). *FROST: Flexible Round-Optimized
  Schnorr Threshold Signatures.* SAC 2020. IACR ePrint 2020/852.
- Crites, E., Komlo, C. & Maller, M. (2023). *Fully Adaptive
  Schnorr Threshold Signatures (Sparkle+).* CRYPTO 2023. IACR
  ePrint 2023/445.
- Crites, E. & Stewart, A. (2025). *A Plausible Attack on the
  Adaptive Security of Threshold Schnorr Signatures.* CRYPTO
  2025. IACR ePrint 2025/1001. (Static security of FROST is
  unaffected; adaptive-security guarantees require modifications
  not in standard FROST.)
- Gennaro, R. & Goldfeder, S. (2018). *Fast Multiparty Threshold
  ECDSA with Fast Trustless Setup.* CCS 2018, pp. 1179–1194.
- Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N. &
  Peled, U. (2020). *UC Non-Interactive, Proactive, Threshold
  ECDSA with Identifiable Aborts.* CCS 2020, pp. 1769–1787.
  (IACR ePrint 2021/060 — note: dated 2021 in ePrint but the
  conference presentation was CCS 2020.)
- Shamir, A. (1979). *How to Share a Secret.* CACM 22(11),
  pp. 612–613.
- Callas, J., Donnerhacke, L., Finney, H., Shaw, D. & Thayer, R.
  (2007). *RFC 4880: OpenPGP Message Format.* §5.2.3.15
  ("Revocation Key" subpacket — colloquially "designated
  revoker"). **Obsoleted by RFC 9580 (2024)** which carries the
  primitive forward unchanged; cite RFC 9580 for current
  references.
- Bitcoin BIP39 (Palatinus, M., Rusnak, P., Voisine, A. & Bowe, S.,
  2013). *Mnemonic code for generating deterministic keys.*
  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- Bitcoin BIP340 (Schnorr signatures), referenced in the
  threshold-recovery section.

## Implementation guardrails (when M5 v1 work begins)

- **Pre-alpha, no production users.** Ship v2 schema directly;
  no migration from v1.
- **Multi-owner invariant** required for orgs with non-owner
  members (single-owner orgs and all-owner orgs are exempt).
- **Recovery-owner** scope: BIP39 + hex file in v1; hardware-key
  variant deferred.
- **Per-policy toggles** deferred to M5 v2.
- **Threshold recovery (FROST-Ed25519)** is **deferred to M5.x.**
  The v1 schema reserves the `threshold_share` owner type and
  the `ThresholdShareSet` table; quorum-policy code paths must
  accept `threshold_share` entries even if v1 doesn't create
  them. Implementation does not land in v1.
- **Protocol-frozen byte literals** (AAD strings, signature
  DSTs, token wire formats, `PMGRA1` magic) stay byte-for-byte
  unchanged. New v2 wire elements use fresh DSTs (e.g.,
  `pmgr-co-owner-set-v1\x00`, `pmgr-org-policy-v1\x00`); pick
  the prefix consistently and document it in this doc.
- **Audit logging** is implemented alongside every signed event,
  not as a follow-up.
- **Strong-mode** policy flips require 2-of-N quorum in both
  directions.
- **Recovery-owner equivalence:** restricted to self-rescue
  when strong-mode is on; full equivalence with human owner
  when strong-mode is off.
- **Citation hygiene:** every external citation (Buterin,
  FROST/CGGMP21, RFC 4880 designated-revoker, BIP39, etc.)
  must remain accessible at its cited URL/DOI before merge.
- **No vendor-specific protocol paths.** The
  Synapticcyber-managed-recovery commercial offering sits atop
  the threshold-recovery primitive; the wire format must treat
  all threshold participants symmetrically.
