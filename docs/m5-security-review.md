# M5 — Internal Adversarial Design Review

Internal red-team of the M5 trust-UX design ([`m5-trust-ux.md`](m5-trust-ux.md)),
conducted 2026-05-30 **before implementation**. Goal: find composition
flaws in how M5 combines sound primitives, while they're still cheap to
fix (design, not code spread across server + every client).

> **Status of this review.** This is an *internal* pass by the same
> party that helped shape the design — it shares the designer's blind
> spots and is **not a substitute for independent external review**. Its
> job is to make M5 audit-ready and catch the obvious composition bugs.
> Findings below are claims to be confirmed/refuted by an external
> cryptographer, not settled verdicts.

**Severity:** 🔴 critical (structural; fix before building) · 🟠 high ·
🟡 medium · ⚪ verify-in-implementation.

---

## What the design gets right (credit where due)

- **Explicit non-goals.** The threat model names what M5 does *not*
  defend against (master-password compromise, simultaneous multi-owner
  compromise, client-only policy enforcement) instead of hand-waving.
- **Fingerprint binds signing + encryption keys together** — `BLAKE3(canonical_bytes ‖ self_sig)` over a bundle containing both `signing_pk` and `x25519_pk`, so the encryption key can't be swapped independently (*provided* the bound key is the one actually used — see F9).
- **Version + parent-hash chains** on roster, co-owner-set, and policy give a basis for rollback detection (*provided* a high-water-mark is persisted — see F6).
- **Honest framing** that strong-mode is "a posture, not a guarantee."
- Reuse of vetted primitives (Ed25519, BLAKE3, X25519).

These are good bones. The findings below are about the *composition*.

---

## 🔴 Critical — fix at the design level

### F1. One signing key signs many object types → cross-object signature confusion + canonicalization ambiguity
An owner's single account Ed25519 key signs **rosters, co-owner-set updates, policy blocks, and rotation-acceptance** records. Bundles carry `self_sig` and `prior_sig`. The design does not show:
1. **Per-object-type domain-separation tags (DSTs).** Without a unique, length-framed DST prefixed into each signed message, a signature produced over one object type can potentially be reinterpreted as valid over another (type confusion / cross-protocol reuse). This is the highest-probability composition bug in the design.
2. **An injective canonical encoding for variable-length fields.** `CoOwnerSet` entries contain a variable-length `label` and a variable-length `entries[]` array; `OrgPolicy` is extensible. The doc says "canonical-encoded bytes" but doesn't pin the encoding. Naive `||` concatenation over variable-length fields is **not injective** — two distinct structures can serialize to identical bytes, breaking both signatures and fingerprints.

**Recommendation:** Define one canonical serialization (length-prefixed TLV or strict DAG-CBOR with fixed field order and no optional-field ambiguity) for *every* signed M5 object, and prefix each with a unique DST (e.g. `b"pmgr-m5-coownerset-v2"`, `b"pmgr-m5-roster-v2"`, …) framed with its length. Make the DST list part of the frozen-identifiers table.

### F2. 2-of-N owner-change quorum has **zero fault tolerance at N=2** — the common topology
`quorum_owner_change = 2`. The multi-owner invariant requires ≥2 owners (and a recovery owner counts as the second for solo users), so the **default solo topology is N=2**: `{human, recovery}`.

To remove a compromised owner you need 2 signatures from *current* owners. With N=2 and one owner compromised, the honest party has 1 signature and **cannot reach quorum without the suspect's cooperation → permanent deadlock.** This holds whether the compromised owner is the human key (hostile rotation, F7) or the recovery key (theft).

This directly contradicts the design's own **"defends against → single owner key compromise"** claim, whose stated defense ("other owners sign a new co-owner-set excluding the compromised key") *requires N ≥ 3*. At N=2 the claimed defense does not exist.

**Recommendation:** Either raise the multi-owner invariant to **≥3 owners** whenever the org holds anything critical (so 2-of-N tolerates one bad owner), or define a distinct, safer owner-*removal* path that doesn't require the suspect's signature (e.g. a recovery-owner-anchored removal with a time-delay + alert, accepting the availability tradeoff). State the fault-tolerance property explicitly: *2-of-N tolerates one compromised owner only for N ≥ 3.*

### F3. Recovery self-rescue (Flow C) is a 1-signature owner-add that can't authenticate the rejoining human
Flow C: a lost-password user re-registers (new `userId`, new bundle), then **the recovery key alone signs a co-owner-set update adding that new `userId` as a human owner.** Two problems:
1. **It bypasses the 2-of-N owner-add quorum** — by necessity, since the locked-out user has only the recovery key. So a stolen recovery key unilaterally mints a new owner.
2. **Accepting owners verify the recovery *key's* signature, not that the new `userId` is the rightful human.** A thief using a stolen recovery key to add *their own* new `userId` is **cryptographically indistinguishable** from legitimate self-rescue. Even strong-mode ("recovery restricted to self-rescue") doesn't help, because the malicious add *is* a self-rescue-shaped action.

**Recommendation:** Bind self-rescue to an out-of-band human-identity confirmation before other owners accept the new fingerprint (the new `userId` must be OOB-attested by a human owner, or the rejoin must carry a pre-committed recovery-time identity anchor). Treat "valid recovery-key signature" as *necessary but not sufficient* to admit a new owner identity. For N≥2-with-human-owners, route Flow C through the same OOB endorsement strong-mode already demands for new members.

### F4. The schema cannot represent a quorum
`org_co_owner_sets` and the policy block each have a **single** `signature BYTEA`. A 2-of-N (or 3-of-N) quorum needs a *set* of `(signer_owner, signature)` pairs, plus verification rules the doc doesn't state:
- signers must be **distinct**,
- signers must belong to the **previous** co-owner-set (not the new one — otherwise an added attacker owner could help authorize their own addition),
- the same signature can't be counted twice.

**Recommendation:** Model the quorum as an explicit signature set with a verifier that enforces distinctness, prior-set membership, and the threshold. Specify it before coding; it's load-bearing for F2/F3.

---

## 🟠 High

### F5. The initial co-owner-set TOFU pin has no specified OOB verification
All org trust reduces to the authenticity of the **co-owner-set v1** a member TOFU-pins on accept — which they receive **from the untrusted server**. A malicious server can hand a fresh invitee a *substituted* owner-set (attacker keys) and the invitee pins it → total org compromise for that member. The strong-mode table mandates OOB for the *owner→new-member* direction but **not** the reverse (member verifying the owner-set). Asymmetric, and the more dangerous direction is unprotected.

**Recommendation:** The invite artifact should commit to the co-owner-set fingerprint, and (at least in strong mode) require the invitee to confirm it OOB against the inviting owner. Add owner-set-pin OOB to the strong-mode table.

### F6. Rollback defense depends on a per-client high-water-mark that fresh/cleared clients lack
"Monotonic version + parent-chain" only detects downgrade if the verifier **remembers the latest version it accepted.** A new device, reinstall, or cleared state re-TOFUs from scratch and the server can present a **stale** co-owner-set/roster (e.g. pre-eviction, re-admitting a removed owner; or pre-rotation, showing an old key) as "current." Hekate already has per-client TOFU stores with no cross-client sync (see the peer-pin-store note in `followups.md`), so this is a known shape applied to the owner-set.

**Recommendation:** Specify how the version high-water-mark is established/synced across a user's devices (e.g. signed into the user's own vault metadata, or anchored in the audit head — see F11), and what a fresh client does beyond blind TOFU.

### F7. Old-signing-key compromise → silent identity takeover + DoS, under a weaker precondition than the doc frames
The doc files hostile rotation under "master-password compromise." But the signing key can be exfiltrated **without** the master password (memory dump, decommissioned device, stale backup). Whoever holds the *old signing key* can forge a valid `prior_sig` rotation envelope to a key they control; **default mode auto-applies it** with no owner interaction, and the legitimate user (who still derives the old key from their password) is now locked out — both takeover *and* denial of service, silently.

**Recommendation:** Reframe the precondition honestly (old-signing-key, not master-password). Add a veto/cool-off: notify the *affected user* on any rotation of their own identity with a window to reject, and/or rate-limit rotations. Consider requiring the rotation be corroborated by the current auth path, not the old signing key alone.

### F8. Alerting is gated on strong-mode — contradicting the events table, and enabling alert-silent attacks
The events table marks **"recovery-owner key used → alert prominently"**, but the alerting-tiers section says **default mode = "no active alerts."** Direct contradiction. Worse: an attacker who reaches quorum can flip **strong→default** (one alert fires) and then operate in **alert silence** for every subsequent action.

**Recommendation:** Make a small set of events **alert unconditionally regardless of mode**: recovery-key use, owner add/remove, strong↔default flips, and hostile-rotation indicators. Strong mode widens the set; it shouldn't be the on/off switch for *all* alerting.

---

## 🟡 Medium

### F9. Every use of a member's `x25519_pk` must be the fingerprint-bound key
The fingerprint binds `signing_pk` + `x25519_pk`. That protection is real only if **org sym-key wrapping and signcryption (M4.5b paths) use the `x25519_pk` from the endorsed, fingerprint-bound bundle** — not an `x25519_pk` fetched separately from the server. If any rewrap path pulls the encryption key independently, a malicious server substitutes it and reads org secrets while the signing fingerprint still checks out. Crosses into M4.5b code.

**Recommendation:** Audit all `x25519_pk` consumers to confirm they resolve the key via the endorsed bundle/fingerprint, and add a test that a substituted encryption key fails closed.

### F10. Roster↔co-owner-set authorization binding is unspecified
A roster is signed 1-of-N by "a current owner." Nothing in the shown schema binds *which co-owner-set version* authorizes a given roster. A roster signed by owner X (valid while X was an owner) could be replayed after X's removal unless the roster explicitly references—and verifiers check—the authorizing co-owner-set version.

**Recommendation:** Include the authorizing `co_owner_set_version` in the roster's signed canonical bytes; verifiers must confirm the signer is an owner *in that version* and that the version is the latest accepted.

### F11. The audit log is not tamper-evident against the server
"Append-only at the schema level" is an app-level policy; the server controls the database. Signed entries are individually verifiable, but nothing chains entries together, so a malicious server can **omit/suppress** entries (e.g. hide the recovery-key-use event F8 is supposed to surface) or reorder them undetectably.

**Recommendation:** Hash-chain audit entries (each commits to the prior entry's hash) and let clients checkpoint/gossip the head (or anchor it in the user's signed vault metadata). Without this, drop "tamper-evident" to "individually-verifiable-but-suppressible" in the audit doc.

---

## ⚪ Verify in implementation

### F12. Bundle verification order
Specify that a verifier checks **both** `prior_sig` (against the previously-endorsed key) **and** `self_sig` (against the new bundle's `signing_pk`), in that order, and rejects if either fails or if `version` doesn't increment by exactly 1 over the endorsed predecessor.

### F13. Cross-org replay
Bundles are per-user (global), rosters/co-owner-sets/policies are org-scoped (`org_id` in canonical bytes). Confirm no signed artifact omits `org_id` where org-scoping is intended, and that a rotation envelope valid in org A can't authorize anything in org B beyond updating the shared per-user bundle.

---

## Cross-cutting themes

1. **Domain separation + canonicalization (F1)** is the single most important pre-implementation fix; it underpins the soundness of every signed object.
2. **N=2 is fragile (F2, F3, F7).** The recovery flows trade safety for availability, and at the default solo topology the quorum offers no fault tolerance and the recovery path can't authenticate the rejoining human. The availability/safety tradeoff is legitimate but must be *explicit*, and the "≥2 owners" invariant likely needs to be "≥3 for critical orgs."
3. **Auto-apply + alert-gating (F7, F8)** create silent windows. Critical actions need a veto path and unconditional alerting.
4. **TOFU + per-client state (F5, F6)** move the trust root but don't eliminate the bootstrap-authenticity and downgrade problems.

## Recommended next steps

1. Revise `m5-trust-ux.md` to address F1–F4 at the design level (canonical encoding + DSTs, quorum representation + fault-tolerance statement, recovery-identity authentication).
2. Then commission an **independent external cryptographer review** of the revised design — *before* implementation, separate from the eventual code audit.
3. Consider a **symbolic protocol model** (e.g. Tamarin or ProVerif) for the rotation (Flow A) and quorum/owner-change flows; they're small enough to model and are where the subtle bugs live.
4. The M5.x FROST threshold-recovery work warrants its own specialist review when it's scoped.

All of this is gated under the project's pre-publish security gate (see [`followups.md`](followups.md) and [`status.md`](status.md) M7).
