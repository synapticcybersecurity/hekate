# Security policy

Hekate is a password manager — vulnerabilities in the server, the
clients, or the cryptography are taken seriously. This document
explains how to report them and what to expect in return.

## Supported versions

Hekate is pre-alpha. Only the latest commit on `main` is supported;
there are no LTS branches, no backported security fixes, and no
binary releases yet. If you find a vulnerability, expect the fix to
land on `main` and not in a tagged release.

## Reporting a vulnerability

**Please report privately, not via a public issue.** Two channels:

1. **GitHub Security Advisories** *(preferred)*. Open a draft
   advisory at
   [`Security` → `Report a vulnerability`](https://github.com/synapticcybersecurity/hekate/security/advisories/new)
   on the repository. This gives us a private space to discuss,
   coordinate a fix, and request a CVE if appropriate.
2. **Email**. If you cannot use GitHub Security Advisories, reach the
   maintainer at the email address in the repository's commit
   history (`git log --format='%ae' | sort -u`).

Please include:
- A clear description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept if you have one.
- The commit hash you tested against.
- Whether you intend to disclose publicly, and on what timeline.

## What's in scope

- The Hekate server (`crates/hekate-server`) — auth, session handling,
  authorization, push, webhooks, attachments.
- The shared crypto core (`crates/hekate-core`) — KDF, EncString,
  manifests, signcryption, attachment chunking, passkey handling.
- The first-party clients — CLI (`crates/hekate-cli`), browser
  extension (`clients/extension/`), web vault (`clients/web/`).
- Documented protocols (BW04 manifest, BW07/LP04 KDF-bind MAC, BW08
  org rosters, signcryption envelopes, EncString v3, PMGRA1
  attachments).

Cryptographic-protocol issues, authentication / authorization
bypasses, vault decryption without the master password, manifest
forgery, and tenant-isolation breaks are all in scope and high
priority.

## What's not in scope

- DoS attacks against an unhardened public-facing instance.
- Vulnerabilities in third-party dependencies that are already filed
  upstream — please report those upstream and let us know if a
  pinned-version mitigation is needed here.
- Self-XSS / clipboard issues that require running attacker code in
  the user's browser.
- Findings from automated scanners without an analysis showing real
  impact.
- The reference Docker compose files (`docker-compose.yml`,
  `docker-compose.sqlite.yml`) — those are for local development
  and ship with hard-coded dev credentials by design.

## Response expectations

This is a part-time open-source project. Best-effort timelines:

- **First response:** within 7 days.
- **Triage and fix plan:** within 14 days for confirmed reports.
- **Fix shipped to `main`:** depends on severity and complexity; we
  will keep you updated.

We do not currently offer a bug bounty.

## Disclosure

We prefer coordinated disclosure. Once a fix has landed on `main`,
the advisory is published with credit to the reporter (unless you'd
rather stay anonymous). If you intend to publish independently,
please give us a reasonable window — typically 90 days from initial
report — to ship a fix first.

## License and warranty

Hekate is distributed under AGPL-3.0-or-later **with no warranty**
— see sections 15 and 16 of the [LICENSE](LICENSE). This security
policy is a statement of intent, not a contract.
