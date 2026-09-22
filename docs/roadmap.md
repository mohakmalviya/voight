# Roadmap

## 0.1 — admission foundation (implemented)

Private-origin gateway, invited passkey enrollment, single-use challenges, short sessions, request budgets, revocation, minimal decision logs, security regression tests, and local demo.

## 0.2 — extraction controls and repeatable evaluation (implemented)

Rolling per-credential byte and resource budgets, bounded concurrent transfers, cancellation, chunk-time revocation, operator usage inspection, additive SQLite upgrades, and regression coverage for persistence and compressed/partial streams.

A loopback benchmark covers unapproved HTTP, approved scripts, query enumeration, session rotation, repeated downloads, and saturated parallel transfers. Approved automation within policy still succeeds. [Method and results](benchmark.md).

## Next — evaluate browser agents and real users

- Extend the controlled benchmark to browser automation, browser agents, and legitimate users on our own demo infrastructure.
- Publish separate results for unapproved access, compromised/approved sessions, extraction volume, latency, and legitimate-user rejection. Do not combine these into a misleading "bot accuracy" score.
- Add optional detection of clearly declared automation and browser inconsistencies. Treat client signals as untrusted evidence, never a way to bypass server admission.
- Evaluate hardware-backed attestation for managed-device deployments. State ecosystem, privacy, accessibility, and availability costs before enabling it.
- Derive threshold defaults and re-verification policies from observed behavior and legitimate-user rejection measurements. Re-verification must not reset extraction budgets.

## Later — operating at scale

Audited trusted-proxy configuration, distributed counters, operator UI, signed rule releases, compatibility adapters, incident review, external security audit, and controlled pilot deployments.

## Public release gate

Choose supported threat models; complete security and dependency review; remove experimental assumptions; document bypasses and false-positive measurements; then the owner can explicitly authorize changing repository visibility. No guarantee of complete agent exclusion.
