# Roadmap

## 0.1 — admission foundation (implemented)

Private-origin gateway, invited passkey enrollment, single-use challenges, short sessions, request budgets, revocation, minimal decision logs, security regression tests, and local demo.

## Next — evaluate agent resistance

- Build a controlled benchmark with direct HTTP scripts, browser automation, browser agents, and legitimate users on our own demo infrastructure.
- Publish separate results for unapproved access, compromised/approved sessions, extraction volume, latency, and legitimate-user rejection. Do not combine these into a misleading "bot accuracy" score.
- Add optional detection of clearly declared automation and browser inconsistencies. Treat client signals as untrusted evidence, never a way to bypass server admission.
- Evaluate hardware-backed attestation for managed-device deployments. State ecosystem, privacy, accessibility, and availability costs before enabling it.
- Add per-credential rolling byte and route-diversity budgets, bounded parallelism, and evidence-backed re-verification policies.

## Later — operating at scale

Audited trusted-proxy configuration, distributed counters, operator UI, signed rule releases, compatibility adapters, incident review, external security audit, and controlled pilot deployments.

## Public release gate

Choose supported threat models; complete security and dependency review; remove experimental assumptions; document bypasses and false-positive measurements; then the owner can explicitly authorize changing repository visibility. No guarantee of complete agent exclusion.
