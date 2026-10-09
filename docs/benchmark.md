# Controlled extraction benchmark

Run `npm run benchmark`, or `npm run benchmark -- --output <report.json>` to save a report. CI runs the same assertions. The harness starts fresh loopback-only gateway/origin pairs, uses the real WebAuthn verifier with a software authenticator, retrieves protected bodies, and closes its in-memory databases and servers. It does not target external websites or use existing accounts.

## Initial measured result

The [saved report](benchmark-results.json) records Node 24.19.0, the exact run time, policy values, request latency and decision reasons. Each case has independent credentials/state and deliberately small thresholds to make the boundary observable.

| Scenario | Requests | Allowed | Blocked | Origin requests | Protected bytes received |
| --- | ---: | ---: | ---: | ---: | ---: |
| Unapproved HTTP extraction | 12 | 0 | 12 | 0 | 0 |
| Approved scripted reading within limits | 6 | 6 | 0 | 6 | 6,144 |
| Approved query enumeration; five-resource limit | 20 | 5 | 15 | 5 | 5,120 |
| Approved session rotation; three-resource limit | 8 | 3 | 5 | 3 | 3,072 |
| Approved repeated download; 8,192-byte limit | 12 | 4 | 8 | 4 | 8,192 |
| Approved parallel saturation; two slots | 8 | 2 | 6 | 2 | 2,048 |

The scripted reading case is an explicit successful automation example, not a human control group. Session rotation performs real passkey logins between requests. The parallel case holds two origin responses while probing six additional requests, then releases them; it verifies bounded overlap without relying on race timing. Other cases run sequentially. Authentication requests are excluded from the table and latency samples.

## What can be concluded

For these inputs, unapproved clients received no origin content; session rotation did not bypass resource budgets; repeated downloads stopped at the byte allowance; and excess simultaneous transfers were refused before reaching the origin. The report records p50/p95 request latency for reproducibility, but loopback timings, harness coordination and a tiny sample are not internet performance measurements.

The unit/integration suite separately covers forged/replayed authentication, multiple concurrent sessions spending one byte budget, compressed bodies, partial transfers, cancellation, revocation, rolling expiry, independent credentials and persistent SQLite usage.

## What remains unmeasured

This HTTP benchmark includes no browser agent, hardware authenticator, accessibility workflow, or real human cohort. The separate [Chromium benchmark](browser-benchmark.md) now exercises UI/passkey workflows and a controlled suppressed-signal case. Human false rejection, classification accuracy and DDoS performance remain unknown. An approved agent can stay within policy or spread work across approved credentials. Do not describe these numbers as a bot-detection success rate.
