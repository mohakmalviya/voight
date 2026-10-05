# Extraction policy

This document describes accounting for a *subject*. In private mode a subject is a credential. In public mode it is a network (IPv4 address or IPv6 /64), or a clearance earned by passing a proof-of-work check. The accounting is identical; public mode stores it in separate tables and has no revocation step. Public mode also turns repeated denials into strikes and timed blocks, as described in the [threat model](threat-model.md).

These controls bound approved clients' access. They do not determine whether a person or an agent is driving the browser. All sessions of a credential share the same policy; a new login, user-agent string, or gateway restart cannot reset its durable extraction usage.

## Enforcement order

1. Validate the request, session and credential; spend a session request and per-minute request allowance.
2. Acquire a per-credential concurrent transfer slot. Excess requests receive HTTP 429 before contacting the origin.
3. Check the rolling byte total and record the requested resource. Refuse a new resource when the credential's resource budget is full.
4. Fetch only the configured private origin. Abort on client disconnect or the ten-second transfer deadline.
5. Before each decoded chunk, enforce the per-response size cap, recheck credential revocation, and atomically charge the rolling byte budget. Then write the chunk with backpressure.
6. Release the slot on completion or failure, and log the outcome once.

Pre-response budget denials return HTTP 429, a stable JSON reason, and `Retry-After` in seconds. If bytes were already sent, changing the HTTP status is impossible: the stream is closed, and the audit record has `completed: false`. Clients must treat a truncated response as incomplete. Single-response size violations use HTTP 502 when headers are still unsent.

| Reason | What happened | Recovery |
| --- | --- | --- |
| `reader_rate` | Per-minute credential request allowance spent | Wait for the request window |
| `resource_budget` | Too many distinct active resources | Wait for an older resource to age out; existing resources may still work |
| `byte_budget` | No room for more decoded content | Wait for charged bytes to age out; a response larger than the entire budget needs operator policy adjustment |
| `parallel_limit` | Too many simultaneous origin transfers | Retry after transfers finish; suggested delay is one second |
| `response_size` | One response exceeds `MAX_RESPONSE_BYTES` | Operator must reduce the response or adjust the cap. Range requests are shrunk to fit and never hit this |
| `credential_revoked` | Approval was removed during a transfer | Contact the operator |
| `ai_agent` | The client declared itself an AI agent (user agent, `Signature-Agent`, or an AI app's browser) | None; set `AI_AGENTS=allow` to admit them |
| `human_check_required` | Public mode with `HUMAN_CHECK=always` and no valid pass | Pass the check in a browser |
| `human_recheck` | One pass opened more than `HUMAN_PAGES_PER_MINUTE` pages in a minute; the pass is revoked | Pass the check again |
| `automation_detected` | The check found automation evidence | None for automated clients |
| `human_check_failed` | Gesture untrusted, too short, or the pointer never moved | Reload and hold the button |
| `human_check_limit` | The network earned `HUMAN_PASSES_PER_HOUR` passes this hour | Wait up to an hour |

`Retry-After` for extraction limits identifies the next accounting expiry, not a guarantee that the entire requested response will fit then. Gate assets and passkey endpoints have separate connection/authentication limits and do not consume protected content budgets.

## Accounting details

**Bytes:** use actual decoded body chunks supplied by `fetch`, including error response bodies, instead of trusting origin headers. Charges commit before writing. Concurrent transfers use SQLite transactions and cannot jointly spend beyond the same credential budget. One-second buckets expire at the end of their second plus the configured window; this conservatively retains charges for at most one extra second. Whole chunks are withheld if they would exceed a budget, so some allowance may remain unused. Charged bytes may include buffered bytes the client never receives; no refunds occur on failure.

**Resources:** use `URL.pathname + URL.search`, including query order and encoding as retained by the URL parser. GET and HEAD share the same key. This catches enumeration such as `/record?id=1`, `/record?id=2`, even though the path is identical. Repeating a resource extends its last-seen expiry and still spends request/byte allowance. API responses, assets, upstream errors and rejected redirects can count. No application-specific canonicalization is assumed. A per-database HMAC avoids storing the plaintext path/query; the key and records are private operational data.

**Concurrency:** includes waiting for origin headers, reading its body, and flushing the response. State is in the gateway process and is cleaned on errors/disconnects. This implementation supports a single gateway process; multiple instances require a shared concurrency mechanism.

**Retention and changes:** expired records are ignored immediately and physically pruned each minute. No login, logout or credential revocation erases usage. New charges/visits take the configured window; existing expiries retain the policy under which they were recorded. Changing the window cannot reconstruct previously expired history. Lowering byte/resource limits applies to the currently retained totals immediately. Restarting does not erase SQLite history.

## Evaluation limits

Ordinary readers may hit these limits on large pages or asset-heavy sites. Defaults have not been validated with human users. A slow agent or a pool of approved credentials can still extract content within its allowances. Use the [benchmark](benchmark.md) to verify mechanical bounds, then measure legitimate traffic and browser agents before claiming resistance or choosing production thresholds.
