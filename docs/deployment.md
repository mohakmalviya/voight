# Deployment requirements

This prototype is ready for local evaluation. Do not treat the demo as a hardened internet deployment.

1. Keep the origin on a private network. Firewall it so only the gateway can connect. Test direct-origin access from outside that network; it must fail. The identity header is not cryptographically authenticated and is safe only behind this network boundary.
2. Terminate HTTPS at a reverse proxy configured to preserve the public `Host`. Set `PUBLIC_ORIGIN` to the exact browser-facing origin. Keep gateway HTTP bound to loopback or a private interface.
3. Route **every** content path through the gateway. Reserve `/_gate/` for gateway assets and ceremonies. Do not let a CDN cache protected responses or directly serve origin assets.
4. Keep `.env`, SQLite files, invitations, and backups private. Run as an unprivileged OS user with write access only to its data directory. Use a persistent local disk; network SQLite filesystems are unsupported.
5. Apply front-end body, header, connection and request-rate limits. The in-process controls cannot absorb a network flood. WebSockets and write methods are rejected.
6. Audit compatibility with your own app. Only Content-Type is forwarded back from the origin. Browser cookies, Authorization, forwarded identity headers and cache validators are not forwarded upstream. Redirects are rejected.
7. Issue invitations privately after approving the recipient. There is no automatic enrollment, email sending, or identity verification service.
8. Test real passkeys and accessibility on the devices your audience uses. A production rollout requires an independent security review and a measured false-rejection study.
9. Tune extraction limits against your actual page/asset sizes and resource URLs. Defaults are evaluation settings, not measured human/bot thresholds. Query strings count toward resource diversity. See [policy semantics](extraction-policy.md).

## Local validation

`npm run demo` starts a loopback origin and the gateway. Verify that a fresh browser sees only the gate, complete enrollment manually, then verify that revocation blocks subsequent requests. Use a new test credential, not a production account.

## Restart and backup

Sessions, counters, byte usage and resource HMACs persist in SQLite; expiry is checked using wall-clock time. Keep the clock synchronized. Use SQLite's backup API or stop the process before copying the database and its WAL. No automatic database deletion, migration rollback, or key recovery is included. Restoring an older backup also restores older usage and can restore allowance; treat restores as security-sensitive operations.

Upgrading from 0.1 adds tables and indexes on startup without replacing credentials or sessions. Preserve the database and its new resource HMAC key across restarts. Run one gateway process; the concurrency guard is process-local. On restart, old connections close and concurrency starts empty, while durable extraction usage remains. Older binaries do not enforce the new policy even if its tables remain.

Changing the public hostname changes the WebAuthn relying party and may require re-enrollment. Do not silently relax origin/RP checks during migrations.
