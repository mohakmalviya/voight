# Deployment requirements

This prototype is ready for local evaluation and careful pilots. Do not treat the demo as a hardened internet deployment.

## Both modes

1. **Keep the origin private.** Firewall it so only the gateway can connect. Test direct-origin access from outside that network; it must fail. In private mode, the `x-voight-user` header sent upstream (named `x-human-gate-user` before 0.10.1) is not cryptographically authenticated and is safe only behind this boundary.
2. **Terminate HTTPS at a reverse proxy** configured to preserve the public `Host`. Set `PUBLIC_ORIGIN` to the exact browser-facing origin. Bind the gateway to loopback or a private interface.
3. **Set `TRUSTED_PROXIES`** to the exact addresses or CIDR ranges of the proxies directly in front of the gateway, and make sure those proxies *append* the client address to `X-Forwarded-For`. Without it, all visitors share the proxy's budget, and one bad client can get everyone blocked. With a range that is too broad, clients inside it can pick their own identity. If you use a CDN, list only its published egress ranges, and update the list when those change.
4. **Route every content path through the gateway.** `/_gate/` is reserved for gateway pages and endpoints. Do not let a CDN cache proxied responses or serve origin assets directly; either bypasses budget accounting. Proxied responses are sent `Cache-Control: private` for this reason.
5. **Keep `.env`, SQLite files and backups private.** Run as an unprivileged user with write access only to its data directory, on a local disk (network filesystems are unsupported for SQLite).
6. **Apply front-end limits** for body size, headers, connections and floods. The in-process controls cannot absorb a network-level attack. WebSockets and write methods are rejected.
7. **Audit compatibility with your site.** Only GET and HEAD are proxied. Redirects from the origin are rejected. Visitor cookies, `Authorization` and forwarding headers never reach the origin. Response headers other than those listed below are dropped.
8. **Tune budgets against your real pages.** Every distinct path-plus-query counts, including assets and API calls. A page with 80 assets spends 80 URLs on first load. See [extraction policy](extraction-policy.md).

## Public mode

- Response headers passed through from the origin: `Content-Type`, `Content-Language`, `Content-Security-Policy`, `X-Frame-Options`, `X-Robots-Tag`, and `Cache-Control` rewritten to `private`. Gateway pages (checks, notices) use the gateway's own strict policy.
- The check needs JavaScript and `crypto.subtle`, which browsers provide only over HTTPS (or on `localhost`).
- Start with the generous defaults and watch the decision log for `resource_budget`, `clearance_issued` and `temporarily_blocked` before tightening anything. The log carries no addresses, so check the volume of blocks against complaints from users.
- **Search engines and monitors** share budgets like everyone else. A crawler that indexes the whole site will be limited and eventually blocked. Verified-crawler allowlisting is not implemented yet. Until it is, keep `RESOURCES_PER_WINDOW` high enough for your crawl rate, or route verified crawlers around the gateway at your proxy.
- `npm run admin -- unban <ip>` lifts a block immediately. Keep that command handy during a pilot.

## Private mode

- Issue invitations privately after approving each recipient. There is no automatic enrollment, email or identity verification.
- Test real passkeys and accessibility on the devices your audience uses.
- Changing the public hostname changes the WebAuthn relying party and requires re-enrollment. Do not relax origin or RP checks during migrations.
- Keep `AUTOMATION_POLICY=observe` while evaluating. `enforce` rejects declarations, not every agent. See [automation policy](automation-policy.md).

## Local validation

`npm run demo` starts a loopback origin and the gateway. Add `MODE=private` to test invitations and passkeys. Add a small `RESOURCES_PER_WINDOW` to see checks and blocks quickly.

## Restart, upgrade and backup

Counters, budgets, clearances, blocks and credentials persist in SQLite. Expiry uses wall-clock time, so keep the clock synchronised. Use SQLite's backup API, or stop the process before copying the database and its WAL. Restoring an older backup restores older usage and blocks, which can reinstate allowance, so treat restores as security-sensitive.

Upgrades add tables and indexes on startup without touching existing data. 0.4 adds public-mode tables and makes `public` the default `MODE`. **Set `MODE=private` explicitly when upgrading an existing private deployment.** Run one gateway process. The concurrency guard is process-local, and multiple instances on one database are untested.
