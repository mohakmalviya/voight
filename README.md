# Human Gate

A self-hosted gateway that sits in front of a website and makes bulk automated extraction slow and expensive, without making ordinary visitors log in or solve image puzzles.

**Status: early prototype, not security-audited.** Read [what this does not promise](#what-this-does-not-promise) before deploying it.

## How it works

Human Gate is a reverse proxy. Every request for your site passes through it, and it decides whether to fetch the page from your origin.

**Public mode** (default): anyone can browse.

1. **Budgets per network.** Each visitor's network (an IPv4 address, or an IPv6 /64) gets a rolling allowance: requests per minute, distinct URLs, decoded bytes and parallel transfers. A person reading a site stays well inside it. A crawler walking every URL does not. Clearing cookies, switching user agent or opening a private window does not reset it.
2. **A check instead of a wall.** When a browser runs out of budget, it gets a short automatic proof-of-work check (no puzzles, no clicks). Solving it gives that browser its own budget. Each further check from the same network costs twice as much work, and the number per network is capped. One person on a busy shared network gets through. A scraper rotating identities pays more each time.
3. **Timed blocks for clients that ignore limits.** A client that keeps sending requests after being told to slow down collects strikes, then gets blocked for 5 minutes. Repeat blocks last 4× longer, up to a day. Every block lifts on its own, and the block page says when. Operators can lift one early.

**Private mode** (`MODE=private`): content is only for invited people. Each person enrols a passkey with a one-time invitation, and every request needs a short passkey-backed session. Budgets apply per credential.

Both modes fetch only from one fixed origin, follow no redirects, forward no visitor cookies or credentials, and charge decoded bytes before releasing each chunk.

## What this does not promise

- **It does not tell humans from bots.** It limits volume and raises cost. An agent that browses slowly, within budget, from a normal network looks like a person here. So does a person driving their browser with an AI agent.
- **Shared networks share a budget.** Offices, campuses, VPNs and mobile carriers (CGNAT) put many people behind one address. The proof-of-work check exists for this, but heavy shared networks can still hit limits. Measure your own traffic before tightening the defaults.
- **Distributed scrapers get more allowance.** A scraper with many residential IPs gets one budget per network. This raises its cost but does not stop it.
- **Content that has been delivered can be copied.** Nothing here prevents screenshots, saving or sharing.
- **It is not DDoS protection.** It is one process with one SQLite database. Put it behind infrastructure that absorbs floods.
- **The site must be read-only.** Only GET and HEAD are proxied: no form posts, logins or WebSockets yet.

The [threat model](docs/threat-model.md) lists each known bypass.

## Quick start

Requires Node.js 24.14 or newer.

```sh
npm ci
npm run build
npm run demo
```

Open **http://localhost:8787**. The demo starts a small origin on `127.0.0.1:8788` and the gateway in public mode. To watch the limits work, run it with a tiny budget:

```sh
RESOURCES_PER_WINDOW=3 npm run demo
```

Visit a few pages to see the check. Then send a burst of requests with a script, such as `for i in $(seq 20); do curl -s -o /dev/null -w "%{http_code} " "localhost:8787/x?$i"; done`, to trigger a timed block. Lift it with `npm run admin -- unban 127.0.0.1`.

For private mode, start the demo with `MODE=private`, then create an invitation with `npm run admin -- invite "My first reader"`. Paste it under **Have an invitation?** and register a passkey.

## Deploy in front of a site

Copy `.env.example` to `.env`, set `PUBLIC_ORIGIN` and `UPSTREAM`, run `npm run build`, then `npm start`. Read the [deployment requirements](docs/deployment.md) first. The two that matter most:

- **The origin must be unreachable except through the gateway.** Otherwise scrapers go around it.
- **If a reverse proxy, CDN or load balancer sits in front, set `TRUSTED_PROXIES`.** Without it, every visitor appears to come from the proxy's address and shares one budget. Set it to that proxy's addresses or CIDR ranges and nothing broader.

| Setting | Default (public / private) | Meaning |
| --- | --- | --- |
| `MODE` | `public` | `public` for anonymous visitors, `private` for invited passkey holders |
| `PUBLIC_ORIGIN` | `http://localhost:8787` | Exact browser-facing origin; HTTPS required outside localhost |
| `UPSTREAM` | `http://127.0.0.1:8788` | Fixed private origin; no path or credentials |
| `HOST` / `PORT` | `127.0.0.1` / `8787` | Gateway listener |
| `DATA_DIR` | `./data` | SQLite database location |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated IPs/CIDRs allowed to set `X-Forwarded-For` |
| `REQUESTS_PER_MINUTE` | `300` / `30` | Requests per subject per minute |
| `EXTRACTION_WINDOW_SECONDS` | `600` | Rolling window for URL and byte budgets |
| `RESOURCES_PER_WINDOW` | `1000` / `60` | Distinct path-plus-query URLs per subject per window |
| `BYTES_PER_WINDOW` | `200 MiB` / `20 MiB` | Decoded response bytes per subject per window |
| `MAX_CONCURRENT_REQUESTS` | `16` / `4` | In-flight origin transfers per subject |
| `CONNECTIONS_PER_MINUTE` | `600` / `180` | All requests per network, including gate assets |
| `MAX_RESPONSE_BYTES` | `5 MiB` | Largest single response |
| `STRIKES_PER_WINDOW` | `30` | Denied requests a network may send in `STRIKE_WINDOW_SECONDS` before a block |
| `STRIKE_WINDOW_SECONDS` | `600` | Strike counting window |
| `BAN_SECONDS` / `MAX_BAN_SECONDS` | `300` / `86400` | First block length, and the cap for repeats (4× each time) |
| `CHALLENGE_DIFFICULTY` | `16` | Leading zero bits for the first check (about 65k hashes, around a second) |
| `CLEARANCES_PER_WINDOW` | `5` | Checks one network can pass per `CLEARANCE_SECONDS` |
| `CLEARANCE_SECONDS` | `3600` | Lifetime of a clearance and its budget |
| `SESSION_SECONDS` / `PAGES_PER_SESSION` | `300` / `60` | Private mode session lifetime and request cap |
| `AUTOMATION_POLICY` | `observe` | `off`, `observe` or `enforce` for self-declared automation ([details](docs/automation-policy.md)) |

A "subject" is a network or a clearance in public mode, and a credential in private mode. The defaults are starting points, not measured thresholds. Asset-heavy pages spend URL budget quickly, so check your own pages.

## Administration

```sh
npm run admin -- bans                  # active blocks (networks are shown as keyed hashes)
npm run admin -- unban 203.0.113.7     # lift a block; IPv6 lifts the whole /64
npm run admin -- invite "Reader name"  # private mode: one-time invitation
npm run admin -- list | usage | revoke <credential-id>
```

## Privacy

No fingerprinting: no mouse, typing, canvas, font or hardware data. Network addresses are stored only as keyed hashes. URLs are stored as keyed hashes for budget counting and never in plain text. Logs record a random request ID, status, decision reason and byte count. They never record IPs, URLs, user agents or cookies. Expired records are deleted every minute.

## Development

```sh
npm run check            # syntax
npm test                 # unit and integration tests (loopback only)
npm run benchmark        # HTTP extraction scenarios
npm run browser:install && npm run benchmark:browser   # real Chromium, virtual passkeys
```

Layout: `src/` gateway, storage, network handling and WebAuthn; `web/` visitor pages and the proof-of-work client; `test/` regression tests; `scripts/` build, demo and benchmarks; `showcase/` offline evidence demo; `docs/` design notes.

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Background

The project started from public discussion about AI agents overwhelming websites and forms. It has no affiliation with any company mentioned in that discussion, and does not reproduce anyone's internal defenses. Design notes and sources are in [docs/research.md](docs/research.md).

## License

[MIT](LICENSE)
