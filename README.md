# Human Gate

A self-hosted gateway for websites that want to restrict automated extraction. The first release is an **admission-control foundation**: protected content stays behind the gateway until an operator-approved visitor completes passkey verification.

**Status: early prototype, not production audited.** The repository is private during development. Source is MIT licensed for a future public release; visibility changes require the owner's decision.

## What works now

- Operator-issued, expiring, single-use enrollment invitations. No public signup or admin HTTP API.
- WebAuthn registration and authentication with mandatory user verification, origin checks, RP-ID checks, cryptographic signature verification, and single-use challenges.
- Opaque, server-side sessions: 5-minute default lifetime, HttpOnly / SameSite=Strict cookies, Secure and `__Host-` cookies on HTTPS.
- Enforcement before every proxied GET or HEAD, including API and asset paths.
- Atomic request budgets, per-credential and connection rate limits, immediate credential revocation, and logout.
- Fixed upstream, no redirects followed, no forwarding of browser cookies or Authorization, no shared caching, response-size and upstream-time limits.
- SQLite persistence, local administration, structured decision logs that omit URLs, IP addresses, invitation codes, cookies, and passkey payloads.
- Tests exercise actual WebAuthn verification using a software authenticator fixture, plus common admission bypasses.

## What this does not promise

Passkey verification does **not** prove that a browser is free of agents. An approved user can automate a session, share an invitation, or use a software authenticator. Our test fixture deliberately demonstrates the latter. A browser that has received content can save it or capture screenshots.

This version excludes unapproved clients and constrains approved sessions. It does not yet provide behavioral bot classification, device attestation, cross-site reputation, large-scale DDoS protection, or complete agent isolation. See [the threat model](docs/threat-model.md) and [roadmap](docs/roadmap.md).

## Run the local demo

Requires Node.js **24.14 or newer in the 24.x line** and npm. Commands work in PowerShell and POSIX shells.

```sh
npm ci
npm run build
npm run demo
```

Open **http://localhost:8787** (use `localhost`, not `127.0.0.1`). In a second terminal, in the same project directory:

```sh
npm run admin -- invite "My first reader"
```

Copy the invitation privately. Expand **Have an invitation?**, paste it, and register a passkey using your device. Successful verification loads the demo origin. When the session expires, use **Continue with a passkey**.

The demo binds its upstream to `127.0.0.1:8788`. Local processes can access that demo port directly; this is a development setup, not protection from programs on your own machine. In deployment the origin must be unreachable except from the gateway.

## Protect an origin

Copy `.env.example` to `.env` and set `PUBLIC_ORIGIN` and `UPSTREAM`. Run `npm start` after building. The public origin must use HTTPS except for local development at `localhost`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | `http://localhost:8787` | Exact public origin used for Host, Origin, and WebAuthn checks |
| `UPSTREAM` | `http://127.0.0.1:8788` | Fixed private content origin; no path or credentials |
| `HOST` / `PORT` | `127.0.0.1` / `8787` | Gateway listener |
| `DATA_DIR` | `./data` | SQLite database and WAL files |
| `SESSION_SECONDS` | `300` | Maximum session lifetime, no sliding refresh |
| `REQUESTS_PER_MINUTE` | `30` | Per-credential protected request allowance |
| `PAGES_PER_SESSION` | `60` | Total protected request allowance, including assets |

The gateway currently supports **read-only origins**. Mutations, WebSockets, upstream login cookies, redirect rewriting, and cross-origin assets are not supported. The strict CSP is suited to self-contained sites; a general-purpose drop-in proxy is not claimed.

Read [deployment requirements](docs/deployment.md) before exposing the gateway.

## Administration

```sh
npm run admin -- list
npm run admin -- revoke "<credential-id>"
```

Revocation invalidates future requests immediately; it cannot retract bytes already sent. Lost passkeys require revoking the old credential and issuing a new invitation. No password/email recovery bypass is included.

## Development

```sh
npm run check
npm test
npm run build
npm audit
```

Tests use temporary in-memory stores and loopback servers. They never contact external websites or create real user passkeys. The synthetic authenticator is isolated to `test/` and is never imported by the application. A real-device enrollment check is a separate manual acceptance test.

Layout: `src/` gateway, storage and WebAuthn; `web/` visitor interface; `scripts/` build and demo; `test/` security regressions; `docs/` design and deployment.

## Technical references

- [SimpleWebAuthn server verification](https://simplewebauthn.dev/docs/packages/server)
- [User verification and passkeys](https://simplewebauthn.dev/docs/advanced/passkeys)
- [Node.js SQLite](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html)

The implementation uses these libraries; this project has no affiliation with X, VideoLAN, or their internal defenses.
