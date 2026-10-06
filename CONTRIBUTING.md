# Contributing

Thanks for helping. Voight is a small project, and changes are judged on whether they keep the security properties honest and testable.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- **Security problems do not go in public issues.** See [SECURITY.md](SECURITY.md).
- Read the [threat model](docs/threat-model.md). A change that adds protection should say which attack it addresses and what still gets through.

## Development

Node.js 24.14 or newer.

```sh
npm ci
npm run check
npm test
npm run benchmark
npm run build
```

`npm run browser:install && npm run benchmark:browser` runs the real-browser checks. CI runs all of these on every pull request.

## Expectations for changes

- **Add a test for every behaviour you change.** Tests run against loopback servers only. Never point tests, benchmarks or demos at sites you do not own.
- **Fail closed.** If a check cannot decide, deny rather than admit.
- **Do not trust the client.** Headers, cookies and browser reports are evidence, not proof. Forwarded headers count only from configured trusted proxies.
- **Keep privacy defaults.** No fingerprinting. Do not log IPs, URLs, user agents or cookies, and do not store addresses or URLs in plain text.
- **Avoid accuracy claims.** Report what a benchmark measured, including what got through. Do not present a "bot detection rate".
- **Keep dependencies minimal.** New runtime dependencies need a clear reason.
- **Match the existing style:** ES modules, small functions, and comments that explain *why*.

## Pull requests

Describe the problem, the change, how you tested it, and any new limitation or bypass. Update the README, docs or `.env.example` when configuration or behaviour changes.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE), and you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
