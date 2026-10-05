# Browser evaluation

This complements the HTTP extraction benchmark by exercising the actual bundled gate UI, browser WebAuthn API, server verifier, cookies, redirects after verification, and human-readable access notices.

```sh
npm ci
npm run browser:install
npm run benchmark:browser
```

The installer stores browser binaries under `.cache/playwright` in the checkout by default. Set `PLAYWRIGHT_BROWSERS_PATH` to another allowed directory before installation and execution if needed. On Windows this project is kept on D:. Linux CI uses `npm run browser:install -- --with-deps` to install required system libraries.

For a recorded result and screenshots, build first, then run:

```sh
node scripts/browser-benchmark.mjs --output docs/browser-benchmark-results.json --artifacts dist/browser-artifacts
```

## Measured scenarios

| Case | Mode | Expected and measured result |
| --- | --- | --- |
| Declared automated Chromium | Observe | Enrollment and subsequent login succeed; declarations recorded |
| Headless user-agent declaration | Enforce | Rejected; zero origin requests |
| Ordinary-looking user agent, WebDriver true | Enforce | Ceremony rejected; zero origin requests |
| Both declarations suppressed | Enforce | Automation admitted with virtual passkey; resource enumeration subsequently limited |

The [saved report](browser-benchmark-results.json) contains the browser version, UTC timestamp, origin request counts and observed signals. The last case is a documented limitation, not a successful automation detection. Its four origin requests include the initial document after enrollment, the same document after login, and two additional resources; the next distinct resource receives 429.

All participants are Playwright-controlled Chromium instances with a CDP virtual authenticator. The tests never contact third-party sites, change real browser profiles, or use production credentials. They do not represent an LLM agent evaluation, a hardware-key test, cross-browser compatibility, or a human study. No human false-rejection or broad detection-accuracy claim can be made.

The suite asserts that pages have no uncaught script errors. The showcase also has checks for mobile overflow, interactive evidence controls, keyboard tab navigation, evidence downloads, and zero outgoing network requests. These are compatibility checks, not a full accessibility audit.
