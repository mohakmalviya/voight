<div align="center">

# Voight

**Keep AI agents and bots off your website. Let people in with one press-and-hold.**

*Named after the Voight-Kampff test in Blade Runner, which tells people from replicants.*

[![CI](https://github.com/mohakmalviya/voight/actions/workflows/ci.yml/badge.svg)](https://github.com/mohakmalviya/voight/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node.js 24.14+](https://img.shields.io/badge/node-24.14%2B-339933?logo=node.js&logoColor=white)
![Status: early prototype](https://img.shields.io/badge/status-early%20prototype-orange)

[Quick start](#quick-start) · [How it works](#how-it-works) · [Limits](#limits) · [Deploy](#deploy) · [Contributing](#contributing)

</div>

---

AI agents and scrapers now browse the web with real browsers. `robots.txt` is only a request, and proof-of-work only slows them down. Voight sits in front of your site and refuses them. People pass with one press-and-hold a day: no accounts, no image puzzles.

> [!WARNING]
> Early prototype, not security-audited. Read the [limits](#limits) before you deploy it.

## Quick start

```sh
git clone https://github.com/mohakmalviya/voight.git
cd voight
npm ci && npm run build && npm run demo
```

Open **http://localhost:8787**. Try `HUMAN_CHECK=always npm run demo` to see the check on every visit.

## How it works

```
Visitor  →  HTTPS proxy (nginx, Caddy…)  →  Voight  →  your site
```

| Who's asking | What Voight does |
| --- | --- |
| 🤖 **Named AI agents** | Refused: GPTBot, ChatGPT agent, ClaudeBot, PerplexityBot, Firefox AI previews… |
| 🕵️ **Suspicious visitors** | Press-and-hold check that looks for automation: webdriver, headless Chrome, DevTools control, scripted mouse input |
| ☁️ **Browsers on servers** | Refused: datacenter address, no graphics card, no sound devices, no screen |
| 🔍 **Search engines** | Let in after DNS verification: Google, Bing, Apple, Yandex |
| 📦 **Bulk scrapers** | Per-network budgets, then proof-of-work, then timed blocks |
| 🪤 **HTML scrapers** | A hidden trap link. Following it gets them blocked |
| 🙂 **People** | Pass once, browse for 6 hours |

**Also included:** your own allow/deny rules (`POLICY_FILE`), link previews for chat apps (`OPEN_GRAPH`), and a private mode where only invited people with a passkey get in.

Full details of every check: [docs/how-it-works.md](docs/how-it-works.md). The trap link and link previews come from [Anubis](https://github.com/TecharoHQ/anubis).

## Limits

- **It can't prove anyone is human.** Everything it measures comes from the visitor's browser.
- **Careful scripts can get through.** A real browser driven carefully (nodriver-style tools, operating-system input) can pass.
- **AI agents in a person's own browser** (Claude in Chrome, Comet, Atlas) stop at the check by design, not because they can't click.
- **Read-only sites only for now:** no forms, logins or WebSockets.
- **Shared networks share a budget:** offices, VPNs, mobile carriers.
- **Not DDoS protection.**

Every known bypass: [threat model](docs/threat-model.md) · [limits in detail](docs/how-it-works.md#limits-in-detail)

## Deploy

1. **Put your site on a private address** that only Voight can reach.
2. **Configure and start Voight:**

   ```sh
   cp .env.example .env    # set PUBLIC_ORIGIN, UPSTREAM, TRUSTED_PROXIES
   npm run cloud-ranges    # datacenter address lists; rerun weekly
   npm start
   ```

3. **Point your HTTPS proxy at Voight** (port 8787). For nginx:

   ```nginx
   location / {
     proxy_pass http://127.0.0.1:8787;
     proxy_set_header Host $host;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
   ```

Caddy, CDNs, every setting and how to test it: [setup guide](docs/setup.md) · [deployment requirements](docs/deployment.md)

### Key settings

| Setting | Default | What it does |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | `http://localhost:8787` | Your site's public address |
| `UPSTREAM` | `http://127.0.0.1:8788` | Where your real site runs |
| `TRUSTED_PROXIES` | *(empty)* | Proxies allowed to pass on the visitor's address |
| `HUMAN_CHECK` | `suspicious` | `always` checks every new visitor, `off` turns the check off |
| `AI_AGENTS` | `block` | `allow` lets named AI agents in |
| `OPEN_GRAPH` | `off` | `on` keeps link previews working in chat apps |
| `POLICY_FILE` | *(none)* | Your own rules ([example](docs/policy.example.json)) |

[All settings →](docs/setup.md#settings)

### Admin commands

```sh
npm run admin -- bans                 # active blocks
npm run admin -- unban 203.0.113.7    # lift a block
npm run admin -- invite "Reader"      # private mode: one-time invitation
npm run stats --silent < gateway.log  # check results by platform and input (the log on standard input)
```

## Privacy

- **No fingerprints kept.** Only the names of flags it found, such as `software_gpu`, go in the log.
- **Logs never contain** IPs, URLs, user agents or cookies.
- **Addresses and URLs** are stored only as keyed hashes and deleted when they expire.

## Contributing

Contributions are welcome:

- 🌱 Start with a [good first issue](https://github.com/mohakmalviya/voight/issues?q=is%3Aopen+label%3A%22good+first+issue%22).
- 💬 [Open an issue](https://github.com/mohakmalviya/voight/issues/new/choose) before a bigger change.
- 🔒 Security problems go to [SECURITY.md](SECURITY.md), never a public issue.

```sh
npm run check            # syntax
npm test                 # tests (loopback only)
npm run benchmark        # HTTP extraction scenarios
npm run load-test        # requests per second through the gateway (loopback)
npm run browser:install && npm run benchmark:browser   # real Chromium
npm run attack:agents    # automated browsers vs the check (opens windows)
```

CI runs everything except `attack:agents` on every pull request.

<details>
<summary><b>Where things live</b></summary>

| Path | What it does |
| --- | --- |
| `src/main.mjs` | Starts the gateway: reads settings, loads rules and opens the store |
| `src/config.mjs` | Every setting, its default and its validation |
| `src/gateway.mjs` | The request pipeline: rate limits, operator rules, AI-agent refusal, the human check, proxying and byte budgets |
| `src/automation.mjs` | Scores the human check's report for signs of automation (`webdriver`, `synthetic_pointer`, …) |
| `src/sandbox.mjs` | Scores signs of a browser running on a server (datacenter address, software GPU, no sound card or screen) |
| `src/agents.mjs` | AI crawlers and assistants that name themselves |
| `src/network.mjs` | Addresses, CIDR ranges and trusted proxies |
| `src/store.mjs` | SQLite storage: passes, budgets, blocks, invitations and passkeys |
| `src/denial.mjs` | HTML for the check, block and error pages |
| `src/scramble.mjs` | Gives every check its own scrambled copy of the browser probe |
| `src/policy.mjs`, `src/preview.mjs`, `src/metrics.mjs`, `src/stats.mjs` | Operator rules, link previews, Prometheus counters and check results read back from the log |
| `src/webauthn.mjs`, `src/admin.mjs` | Passkeys for private mode, and the `npm run admin` command |
| `web/human.mjs` | The press-and-hold check in the visitor's browser |
| `web/probe.template.js`, `web/probe-worker.template.js`, `web/shared.js` | What the check measures in the page, in a worker and in a shared worker |
| `web/hop.mjs`, `web/challenge.mjs`, `web/client.mjs` | The hop page, the proof-of-work client and private-mode sign-in |
| `test/` | Tests. `fixture.mjs` runs a gateway and a sample site on loopback |
| `scripts/` | Build, demo, benchmarks and attack runs |
| `showcase/`, `docs/` | The offline evidence demo, and design notes, benchmark results and research |

</details>

<details>
<summary><b>Adding or changing a detection</b></summary>

1. Measure it in `web/probe.template.js`. Wrap strings in `$S('…')` so the scrambler hides them.
2. Turn it into a flag in `humanReport` (`src/automation.mjs`) or `sandboxReport` (`src/sandbox.mjs`). Validate every reported value.
3. Test it in `test/human.test.mjs`: one case where it fires, one where a normal browser doesn't trip it.
4. Try real tools (`npm run attack:agents`) and ordinary Chrome, Edge, Firefox and Safari.
5. Add a row to the [threat model](docs/threat-model.md): what it catches, what gets around it.

</details>

<details>
<summary><b>Rules for every change</b></summary>

- **Test every behaviour you change.** Never point tests or demos at sites you don't own.
- **Fail closed.** If a check can't decide, deny.
- **Don't trust the client.** Headers, cookies and browser reports are evidence, not proof.
- **Keep privacy defaults.** No fingerprinting, no IPs, URLs, user agents or cookies in logs.
- **No accuracy claims.** Report what a test measured, including what got through.
- **Few dependencies.** A new one needs a clear reason.
- **Match the style:** ES modules, small functions, comments that explain *why*.

</details>

Pull requests: one change each. Say what you changed, how you tested it, and any new bypass. By contributing you agree to the [MIT License](LICENSE) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) · Design notes and sources: [docs/research.md](docs/research.md)
