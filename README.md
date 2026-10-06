# Human Gate

A self-hosted gateway that sits in front of a website, keeps AI agents and automated browsers out, and makes bulk extraction slow and expensive. Visitors confirm they are human with one press-and-hold a day: no accounts, no image puzzles.

**Status: early prototype, not security-audited.** Read [what this does not promise](#what-this-does-not-promise) before deploying it.

## How it works

Human Gate is a reverse proxy. Every request for your site passes through it, and it decides whether to fetch the page from your origin.

**Public mode** (default): any person can browse.

1. **AI agents that identify themselves are refused.** Crawlers and assistants such as GPTBot, ChatGPT-User, ClaudeBot, Claude-User, PerplexityBot and Perplexity-User, agents that sign their requests (Web Bot Auth, used by ChatGPT agent), and AI apps whose built-in browser names itself are refused on every request. `robots.txt` stays readable.
2. **People see nothing; suspicious visitors get a human check.** A visitor in an ordinary browser reads the site directly. The check appears only when there is a reason: a datacenter address, an automation tool's user agent, headers no current browser would send (scripts such as curl, Python or Node usually give themselves away here), Playwright's or Puppeteer's own unbranded Chromium on a Windows or Mac desktop, more than `HUMAN_PAGES_PER_MINUTE` page loads a minute from one network, or a failed check or block from that network in the last hour. `HUMAN_CHECK=always` shows it to every new visitor instead. The check is a clearly labelled "Confirm you are human" page with a press-and-hold button. While the person holds it, the page checks for automation: the webdriver flag, automation-tool globals, headless Chrome, a pointer that jumps onto the button or glides in identical steps, and a DevTools-protocol client attached to the browser, which is how Playwright, Puppeteer and most AI-agent browsers drive Chrome and Edge (timed: logging errors costs several times more when something is listening, measured both in the page and in a Web Worker that page hooks do not reach). On Windows it also looks at how the input arrives: a person's mouse moves come a few milliseconds apart, so Chrome and Edge attach predictions of where the pointer goes next, while a script stepping the pointer with pauses gets none; a mouse cursor sits on whole screen pixels, while a script's path lands between them; a tool that intercepts the page's requests makes cached fetches from the page slower than the same fetches from a shared worker; a key held down repeats, a scripted press does not; and touch on a PC without a touchscreen is emulation. In desktop Firefox the page first steps to a gateway page and straight back: Firefox shows it again from its back/forward cache, while Camoufox and Playwright's Firefox switch that cache off and load it again, which the gateway refuses. On Windows, Firefox also stamps a mouse move with the time of the Windows message it came from, which counts in 15.6 ms ticks, so a person's moves reach the page a varying few milliseconds after their stamp, while moves that Playwright's Firefox or Camoufox make reach it at once, every time. The measuring script is generated for each check, with different names and numbers, and encrypts its report with a key only that copy holds, so a client cannot find the check by name or rewrite its result in transit. It also notes what kind of machine is asking: cloud browsers come from datacenter addresses and have no graphics card, sound devices, speech voices or taskbar, and often run Linux behind a Windows user agent, and a score of 4 or more is refused. Passing gives a pass for six hours, tied to that browser and good for `HUMAN_PAGES_PER_PASS` pages. Mainstream AI agents are built to stop at human checks and hand control back to the person. A visitor opening pages faster than anyone reads is asked again.
3. **Search engines still index the site.** Googlebot, Bingbot, Applebot and YandexBot skip the check once their address is verified by reverse and forward DNS, as each engine documents. A crawler name alone gets nothing.
4. **Budgets per network.** Each visitor's network (an IPv4 address, or an IPv6 /64) gets a rolling allowance: requests per minute, distinct URLs, decoded bytes and parallel transfers. A person reading a site stays well inside it. A crawler walking every URL does not. Clearing cookies, switching user agent or opening a private window does not reset it.
5. **A check instead of a wall.** When a browser runs out of budget, it gets a short automatic proof-of-work check (no puzzles, no clicks). Solving it gives that browser its own budget. Each further check from the same network costs twice as much work, and the number per network is capped. One person on a busy shared network gets through. A scraper rotating identities pays more each time.
6. **Timed blocks for clients that ignore limits.** A client that keeps sending requests after being told to slow down collects strikes, then gets blocked for 5 minutes. Repeat blocks last 4× longer, up to a day. Every block lifts on its own, and the block page says when. Operators can lift one early.

**Private mode** (`MODE=private`): content is only for invited people. Each person enrols a passkey with a one-time invitation, and every request needs a short passkey-backed session. Budgets apply per credential.

Both modes fetch only from one fixed origin, follow no redirects, forward no visitor cookies or credentials, and charge decoded bytes before releasing each chunk.

## What this does not promise

- **It cannot prove a visitor is human.** Every signal the check uses comes from the visitor's browser. In our tests it stopped every stock Playwright setup we tried, including installed Edge with a faked human mouse path, Playwright attached to an Edge window that was already open, and nine ways of hiding from the timing (replacing or wrapping `console.debug`, rewriting the report, patching the script, blocking the worker). Camoufox, a Firefox build for scraping, got through until 0.9.1 and is now refused, but turning Firefox's back/forward cache back on gets it past that step; with the opener-policy header also stripped it got past that step on the live site, and its mouse hold is now refused on Windows because its moves reach the page as soon as they are stamped. Camoufox claiming macOS or Linux is not judged by that timing, a keyboard hold with faked key repeat is not either, and driving the window with operating-system input gets through. **patchright**, a Playwright fork built to avoid the DevTools feature the check times, got through driving installed Edge with a faked mouse path until 0.9.2. It is now refused on Windows because its moves carry no pointer predictions, or, sent without pauses, fall between screen pixels, its keyboard and emulated-touch holds fail too, and, whatever the input, it holds every request the page makes, which makes cached fetches from the page take 2.5 to 3 times as long as from a shared worker. Playwright, Puppeteer and the tools built on them, including the AI browser agents browser-use and Stagehand and the stealth tools SeleniumBase and rebrowser, start the browser with a switch that lifts Chromium's limit on history changes, which the check tests, so they are refused as they come. A copy of patchright edited not to hold requests, rounding every point to a whole screen pixel and sending them without pauses, still gets through (patchright leaves that switch out), as is expected of nodriver-style tools driven the same way and of any tool that drives a real browser with human-like operating-system input; agents that jump the real cursor onto the button, and `pyautogui`-style glides, are refused. Stock Playwright also got through with a console wrapper written for this check (it reads what a real console reads, then swaps the arguments) injected into both the page and the worker. The key that seals the report travels inside the script, so a client willing to take each check's script apart can always forge it. The check stops tools used as they come and raises the cost for someone who has read this code; it does not stop them. Budgets, re-checks and blocks still apply.
- **Developers with DevTools open are asked to close it.** An open DevTools window looks like an attached automation client to the timing check. The message says so, and closing DevTools and reloading passes.
- **Sandbox detection only catches servers.** Agents running on a person's own computer look like that computer. A cloud browser with a real GPU behind a residential proxy can also look like a person. Real people on VPNs and virtual desktops share some server traits; a score needs several of them to reach 4, but an operator who sees real visitors refused can set `SANDBOX_CHECK=log`.
- **Agents in a person's own browser rely on good behaviour.** Agents such as Claude in Chrome, Comet or Atlas drive a real browser that looks like a person's. They stop at the human check because they are designed to, not because they cannot click. Once the person passes it, an agent can continue in that browser; only the fast-paging re-check and budgets apply then.
- **Shared networks share a budget.** Offices, campuses, VPNs and mobile carriers (CGNAT) put many people behind one address. The proof-of-work check exists for this, but heavy shared networks can still hit limits. Measure your own traffic before tightening the defaults.
- **Distributed scrapers get more allowance.** A scraper with many residential IPs gets one budget per network. This raises its cost but does not stop it.
- **Content that has been delivered can be copied.** Nothing here prevents screenshots, saving or sharing.
- **It is not DDoS protection.** It is one process with one SQLite database. Put it behind infrastructure that absorbs floods.
- **An automated browser that reads slowly from a home connection is not asked.** In the default `suspicious` mode, a real browser driven by a script on a personal computer sends the same headers as a person, so it reads until it pages too fast, runs out of budget, or trips another rule. Use `HUMAN_CHECK=always` where that matters more than friction.
- **Link previews and AI search do not see your pages.** Chat and social apps (Slack, WhatsApp, X) fetch pages with their own non-browser clients, so they get the check and shared links show no preview. AI search engines are refused by design. Set `HUMAN_CHECK=off` or `AI_AGENTS=allow` if you need either.
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

## Add it to your website

Human Gate runs as a reverse proxy between your HTTPS front end and your site. The site itself needs no code changes:

```
Visitor → HTTPS proxy (nginx, Caddy, Cloudflare…) → Human Gate :8787 → your site (private address)
```

### Is your site a fit today?

**Yes, if it is read-only content:** blogs, documentation, news, catalogues, public datasets. These are the sites crawlers and AI agents hit hardest.

**Not yet, if visitors submit forms, log in or check out.** The gateway currently:

- proxies only GET and HEAD, so form posts, logins and POST-based search fail;
- does not forward visitor cookies to your site, so user sessions do not work;
- shows the human check to link-preview fetchers, so links shared in chat apps have no preview;
- runs as a single process with one SQLite database.

These are on the [roadmap](docs/roadmap.md).

### Steps

1. **Move your site to a private address**, for example `127.0.0.1:8788` or an internal IP. Firewall it so only the gateway can reach it. If scrapers can reach the site directly, they bypass every check.
2. **Configure and start Human Gate:**

   ```sh
   git clone https://github.com/mohakmalviya/human-gate.git
   cd human-gate
   npm ci
   npm run build
   npm run cloud-ranges    # datacenter address lists; rerun weekly (cron)
   cp .env.example .env    # then edit it, see below
   npm start
   ```

   The minimum `.env` for a site at `https://example.com` behind a proxy on the same machine:

   ```
   PUBLIC_ORIGIN=https://example.com
   UPSTREAM=http://127.0.0.1:8788
   TRUSTED_PROXIES=127.0.0.1
   ```

3. **Point your HTTPS proxy at the gateway** instead of at the site. It must keep the original `Host` and *append* the client address to `X-Forwarded-For`. For nginx:

   ```nginx
   location / {
     proxy_pass http://127.0.0.1:8787;
     proxy_set_header Host $host;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
   ```

   For Caddy:

   ```
   example.com {
     reverse_proxy 127.0.0.1:8787
   }
   ```

4. **If a CDN such as Cloudflare sits in front of your proxy**, add the CDN's published IP ranges to `TRUSTED_PROXIES` as well, for example `TRUSTED_PROXIES=127.0.0.1,173.245.48.0/20,...`. Otherwise every visitor appears to be a CDN server and they all share one budget. List only ranges you actually use, and nothing broader: anyone inside a trusted range can choose their own identity. Also make sure the CDN does not cache pages, or it will serve them without the gateway counting them.

5. **Check it works.** Load your site normally. Then, from another machine, send a burst of requests with a script and confirm you get `429` and then a timed block. Lift it with `npm run admin -- unban <that-ip>`.

Read the full [deployment requirements](docs/deployment.md) before going live, and start with the default budgets: they are deliberately generous. Watch the logs for `resource_budget`, `clearance_issued` and `temporarily_blocked` before tightening anything. `SANDBOX_CHECK=enforce` is the default: scores of 4 or more are refused, 2–3 get hour-long passes. Watch `sandbox_detected` lines and the `sandbox:<score>` notes on `human_pass_issued`; if real visitors are being refused, switch to `log` while you look.

### Settings

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
| `MAX_RESPONSE_BYTES` | `5 MiB` | Largest single response. Byte-range requests (video, audio, resumable downloads) are shrunk to fit, so larger media still plays in slices |
| `STRIKES_PER_WINDOW` | `30` | Denied requests a network may send in `STRIKE_WINDOW_SECONDS` before a block |
| `STRIKE_WINDOW_SECONDS` | `600` | Strike counting window |
| `BAN_SECONDS` / `MAX_BAN_SECONDS` | `300` / `86400` | First block length, and the cap for repeats (4× each time) |
| `CHALLENGE_DIFFICULTY` | `16` | Leading zero bits for the first check (about 65k hashes, around a second) |
| `CLEARANCES_PER_WINDOW` | `5` | Checks one network can pass per `CLEARANCE_SECONDS` |
| `CLEARANCE_SECONDS` | `3600` | Lifetime of a clearance and its budget |
| `SESSION_SECONDS` / `PAGES_PER_SESSION` | `300` / `60` | Private mode session lifetime and request cap |
| `AI_AGENTS` | `block` | `block` refuses self-declared and signed AI agents; `allow` lets them through |
| `HUMAN_CHECK` | `suspicious` | Public mode: `suspicious` shows the press-and-hold check only to visitors with a reason (see above); `always` shows it to every new visitor; `off` turns it off |
| `OPEN_PATHS` | `/robots.txt` | Comma-separated paths anyone can fetch without the check, for example `/robots.txt,/feed.xml,/sitemap.xml` for feed readers |
| `HUMAN_PASS_SECONDS` | `21600` | How long a passed check lasts in that browser |
| `HUMAN_PAGES_PER_PASS` | `300` | Page loads one pass covers before the visitor is asked again, so a pass handed to a scraper runs out |
| `HUMAN_PASSES_PER_HOUR` | `60` | Passes one network can earn per hour |
| `HUMAN_PAGES_PER_MINUTE` | `20` | Page loads per minute before a visitor is asked again (images, scripts and styles do not count) |
| `VERIFIED_CRAWLERS` | `googlebot,bingbot,applebot,yandexbot` | Search engines that skip the check after DNS verification; `off` for none |
| `SANDBOX_CHECK` | `enforce` | `enforce` refuses a score of 4+ for server and virtual-machine signals and gives 2–3 an hour-long pass; `log` only records them; `off` ignores them |
| `CLOUD_RANGES_FILE` | `$DATA_DIR/cloud-ranges.txt` | Datacenter address list written by `npm run cloud-ranges` (AWS, Google Cloud, Oracle, DigitalOcean, Linode) |
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

The human check reads pointer movement, browser traits and machine traits (GPU name, a rendered test image, whether a few system fonts exist, how many speech voices and media devices there are, screen and taskbar size, time zone) in the browser and sends them once. The server scores them and keeps only the names of the flags it found, such as `software_gpu`, in the log. Raw values are never stored, and nothing is used to recognise a visitor later. Network addresses are stored only as keyed hashes. URLs are stored as keyed hashes for budget counting and never in plain text. Logs record a random request ID, status, decision reason and byte count. They never record IPs, URLs, user agents or cookies. Expired records are deleted every minute.

## Development

```sh
npm run check            # syntax
npm test                 # unit and integration tests (loopback only)
npm run benchmark        # HTTP extraction scenarios
npm run browser:install && npm run benchmark:browser   # real Chromium, virtual passkeys
npm run attack:agents    # automated browsers against the human check (opens real windows)
```

Layout: `src/` gateway, storage, network handling and WebAuthn; `web/` visitor pages and the proof-of-work client; `test/` regression tests; `scripts/` build, demo and benchmarks; `showcase/` offline evidence demo; `docs/` design notes.

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Background

The project started from public discussion about AI agents overwhelming websites and forms. It has no affiliation with any company mentioned in that discussion, and does not reproduce anyone's internal defenses. Design notes and sources are in [docs/research.md](docs/research.md).

## License

[MIT](LICENSE)
