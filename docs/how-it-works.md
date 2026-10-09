# How Voight works

The full version of the README's summary: what each check looks at, and the limits in detail.

## The checks

Voight is a reverse proxy. Every request for your site passes through it, and it decides whether to fetch the page from your origin.

**Public mode** (default): any person can browse.

1. **AI agents that identify themselves are refused.** Crawlers and assistants such as GPTBot, ChatGPT-User, ClaudeBot, Claude-User, PerplexityBot and Perplexity-User, agents that sign their requests (Web Bot Auth, used by ChatGPT agent), AI apps whose built-in browser names itself, and Firefox's AI link previews (sent with `X-Firefox-Ai`) are refused on every request. `robots.txt`, the favicon and files under `/.well-known/` (such as `security.txt`) stay readable.
2. **People see nothing; suspicious visitors get a human check.** A visitor in an ordinary browser reads the site directly. The check appears only when there is a reason: a datacenter address, an automation tool's user agent, headers no current browser would send (scripts such as curl, Python or Node usually give themselves away here), more than `HUMAN_PAGES_PER_MINUTE` page loads a minute from one network, or a failed check or block from that network in the last hour. `HUMAN_CHECK=always` shows it to every new visitor instead. The check is a clearly labelled "Confirm you are human" page with a press-and-hold button. While the person holds it, a small script measures the browser and sends a report, and the [detection rules](#detection-rules) decide whether it looks automated. The measuring script is generated for each check, with scrambled names and strings, and encrypts its report with a key only that copy holds, so a client cannot find the check by name or rewrite its result in transit; a report that does not open is refused (`report_tampered`). In desktop Firefox the check page may first step to a small hop page and straight back. Passing gives a pass for six hours, tied to that browser and good for `HUMAN_PAGES_PER_PASS` pages. Mainstream AI agents are built to stop at human checks and hand control back to the person. A visitor opening pages faster than anyone reads is asked again.
3. **Search engines still index the site.** Googlebot, Bingbot, Applebot and YandexBot skip the check once their address is verified by reverse and forward DNS, as each engine documents. A crawler name alone gets nothing.
4. **Budgets per network.** Each visitor's network (an IPv4 address, or an IPv6 /64) gets a rolling allowance: requests per minute, distinct URLs, decoded bytes and parallel transfers. A person reading a site stays well inside it. A crawler walking every URL does not. Clearing cookies, switching user agent or opening a private window does not reset it.
5. **A check instead of a wall.** When a browser runs out of budget, it gets a short automatic proof-of-work check (no puzzles, no clicks). Solving it gives that browser its own budget. Each further check from the same network costs twice as much work, and the number per network is capped. One person on a busy shared network gets through. A scraper rotating identities pays more each time.
6. **Timed blocks for clients that ignore limits.** A client that keeps sending requests after being told to slow down collects strikes, then gets blocked for 5 minutes. Repeat blocks last 4× longer, up to a day. Every block lifts on its own, and the block page says when. Operators can lift one early.
7. **A trap for tools that read the HTML.** Every gate page carries a link inside a `<template>`, which browsers never show, follow or prefetch and screen readers do not read. Scrapers and agents that pull links out of the page's HTML find it, and fetching it blocks that network the same way (`HONEYPOT`). A tool written to skip `/_gate/more/` is not caught by this.
8. **Your own rules.** `POLICY_FILE` names a JSON list of rules that allow, deny or always check requests by path, user agent, header or network, checked before anything else ([example](policy.example.json)). Budgets and blocks still apply to allowed requests. Anyone can copy a user agent, so allow networks rather than user agents.
9. **Link previews, if you want them.** With `OPEN_GRAPH=on`, chat and social apps that fetch a shared link get the check page carrying that page's own title, description and preview image, so the link still shows a card; the page itself stays behind the check.

Ideas 7 to 9, and the open `/.well-known/` files, come from [Anubis](https://github.com/TecharoHQ/anubis), an open-source proxy that slows AI crawlers down with proof-of-work. Voight aims further: it tries to refuse automated browsers outright, not only make them pay. Set `CONTACT` to show refused people how to reach you, and `METRICS_PORT` for Prometheus counters on loopback.

**Private mode** (`MODE=private`): content is only for invited people. Each person enrols a passkey with a one-time invitation, and every request needs a short passkey-backed session. Budgets apply per credential.

Both modes fetch only from one fixed origin, follow no redirects, forward no visitor cookies or credentials, and charge decoded bytes before releasing each chunk.

## Detection rules

`src/rules.mjs` loads the rules the human check uses: a private rules pack from the folder named by `RULES_DIR`, or `rules/` in the app folder if it exists (it is gitignored). Otherwise it uses the basic rules in `src/basic.mjs`. A pack is a folder whose `index.mjs` has the same exports as `src/basic.mjs`, and it replaces the basic rules entirely. To deploy with a pack, copy its folder next to `src/`.

The basic rules catch only the obvious:

- **Declared automation** (`automation_detected`): `navigator.webdriver`, HeadlessChrome, Playwright, Puppeteer or Selenium in the user agent or brand list, or desktop Chrome with no window frame and no plugins.
- **A gesture that isn't a person's** (`human_check_failed`): an untrusted gesture, a hold shorter than 1.5 s by the page's clock or the server's, or a mouse that never moved before pressing.
- **Odd headers** (`suspicious` mode only): a request that isn't from a browser user agent, or lacks Fetch Metadata, is asked to pass the check.
- **Servers**: a datacenter address (from the cloud ranges file) scores 2, which gives a pass that lasts an hour. A score of 4 is refused (`sandbox_detected`), but the basic rules never reach it.

The rules Voight runs in production are not published, because published rules are easy to tune a bot against.

**Refusals are not explained to the browser.** For any refused check it gets only `human_check_failed`, as a JSON error or a page, with one generic message. The real reason (`automation_detected`, `sandbox_detected` or `human_check_failed`) and the signals behind it stay in the server log, under the request id shown on the page. The pass cookie always carries the full pass length; a pass cut to an hour is enforced on the server.

## Limits in detail

- **It cannot prove a visitor is human.** Every signal the check uses comes from the visitor's browser, so a client that controls the browser can forge it. The key that seals the report travels inside the script, so a client willing to take each check's script apart can always forge the report. The basic rules stop tools that announce themselves, not tools built to hide. A private rules pack can look for much more, but bypasses exist: a careful attacker driving a real browser on a real device can get through. The rules raise the cost; they don't make bots impossible. Budgets, re-checks and blocks still apply.
- **Server detection only catches servers.** Agents running on a person's own computer look like that computer, and a browser on a server behind a residential proxy can look like a person's. Real people on VPNs and virtual desktops share some server traits; with the basic rules a datacenter address only shortens the pass to an hour. If a rules pack refuses real visitors, set `SANDBOX_CHECK=log` while you look.
- **Agents in a person's own browser rely on good behaviour.** Agents such as Claude in Chrome, Comet or Atlas drive a real browser that looks like a person's. They stop at the human check because they are designed to, not because they cannot click. Once the person passes it, an agent can continue in that browser; only the fast-paging re-check and budgets apply then.
- **Shared networks share a budget.** Offices, campuses, VPNs and mobile carriers (CGNAT) put many people behind one address. The proof-of-work check exists for this, but heavy shared networks can still hit limits. Measure your own traffic before tightening the defaults.
- **Distributed scrapers get more allowance.** A scraper with many residential IPs gets one budget per network. This raises its cost but does not stop it.
- **Content that has been delivered can be copied.** Nothing here prevents screenshots, saving or sharing.
- **It is not DDoS protection.** It is one process with one SQLite database. Put it behind infrastructure that absorbs floods.
- **An automated browser that reads slowly from a home connection is not asked.** In the default `suspicious` mode, a real browser driven by a script on a personal computer sends the same headers as a person, so it reads until it pages too fast, runs out of budget, or trips another rule. Use `HUMAN_CHECK=always` where that matters more than friction.
- **Link previews and AI search do not see your pages.** Chat and social apps (Slack, WhatsApp, X) fetch pages with their own non-browser clients, so they get the check and shared links show no preview unless `OPEN_GRAPH=on`, which gives every such client (scrapers included) the page's title, description and preview image, and nothing else. AI search engines are refused by design. Set `HUMAN_CHECK=off` or `AI_AGENTS=allow` if you need more.
- **The site must be read-only.** Only GET and HEAD are proxied: no form posts, logins or WebSockets yet.

The [threat model](threat-model.md) summarises what is defended and what isn't.
