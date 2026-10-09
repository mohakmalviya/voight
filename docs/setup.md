# Add Voight to your website

The full setup guide and every setting. The README has the short version.

Voight runs as a reverse proxy between your HTTPS front end and your site. The site itself needs no code changes:

```
Visitor → HTTPS proxy (nginx, Caddy, Cloudflare…) → Voight :8787 → your site (private address)
```

## Is your site a fit today?

**Yes, if it is read-only content:** blogs, documentation, news, catalogues, public datasets. These are the sites crawlers and AI agents hit hardest.

**Not yet, if visitors submit forms, log in or check out.** The gateway currently:

- proxies only GET and HEAD, so form posts, logins and POST-based search fail;
- does not forward visitor cookies to your site, so user sessions do not work;
- shows the human check to link-preview fetchers, so links shared in chat apps have no preview;
- runs as a single process with one SQLite database.

These are on the [roadmap](roadmap.md).

## Steps

1. **Move your site to a private address**, for example `127.0.0.1:8788` or an internal IP. Firewall it so only the gateway can reach it. If scrapers can reach the site directly, they bypass every check.
2. **Configure and start Voight:**

   ```sh
   git clone https://github.com/mohakmalviya/voight.git
   cd voight
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

   If you have a private detection rules pack, copy its folder next to `src/` as `rules/`, or set `RULES_DIR` to its folder. Without one, the basic rules in `src/basic.mjs` apply.

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

Read the full [deployment requirements](deployment.md) before going live, and start with the default budgets: they are deliberately generous. Watch the logs for `resource_budget`, `clearance_issued` and `temporarily_blocked` before tightening anything. `SANDBOX_CHECK=enforce` is the default: scores of 4 or more are refused, 2–3 get hour-long passes (with the basic rules only a datacenter address scores, at 2). Watch `sandbox_detected` lines and the `sandbox:<score>` notes on `human_pass_issued`; if real visitors are being refused, switch to `log` while you look. `npm run stats` reads the log from a file or standard input and shows, per platform and input (mouse, touch, keyboard), how many checks passed, failed or were refused, the signals behind each failure, and the sandbox scores of passes. It counts only; the log holds no addresses or user agents. A refused visitor sees one generic message and a reference: the reason and signals are in the log under that request id.

## Settings

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
| `HUMAN_CHECK` | `suspicious` | Public mode: `suspicious` shows the press-and-hold check only to visitors with a reason (see [how it works](how-it-works.md)); `always` shows it to every new visitor; `off` turns it off |
| `OPEN_PATHS` | `/robots.txt,/favicon.ico,/.well-known/*` | Comma-separated paths anyone can fetch without the check; a trailing `*` opens everything under that path. For example add `/feed.xml,/sitemap.xml` for feed readers |
| `POLICY_FILE` | *(none)* | JSON rules that `allow` (skip the check and the AI-agent refusal), `deny` or always `check` requests by `path`, `userAgent`, `headers` (name to pattern; a missing header reads as empty) or `cidr`, first match wins. See [the example](policy.example.json) |
| `HONEYPOT` | `block` | The hidden link in gate pages: `block` blocks a network that fetches it (as for ignored limits), `log` only records `honeypot`, `off` leaves the link out |
| `OPEN_GRAPH` / `OPEN_GRAPH_SECONDS` | `off` / `86400` | `on` gives link-preview clients the page's own preview tags (read from the origin, cached this long) and opens the preview images they name |
| `CONTACT` | *(none)* | An email address or `https://` link shown on gate pages so refused people can reach you; emails get the reference filled in |
| `METRICS_PORT` | *(none)* | Serves Prometheus counters (decisions, signal names, charged bytes) at `http://127.0.0.1:<port>/metrics` |
| `HUMAN_PASS_SECONDS` | `21600` | How long a passed check lasts in that browser |
| `HUMAN_PAGES_PER_PASS` | `300` | Page loads one pass covers before the visitor is asked again, so a pass handed to a scraper runs out |
| `HUMAN_PASSES_PER_HOUR` | `60` | Passes one network can earn per hour |
| `HUMAN_PAGES_PER_MINUTE` | `20` | Page loads per minute before a visitor is asked again (images, scripts and styles do not count) |
| `VERIFIED_CRAWLERS` | `googlebot,bingbot,applebot,yandexbot` | Search engines that skip the check after DNS verification; `off` for none |
| `SANDBOX_CHECK` | `enforce` | `enforce` refuses a server-signal score of 4+ and gives 2–3 an hour-long pass; `log` only records them; `off` ignores them |
| `CLOUD_RANGES_FILE` | `$DATA_DIR/cloud-ranges.txt` | Datacenter address list written by `npm run cloud-ranges` (AWS, Google Cloud, Oracle, DigitalOcean, Linode) |
| `AUTOMATION_POLICY` | `observe` | `off`, `observe` or `enforce` for self-declared automation ([details](automation-policy.md)) |
| `RULES_DIR` | *(none)* | Folder of a private detection rules pack (a folder whose `index.mjs` has the same exports as `src/basic.mjs`). Startup fails if it has no `index.mjs`. Without it, `rules/` in the app folder is used if it has one, otherwise the basic rules |

A "subject" is a network or a clearance in public mode, and a credential in private mode. The defaults are starting points, not measured thresholds. Asset-heavy pages spend URL budget quickly, so check your own pages.
