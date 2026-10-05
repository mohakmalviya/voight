import http from 'node:http';
import { once } from 'node:events';
import { finished } from 'node:stream/promises';
import { createHash, randomUUID } from 'node:crypto';
import { token, digest } from './store.mjs';
import { webauthn } from './webauthn.mjs';
import { automationSignals, reportedWebdriver, automationDecision } from './automation.mjs';
import { denialPage, challengePage } from './denial.mjs';
import { clientAddress, networkPrefix } from './network.mjs';

const PREFIX = '/_gate/';
// Public-mode denials that count as a strike when a client keeps sending requests anyway.
const BUDGET_REASONS = new Set(['connection_rate', 'reader_rate', 'resource_budget', 'byte_budget']);
// A clearance moves a visitor onto its own budget, which helps with these but not the per-network flood limit.
const CLEARABLE_REASONS = new Set(['reader_rate', 'resource_budget', 'byte_budget']);
// Origin response headers a public site needs to keep working. Everything else is dropped.
const PUBLIC_RESPONSE_HEADERS = ['content-language', 'content-security-policy', 'x-frame-options', 'x-robots-tag'];

class Denied extends Error {
  constructor(status, reason, retryAfter = 60) { super(reason); this.status = status; this.retryAfter = retryAfter; }
}

function cookie(req, name) {
  const values = (req.headers.cookie ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(`${name}=`));
  if (values.length !== 1) return '';
  const value = values[0].slice(name.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : '';
}
function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'content-type': type });
  res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
}
async function json(req) {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new Denied(415, 'json_required');
  let size = 0; const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16384) throw new Denied(413, 'body_too_large');
    chunks.push(chunk);
  }
  try { const value = JSON.parse(Buffer.concat(chunks).toString()); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; }
  catch { throw new Denied(400, 'invalid_json'); }
}

export function leadingZeroBits(bytes) {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) { bits += 8; continue; }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

// A shared cache in front of the gateway would serve content without charging any budget.
export function privateCacheControl(value) {
  const directives = (value ?? '').split(',').map(d => d.trim()).filter(d => d && !/^(public|private|s-maxage=.*|proxy-revalidate)$/i.test(d));
  if (!value || directives.some(d => /^no-store$/i.test(d))) return 'no-store, private';
  return ['private', ...directives].join(', ');
}

export function createGateway({ config, store, assets, auth = webauthn(config), audit = event => console.log(JSON.stringify(event)) }) {
  // One process owns all active transfers. Durable extraction budgets live in SQLite.
  const activeTransfers = new Map();
  const sessionCookie = config.secure ? '__Host-hg_session' : 'hg_session';
  const ceremonyCookie = config.secure ? '__Host-hg_ceremony' : 'hg_ceremony';
  const clearanceCookie = config.secure ? '__Host-hg_clearance' : 'hg_clearance';
  const setCookie = (res, name, value, seconds, sameSite = 'Strict') => res.appendHeader('set-cookie', `${name}=${value}; Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${seconds}${config.secure ? '; Secure' : ''}`);
  const server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    const requestID = randomUUID();
    const isPublic = config.mode === 'public';
    let outcome = 'internal_error';
    let releaseSlot, controller, proxySignal, abortOnClose, network, chargedBytes = 0;
    let signals = [];
    res.setHeader('x-request-id', requestID);
    res.setHeader('cache-control', 'no-store, private');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (config.secure) res.setHeader('strict-transport-security', 'max-age=31536000');
    // A client that keeps going after being told to slow down earns a timed block.
    const penalize = failure => {
      if (!network || !BUDGET_REASONS.has(failure.message)) return failure;
      if (store.limit(`strike:${network}`, config.strikesPerWindow, config.strikeWindowSeconds * 1000)) return failure;
      store.resetLimit(`strike:${network}`);
      return new Denied(429, 'temporarily_blocked', store.ban(network, config.banSeconds, config.maxBanSeconds));
    };
    try {
      if (req.headers.host !== new URL(config.origin).host) throw new Denied(421, 'wrong_host');
      if (!req.url?.startsWith('/') || req.url.startsWith('//') || /[\\\x00-\x20]/.test(req.url)) throw new Denied(400, 'invalid_target');
      const url = new URL(req.url, config.origin);
      // Forwarded headers count only when the direct peer is a configured trusted proxy.
      const ip = clientAddress(req.socket.remoteAddress, req.headers['x-forwarded-for'], config.trustedProxies);
      const ua = req.headers['user-agent'] ?? '';
      if (config.automationPolicy !== 'off') signals = automationSignals(ua);
      const gateAsset = req.method === 'GET' && assets[url.pathname];
      if (isPublic) {
        network = store.pseudonym(networkPrefix(ip));
        // Blocked visitors still get the stylesheet and script that explain the block.
        const ban = !gateAsset && store.banned(network);
        if (ban) throw new Denied(429, 'temporarily_blocked', Math.max(1, Math.ceil((ban.until - store.now()) / 1000)));
      }
      if (!store.limit(`all:${network ?? digest(ip)}`, config.connectionsPerMinute)) throw new Denied(429, 'connection_rate');
      // Public sites must accept people arriving from links elsewhere; embedding stays same-site.
      const navigation = isPublic && req.headers['sec-fetch-mode'] === 'navigate' && ['GET', 'HEAD'].includes(req.method);
      if (req.headers['sec-fetch-site'] === 'cross-site' && !navigation) throw new Denied(403, 'cross_site');
      if (url.pathname.startsWith(PREFIX)) {
        if (gateAsset) {
          outcome = 'gate_asset'; return send(res, 200, assets[url.pathname].body, assets[url.pathname].type);
        }
        if (req.method !== 'POST') throw new Denied(404, 'not_found');
        if (req.headers.origin !== config.origin) throw new Denied(403, 'origin_mismatch');
        if (!store.limit(`auth:${network ?? digest(ip)}`, 20)) throw new Denied(429, 'auth_rate');
        const body = await json(req);
        if (isPublic) {
          const denied = automationDecision(config.automationPolicy, ua, null, false);
          if (denied) throw new Denied(403, denied);
          if (url.pathname === `${PREFIX}challenge/options`) {
            const issued = store.clearanceCount(network);
            if (issued >= config.clearancesPerWindow) throw new Denied(429, 'challenge_limit', config.clearanceSeconds);
            // Every clearance a network has already minted doubles the work for the next one.
            const challenge = token(), difficulty = config.challengeDifficulty + issued;
            store.takeChallenge(cookie(req, ceremonyCookie));
            setCookie(res, ceremonyCookie, store.challenge({ kind: 'work', challenge, difficulty, network }), 120);
            outcome = 'challenge_issued'; return send(res, 200, { challenge, difficulty });
          }
          if (url.pathname === `${PREFIX}challenge/verify`) {
            const pending = store.takeChallenge(cookie(req, ceremonyCookie));
            if (!pending || pending.kind !== 'work' || pending.network !== network) throw new Denied(403, 'invalid_challenge');
            if (typeof body.nonce !== 'string' || !/^\d{1,16}$/.test(body.nonce)) throw new Denied(403, 'invalid_solution');
            const hash = createHash('sha256').update(`${pending.challenge}:${body.nonce}`).digest();
            if (leadingZeroBits(hash) < pending.difficulty) throw new Denied(403, 'invalid_solution');
            const clearance = store.clear(network, config.clearancesPerWindow, config.clearanceSeconds);
            if (!clearance) throw new Denied(429, 'challenge_limit', config.clearanceSeconds);
            // Lax so the clearance survives arriving from a link on another site.
            setCookie(res, clearanceCookie, clearance, config.clearanceSeconds, 'Lax');
            outcome = 'clearance_issued'; return send(res, 200, { ok: true });
          }
          throw new Denied(404, 'not_found');
        }
        if (url.pathname === `${PREFIX}logout`) {
          store.logout(cookie(req, sessionCookie)); setCookie(res, sessionCookie, '', 0);
          outcome = 'logged_out'; return send(res, 200, { ok: true });
        }
        if (url.pathname.endsWith('/options')) {
          const webdriver = config.automationPolicy === 'off' ? null : reportedWebdriver(body);
          if (config.automationPolicy !== 'off') signals = automationSignals(ua, webdriver);
          const denied = automationDecision(config.automationPolicy, ua, webdriver);
          if (denied) throw new Denied(403, denied);
          let options, payload;
          if (url.pathname === `${PREFIX}register/options`) {
            if (typeof body.invite !== 'string' || body.invite.length !== 43) throw new Denied(403, 'invalid_invite');
            const invite = store.getInvite(body.invite);
            if (!invite) throw new Denied(403, 'invalid_invite');
            const userID = token(); options = await auth.registrationOptions(userID, invite.label);
            payload = { kind: 'register', invite: digest(body.invite), userID };
          } else if (url.pathname === `${PREFIX}login/options`) {
            options = await auth.authenticationOptions(); payload = { kind: 'login' };
          } else throw new Denied(404, 'not_found');
          // Only one outstanding ceremony per browser. The challenge is held server-side.
          store.takeChallenge(cookie(req, ceremonyCookie));
          const id = store.challenge({ ...payload, challenge: options.challenge, ua: digest(ua), webdriver });
          setCookie(res, ceremonyCookie, id, 120); outcome = 'challenge_issued'; return send(res, 200, options);
        }
        if (![`${PREFIX}register/verify`, `${PREFIX}login/verify`].includes(url.pathname)) throw new Denied(404, 'not_found');
        const pending = store.takeChallenge(cookie(req, ceremonyCookie));
        if (!pending || pending.ua !== digest(ua)) throw new Denied(403, 'invalid_challenge');
        const webdriver = config.automationPolicy === 'off' ? null : pending.webdriver ?? null;
        if (config.automationPolicy !== 'off') signals = automationSignals(ua, webdriver);
        const denied = automationDecision(config.automationPolicy, ua, webdriver);
        if (denied) throw new Denied(403, denied);
        let credentialID;
        if (url.pathname === `${PREFIX}register/verify` && pending.kind === 'register') {
          const result = await auth.verifyRegistration(body, pending.challenge);
          if (!result.verified || !result.registrationInfo?.userVerified) throw new Denied(403, 'verification_failed');
          store.enroll(pending.invite, pending.userID, result.registrationInfo.credential);
          credentialID = result.registrationInfo.credential.id;
        } else if (url.pathname === `${PREFIX}login/verify` && pending.kind === 'login') {
          if (typeof body.id !== 'string' || body.id.length > 2048) throw new Denied(403, 'verification_failed');
          const credential = store.credential(body.id);
          if (!credential) throw new Denied(403, 'verification_failed');
          if (body.response?.userHandle && body.response.userHandle !== credential.user_id) throw new Denied(403, 'verification_failed');
          const result = await auth.verifyAuthentication(body, pending.challenge, credential);
          if (!result.verified || !result.authenticationInfo?.userVerified || !store.updateCounter(credential.id, credential.counter, result.authenticationInfo.newCounter)) throw new Denied(403, 'verification_failed');
          credentialID = credential.id;
        } else throw new Denied(403, 'ceremony_mismatch');
        // Budgets are ALSO enforced by credential, so logging in again cannot reset the minute limit.
        const session = store.session(credentialID, ua, config.sessionSeconds, webdriver);
        setCookie(res, sessionCookie, session, config.sessionSeconds);
        outcome = 'verified'; return send(res, 200, { ok: true });
      }
      if (!['GET', 'HEAD'].includes(req.method)) throw new Denied(405, 'read_only_gateway');
      const declared = automationDecision(config.automationPolicy, ua, null, false);
      if (declared) throw new Denied(403, declared);
      // The subject is whoever the budgets are charged to: a credential, a clearance, or a network.
      let subject, scope, identity;
      if (isPublic) {
        // Clearing cookies only drops a visitor back onto the network's shared budget.
        const clearance = store.clearance(cookie(req, clearanceCookie));
        subject = clearance ? `clearance:${clearance.hash}` : `network:${network}`;
        scope = 'public'; identity = {};
      } else {
        const session = cookie(req, sessionCookie);
        const admitted = session && store.admit(session, ua, config.pagesPerSession);
        if (!admitted || (config.automationPolicy === 'enforce' && admitted.webdriver === null)) {
          outcome = 'admission_required';
          return send(res, 401, assets[`${PREFIX}index.html`].body, 'text/html; charset=utf-8');
        }
        if (config.automationPolicy !== 'off') signals = automationSignals(ua, admitted.webdriver);
        const automated = automationDecision(config.automationPolicy, ua, admitted.webdriver);
        if (automated) throw new Denied(403, automated);
        subject = admitted.credential_id; scope = 'credential'; identity = { 'x-human-gate-user': subject };
      }
      if (!store.limit(`reader:${subject}`, config.requestsPerMinute)) throw new Denied(429, 'reader_rate');
      const active = activeTransfers.get(subject) ?? 0;
      if (active >= config.maxConcurrentRequests) throw new Denied(429, 'parallel_limit', 1);
      activeTransfers.set(subject, active + 1);
      releaseSlot = () => {
        const remaining = activeTransfers.get(subject) - 1;
        if (remaining) activeTransfers.set(subject, remaining); else activeTransfers.delete(subject);
      };
      const restriction = store.beginResource(subject, url.pathname + url.search, config, scope);
      if (restriction) throw new Denied(429, restriction.reason, restriction.retryAfter);
      controller = new AbortController();
      proxySignal = AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]);
      abortOnClose = () => { if (!res.writableFinished) controller.abort(new Denied(499, 'client_closed')); };
      res.on('close', abortOnClose);
      if (res.destroyed) throw new Denied(499, 'client_closed');
      // Construct a fixed-origin URL without allowing protocol-relative or absolute URL overrides.
      const target = new URL(config.upstream); target.pathname = url.pathname; target.search = url.search;
      const upstream = await fetch(target, {
        method: req.method, redirect: 'manual', signal: proxySignal,
        headers: {
          accept: req.headers.accept ?? '*/*', 'user-agent': 'HumanGate/0.4', ...identity,
          ...(req.headers['accept-language'] ? { 'accept-language': req.headers['accept-language'] } : {}),
        },
      });
      if (upstream.status >= 300 && upstream.status < 400) { await upstream.body?.cancel(); throw new Denied(502, 'upstream_redirect_rejected'); }
      // No cookies, authorization, forwarding headers, cache validators, or untrusted response headers cross this boundary.
      res.statusCode = upstream.status;
      res.setHeader('content-type', upstream.headers.get('content-type') ?? 'application/octet-stream');
      if (isPublic) {
        // The site's own page policy applies to its pages; the gateway's strict defaults are for gate pages.
        for (const name of ['content-security-policy', 'referrer-policy', 'x-robots-tag']) res.removeHeader(name);
        for (const name of PUBLIC_RESPONSE_HEADERS) { const value = upstream.headers.get(name); if (value) res.setHeader(name, value); }
        res.setHeader('cache-control', privateCacheControl(upstream.headers.get('cache-control')));
      }
      outcome = 'admitted';
      if (!upstream.body || req.method === 'HEAD') {
        await upstream.body?.cancel(); res.end(); await finished(res, { signal: proxySignal, cleanup: true }); return;
      }
      let bytes = 0;
      for await (const chunk of upstream.body) {
        proxySignal.throwIfAborted();
        bytes += chunk.length;
        if (bytes > config.maxResponseBytes) throw new Denied(502, 'response_size');
        // fetch decodes compressed bodies. Charge every chunk BEFORE releasing it to the client.
        const denied = store.chargeBytes(subject, chunk.length, config, scope);
        if (denied) throw new Denied(denied.status ?? 429, denied.reason, denied.retryAfter);
        chargedBytes += chunk.length;
        if (!res.write(chunk)) await once(res, 'drain', { signal: proxySignal });
      }
      res.end(); await finished(res, { signal: proxySignal, cleanup: true });
    } catch (error) {
      const failure = penalize(error instanceof Denied ? error : proxySignal?.reason instanceof Denied ? proxySignal.reason
        : proxySignal?.reason?.name === 'TimeoutError' ? new Denied(504, 'upstream_timeout')
        : new Denied(controller ? 502 : 403, controller ? 'upstream_failure' : 'request_rejected'));
      outcome = failure.message;
      if (res.headersSent || res.destroyed) { if (!res.headersSent) res.statusCode = failure.status; res.destroy(); return; }
      const status = failure.status;
      if (status === 429) res.setHeader('retry-after', String(failure.retryAfter));
      if (['GET', 'HEAD'].includes(req.method) && req.headers.accept?.includes('text/html')) {
        // A person over budget can pay a little CPU instead of waiting. Scrapers pay it on every reset.
        const challenge = network && CLEARABLE_REASONS.has(outcome) && store.clearanceCount(network) < config.clearancesPerWindow;
        send(res, status, challenge ? challengePage(failure.retryAfter, requestID) : denialPage(status, outcome, failure.retryAfter, requestID), 'text/html; charset=utf-8');
        return;
      }
      send(res, status, { error: outcome, requestID });
    } finally {
      if (abortOnClose) res.off('close', abortOnClose);
      controller?.abort();
      releaseSlot?.();
      // Close includes partial/aborted streams, which the old finish-only log missed.
      const record = () => audit({ at: new Date().toISOString(), requestID, mode: config.mode, status: res.statusCode, reason: outcome, completed: res.writableFinished, chargedBytes, automationSignals: signals });
      if (res.destroyed || res.writableFinished) record(); else res.once('close', record);
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000;
  server.on('upgrade', (_, socket) => socket.destroy());
  const cleanup = setInterval(() => store.prune(), 60000); cleanup.unref();
  server.on('close', () => clearInterval(cleanup));
  return server;
}
