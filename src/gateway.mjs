import http from 'node:http';
import { once } from 'node:events';
import { finished } from 'node:stream/promises';
import { randomUUID } from 'node:crypto';
import { token, digest } from './store.mjs';
import { webauthn } from './webauthn.mjs';

const PREFIX = '/_gate/';
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

export function createGateway({ config, store, assets, auth = webauthn(config), audit = event => console.log(JSON.stringify(event)) }) {
  // One process owns all active transfers. Durable extraction budgets live in SQLite.
  const activeTransfers = new Map();
  const sessionCookie = config.secure ? '__Host-hg_session' : 'hg_session';
  const ceremonyCookie = config.secure ? '__Host-hg_ceremony' : 'hg_ceremony';
  const setCookie = (res, name, value, seconds) => res.setHeader('set-cookie', `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${seconds}${config.secure ? '; Secure' : ''}`);
  const server = http.createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    const requestID = randomUUID();
    let outcome = 'internal_error';
    let releaseSlot, controller, proxySignal, abortOnClose, chargedBytes = 0;
    res.setHeader('x-request-id', requestID);
    res.setHeader('cache-control', 'no-store, private');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-robots-tag', 'noindex, nofollow, noarchive');
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (config.secure) res.setHeader('strict-transport-security', 'max-age=31536000');
    try {
      // Ignore forwarded headers: clients cannot choose the canonical host or their rate-limit identity.
      if (req.headers.host !== new URL(config.origin).host) throw new Denied(421, 'wrong_host');
      if (!req.url?.startsWith('/') || req.url.startsWith('//') || /[\\\x00-\x20]/.test(req.url)) throw new Denied(400, 'invalid_target');
      const url = new URL(req.url, config.origin);
      const ip = req.socket.remoteAddress ?? 'unknown';
      const ua = req.headers['user-agent'] ?? '';
      if (!store.limit(`all:${digest(ip)}`, 180)) throw new Denied(429, 'connection_rate');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new Denied(403, 'cross_site');
      if (url.pathname.startsWith(PREFIX)) {
        if (req.method === 'GET' && assets[url.pathname]) {
          outcome = 'gate_asset'; return send(res, 200, assets[url.pathname].body, assets[url.pathname].type);
        }
        if (req.method !== 'POST') throw new Denied(404, 'not_found');
        if (req.headers.origin !== config.origin) throw new Denied(403, 'origin_mismatch');
        if (!store.limit(`auth:${digest(ip)}`, 20)) throw new Denied(429, 'auth_rate');
        const body = await json(req);
        if (url.pathname === `${PREFIX}logout`) {
          store.logout(cookie(req, sessionCookie)); setCookie(res, sessionCookie, '', 0);
          outcome = 'logged_out'; return send(res, 200, { ok: true });
        }
        if (url.pathname.endsWith('/options')) {
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
          const id = store.challenge({ ...payload, challenge: options.challenge, ua: digest(ua) });
          setCookie(res, ceremonyCookie, id, 120); outcome = 'challenge_issued'; return send(res, 200, options);
        }
        if (![`${PREFIX}register/verify`, `${PREFIX}login/verify`].includes(url.pathname)) throw new Denied(404, 'not_found');
        const pending = store.takeChallenge(cookie(req, ceremonyCookie));
        if (!pending || pending.ua !== digest(ua)) throw new Denied(403, 'invalid_challenge');
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
        const session = store.session(credentialID, ua, config.sessionSeconds);
        setCookie(res, sessionCookie, session, config.sessionSeconds);
        outcome = 'verified'; return send(res, 200, { ok: true });
      }
      if (!['GET', 'HEAD'].includes(req.method)) throw new Denied(405, 'read_only_gateway');
      const session = cookie(req, sessionCookie);
      const admitted = session && store.admit(session, ua, config.pagesPerSession);
      if (!admitted) {
        outcome = 'admission_required';
        return send(res, 401, assets[`${PREFIX}index.html`].body, 'text/html; charset=utf-8');
      }
      if (!store.limit(`reader:${admitted.credential_id}`, config.requestsPerMinute)) throw new Denied(429, 'reader_rate');
      const credentialID = admitted.credential_id;
      const active = activeTransfers.get(credentialID) ?? 0;
      if (active >= config.maxConcurrentRequests) throw new Denied(429, 'parallel_limit', 1);
      activeTransfers.set(credentialID, active + 1);
      releaseSlot = () => {
        const remaining = activeTransfers.get(credentialID) - 1;
        if (remaining) activeTransfers.set(credentialID, remaining); else activeTransfers.delete(credentialID);
      };
      const restriction = store.beginResource(credentialID, url.pathname + url.search, config);
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
        headers: { accept: req.headers.accept ?? '*/*', 'user-agent': 'HumanGate/0.2', 'x-human-gate-user': credentialID },
      });
      if (upstream.status >= 300 && upstream.status < 400) { await upstream.body?.cancel(); throw new Denied(502, 'upstream_redirect_rejected'); }
      // No cookies, authorization, forwarding headers, cache validators, or untrusted response headers cross this boundary.
      res.statusCode = upstream.status;
      res.setHeader('content-type', upstream.headers.get('content-type') ?? 'application/octet-stream');
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
        const denied = store.chargeBytes(credentialID, chunk.length, config);
        if (denied) throw new Denied(denied.status ?? 429, denied.reason, denied.retryAfter);
        chargedBytes += chunk.length;
        if (!res.write(chunk)) await once(res, 'drain', { signal: proxySignal });
      }
      res.end(); await finished(res, { signal: proxySignal, cleanup: true });
    } catch (error) {
      const failure = error instanceof Denied ? error : proxySignal?.reason instanceof Denied ? proxySignal.reason
        : proxySignal?.reason?.name === 'TimeoutError' ? new Denied(504, 'upstream_timeout')
        : new Denied(controller ? 502 : 403, controller ? 'upstream_failure' : 'request_rejected');
      outcome = failure.message;
      if (res.headersSent || res.destroyed) { if (!res.headersSent) res.statusCode = failure.status; res.destroy(); return; }
      const status = failure.status;
      if (status === 429) res.setHeader('retry-after', String(failure.retryAfter));
      send(res, status, { error: outcome, requestID });
    } finally {
      if (abortOnClose) res.off('close', abortOnClose);
      controller?.abort();
      releaseSlot?.();
      // Close includes partial/aborted streams, which the old finish-only log missed.
      const record = () => audit({ at: new Date().toISOString(), requestID, status: res.statusCode, reason: outcome, completed: res.writableFinished, chargedBytes });
      if (res.destroyed || res.writableFinished) record(); else res.once('close', record);
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000;
  server.on('upgrade', (_, socket) => socket.destroy());
  const cleanup = setInterval(() => store.prune(), 60000); cleanup.unref();
  server.on('close', () => clearInterval(cleanup));
  return server;
}
