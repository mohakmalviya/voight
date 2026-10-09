import { resolve } from 'node:path';
import { parseCIDR } from './network.mjs';
import { CRAWLERS } from './agents.mjs';

function integer(env, name, fallback, min, max) {
  const value = Number(env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${name}`);
  return value;
}

// Public mode serves anonymous visitors, so its budgets must fit a real person reading a real site.
// Private mode keeps the tighter limits that suit a small set of invited readers.
const DEFAULTS = {
  public: { requests: 300, resources: 1000, bytes: 200 * 1024 * 1024, concurrent: 16, connections: 600 },
  private: { requests: 30, resources: 60, bytes: 20 * 1024 * 1024, concurrent: 4, connections: 180 },
};

export function configFromEnv(env = process.env) {
  const mode = env.MODE ?? 'public';
  if (!['public', 'private'].includes(mode)) throw new Error('Invalid MODE');
  const defaults = DEFAULTS[mode];
  const automationPolicy = env.AUTOMATION_POLICY ?? 'observe';
  if (!['off', 'observe', 'enforce'].includes(automationPolicy)) throw new Error('Invalid AUTOMATION_POLICY');
  const aiAgents = env.AI_AGENTS ?? 'block';
  if (!['block', 'allow'].includes(aiAgents)) throw new Error('Invalid AI_AGENTS');
  const humanCheck = env.HUMAN_CHECK ?? 'suspicious';
  if (!['suspicious', 'always', 'off'].includes(humanCheck)) throw new Error('Invalid HUMAN_CHECK');
  // A path ending in * opens everything under it. Machine-read files (robots.txt, the favicon, /.well-known/ files such as
  // security.txt) stay readable by default.
  const openPaths = (env.OPEN_PATHS ?? '/robots.txt,/favicon.ico,/.well-known/*').split(',').map(path => path.trim()).filter(Boolean);
  for (const path of openPaths) if (!/^\/[^?#\s*]*\*?$/.test(path)) throw new Error(`Invalid OPEN_PATHS entry ${path}`);
  const honeypot = env.HONEYPOT ?? 'block';
  if (!['block', 'log', 'off'].includes(honeypot)) throw new Error('Invalid HONEYPOT');
  const openGraph = env.OPEN_GRAPH ?? 'off';
  if (!['on', 'off'].includes(openGraph)) throw new Error('Invalid OPEN_GRAPH');
  const contact = env.CONTACT ?? '';
  if (contact && !/^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(contact) && !/^https:\/\/[^\s<>"']+$/.test(contact)) throw new Error('CONTACT must be an email address or an https:// link');
  const verifiedCrawlers = (env.VERIFIED_CRAWLERS ?? Object.keys(CRAWLERS).join(',')).split(',').map(name => name.trim().toLowerCase()).filter(name => name && name !== 'off');
  for (const name of verifiedCrawlers) if (!CRAWLERS[name]) throw new Error(`Unknown VERIFIED_CRAWLERS entry ${name}`);
  const sandboxCheck = env.SANDBOX_CHECK ?? 'enforce';
  if (!['off', 'log', 'enforce'].includes(sandboxCheck)) throw new Error('Invalid SANDBOX_CHECK');
  const dataDir = resolve(env.DATA_DIR ?? './data');
  const origin = new URL(env.PUBLIC_ORIGIN ?? 'http://localhost:8787');
  if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('PUBLIC_ORIGIN must be an origin');
  if (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && origin.hostname === 'localhost')) throw new Error('Use HTTPS outside localhost');
  const upstream = new URL(env.UPSTREAM ?? 'http://127.0.0.1:8788');
  if (!['http:', 'https:'].includes(upstream.protocol) || upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname !== '/') throw new Error('UPSTREAM must be an HTTP(S) origin');
  if (origin.origin === upstream.origin) throw new Error('UPSTREAM cannot point to this gateway');
  const banSeconds = integer(env, 'BAN_SECONDS', 300, 10, 86400);
  return {
    mode, automationPolicy,
    origin: origin.origin, rpID: origin.hostname, upstream: upstream.origin,
    host: env.HOST ?? '127.0.0.1', port: integer(env, 'PORT', 8787, 1, 65535),
    dataDir, secure: origin.protocol === 'https:',
    trustedProxies: (env.TRUSTED_PROXIES ?? '').split(',').map(entry => entry.trim()).filter(Boolean).map(parseCIDR),
    connectionsPerMinute: integer(env, 'CONNECTIONS_PER_MINUTE', defaults.connections, 1, 100000),
    sessionSeconds: integer(env, 'SESSION_SECONDS', 300, 15, 3600),
    requestsPerMinute: integer(env, 'REQUESTS_PER_MINUTE', defaults.requests, 1, 100000),
    pagesPerSession: integer(env, 'PAGES_PER_SESSION', 60, 1, 10000),
    extractionWindowSeconds: integer(env, 'EXTRACTION_WINDOW_SECONDS', 600, 60, 3600),
    bytesPerWindow: integer(env, 'BYTES_PER_WINDOW', defaults.bytes, 1, 16 * 1024 * 1024 * 1024),
    resourcesPerWindow: integer(env, 'RESOURCES_PER_WINDOW', defaults.resources, 1, 100000),
    maxConcurrentRequests: integer(env, 'MAX_CONCURRENT_REQUESTS', defaults.concurrent, 1, 256),
    maxResponseBytes: integer(env, 'MAX_RESPONSE_BYTES', 5 * 1024 * 1024, 1, 32 * 1024 * 1024),
    // Escalation (public mode): budget denials a network may ignore before a timed block.
    strikesPerWindow: integer(env, 'STRIKES_PER_WINDOW', 30, 1, 10000),
    strikeWindowSeconds: integer(env, 'STRIKE_WINDOW_SECONDS', 600, 60, 86400),
    banSeconds, maxBanSeconds: integer(env, 'MAX_BAN_SECONDS', 86400, banSeconds, 30 * 86400),
    challengeDifficulty: integer(env, 'CHALLENGE_DIFFICULTY', 16, 1, 28),
    clearancesPerWindow: integer(env, 'CLEARANCES_PER_WINDOW', 5, 0, 100),
    clearanceSeconds: integer(env, 'CLEARANCE_SECONDS', 3600, 60, 86400),
    // Human check (public mode): visitors who look automated (or everyone, with `always`) confirm once,
    // then browse for humanPassSeconds. Open paths skip it, for robots.txt, feeds and the like.
    aiAgents, humanCheck, verifiedCrawlers, openPaths,
    humanPassSeconds: integer(env, 'HUMAN_PASS_SECONDS', 21600, 300, 30 * 86400),
    humanPagesPerPass: integer(env, 'HUMAN_PAGES_PER_PASS', 300, 1, 1000000),
    humanPassesPerHour: integer(env, 'HUMAN_PASSES_PER_HOUR', 60, 1, 100000),
    humanPagesPerMinute: integer(env, 'HUMAN_PAGES_PER_MINUTE', 20, 1, 10000),
    // Server traits (a datacenter address, and whatever the rules add) scored at the human check. `log` only records them;
    // `enforce` refuses a score of 4 or more and shortens passes at 2 or 3.
    sandboxCheck, cloudRangesFile: resolve(env.CLOUD_RANGES_FILE ?? resolve(dataDir, 'cloud-ranges.txt')),
    // Operator rules (see policy.mjs), loaded at start. A hidden link in every gate page that only tools follow: `block`
    // blocks that network, `log` only records it. Link-preview tags for chat apps, cached for OPEN_GRAPH_SECONDS.
    policyFile: env.POLICY_FILE ? resolve(env.POLICY_FILE) : null, policy: [], honeypot,
    openGraph: openGraph === 'on', openGraphSeconds: integer(env, 'OPEN_GRAPH_SECONDS', 86400, 60, 7 * 86400),
    // Shown on gate pages so a person who was refused can reach the operator. Prometheus counters on loopback.
    contact, metricsPort: env.METRICS_PORT ? integer(env, 'METRICS_PORT', 0, 1, 65535) : null,
  };
}
