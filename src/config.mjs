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
  const humanCheck = env.HUMAN_CHECK ?? 'always';
  if (!['always', 'off'].includes(humanCheck)) throw new Error('Invalid HUMAN_CHECK');
  const verifiedCrawlers = (env.VERIFIED_CRAWLERS ?? Object.keys(CRAWLERS).join(',')).split(',').map(name => name.trim().toLowerCase()).filter(name => name && name !== 'off');
  for (const name of verifiedCrawlers) if (!CRAWLERS[name]) throw new Error(`Unknown VERIFIED_CRAWLERS entry ${name}`);
  const sandboxCheck = env.SANDBOX_CHECK ?? 'log';
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
    // Human check (public mode): every new visitor confirms once, then browses for humanPassSeconds.
    aiAgents, humanCheck, verifiedCrawlers,
    humanPassSeconds: integer(env, 'HUMAN_PASS_SECONDS', 86400, 300, 30 * 86400),
    humanPassesPerHour: integer(env, 'HUMAN_PASSES_PER_HOUR', 60, 1, 100000),
    humanPagesPerMinute: integer(env, 'HUMAN_PAGES_PER_MINUTE', 20, 1, 10000),
    // Sandbox signals (datacenter address, software GPU, missing devices) scored at the human check. `log` only records them.
    sandboxCheck, cloudRangesFile: resolve(env.CLOUD_RANGES_FILE ?? resolve(dataDir, 'cloud-ranges.txt')),
  };
}
