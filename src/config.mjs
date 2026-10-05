import { resolve } from 'node:path';

function integer(env, name, fallback, min, max) {
  const value = Number(env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`Invalid ${name}`);
  return value;
}

export function configFromEnv(env = process.env) {
  const automationPolicy = env.AUTOMATION_POLICY ?? 'observe';
  if (!['off', 'observe', 'enforce'].includes(automationPolicy)) throw new Error('Invalid AUTOMATION_POLICY');
  const origin = new URL(env.PUBLIC_ORIGIN ?? 'http://localhost:8787');
  if (origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('PUBLIC_ORIGIN must be an origin');
  if (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && origin.hostname === 'localhost')) throw new Error('Use HTTPS outside localhost');
  const upstream = new URL(env.UPSTREAM ?? 'http://127.0.0.1:8788');
  if (!['http:', 'https:'].includes(upstream.protocol) || upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname !== '/') throw new Error('UPSTREAM must be an HTTP(S) origin');
  if (origin.origin === upstream.origin) throw new Error('UPSTREAM cannot point to this gateway');
  return {
    automationPolicy,
    origin: origin.origin, rpID: origin.hostname, upstream: upstream.origin,
    host: env.HOST ?? '127.0.0.1', port: integer(env, 'PORT', 8787, 1, 65535),
    dataDir: resolve(env.DATA_DIR ?? './data'), secure: origin.protocol === 'https:',
    sessionSeconds: integer(env, 'SESSION_SECONDS', 300, 15, 3600),
    requestsPerMinute: integer(env, 'REQUESTS_PER_MINUTE', 30, 1, 1000),
    pagesPerSession: integer(env, 'PAGES_PER_SESSION', 60, 1, 10000),
    extractionWindowSeconds: integer(env, 'EXTRACTION_WINDOW_SECONDS', 600, 60, 3600),
    bytesPerWindow: integer(env, 'BYTES_PER_WINDOW', 20 * 1024 * 1024, 1, 1024 * 1024 * 1024),
    resourcesPerWindow: integer(env, 'RESOURCES_PER_WINDOW', 60, 1, 10000),
    maxConcurrentRequests: integer(env, 'MAX_CONCURRENT_REQUESTS', 4, 1, 32),
    maxResponseBytes: integer(env, 'MAX_RESPONSE_BYTES', 5 * 1024 * 1024, 1, 32 * 1024 * 1024),
  };
}
