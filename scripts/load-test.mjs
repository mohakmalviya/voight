// Loopback load test: a stand-in origin, the real gateway (one process, SQLite on disk, decision log on), and simulated visitors.
// Visitors come from the 198.18.0.0/15 benchmarking range through X-Forwarded-For, each with its own address.
// Usage: npm run load-test [-- seconds per run]. ONLY=people|bots and CONNS=n narrow it; PROFILE_DIR=dir writes a CPU profile of the gateway.
import http from 'node:http';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const self = fileURLToPath(import.meta.url);
const role = process.argv[2];
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const PAGE = Buffer.from(`<!doctype html><title>Origin</title>${'<p>Real site content. '.repeat(1500)}`); // ~33 KB, like a portfolio page
const address = i => `198.${18 + (i >> 16)}.${(i >> 8) & 255}.${i & 255}`;

if (role === 'origin') {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': PAGE.length, 'cache-control': 'public, max-age=60' });
    res.end(PAGE);
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  process.send({ port: server.address().port });
} else if (role === 'gateway') {
  const { start } = await import('../src/main.mjs');
  const server = await start();
  process.send({ ready: true });
  process.on('message', message => {
    if (message === 'stats') process.send({ cpu: process.cpuUsage(), rss: process.memoryUsage().rss });
    if (message === 'stop') { server.close(); server.closeAllConnections(); setTimeout(() => process.exit(0), 200); }
  });
} else if (role === 'client') {
  process.on('message', async ({ port, connections, seconds, visitors, kind, worker, workers }) => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: connections });
    const latencies = [], statuses = {};
    let bytes = 0, next = worker;
    const errors = {};
    const end = performance.now() + seconds * 1000;
    const one = () => new Promise(resolve => {
      const v = visitors[(next += workers) % visitors.length];
      const started = performance.now();
      const req = http.request({ host: '127.0.0.1', port, path: `/page-${next % 200}`, agent, headers: {
        host: `localhost:${port}`, 'user-agent': UA, accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-US,en;q=0.9',
        'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none', 'sec-fetch-user': '?1',
        'x-forwarded-for': v.ip, ...(v.cookie && kind !== 'bots' ? { cookie: v.cookie } : {}),
      } }, res => {
        res.on('data', chunk => { bytes += chunk.length; });
        res.on('end', () => { statuses[res.statusCode] = (statuses[res.statusCode] ?? 0) + 1; latencies.push(performance.now() - started); resolve(); });
      });
      req.on('error', error => { errors[error.code] = (errors[error.code] ?? 0) + 1; resolve(); });
      req.end();
    });
    await Promise.all(Array.from({ length: connections }, async () => { while (performance.now() < end) await one(); }));
    agent.destroy();
    process.send({ latencies, statuses, bytes, errors });
    process.exit(0);
  });
} else {
  const seconds = Number(process.argv[2] ?? 10);
  const dataDir = await mkdtemp(join(process.env.LOAD_TEST_DIR ?? tmpdir(), 'voight-load-'));
  const VISITORS = 40000;

  // Passes are written straight into the test store, as the check would after a press-and-hold.
  const { Store } = await import('../src/store.mjs');
  const store = new Store(join(dataDir, 'gate.sqlite'));
  const visitors = [];
  store.db.exec('BEGIN');
  for (let i = 0; i < VISITORS; i++) visitors.push({ ip: address(i), cookie: `hg_human=${store.pass(UA, 21600)}` });
  store.db.exec('COMMIT');
  store.close();

  const origin = fork(self, ['origin']);
  const [{ port: originPort }] = await once(origin, 'message');
  const gateway = fork(self, ['gateway'], {
    execArgv: process.env.PROFILE_DIR ? ['--cpu-prof', `--cpu-prof-dir=${process.env.PROFILE_DIR}`] : [],
    stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
    env: { ...process.env, DATA_DIR: dataDir, UPSTREAM: `http://127.0.0.1:${originPort}`, PORT: '8799', PUBLIC_ORIGIN: 'http://localhost:8799',
      TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'always', OPEN_GRAPH: 'on', SANDBOX_CHECK: 'off' },
  });
  await once(gateway, 'message');
  const stats = () => new Promise(resolve => { gateway.once('message', resolve); gateway.send('stats'); });

  function errorText(results) {
    const errors = {};
    for (const r of results) for (const [code, n] of Object.entries(r.errors)) errors[code] = (errors[code] ?? 0) + n;
    return Object.keys(errors).length ? ` errors ${JSON.stringify(errors)}` : '';
  }
  async function run(label, port, kind, connections) {
    const workers = Math.min(8, connections);
    const before = port === 8799 ? await stats() : null;
    const started = performance.now();
    const results = await Promise.all(Array.from({ length: workers }, (_, worker) => {
      const child = fork(self, ['client']);
      child.send({ port, connections: Math.ceil(connections / workers), seconds, visitors, kind, worker, workers });
      return once(child, 'message').then(([result]) => result);
    }));
    const elapsed = (performance.now() - started) / 1000;
    const after = port === 8799 ? await stats() : null;
    const latencies = results.flatMap(r => r.latencies).sort((a, b) => a - b);
    const statuses = {};
    for (const r of results) for (const [code, n] of Object.entries(r.statuses)) statuses[code] = (statuses[code] ?? 0) + n;
    const pct = p => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))]?.toFixed(1);
    const cpu = after ? ((after.cpu.user + after.cpu.system - before.cpu.user - before.cpu.system) / 1e6 / elapsed * 100).toFixed(0) + '%' : '-';
    console.log(`${label.padEnd(34)} conns ${String(connections).padStart(4)}  ${String(Math.round(latencies.length / elapsed)).padStart(6)} req/s  p50 ${pct(0.5)} ms  p99 ${pct(0.99)} ms  ` +
      `gateway CPU ${cpu}  RSS ${after ? Math.round(after.rss / 2 ** 20) + ' MB' : '-'}  ${JSON.stringify(statuses)}${errorText(results)}`);
  }

  console.log(`${seconds} s per run, ${VISITORS} visitors with passes, Node ${process.version}\n`);
  if (!process.env.ONLY) await run('origin alone (no gateway)', originPort, 'people', 128);
  const only = process.env.ONLY;
  if (!only || only === 'people') for (const c of (process.env.CONNS ? [Number(process.env.CONNS)] : [32, 128])) await run('people with a pass -> site', 8799, 'people', c);
  if (!only || only === 'bots') for (const c of [128]) await run('bots without a pass -> check page', 8799, 'bots', c);

  gateway.send('stop'); origin.kill();
  await once(gateway, 'exit');
  await rm(dataDir, { recursive: true, force: true });
}
