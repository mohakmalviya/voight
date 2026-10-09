import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { configFromEnv } from './config.mjs';
import { Store } from './store.mjs';
import { createGateway } from './gateway.mjs';
import { loadCloudRanges } from './cloud.mjs';
import { rules, basic } from './rules.mjs';
import { loadPolicy } from './policy.mjs';
import { createMetrics, metricsServer } from './metrics.mjs';

export async function loadAssets(pack = rules) {
  const assets = {};
  for (const [file, type] of [['index.html', 'text/html; charset=utf-8'], ['style.css', 'text/css; charset=utf-8'], ['client.js', 'text/javascript; charset=utf-8'], ['challenge.js', 'text/javascript; charset=utf-8'], ['human.js', 'text/javascript; charset=utf-8'], ['hop.js', 'text/javascript; charset=utf-8']]) {
    assets[`/_gate/${file}`] = { body: await readFile(new URL(`../dist/${file}`, import.meta.url)), type };
  }
  // Files the detection rules need served, as { file or body, type, cache }.
  for (const [path, { file, body, type, cache }] of Object.entries(pack.assets ?? {})) assets[`/_gate/${path}`] = { body: file ? await readFile(file) : body, type, cache };
  return assets;
}

export async function start(config = configFromEnv()) {
  await mkdir(config.dataDir, { recursive: true, mode: 0o700 });
  const assets = await loadAssets();
  const store = new Store(join(config.dataDir, 'gate.sqlite'));
  const cloud = config.sandboxCheck === 'off' ? null : await loadCloudRanges(config.cloudRangesFile);
  if (config.sandboxCheck !== 'off' && !cloud) console.warn(`No cloud ranges at ${config.cloudRangesFile}; run npm run cloud-ranges to score datacenter addresses.`);
  if (config.policyFile) config.policy = await loadPolicy(config.policyFile);
  const metrics = config.metricsPort ? createMetrics() : null;
  const audit = event => { metrics?.record(event); console.log(JSON.stringify(event)); };
  const server = createGateway({ config, store, assets, cloud, audit });
  const monitor = metrics && metricsServer(metrics);
  server.once('close', () => { store.close(); monitor?.close(); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.port, config.host, resolve); });
  if (monitor) await new Promise((resolve, reject) => { monitor.once('error', reject); monitor.listen(config.metricsPort, '127.0.0.1', resolve); });
  console.log(`Voight (${config.mode} mode) listening at ${config.origin}, ${rules === basic ? 'basic' : 'private'} detection rules${config.policy.length ? `, ${config.policy.length} policy rules` : ''}${monitor ? `, metrics at http://127.0.0.1:${config.metricsPort}/metrics` : ''}`);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await start();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { server.close(); server.closeIdleConnections(); });
}
