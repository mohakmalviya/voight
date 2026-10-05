import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { configFromEnv } from './config.mjs';
import { Store } from './store.mjs';
import { createGateway } from './gateway.mjs';

export async function loadAssets() {
  const assets = {};
  for (const [file, type] of [['index.html', 'text/html; charset=utf-8'], ['style.css', 'text/css; charset=utf-8'], ['client.js', 'text/javascript; charset=utf-8']]) {
    assets[`/_gate/${file}`] = { body: await readFile(new URL(`../dist/${file}`, import.meta.url)), type };
  }
  return assets;
}

export async function start(config = configFromEnv()) {
  await mkdir(config.dataDir, { recursive: true, mode: 0o700 });
  const assets = await loadAssets();
  const store = new Store(join(config.dataDir, 'gate.sqlite'));
  const server = createGateway({ config, store, assets });
  server.once('close', () => store.close());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.port, config.host, resolve); });
  console.log(`Human Gate listening at ${config.origin}`);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = await start();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { server.close(); server.closeIdleConnections(); });
}
