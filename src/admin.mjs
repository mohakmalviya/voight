import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { configFromEnv } from './config.mjs';
import { Store } from './store.mjs';

const config = configFromEnv();
mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
const store = new Store(join(config.dataDir, 'gate.sqlite'));
try {
  const [command, argument] = process.argv.slice(2);
  if (command === 'invite' && argument && argument.length <= 100) {
    console.log(`One-time invitation for ${argument} (expires in 1 hour):\n${store.invite(argument)}\nShare privately. Paste into the gate; do not put it in a URL.`);
  } else if (command === 'list') console.table(store.list());
  else if (command === 'usage') console.table(store.usage());
  else if (command === 'revoke' && argument) { store.revoke(argument); console.log('Credential and sessions revoked.'); }
  else { console.error('Usage: npm run admin -- invite <label> | list | usage | revoke <credential-id>'); process.exitCode = 1; }
} finally { store.close(); }
