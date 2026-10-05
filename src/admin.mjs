import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { configFromEnv } from './config.mjs';
import { Store } from './store.mjs';
import { networkPrefix, parseAddress } from './network.mjs';

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
  else if (command === 'bans') console.table(store.bans());
  // Bans are stored by keyed hash, so the operator names the address and we hash it the same way.
  else if (command === 'unban' && parseAddress(argument)) {
    const prefix = networkPrefix(argument);
    console.log(store.unban(store.pseudonym(prefix)) ? `Unblocked ${prefix}.` : `No active record for ${prefix}.`);
  } else {
    console.error('Usage: npm run admin -- invite <label> | list | usage | revoke <credential-id> | bans | unban <ip-address>');
    process.exitCode = 1;
  }
} finally { store.close(); }
