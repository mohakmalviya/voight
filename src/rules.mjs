import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as basic from './basic.mjs';

// The detection rules the gateway runs. This repository ships basic ones (basic.mjs). Production rules live in a private
// pack, because published rules are easy to tune a bot against: a folder whose index.mjs has the same exports as
// basic.mjs, named by RULES_DIR or found at rules/ in the app folder. A pack replaces the basic rules entirely.
const EXPORTS = ['probe', 'assets', 'humanReport', 'headerAnomaly', 'sandboxReport', 'SANDBOX_BLOCK_SCORE', 'SANDBOX_STRICT_SCORE'];
const DEFAULT_DIR = fileURLToPath(new URL('../rules/', import.meta.url));

export { basic };

export async function loadRules(dir = process.env.RULES_DIR || '') {
  const index = resolve(dir || DEFAULT_DIR, 'index.mjs');
  if (!existsSync(index)) {
    // A folder the operator named must be there; the default one is optional.
    if (dir) throw new Error(`RULES_DIR has no index.mjs: ${index}`);
    return basic;
  }
  const pack = await import(pathToFileURL(index).href);
  const missing = EXPORTS.filter(name => !(name in pack));
  if (missing.length) throw new Error(`The rules pack at ${index} does not export ${missing.join(', ')}`);
  return pack;
}

export const rules = await loadRules();
