import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createStats } from '../src/stats.mjs';

// Summarises human checks from the decision log, read from a file or standard input:
//   journalctl -u voight -o cat --since -7d | npm run stats --silent
const stats = createStats();
const input = process.argv[2] ? createReadStream(process.argv[2]) : process.stdin;
for await (const line of createInterface({ input, crlfDelay: Infinity })) {
  if (!line.startsWith('{')) continue;
  try { stats.add(JSON.parse(line)); } catch {}
}
console.log(stats.render());
