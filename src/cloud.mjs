import { readFile } from 'node:fs/promises';
import { parseAddress, parseCIDR } from './network.mjs';

// Addresses that cloud providers publish for their servers (`npm run cloud-ranges` downloads them). The detection rules
// count a visitor on one as a datacenter visitor.

// Address ranges as sorted, merged [start, end] pairs per IP version, searched by bisection.
export function cloudRanges(lines) {
  const spans = { 4: [], 6: [] };
  for (const raw of lines) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    let range;
    try { range = parseCIDR(line); } catch { throw new Error(`Invalid cloud range: ${line}`); }
    const bits = BigInt(range.version === 4 ? 32 : 128) - BigInt(range.prefix);
    const start = (range.value >> bits) << bits;
    spans[range.version].push([start, start + (1n << bits) - 1n]);
  }
  for (const version of [4, 6]) {
    spans[version].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const merged = [];
    for (const span of spans[version]) {
      const last = merged.at(-1);
      if (last && span[0] <= last[1] + 1n) { if (span[1] > last[1]) last[1] = span[1]; } else merged.push([...span]);
    }
    spans[version] = merged;
  }
  return {
    size: spans[4].length + spans[6].length,
    has(text) {
      const address = parseAddress(text);
      if (!address) return false;
      const list = spans[address.version];
      let low = 0, high = list.length - 1;
      while (low <= high) {
        const mid = (low + high) >> 1;
        if (address.value < list[mid][0]) high = mid - 1;
        else if (address.value > list[mid][1]) low = mid + 1;
        else return true;
      }
      return false;
    },
  };
}

// A missing file just means the datacenter signal is unavailable. `npm run cloud-ranges` writes it.
export async function loadCloudRanges(file) {
  try { return cloudRanges((await readFile(file, 'utf8')).split('\n')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
