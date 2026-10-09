// Downloads the address ranges cloud providers publish for their servers and writes one CIDR per line.
// Run it on deploy and then weekly; providers add ranges often. Usage: npm run cloud-ranges [-- output-file]
// Azure is left out on purpose: Windows 365 and Azure Virtual Desktop put real people on Azure addresses.
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { cloudRanges } from '../src/cloud.mjs';

const SOURCES = {
  aws: ['https://ip-ranges.amazonaws.com/ip-ranges.json', body => {
    const data = JSON.parse(body);
    return [...data.prefixes.map(p => p.ip_prefix), ...data.ipv6_prefixes.map(p => p.ipv6_prefix)];
  }],
  google_cloud: ['https://www.gstatic.com/ipranges/cloud.json', body => JSON.parse(body).prefixes.map(p => p.ipv4Prefix ?? p.ipv6Prefix)],
  oracle: ['https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', body => JSON.parse(body).regions.flatMap(r => r.cidrs.map(c => c.cidr))],
  digitalocean: ['https://digitalocean.com/geo/google.csv', body => body.split('\n').map(line => line.split(',')[0])],
  linode: ['https://geoip.linode.com/', body => body.split('\n').filter(line => !line.startsWith('#')).map(line => line.split(',')[0])],
};

const output = resolve(process.argv[2] ?? join(process.env.DATA_DIR ?? './data', 'cloud-ranges.txt'));
const lines = [`# Cloud provider server ranges, fetched ${new Date().toISOString()}`];
let failed = 0;
for (const [name, [url, parse]] of Object.entries(SOURCES)) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const ranges = parse(await response.text()).map(range => String(range ?? '').trim()).filter(Boolean);
    cloudRanges(ranges); // Throws on anything malformed, so a changed format never writes a broken file.
    lines.push(`# ${name}: ${ranges.length}`, ...ranges);
    console.log(`${name}: ${ranges.length} ranges`);
  } catch (error) { failed++; console.error(`${name}: ${error.message}`); }
}
if (failed === Object.keys(SOURCES).length) throw new Error('No provider list could be fetched; the existing file was kept');
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${lines.join('\n')}\n`);
console.log(`Wrote ${output} (${cloudRanges(lines).size} merged ranges)`);
