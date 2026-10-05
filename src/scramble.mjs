import { readFileSync } from 'node:fs';
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

// Every human check gets its own copy of web/probe.template.js. A client that rewrites the report, or patches the
// script by name, has to work out a different script each time. This raises the cost of forging; it cannot prevent it,
// because the key travels inside the script.
const template = file => readFileSync(new URL(`../web/${file}`, import.meta.url), 'utf8').replace(/^\s*\/\/.*$/gm, '').replace(/\n{2,}/g, '\n');
const PAGE = template('probe.template.js'), WORKER = template('probe-worker.template.js');
const LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

function names() {
  const used = new Set();
  return () => {
    for (;;) {
      let name = LETTERS[randomInt(LETTERS.length)];
      for (let i = randomInt(2, 5); i > 0; i--) name += (LETTERS + '0123456789_')[randomInt(63)];
      if (!used.has(name) && !/^(do|if|in|for|let|new|try|var|case|else|enum|eval|null|this|true|void|with|break|catch|class|const|false|super|throw|while|yield|delete|export|import|public|return|static|switch|typeof|default|extends|finally|package|private|continue|debugger|function|arguments|interface|protected|implements|instanceof|async|await|of)$/.test(name)) { used.add(name); return name; }
    }
  };
}
const shuffle = list => { for (let i = list.length - 1; i > 0; i--) { const j = randomInt(i + 1); [list[i], list[j]] = [list[j], list[i]]; } return list; };

// Returns the page and worker scripts for one check, each with the key that opens its report.
export function scrambledProbe() {
  const page = scramble(PAGE), worker = scramble(WORKER);
  return { source: page.source, key: page.key, workerSource: worker.source, workerKey: worker.key };
}

function scramble(TEMPLATE) {
  const key = randomBytes(32).toString('hex');
  const fresh = names();
  let source = TEMPLATE.replace("$S('@KEY@')", `$S('${key}')`)
    .replace(/\$N\((\d+), (\d+)\)/g, (_, low, high) => String(randomInt(Number(low), Number(high) + 1)));
  // Strings move into a table of XOR-encoded byte arrays, in random order, decoded by index.
  const strings = [...new Set([...source.matchAll(/\$S\('([^'\\]*)'\)/g)].map(match => match[1]))];
  const order = shuffle(strings.map((_, i) => i));
  const mask = [...randomBytes(randomInt(5, 12))];
  const slot = new Map(strings.map((text, i) => [text, order[i]]));
  const table = [];
  for (const [text, index] of slot) table[index] = [...Buffer.from(text, 'utf8')].map((byte, i) => byte ^ mask[(i + index) % mask.length]);
  const [decode, data, maskName, cache] = [fresh(), fresh(), fresh(), fresh()];
  source = source.replace(/\$S\('([^'\\]*)'\)/g, (_, text) => `${decode}(${slot.get(text)})`);
  const identifiers = new Map();
  source = source.replace(/\$_\w+/g, name => { if (!identifiers.has(name)) identifiers.set(name, fresh()); return identifiers.get(name); });
  const prelude = `const ${data}=${JSON.stringify(table)},${maskName}=${JSON.stringify(mask)},${cache}=[];`
    + `const ${decode}=i=>${cache}[i]??=new TextDecoder().decode(Uint8Array.from(${data}[i],(b,j)=>b^${maskName}[(j+i)%${maskName}.length]));`;
  return { source: prelude + source, key };
}

const stream = (key, length) => {
  const out = Buffer.alloc(length);
  for (let block = 0; block * 32 < length; block++) {
    const input = Buffer.alloc(36); key.copy(input); input.writeUInt32BE(block, 32);
    createHash('sha256').update(input).digest().copy(out, block * 32, 0, Math.min(32, length - block * 32));
  }
  return out;
};
const checksum = (key, cipher) => createHash('sha256').update(Buffer.concat([key, Buffer.from([255]), cipher])).digest().subarray(0, 16);

// The same encryption the script performs. Used by tests and by anyone verifying the format.
export function sealReport(report, keyHex) {
  const key = Buffer.from(keyHex, 'hex'), plain = Buffer.from(JSON.stringify(report)), pad = stream(key, plain.length);
  const cipher = Buffer.from(plain.map((byte, i) => byte ^ pad[i]));
  return `${cipher.toString('base64')}.${checksum(key, cipher).toString('base64')}`;
}

// Returns the report as an object, or null if it is malformed, altered or sealed with another check's key.
export function openReport(text, keyHex) {
  if (typeof text !== 'string' || text.length > 65536 || typeof keyHex !== 'string' || !/^[0-9a-f]{64}$/.test(keyHex)) return null;
  const [body, sum, extra] = text.split('.');
  if (extra !== undefined || !body || !sum) return null;
  const key = Buffer.from(keyHex, 'hex'), cipher = Buffer.from(body, 'base64'), given = Buffer.from(sum, 'base64');
  if (given.length !== 16 || !timingSafeEqual(given, checksum(key, cipher))) return null;
  const pad = stream(key, cipher.length);
  try {
    const report = JSON.parse(Buffer.from(cipher.map((byte, i) => byte ^ pad[i])).toString('utf8'));
    return report && typeof report === 'object' && !Array.isArray(report) ? report : null;
  } catch { return null; }
}
