import { isIP } from 'node:net';

// Addresses are compared as integers so CIDR checks need no string tricks.
function strip(text) {
  const value = String(text ?? '').trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) return bracketed[1];
  const v4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(value);
  return (v4WithPort ? v4WithPort[1] : value).split('%')[0];
}
function v6Value(text) {
  if (text.includes('.')) {
    const at = text.lastIndexOf(':');
    const [a, b, c, d] = text.slice(at + 1).split('.').map(Number);
    text = `${text.slice(0, at + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail === undefined ? null : tail ? tail.split(':') : [];
  const groups = right === null ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.reduce((total, group) => (total << 16n) | BigInt(parseInt(group, 16)), 0n);
}

export function parseAddress(text) {
  const value = strip(text);
  const version = isIP(value);
  if (version === 4) return { version: 4, value: value.split('.').reduce((total, octet) => (total << 8n) | BigInt(octet), 0n) };
  if (version !== 6) return null;
  const parsed = v6Value(value);
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) is the same client as a.b.c.d.
  if (parsed >> 32n === 0xffffn) return { version: 4, value: parsed & 0xffffffffn };
  return { version: 6, value: parsed };
}

export function formatAddress({ version, value }) {
  if (version === 4) return [24n, 16n, 8n, 0n].map(shift => String((value >> shift) & 255n)).join('.');
  return Array.from({ length: 8 }, (_, i) => ((value >> BigInt((7 - i) * 16)) & 0xffffn).toString(16)).join(':');
}

export function parseCIDR(text) {
  const [address, length, extra] = String(text).trim().split('/');
  const parsed = parseAddress(address);
  const bits = parsed?.version === 4 ? 32 : 128;
  const prefix = length === undefined ? bits : Number(length);
  if (!parsed || extra !== undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > bits || (length !== undefined && !/^\d+$/.test(length))) {
    throw new Error(`Invalid TRUSTED_PROXIES entry: ${text}`);
  }
  return { ...parsed, prefix };
}

export function inRanges(address, ranges) {
  return ranges.some(range => {
    if (range.version !== address.version) return false;
    const shift = BigInt((address.version === 4 ? 32 : 128) - range.prefix);
    return address.value >> shift === range.value >> shift;
  });
}

// Walk X-Forwarded-For from the right, skipping only proxies the operator trusts.
// Anything left of the first untrusted hop was written by the client and is ignored.
export function clientAddress(peer, forwarded, trusted = []) {
  let current = parseAddress(peer);
  if (!current) return 'unknown';
  if (!trusted.length || !inRanges(current, trusted)) return formatAddress(current);
  const hops = String(forwarded ?? '').split(',').map(hop => hop.trim()).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = parseAddress(hops[i]);
    if (!hop) break;
    current = hop;
    if (!inRanges(hop, trusted)) break;
  }
  return formatAddress(current);
}

// One IPv6 subscriber usually controls a whole /64, so budgets and bans apply to it as a unit.
export function networkPrefix(address) {
  const parsed = parseAddress(address);
  if (!parsed) return 'unknown';
  if (parsed.version === 4) return formatAddress(parsed);
  return `${formatAddress({ version: 6, value: (parsed.value >> 64n) << 64n }).split(':').slice(0, 4).join(':')}::/64`;
}
