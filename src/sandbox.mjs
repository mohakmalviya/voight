import { readFile } from 'node:fs/promises';
import { parseAddress, parseCIDR } from './network.mjs';
import { unbrandedChromium } from './automation.mjs';

// Cloud agents and scraping farms run browsers on servers: a datacenter address, no graphics card, no sound card,
// no screen. None of these prove anything alone (VPNs and virtual desktops share some of them), so they add up to a score.

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

// Software renderers stand in for a missing GPU. Hypervisor adapters are what virtual machines show.
const SOFTWARE_GPU = /SwiftShader|llvmpipe|softpipe|lavapipe|Basic Render|OSMesa|Mesa OffScreen/i;
const VIRTUAL_GPU = /VMware|VirtualBox|Parallels|QEMU|virgl|virtio|Hyper-V|Red Hat/i;
// What the check page's test scene looks like through SwiftShader, Chrome's software renderer (field-measured).
// A browser that names a real GPU but draws exactly this has had its GPU name faked.
export const SOFTWARE_RENDER_HASHES = new Set(['6cf4933af807630f']);
// Fonts that ship with the operating system and cannot be uninstalled.
const SYSTEM_FONTS = { windows: ['Segoe UI', 'Calibri', 'Consolas'], mac: ['Helvetica Neue', 'Menlo', 'Avenir'] };
export const PROBE_FONTS = [...SYSTEM_FONTS.windows, ...SYSTEM_FONTS.mac];
const WEIGHTS = { datacenter: 2, unbranded_browser: 3, software_gpu: 2, gpu_spoofed: 3, os_mismatch: 2, virtual_gpu: 1, no_webgl: 1, no_voices: 1, no_media_devices: 1, bare_screen: 1, utc_clock: 1 };
export const SANDBOX_BLOCK_SCORE = 4;
export const SANDBOX_STRICT_SCORE = 2;

function desktopOS(userAgent, touch) {
  if (/Android|iPhone|iPad|Mobile/.test(userAgent)) return null;
  if (/Windows NT/.test(userAgent)) return 'windows';
  // iPads ask for desktop sites with a Mac user agent; they have touch points, Macs do not.
  if (/Macintosh/.test(userAgent)) return touch > 0 ? null : 'mac';
  if (/Linux|X11|CrOS/.test(userAgent)) return 'linux';
  return null;
}

// `env` is what the check page reports. Everything in it is client-controlled, so malformed values are ignored.
// `brands` is the brand list the check page reported, joined with `|`.
export function sandboxReport(env, userAgent = '', { datacenter = false, brands = '' } = {}) {
  const value = env && typeof env === 'object' && !Array.isArray(env) ? env : {};
  const text = (field, max = 300) => (typeof value[field] === 'string' ? value[field].slice(0, max) : null);
  const count = field => (Number.isSafeInteger(value[field]) && value[field] >= 0 ? value[field] : null);
  const found = [];
  if (datacenter) found.push('datacenter');
  const os = desktopOS(userAgent, count('touch') ?? 0);
  // Playwright's own Chromium on a Windows or Mac desktop, where people run Chrome, Edge, Brave or Opera.
  if ((os === 'windows' || os === 'mac') && typeof brands === 'string' && unbrandedChromium(brands.slice(0, 300).split('|'))) found.push('unbranded_browser');
  const gpu = text('gpu');
  if (value.webgl === false) found.push('no_webgl');
  else if (gpu) {
    if (SOFTWARE_GPU.test(gpu)) found.push('software_gpu');
    else if (VIRTUAL_GPU.test(gpu)) found.push('virtual_gpu');
    // A patched WebGL getter, or a real GPU name over software-rendered pixels, means the name was faked.
    if (value.glNative === false || (!SOFTWARE_GPU.test(gpu) && SOFTWARE_RENDER_HASHES.has(text('render', 64)))) found.push('gpu_spoofed');
  }
  const fonts = Array.isArray(value.fonts) ? value.fonts.filter(font => typeof font === 'string') : null;
  if (fonts && SYSTEM_FONTS[os] && !SYSTEM_FONTS[os].some(font => fonts.includes(font))) found.push('os_mismatch');
  // Windows and macOS always ship local speech voices; Linux often has none, so it is not judged.
  if ((os === 'windows' || os === 'mac') && count('voices') === 0) found.push('no_voices');
  if (count('media') === 0) found.push('no_media_devices');
  // A desktop always loses some screen to a taskbar, dock or menu bar. Virtual displays have none.
  const screen = Array.isArray(value.screen) && value.screen.length === 4 && value.screen.every(Number.isFinite) ? value.screen : null;
  if (os && screen && screen[0] === screen[2] && screen[1] === screen[3]) found.push('bare_screen');
  if (['UTC', 'Etc/UTC', 'Etc/GMT', 'GMT', 'Etc/Unknown'].includes(text('tz', 64))) found.push('utc_clock');
  const score = found.reduce((total, flag) => total + WEIGHTS[flag], 0);
  return { score, found, notes: [...found, `sandbox:${score}`] };
}
