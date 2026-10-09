// The part of the human check that measures the browser, in its basic form. src/scramble.mjs turns this into a different
// script for every check: $S('…') strings move into an encoded table, $_names get random names, $N(a,b) becomes a random
// number, and the report is encrypted with a key that exists only in that one script. A rewritten report fails its
// checksum. It does not make forgery impossible, only specific to each check. A rules pack brings its own script.
const $_g = globalThis;
const $_nav = $_g[$S('navigator')];

// The report, encrypted with this script's key: SHA-256(key ‖ block) keystream, then a SHA-256 checksum.
async function $_seal($_report) {
  const $_subtle = $_g[$S('crypto')][$S('subtle')];
  const $_key = Uint8Array.from($S('@KEY@').match(/../g), $_h => parseInt($_h, 16));
  const $_plain = new TextEncoder().encode(JSON.stringify($_report));
  const $_out = new Uint8Array($_plain.length);
  for (let $_block = 0; $_block * 32 < $_plain.length; $_block++) {
    const $_input = new Uint8Array(36); $_input.set($_key); new DataView($_input.buffer).setUint32(32, $_block);
    const $_stream = new Uint8Array(await $_subtle[$S('digest')]($S('SHA-256'), $_input));
    for (let $_i = 0; $_i < 32 && $_block * 32 + $_i < $_plain.length; $_i++) $_out[$_block * 32 + $_i] = $_plain[$_block * 32 + $_i] ^ $_stream[$_i];
  }
  const $_check = new Uint8Array(33 + $_out.length); $_check.set($_key); $_check[32] = 255; $_check.set($_out, 33);
  const $_sum = new Uint8Array(await $_subtle[$S('digest')]($S('SHA-256'), $_check)).slice(0, 16);
  const $_text = $_bytes => { let $_s = ''; for (const $_b of $_bytes) $_s += String.fromCharCode($_b); return btoa($_s); };
  return `${$_text($_out)}.${$_text($_sum)}`;
}

// `seal` adds the gesture the page saw to what this script measures, and encrypts the lot.
export default function $_start() {
  return {
    async seal($_gesture) {
      const $_brands = $_nav[$S('userAgentData')]?.[$S('brands')]?.map($_entry => $_entry.brand).join('|') ?? '';
      return $_seal({ ...$_gesture, [$S('webdriver')]: $_nav[$S('webdriver')] === true,
        [$S('frame')]: [$_g.outerWidth - $_g.innerWidth, $_g.outerHeight - $_g.innerHeight], [$S('plugins')]: $_nav[$S('plugins')]?.length ?? -1,
        [$S('brands')]: $_brands, [$S('env')]: { [$S('touch')]: $_nav[$S('maxTouchPoints')] ?? 0 } });
    },
  };
}
