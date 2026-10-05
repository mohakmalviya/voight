// The DevTools timing again, inside a worker. Page init scripts (Playwright's addInitScript and the like) do not run
// in workers, but an attached DevTools client still listens to them, so a console hooked in the page is no cover here.
// Scrambled per check like probe.template.js, with its own key.
const $_g = globalThis;
const $_con = $_g[$S('console')], $_perf = $_g[$S('performance')];
const $_debug = $_con[$S('debug')], $_nowFn = $_perf[$S('now')];
const $_now = () => $_nowFn[$S('call')]($_perf);
// A real console reads a logged Error's name and message, attached or not. A hook that swaps the arguments does not.
const $_touched = $_Error => {
  const $_reads = [], $_error = new $_Error($S('check'));
  for (const $_key of [$S('name'), $S('message')]) { const $_value = $_error[$_key]; Object.defineProperty($_error, $_key, { get() { $_reads.push($_key); return $_value; }, configurable: true }); }
  $_debug[$S('apply')]($_con, [$_error]);
  return $_reads.length > 0;
};
function $_inspector() {
  const $_error = new $_g[$S('Error')]($S('check'));
  const $_errors = [$_error, $_error, $_error, $_error], $_numbers = [$N(0, 9), $N(10, 99), $N(100, 999), $N(1000, 9999)];
  const $_time = $_values => { const $_start = $_now(); for (let $_i = 0; $_i < $N(400, 520); $_i++) $_debug[$S('apply')]($_con, $_values); return $_now() - $_start; };
  const $_ratios = [];
  for (let $_round = 0; $_round < 7; $_round++) { const $_plain = $_time($_numbers); $_ratios.push($_time($_errors) / Math.max($_plain, 0.05)); }
  return +$_ratios.sort(($_a, $_b) => $_a - $_b)[3].toFixed(2);
}
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
let $_ratio = null, $_touch = null; try { $_touch = $_touched($_g[$S('Error')]); $_ratio = $_inspector(); } catch {}
$_seal({ [$S('devtools')]: $_ratio, [$S('touched')]: $_touch }).then($_sealed => $_g[$S('postMessage')]($_sealed));
