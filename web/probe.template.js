// The part of the human check that measures the browser. src/scramble.mjs turns this into a different script for
// every check: $S('…') strings move into an encoded table, $_names get random names, $N(a,b) becomes a random number,
// and the report is encrypted with a key that exists only in that one script. Nothing here can be found or patched by
// name, and a rewritten report fails its checksum. It does not make forgery impossible, only specific to each check.
const $_g = globalThis;
const $_doc = $_g[$S('document')], $_nav = $_g[$S('navigator')], $_con = $_g[$S('console')], $_perf = $_g[$S('performance')];
const $_debug = $_con[$S('debug')], $_clear = $_con[$S('clear')], $_nowFn = $_perf[$S('now')], $_fetch = $_g[$S('fetch')];
const $_now = () => $_nowFn[$S('call')]($_perf);

// A fresh frame lends a second realm: its Error objects slip past hooks that test `instanceof Error`, and its
// Function.prototype.toString shows whether this page's functions were replaced.
const $_frame = $_doc[$S('createElement')]($S('iframe'));
$_frame[$S('style')][$S('display')] = $S('none');
$_doc[$S('documentElement')][$S('appendChild')]($_frame);
const $_realm = $_frame[$S('contentWindow')];
const $_source = $_realm[$S('Function')][$S('prototype')][$S('toString')];
const $_native = $_fn => { try { return $_source[$S('call')]($_fn)[$S('includes')]($S('[native code]')); } catch { return false; } };

// Logging Errors costs several times what logging numbers does when a DevTools client is attached (see DEVTOOLS_RATIO).
function $_inspector() {
  if (!$_nav[$S('userAgentData')]) return null;
  const $_error = new $_realm[$S('Error')]($S('check'));
  const $_errors = [$_error, $_error, $_error, $_error], $_numbers = [$N(0, 9), $N(10, 99), $N(100, 999), $N(1000, 9999)];
  const $_time = $_values => { const $_start = $_now(); for (let $_i = 0; $_i < $N(90, 130); $_i++) $_debug[$S('apply')]($_con, $_values); return $_now() - $_start; };
  const $_ratios = [];
  for (let $_round = 0; $_round < 7; $_round++) { const $_plain = $_time($_numbers); $_ratios.push($_time($_errors) / Math.max($_plain, 0.05)); }
  $_clear[$S('call')]($_con);
  return +$_ratios.sort(($_a, $_b) => $_a - $_b)[3].toFixed(2);
}
// A real console reads a logged Error's name and message, attached or not. A hook that swaps the arguments does not.
const $_touched = $_Error => {
  const $_reads = [], $_error = new $_Error($S('check'));
  for (const $_key of [$S('name'), $S('message')]) { const $_value = $_error[$_key]; Object.defineProperty($_error, $_key, { get() { $_reads.push($_key); return $_value; }, configurable: true }); }
  $_debug[$S('apply')]($_con, [$_error]);
  return $_reads.length > 0;
};
// Mouse moves, and how many of them carried Chromium's predictions of where the pointer goes next (see
// PREDICTED_MIN_MOVES on the server). Counted here, inside this check's own script, from the moment it loads.
const $_pointerProto = $_g[$S('PointerEvent')]?.[$S('prototype')];
const $_predict = $_pointerProto?.[$S('getPredictedEvents')];
const $_input = [0, 0], $_points = [], $_lags = [];
let $_lastMove = null;
$_g[$S('addEventListener')]($S('pointermove'), $_event => {
  if (!$_event[$S('isTrusted')] || $_event[$S('pointerType')] !== $S('mouse')) return;
  const $_at = $_event[$S('clientX')] + ',' + $_event[$S('clientY')];
  if ($_at === $_lastMove) return; // Browsers re-send the position after layout changes.
  $_lastMove = $_at; $_input[0]++;
  // Where on the screen, for the pixel-grid check (pixelGridShare on the server).
  $_points.push([$_event[$S('screenX')], $_event[$S('screenY')]]); if ($_points.length > 64) $_points.shift();
  // How long after its own time stamp the move reached this handler (EVENT_TIME_MIN_MOVES on the server).
  $_lags.push(+($_now() - $_event[$S('timeStamp')]).toFixed(1)); if ($_lags.length > 64) $_lags.shift();
  try { if ($_predict && $_predict[$S('call')]($_event)[$S('length')] > 0) $_input[1]++; } catch {}
}, { capture: true, passive: true });

// Replaced console or timer functions, swapped after this script loaded or rewritten to look native.
const $_hooked = () => $_con[$S('debug')] !== $_debug || $_perf[$S('now')] !== $_nowFn || $_g[$S('fetch')] !== $_fetch
  || ($_predict && $_pointerProto[$S('getPredictedEvents')] !== $_predict)
  || ![$_debug, $_clear, $_nowFn, $_fetch, $_g[$S('Function')][$S('prototype')][$S('toString')], ...($_predict ? [$_predict] : [])].every($_native);

const $_globals = () => [$S('__playwright__binding__'), $S('__pwInitScripts'), $S('_selenium'), $S('callSelenium'), $S('__webdriver_evaluate'),
  $S('__selenium_evaluate'), $S('__nightmare'), $S('domAutomation'), $S('domAutomationController'), $S('callPhantom'), $S('_phantom')].some($_name => $_name in $_g)
  || Object.keys($_doc).some($_key => $_key.startsWith($S('$cdc_')) || $_key.startsWith($S('cdc_')));

// The smallest step performance.now() takes: 1 ms or less, unless the browser coarsens its clock (resistFingerprinting
// does), which hides the move timing above.
const $_clockStep = () => {
  const $_limit = Date.now() + 250; let $_last = $_now(), $_step = Infinity;
  for (let $_steps = 0; $_steps < 4 && Date.now() < $_limit;) {
    const $_time = $_now(); if ($_time === $_last) continue;
    if ($_steps++) $_step = Math.min($_step, $_time - $_last); // The first change only lines up with the clock.
    $_last = $_time;
  }
  return Number.isFinite($_step) ? +$_step.toFixed(3) : null;
};

// Which engine runs the page, whatever the user agent says: Firefox keeps navigator.buildID and -moz- styles, Chromium
// has userAgentData or window.chrome.
const $_engine = () => typeof $_nav[$S('buildID')] === $S('string') || $S('MozAppearance') in $_doc[$S('documentElement')][$S('style')] ? $S('gecko')
  : $_nav[$S('userAgentData')] || $_g[$S('chrome')] ? $S('chromium') : $S('other');

// What kind of machine this is (weighed by sandboxReport on the server).
const $_sha = async $_bytes => [...new Uint8Array(await $_g[$S('crypto')][$S('subtle')][$S('digest')]($S('SHA-256'), $_bytes))].slice(0, 8).map($_b => $_b.toString(16).padStart(2, '0')).join('');
async function $_graphics() {
  const $_gl = $_doc[$S('createElement')]($S('canvas'))[$S('getContext')]($S('webgl'), { preserveDrawingBuffer: true });
  if (!$_gl) return { [$S('webgl')]: false };
  const $_info = $_gl[$S('getExtension')]($S('WEBGL_debug_renderer_info'));
  const $_gpu = String($_gl[$S('getParameter')]($_info ? $_info[$S('UNMASKED_RENDERER_WEBGL')] : $_gl[$S('RENDERER')]) ?? '');
  const $_glNative = $_native($_g[$S('WebGLRenderingContext')][$S('prototype')][$S('getParameter')]);
  $_gl.canvas.width = $_gl.canvas.height = 64; $_gl.viewport(0, 0, 64, 64);
  const $_shader = ($_type, $_text) => { const $_s = $_gl.createShader($_type); $_gl.shaderSource($_s, $_text); $_gl.compileShader($_s); return $_s; };
  const $_program = $_gl.createProgram();
  $_gl.attachShader($_program, $_shader($_gl.VERTEX_SHADER, 'attribute vec2 p;varying vec2 v;void main(){v=p;gl_Position=vec4(p,0.,1.);}'));
  $_gl.attachShader($_program, $_shader($_gl.FRAGMENT_SHADER, 'precision mediump float;varying vec2 v;void main(){float a=sin(v.x*37.1)*cos(v.y*23.7)+fract(sin(dot(v,vec2(12.9898,78.233)))*43758.5453);gl_FragColor=vec4(fract(a*7.),v*.5+.5,1.);}'));
  $_gl.linkProgram($_program); $_gl.useProgram($_program);
  $_gl.bindBuffer($_gl.ARRAY_BUFFER, $_gl.createBuffer());
  $_gl.bufferData($_gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -.2, 1, .9, .8]), $_gl.STATIC_DRAW);
  $_gl.enableVertexAttribArray(0); $_gl.vertexAttribPointer(0, 2, $_gl.FLOAT, false, 0, 0);
  $_gl.drawArrays($_gl.TRIANGLE_STRIP, 0, 4);
  const $_pixels = new Uint8Array(64 * 64 * 4); $_gl.readPixels(0, 0, 64, 64, $_gl.RGBA, $_gl.UNSIGNED_BYTE, $_pixels);
  return { [$S('webgl')]: true, [$S('gpu')]: $_gpu.slice(0, 300), [$S('glNative')]: $_glNative, [$S('render')]: await $_sha($_pixels) };
}
// Fonts every Windows or Mac install has (kept in step with PROBE_FONTS on the server).
function $_fonts() {
  const $_context = $_doc[$S('createElement')]($S('canvas'))[$S('getContext')]('2d');
  const $_width = $_font => { $_context.font = `72px ${$_font}`; return $_context.measureText('mmmmmmmmmmlli1WQ@#').width; };
  const $_generic = ['monospace', 'serif', 'sans-serif'];
  const $_base = $_generic.map($_width);
  return [$S('Segoe UI'), $S('Calibri'), $S('Consolas'), $S('Helvetica Neue'), $S('Menlo'), $S('Avenir')]
    .filter($_font => $_generic.some(($_fallback, $_i) => $_width(`"${$_font}", ${$_fallback}`) !== $_base[$_i]));
}
const $_voices = () => new Promise($_resolve => {
  const $_speech = $_g[$S('speechSynthesis')];
  if (!$_speech) return $_resolve(-1);
  const $_local = () => $_speech[$S('getVoices')]().filter($_v => $_v.localService).length;
  if ($_local()) return $_resolve($_local());
  $_speech.addEventListener('voiceschanged', () => $_resolve($_local()), { once: true });
  setTimeout(() => $_resolve($_local()), 1200);
});
async function $_environment() {
  const $_settle = ($_promise, $_fallback) => $_promise.catch(() => $_fallback);
  const $_media = $_nav[$S('mediaDevices')];
  const [$_gl, $_voiceCount, $_devices] = await Promise.all([$_settle($_graphics(), {}), $_settle($_voices(), -1),
    $_settle($_media ? $_media[$S('enumerateDevices')]() : Promise.reject(), null)]);
  let $_found = null; try { $_found = $_fonts(); } catch {}
  const $_screen = $_g[$S('screen')];
  return { ...$_gl, [$S('fonts')]: $_found, [$S('voices')]: $_voiceCount, [$S('media')]: $_devices ? $_devices.length : -1, [$S('touch')]: $_nav[$S('maxTouchPoints')] ?? 0,
    [$S('screen')]: [$_screen.width, $_screen.height, $_screen.availWidth, $_screen.availHeight], [$S('tz')]: Intl.DateTimeFormat().resolvedOptions().timeZone ?? '' };
}

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

// The same timing from a worker (probe-worker.template.js), sealed there with its own key. Page-level hooks such as
// Playwright's init scripts do not run in workers, but an attached DevTools client still listens to them.
const $_workerTiming = () => new Promise($_resolve => {
  try {
    const $_worker = new $_g[$S('Worker')]($S('/_gate/human/probe-worker.js'));
    $_worker.addEventListener($S('message'), $_event => { $_resolve(typeof $_event.data === 'string' ? $_event.data : null); $_worker.terminate(); }, { once: true });
    $_worker.addEventListener($S('error'), () => $_resolve(null), { once: true });
    setTimeout(() => $_resolve(null), 4000);
  } catch { $_resolve(null); }
});

// A DevTools client that intercepts requests (patchright always does; Playwright and Puppeteer when a script routes
// them) holds every request from the page until it answers, cache hits included. Shared workers are outside its reach,
// and extensions that watch requests see both alike. So: the same cached byte, fetched 8 times in a row from the page
// and from a shared worker (web/shared.js), 6 rounds, fastest of each (see INTERCEPTION_RATIO on the server).
async function $_fetchTiming() {
  const $_Shared = $_g[$S('SharedWorker')];
  if (!$_Shared || !$_nav[$S('userAgentData')]) return null;
  const $_url = new URL($S('/_gate/human/cached?') + $N(100000, 999999), $_g[$S('location')][$S('href')])[$S('href')];
  const $_one = async () => { await (await $_fetch[$S('call')]($_g, $_url, { [$S('cache')]: $S('force-cache') }))[$S('arrayBuffer')](); };
  const $_cached = $_count => $_perf[$S('getEntriesByName')]($_url).slice(-$_count).every($_entry => $_entry[$S('transferSize')] === 0);
  await $_one(); await $_one();
  if (!$_cached(1)) return null; // The cache is off (an open DevTools can do that): nothing to compare.
  const $_port = new $_Shared($S('/_gate/shared.js'))[$S('port')];
  const $_ask = $_count => new Promise($_resolve => { $_port[$S('onmessage')] = $_event => $_resolve($_event.data); $_port[$S('postMessage')]([$_url, $_count]); setTimeout(() => $_resolve(null), 3000); });
  try {
    if (typeof await $_ask(1) !== 'number') return null;
    const $_page = [], $_shared = [];
    for (let $_round = 0; $_round < 6; $_round++) {
      const $_start = $_now(); for (let $_i = 0; $_i < 8; $_i++) await $_one(); $_page.push($_now() - $_start);
      const $_took = await $_ask(8); if (typeof $_took !== 'number') return null; $_shared.push($_took);
    }
    return $_cached(8) ? [+Math.min(...$_page).toFixed(2), +Math.min(...$_shared).toFixed(2), 8] : null;
  } finally { $_port[$S('close')](); }
}

// Starts measuring the machine at once (voices take a moment). `seal` adds the gesture and the final checks.
export default function $_start() {
  const $_machine = $_environment().catch(() => ({}));
  const $_worker = $_nav[$S('userAgentData')] ? $_workerTiming() : Promise.resolve(null);
  // After the rest, so nothing else competes with the timing.
  const $_fetches = Promise.all([$_machine, $_worker]).then($_fetchTiming).catch(() => null);
  return {
    async seal($_gesture) {
      const [$_env, $_workerReport, $_fetched] = await Promise.all([$_machine, $_worker, $_fetches]);
      let $_ratio = null, $_touch = null; try { if ($_nav[$S('userAgentData')]) $_touch = $_touched($_realm[$S('Error')]); $_ratio = $_inspector(); } catch {}
      const $_brands = $_nav[$S('userAgentData')]?.[$S('brands')]?.map($_entry => $_entry.brand).join('|') ?? '';
      return $_seal({ ...$_gesture,
        [$S('webdriver')]: $_nav[$S('webdriver')] === true, [$S('automationGlobals')]: $_globals(), [$S('hooked')]: $_hooked(), [$S('devtools')]: $_ratio, [$S('worker')]: $_workerReport, [$S('touched')]: $_touch,
        [$S('frame')]: [$_g.outerWidth - $_g.innerWidth, $_g.outerHeight - $_g.innerHeight], [$S('plugins')]: $_nav[$S('plugins')]?.length ?? -1,
        [$S('brands')]: $_brands, [$S('engine')]: $_engine(), [$S('input')]: [...$_input], [$S('points')]: [...$_points], [$S('dpr')]: $_g[$S('devicePixelRatio')], [$S('heights')]: [$_g.outerHeight, $_g.innerHeight], [$S('fetches')]: $_fetched,
        [$S('lags')]: [...$_lags], [$S('clock')]: $_clockStep(), [$S('env')]: $_env });
    },
  };
}
