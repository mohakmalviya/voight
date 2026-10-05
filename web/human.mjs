// Human check: press and hold, while the page looks for signs that software is driving the browser.
const button = document.querySelector('#hold');
const label = button.querySelector('span');
const status = document.querySelector('#status');
const heading = document.querySelector('#human-heading');

const AUTOMATION_GLOBALS = ['__playwright__binding__', '__pwInitScripts', '_selenium', 'callSelenium', '__webdriver_evaluate',
  '__selenium_evaluate', '__nightmare', 'domAutomation', 'domAutomationController', 'callPhantom', '_phantom'];
const automationGlobals = () => AUTOMATION_GLOBALS.some(name => name in window)
  || Object.keys(document).some(key => key.startsWith('$cdc_') || key.startsWith('cdc_'));

async function post(path, body) {
  const response = await fetch(`/_gate/human/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(result.error === 'sandbox_detected' ? 'This browser appears to be running on a server or in a virtual machine, not on a personal device. If you are browsing yourself, contact this website’s operator.'
      : result.error === 'automation_detected' ? 'This browser appears to be controlled by automation software or an AI agent, so it cannot continue.'
      : result.error === 'human_check_limit' || response.status === 429 ? 'Too many checks from your network. Wait a while, then reload.'
      : result.error === 'human_check_failed' ? 'Move the pointer onto the button, then hold it until it fills. Reload to try again.'
      : 'The check could not be completed. Reload the page to try again.');
  }
  return result;
}

function zeroBits(bytes) {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) { bits += 8; continue; }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}
async function work(challenge, difficulty) {
  const encoder = new TextEncoder();
  for (let nonce = 0; ; nonce++) {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`${challenge}:${nonce}`)));
    if (zeroBits(hash) >= difficulty) return String(nonce);
  }
}

let holdMs = 1500, started = 0, frame = 0, timer = 0, pressGap = -1, pointer = 'unknown', trusted = false, solution, last;
// The last steps the pointer took. People move in uneven curves; scripted pointers jump or move in identical steps.
const path = [];
addEventListener('pointermove', event => {
  if (!event.isTrusted || started) return;
  // Browsers re-send the current position after layout changes; only real movement counts.
  if (last && event.clientX === last.clientX && event.clientY === last.clientY) return;
  if (last) path.push([+(event.clientX - last.clientX).toFixed(2), +(event.clientY - last.clientY).toFixed(2), Math.round(event.timeStamp - last.timeStamp)]);
  if (path.length > 64) path.shift();
  last = event;
}, { passive: true });
// Headless browsers have no window frame, no plugins and say so in their brand list.
const browserShape = () => ({
  frame: [outerWidth - innerWidth, outerHeight - innerHeight], plugins: navigator.plugins?.length ?? -1,
  brands: navigator.userAgentData?.brands?.map(entry => entry.brand).join('|') ?? '',
});

// What kind of machine this is. Cloud browsers have no graphics card, sound devices, voices or taskbar,
// and often run Linux under a Windows user agent. The server weighs these; none decides alone.
const sha = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
async function graphics() {
  const gl = document.createElement('canvas').getContext('webgl', { preserveDrawingBuffer: true });
  if (!gl) return { webgl: false };
  const info = gl.getExtension('WEBGL_debug_renderer_info');
  const gpu = String(gl.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : gl.RENDERER) ?? '');
  const glNative = /\[native code\]/.test(Function.prototype.toString.call(WebGLRenderingContext.prototype.getParameter));
  // A fixed scene whose exact pixels depend on the renderer. The server knows what software rendering draws.
  gl.canvas.width = gl.canvas.height = 64; gl.viewport(0, 0, 64, 64);
  const shader = (type, source) => { const s = gl.createShader(type); gl.shaderSource(s, source); gl.compileShader(s); return s; };
  const program = gl.createProgram();
  gl.attachShader(program, shader(gl.VERTEX_SHADER, 'attribute vec2 p;varying vec2 v;void main(){v=p;gl_Position=vec4(p,0.,1.);}'));
  gl.attachShader(program, shader(gl.FRAGMENT_SHADER, 'precision mediump float;varying vec2 v;void main(){float a=sin(v.x*37.1)*cos(v.y*23.7)+fract(sin(dot(v,vec2(12.9898,78.233)))*43758.5453);gl_FragColor=vec4(fract(a*7.),v*.5+.5,1.);}'));
  gl.linkProgram(program); gl.useProgram(program);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -.2, 1, .9, .8]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  const pixels = new Uint8Array(64 * 64 * 4); gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
  return { webgl: true, gpu: gpu.slice(0, 300), glNative, render: await sha(pixels) };
}
// Fonts every Windows or Mac install has (kept in step with PROBE_FONTS on the server).
const FONTS = ['Segoe UI', 'Calibri', 'Consolas', 'Helvetica Neue', 'Menlo', 'Avenir'];
function fonts() {
  const context = document.createElement('canvas').getContext('2d');
  const width = font => { context.font = `72px ${font}`; return context.measureText('mmmmmmmmmmlli1WQ@#').width; };
  const generic = ['monospace', 'serif', 'sans-serif'];
  const base = generic.map(width);
  return FONTS.filter(font => generic.some((fallback, i) => width(`"${font}", ${fallback}`) !== base[i]));
}
// Voices load asynchronously; give them a moment.
const voices = () => new Promise(resolve => {
  if (!window.speechSynthesis) return resolve(-1);
  const local = () => speechSynthesis.getVoices().filter(voice => voice.localService).length;
  if (local()) return resolve(local());
  speechSynthesis.addEventListener('voiceschanged', () => resolve(local()), { once: true });
  setTimeout(() => resolve(local()), 1200);
});
async function environment() {
  const settle = (promise, fallback) => promise.catch(() => fallback);
  const [gl, voiceCount, devices] = await Promise.all([settle(graphics(), {}), settle(voices(), -1),
    settle(navigator.mediaDevices?.enumerateDevices() ?? Promise.reject(), null)]);
  let found = null; try { found = fonts(); } catch {}
  return { ...gl, fonts: found, voices: voiceCount, media: devices ? devices.length : -1, touch: navigator.maxTouchPoints ?? 0,
    screen: [screen.width, screen.height, screen.availWidth, screen.availHeight], tz: Intl.DateTimeFormat().resolvedOptions().timeZone ?? '' };
}
const machine = environment().catch(() => ({}));

function fail(message) {
  heading.textContent = 'Check stopped.'; status.textContent = message;
  button.disabled = true; button.style.setProperty('--fill', 0);
}
function begin(event, kind) {
  if (button.disabled || started) return;
  trusted = event.isTrusted; pointer = kind; started = performance.now();
  label.textContent = 'Keep holding…'; status.textContent = '';
  // Animation frames only draw the fill; they pause in covered windows, so a timer completes the hold.
  const tick = () => {
    button.style.setProperty('--fill', Math.min(1, (performance.now() - started) / holdMs));
    frame = requestAnimationFrame(tick);
  };
  frame = requestAnimationFrame(tick);
  timer = setTimeout(finish, holdMs);
}
function cancel() {
  if (!started) return;
  cancelAnimationFrame(frame); clearTimeout(timer); started = 0;
  button.style.setProperty('--fill', 0); label.textContent = 'Press and hold';
  status.textContent = 'Keep holding until the button fills.';
}
async function finish() {
  const held = performance.now() - started;
  cancelAnimationFrame(frame); button.style.setProperty('--fill', 1);
  started = 0; button.disabled = true; label.textContent = 'Checking…';
  try {
    const [nonce, env] = await Promise.all([solution, machine]);
    await post('verify', { nonce, signals: { webdriver: navigator.webdriver === true, automationGlobals: automationGlobals(), trusted, holdMs: Math.round(held), pointer, path, pressGap, ...browserShape(), env } });
    heading.textContent = 'Thanks.'; status.textContent = 'Opening the page…';
    location.reload();
  } catch (error) { fail(error.message); }
}

button.addEventListener('pointerdown', event => {
  // A real press lands where the pointer last moved. A pointer that teleports onto the button does not.
  pressGap = last ? Math.round(Math.hypot(event.clientX - last.clientX, event.clientY - last.clientY)) : -1;
  button.setPointerCapture?.(event.pointerId);
  begin(event, event.pointerType || 'mouse');
});
for (const name of ['pointerup', 'pointercancel', 'lostpointercapture']) button.addEventListener(name, cancel);
button.addEventListener('keydown', event => {
  if (event.key !== ' ' && event.key !== 'Enter') return;
  event.preventDefault();
  if (!event.repeat) begin(event, 'keyboard');
});
button.addEventListener('keyup', event => { if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); cancel(); } });
button.addEventListener('contextmenu', event => event.preventDefault());

(async () => {
  if (!crypto.subtle) throw new Error('This browser cannot run the check here. Try a current browser.');
  const options = await post('options', {});
  holdMs = options.holdMs ?? holdMs;
  solution = work(options.challenge, options.difficulty);
  solution.catch(() => {});
  button.disabled = false; status.textContent = 'Ready.';
})().catch(error => fail(error.message));
