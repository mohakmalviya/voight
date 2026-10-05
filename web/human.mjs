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
    throw new Error(result.error === 'automation_detected' ? 'This browser appears to be controlled by automation software or an AI agent, so it cannot continue.'
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
    const nonce = await solution;
    await post('verify', { nonce, signals: { webdriver: navigator.webdriver === true, automationGlobals: automationGlobals(), trusted, holdMs: Math.round(held), pointer, path, pressGap, ...browserShape() } });
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
