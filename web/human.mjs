// Human check: press and hold, while the page looks for signs that software is driving the browser.
const button = document.querySelector('#hold');
const label = button.querySelector('span');
const status = document.querySelector('#status');
const heading = document.querySelector('#human-heading');
// The stylesheet swaps the icon, colours and buttons for each state: loading, ready, holding, checking, done, error.
const panel = document.querySelector('.panel');
const setState = state => { panel.dataset.state = state; };

async function post(path, body) {
  const response = await fetch(`/_gate/human/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(result.error === 'sandbox_detected' ? 'This browser appears to be running on a server or in a virtual machine, not on a personal device. If you are browsing yourself, contact this website’s operator.'
      : result.error === 'automation_detected' ? 'This browser appears to be controlled by automation software or an AI agent, so it cannot continue. If you have developer tools open, close them and reload.'
      : result.error === 'human_check_limit' || response.status === 429 ? 'Too many checks from your network. Wait a while, then reload.'
      : result.error === 'human_check_failed' ? (pointer === 'keyboard' ? 'Hold the key down until the button fills, or move the pointer onto the button and hold it. Reload to try again.'
        : 'Move the pointer onto the button, then hold it until it fills. Reload to try again.')
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

let holdMs = 1500, started = 0, frame = 0, timer = 0, pressGap = -1, pointer = 'unknown', trusted = false, repeats = 0, solution, probe, last;
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
function fail(message) {
  setState('error'); heading.textContent = 'Check stopped'; status.textContent = message;
  button.disabled = true; button.style.setProperty('--fill', 0);
}
function begin(event, kind) {
  if (button.disabled || started) return;
  trusted = event.isTrusted; pointer = kind; repeats = 0; started = performance.now(); setState('holding');
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
  button.style.setProperty('--fill', 0); label.textContent = 'Press and hold'; setState('ready');
  status.textContent = 'Keep holding until the button fills.';
}
async function finish() {
  const held = performance.now() - started;
  cancelAnimationFrame(frame); button.style.setProperty('--fill', 1);
  started = 0; button.disabled = true; label.textContent = 'Checking…'; setState('checking');
  try {
    // The probe measures the browser at the end, so a client that attaches after the page loads is still seen.
    const [nonce, report] = await Promise.all([solution, probe.then(measure => measure.seal({ trusted, holdMs: Math.round(held), pointer, path, pressGap, repeats }))]);
    await post('verify', { nonce, report });
    setState('done'); heading.textContent = 'Verified'; label.textContent = 'Verified'; status.textContent = 'Opening the page…';
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
  // A key held down repeats; the gateway expects that on Windows.
  if (!event.repeat) begin(event, 'keyboard');
  else if (started && pointer === 'keyboard' && event.isTrusted) repeats++;
});
button.addEventListener('keyup', event => { if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); cancel(); } });
button.addEventListener('contextmenu', event => event.preventDefault());
document.querySelector('#retry').addEventListener('click', () => location.reload());

// Desktop Firefox keeps this page in its back/forward cache while it steps to the gate's hop page, and shows it again
// when the hop page goes back. Camoufox and Playwright's Firefox switch that cache off, so they load the page again,
// which the gateway refuses. Resolves to the hop's id once this page has come back (undefined: not made or not back).
const here = location.pathname + location.search;
const HOPPED = 'voight-hop';
function roundTrip() {
  const gecko = typeof navigator.buildID === 'string' || 'MozAppearance' in document.documentElement.style;
  if (!gecko || (/Android/.test(navigator.userAgent) && navigator.maxTouchPoints > 0)) return Promise.resolve(undefined);
  let left = null;
  try { left = JSON.parse(sessionStorage.getItem(HOPPED)); } catch {}
  const recent = left?.to === here && Date.now() - left.at < 15000 ? left.tries : 0;
  // Loaded again twice in a row instead of coming back: stop going round. The report then says the page did not return.
  if (recent >= 2) { try { sessionStorage.removeItem(HOPPED); } catch {} return Promise.resolve(undefined); }
  const id = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return new Promise(resolve => {
    addEventListener('pageshow', event => {
      if (!event.persisted) return;
      try { sessionStorage.removeItem(HOPPED); } catch {}
      resolve(id);
    });
    // After load and with nothing still loading: Firefox does not keep pages that are busy.
    const go = () => setTimeout(() => {
      status.textContent = 'Checking this browser…';
      try { sessionStorage.setItem(HOPPED, JSON.stringify({ to: here, at: Date.now(), tries: recent + 1 })); } catch {}
      location.assign(`/_gate/human/hop?id=${id}&to=${encodeURIComponent(here)}`);
    }, 50);
    if (document.readyState === 'complete') go(); else addEventListener('load', go, { once: true });
  });
}

(async () => {
  if (!crypto.subtle) throw new Error('This browser cannot run the check here. Try a current browser.');
  const hop = await roundTrip();
  const options = await post('options', { hop });
  holdMs = options.holdMs ?? holdMs;
  solution = work(options.challenge, options.difficulty);
  solution.catch(() => {});
  // This check's own measuring script: different names, numbers and report key every time.
  probe = import(`/_gate/human/probe.js?check=${encodeURIComponent(options.challenge)}`).then(module => module.default());
  await probe;
  button.disabled = false; setState('ready'); status.textContent = 'Ready.';
})().catch(error => fail(error.message));
