// Human check: press and hold, while the rules' measuring script looks at the browser.
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
    // The gateway never says which rule refused a check, so the advice is the same whatever happened.
    throw new Error(result.error === 'human_check_limit' || response.status === 429 ? 'Too many checks from your network. Wait a while, then reload.'
      : result.error === 'human_check_failed' ? (pointer === 'keyboard' ? 'The check did not pass. Hold the key down until the button fills, or move the pointer onto the button and hold it. Reload to try again.'
        : 'The check did not pass. Move the pointer onto the button, then hold it until it fills. Reload to try again. If it keeps failing, try another browser.')
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
// The check's one-time ticket lasts 120 s on the server. An open page swaps it for a fresh one at 90 s.
const TICKET_MS = 120000, RENEW_MS = 90000;
// When the ticket was issued, the planned swap, a swap in flight, and whether the ticket ran out (the computer slept,
// or the page sat open past the gateway's limit) so the next visit starts a new check.
let ticket = 0, renewal = 0, renewing = null, stale = false, checking = false, restarting = false;
// The last steps the pointer took before the press.
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
  // A ticket that would run out before the hold ends: get a new check instead.
  if (stale || Date.now() - ticket > TICKET_MS - holdMs - 5000) { restart(); return; }
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
  checking = true; clearTimeout(renewal);
  try {
    // A swap that was already on its way finishes first, so the answer goes with the ticket the gateway now holds.
    await renewing;
    if (stale) throw new Error('The check could not be completed. Reload the page to try again.');
    const [nonce, report] = await Promise.all([solution, probe.then(measure => measure.seal({ trusted, holdMs: Math.round(held), pointer, path, pressGap, repeats }))]);
    await post('verify', { nonce, report });
    setState('done'); heading.textContent = 'Verified'; label.textContent = 'Verified'; status.textContent = 'Opening the page…';
    location.reload();
  } catch (error) { fail(error.message); }
}

button.addEventListener('pointerdown', event => {
  pressGap = last ? Math.round(Math.hypot(event.clientX - last.clientX, event.clientY - last.clientY)) : -1;
  button.setPointerCapture?.(event.pointerId);
  begin(event, event.pointerType || 'mouse');
});
for (const name of ['pointerup', 'pointercancel', 'lostpointercapture']) button.addEventListener(name, cancel);
button.addEventListener('keydown', event => {
  if (event.key !== ' ' && event.key !== 'Enter') return;
  event.preventDefault();
  if (!event.repeat) begin(event, 'keyboard');
  else if (started && pointer === 'keyboard' && event.isTrusted) repeats++;
});
button.addEventListener('keyup', event => { if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); cancel(); } });
button.addEventListener('contextmenu', event => event.preventDefault());
document.querySelector('#retry').addEventListener('click', () => location.reload());

// Desktop Firefox steps to the gate's hop page and straight back. Resolves to the hop's id, or undefined.
const here = location.pathname + location.search;
const HOPPED = 'voight-hop';
function roundTrip() {
  const gecko = typeof navigator.buildID === 'string' || 'MozAppearance' in document.documentElement.style;
  if (!gecko || (/Android/.test(navigator.userAgent) && navigator.maxTouchPoints > 0)) return Promise.resolve(undefined);
  let left = null;
  try { left = JSON.parse(sessionStorage.getItem(HOPPED)); } catch {}
  const recent = left?.to === here && Date.now() - left.at < 15000 ? left.tries : 0;
  // Twice in a row already: stop going round.
  if (recent >= 2) { try { sessionStorage.removeItem(HOPPED); } catch {} return Promise.resolve(undefined); }
  const id = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return new Promise(resolve => {
    addEventListener('pageshow', event => {
      if (!event.persisted) return;
      try { sessionStorage.removeItem(HOPPED); } catch {}
      resolve(id);
    });
    // After load, with nothing still loading.
    const go = () => setTimeout(() => {
      status.textContent = 'Checking this browser…';
      try { sessionStorage.setItem(HOPPED, JSON.stringify({ to: here, at: Date.now(), tries: recent + 1 })); } catch {}
      location.assign(`/_gate/human/hop?id=${id}&to=${encodeURIComponent(here)}`);
    }, 50);
    if (document.readyState === 'complete') go(); else addEventListener('load', go, { once: true });
  });
}

// Takes a ticket: starts its proof of work and plans its swap.
function accept(options) {
  holdMs = options.holdMs ?? holdMs;
  solution = work(options.challenge, options.difficulty);
  solution.catch(() => {});
  ticket = Date.now(); stale = false;
  clearTimeout(renewal); renewal = setTimeout(renew, RENEW_MS);
}
// Swaps the ticket in place, never during a press.
function renew() {
  if (checking || renewing) return;
  if (started) { renewal = setTimeout(renew, 5000); return; }
  renewing = post('renew', {}).then(accept, () => { stale = true; }).finally(() => { renewing = null; });
}
async function start() {
  if (!crypto.subtle) throw new Error('This browser cannot run the check here. Try a current browser.');
  const hop = await roundTrip();
  const options = await post('options', { hop });
  accept(options);
  // This check's own measuring script: different names, numbers and report key every time.
  probe = import(`/_gate/human/probe.js?check=${encodeURIComponent(options.challenge)}`).then(module => module.default());
  await probe;
  button.disabled = false; setState('ready'); label.textContent = 'Press and hold'; status.textContent = 'Ready.';
}
// A new check from the beginning, for a page that comes back after its ticket ran out.
async function restart() {
  if (restarting || checking || started) return;
  restarting = true; clearTimeout(renewal);
  button.disabled = true; setState('loading'); status.textContent = 'Getting a fresh check…';
  path.length = 0; last = undefined;
  try { await start(); } catch (error) { fail(error.message); } finally { restarting = false; }
}
// Someone is back at the page: renew a ticket that is due, or start over if it ran out while they were away.
function wake() {
  if (!ticket || document.hidden || started || checking || restarting || renewing) return;
  const age = Date.now() - ticket;
  if (stale || age > TICKET_MS - 10000) restart();
  else if (age >= RENEW_MS) renew();
}
for (const name of ['pointermove', 'pointerdown', 'keydown', 'focus']) addEventListener(name, wake, { passive: true });
document.addEventListener('visibilitychange', wake);

start().catch(error => fail(error.message));
