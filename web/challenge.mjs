// Find a nonce whose SHA-256 with the server's challenge starts with `difficulty` zero bits.
const status = document.querySelector('#status');
const heading = document.querySelector('#challenge-heading');
const panel = document.querySelector('.panel');
document.querySelector('#retry').addEventListener('click', () => location.reload());

async function post(path, body) {
  const response = await fetch(`/_gate/challenge/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const wait = Number(response.headers.get('retry-after')) || 60;
    throw new Error(result.error === 'challenge_limit' || response.status === 429
      ? `Too many checks from your network. Wait about ${Math.ceil(wait / 60)} minutes, then reload.`
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

async function solve() {
  if (!crypto.subtle) throw new Error('This browser cannot run the check here. Wait a few minutes and reload.');
  const { challenge, difficulty } = await post('options', {});
  const encoder = new TextEncoder();
  const started = performance.now();
  for (let nonce = 0; ; nonce++) {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`${challenge}:${nonce}`)));
    if (zeroBits(hash) >= difficulty) return post('verify', { nonce: String(nonce) });
    if (nonce % 20000 === 0 && nonce) status.textContent = `Still working (${Math.round((performance.now() - started) / 1000)} s)…`;
  }
}

solve().then(() => {
  panel.dataset.state = 'done'; heading.textContent = 'Check complete'; status.textContent = 'Reloading the page…';
  location.reload();
}, error => {
  panel.dataset.state = 'error'; heading.textContent = 'Check stopped'; status.textContent = error.message;
});
