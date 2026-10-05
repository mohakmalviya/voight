import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

const status = document.querySelector('#status');
const buttons = [...document.querySelectorAll('button')];
async function post(path, body) {
  const response = await fetch(`/_gate/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const result = await response.json();
  if (!response.ok) throw new Error(response.status === 429 ? `Too many attempts. Please wait ${Number(response.headers.get('retry-after')) || 60} seconds.`
    : result.error === 'automation_declared' ? 'This browser reported automation. Contact the website operator if you are browsing yourself or use assistive tools.'
    : result.error === 'automation_report_required' ? 'Reload this page and try again. Contact the operator if the problem continues.'
    : result.error === 'invalid_invite' ? 'That invitation is invalid, expired, or already used.' : 'Access could not be verified. Try again or contact the operator.');
  return result;
}
async function ceremony(kind) {
  buttons.forEach(button => { button.disabled = true; });
  status.textContent = 'Waiting for your device…';
  try {
    const optionsJSON = await post(`${kind}/options`, { ...(kind === 'register' ? { invite: document.querySelector('#invite').value.trim() } : {}), clientSignals: { webdriver: navigator.webdriver === true } });
    const result = kind === 'register' ? await startRegistration({ optionsJSON }) : await startAuthentication({ optionsJSON });
    await post(`${kind}/verify`, result);
    document.querySelector('#invite').value = '';
    status.textContent = 'Verified. Opening the website…';
    location.replace(location.pathname.startsWith('/_gate/') ? '/' : location.pathname + location.search);
  } catch (error) {
    status.textContent = error.name === 'NotAllowedError' ? 'Verification was cancelled or timed out. You can try again.' : error.message;
  } finally { buttons.forEach(button => { button.disabled = false; }); }
}
document.querySelector('#login').addEventListener('click', () => ceremony('login'));
document.querySelector('#enroll').addEventListener('submit', event => { event.preventDefault(); ceremony('register'); });
if (!window.PublicKeyCredential) { status.textContent = 'This browser does not support passkeys. Use a supported browser or contact the operator.'; buttons.forEach(button => { button.disabled = true; }); }
