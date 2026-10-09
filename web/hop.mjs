// The human check's hop page: go straight back to the check.
const panel = document.querySelector('.panel');
const status = document.querySelector('#status');
const back = () => (history.length > 1 ? history.back() : location.assign('/'));
document.querySelector('#retry').addEventListener('click', back);
// Shown only if going back did not happen, for example when this page was opened on its own.
setTimeout(() => {
  panel.dataset.state = 'error';
  status.textContent = 'This page is a step of the human check. Go back to the page you were opening.';
}, 4000);
// After load, as measured: going back from a page that is still loading was not tested.
if (document.readyState === 'complete') setTimeout(back, 200); else addEventListener('load', () => setTimeout(back, 200), { once: true });
