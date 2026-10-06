const evidence = JSON.parse(document.querySelector('#evidence-data').textContent);
document.querySelector('#measured-date').textContent = new Date(evidence.browser.generatedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata' });
document.querySelector('#measured-date').dateTime = evidence.browser.generatedAt;
const copy = {
  headless: ['BLOCKED', 'Stopped before the origin.', 'WHY IT STOPPED', 'The user agent declared browser automation. Enforcement rejected the request; no protected origin content was fetched.'],
  webdriver: ['BLOCKED', 'A second signal caught it.', 'WHY IT STOPPED', 'Changing the user agent was not enough. The browser still declared WebDriver control during the passkey ceremony.'],
  observe: ['OBSERVED', 'Visible, but not rejected.', 'WHY OBSERVE EXISTS', 'The automation signal was recorded while passkey admission remained mandatory. Observe mode lets an operator evaluate impact before enabling rejection.'],
  masked: ['KNOWN GAP', 'Automation was admitted.', 'THE REMAINING BOUNDARY', 'Both declarations were suppressed. An invitation and virtual passkey granted access, but a fourth distinct resource was blocked by the extraction budget.'],
};
function selectCase(id) {
  const row = evidence.browser.scenarios.find(s => s.id === id); const words = copy[id];
  for (const button of document.querySelectorAll('[data-case]')) button.setAttribute('aria-pressed', String(button.dataset.case === id));
  document.querySelector('#verdict').textContent = words[0];
  document.querySelector('#verdict').classList.toggle('caution', row.accessGranted);
  document.querySelector('#outcome-title').textContent = words[1];
  document.querySelector('#outcome-description').textContent = row.description;
  document.querySelector('#origin-count').textContent = row.originRequests;
  document.querySelector('#signal-count').textContent = row.signals.length;
  document.querySelector('#finding-label').textContent = words[2];
  document.querySelector('#finding-detail').textContent = words[3];
}
for (const button of document.querySelectorAll('[data-case]')) button.addEventListener('click', () => selectCase(button.dataset.case));
const tabs = [...document.querySelectorAll('[role=tab]')];
function selectTab(tab) {
  for (const item of tabs) { const active = item === tab; item.setAttribute('aria-selected', String(active)); item.tabIndex = active ? 0 : -1; document.querySelector(`#${item.getAttribute('aria-controls')}`).hidden = !active; }
}
for (const tab of tabs) {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs.at(-1) : tabs[(tabs.indexOf(tab) + 1) % tabs.length];
    selectTab(next); next.focus();
  });
}
for (const scenario of evidence.http.scenarios) {
  const row = document.createElement('tr');
  for (const value of [scenario.name, `${scenario.allowed} / ${scenario.requests}`, scenario.blocked, `${scenario.protectedBytes.toLocaleString('en-US')} bytes`]) {
    const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
  }
  document.querySelector('#extraction-rows').append(row);
}
document.querySelector('#download').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(evidence, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'voight-evidence.json'; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
selectCase('headless');
