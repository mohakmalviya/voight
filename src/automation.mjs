// Automation that announces itself: a user agent naming an automation tool, or a browser reporting navigator.webdriver.
// Used by the passkey mode's automation policy and by the human check's rules. These are declarations, not proof of
// humanity: clients can suppress both.
const declaredUA = /(?:^|[\s;(])(?:HeadlessChrome|Playwright|Puppeteer|Selenium)(?:[\/\s;)]|$)/i;

export function automationSignals(userAgent, webdriver = null) {
  const signals = [];
  if (declaredUA.test(userAgent)) signals.push('declared_user_agent');
  if (webdriver === true) signals.push('webdriver');
  return signals;
}

export function reportedWebdriver(body) {
  const report = body?.clientSignals;
  return report && !Array.isArray(report) && typeof report.webdriver === 'boolean' ? report.webdriver : null;
}

export function automationDecision(mode, userAgent, webdriver, requireReport = true) {
  if (mode !== 'enforce') return null;
  if (automationSignals(userAgent, webdriver).length) return 'automation_declared';
  if (requireReport && webdriver === null) return 'automation_report_required';
  return null;
}
