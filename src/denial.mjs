const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

export function duration(seconds) {
  const s = Math.max(1, Math.ceil(seconds));
  if (s < 90) return `${s} seconds`;
  if (s < 5400) return `${Math.round(s / 60)} minutes`;
  return `${Math.round(s / 3600)} hours`;
}

// Stroke icons (24×24), drawn in currentColor by the stylesheet.
const ICONS = {
  shield: '<path d="M12 3l7 3v5.2c0 4.3-2.9 8.1-7 9.8-4.1-1.7-7-5.5-7-9.8V6l7-3z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8.5 12.4l2.4 2.4 4.6-4.8"/>',
  alert: '<path d="M10.3 4.2 2.7 17.5A2 2 0 0 0 4.4 20.5h15.2a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4"/><path d="M12 17h.01"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.7 5.7l12.6 12.6"/>',
  bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 4.5V8"/><circle cx="12" cy="3.5" r="1"/><path d="M9 13.5v1M15 13.5v1"/><path d="M2 13v3M22 13v3"/>',
  server: '<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
  lock: '<rect x="5" y="11" width="14" height="9.5" rx="2"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>',
  spinner: '<circle class="track" cx="12" cy="12" r="9"/><path class="arc" d="M21 12a9 9 0 0 0-9-9"/>',
};
const icon = (name, extra = '') => `<svg class="icon icon-${name}${extra}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;
// The check pages swap their mark as the scripts move through states (see data-state in style.css).
const STATE_MARKS = icon('spinner', ' when-busy') + icon('shield', ' when-ready') + icon('check', ' when-done') + icon('alert', ' when-error');
const RETRY = '<button id="retry" class="button secondary" type="button">Reload page</button>';

// One centred panel: the site it guards, a mark that shows the state, the message, the action, and a reference.
function page({ title, intro, body = '', marks, tone, state, requestID, site, head = '', headingID = 'title' }) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + `<meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>${title} · Human Gate</title><link rel="stylesheet" href="/_gate/style.css">${head}</head>`
    + '<body class="gate"><main class="stage">'
    + (site ? `<div class="site">${icon('lock')}<span>${escape(site)}</span></div>` : '')
    + `<section class="panel" data-tone="${tone}"${state ? ` data-state="${state}"` : ''} aria-labelledby="${headingID}">`
    + `<div class="mark">${marks}</div><h1 id="${headingID}">${title}</h1><p class="lede">${intro}</p>${body}</section>`
    + `<footer class="meta"><span>Reference <code>${escape(requestID)}</code></span><span>Protected by Human Gate</span></footer>`
    + '</main></body></html>';
}

const DENIALS = {
  temporarily_blocked: { mark: 'ban', tone: 'warning', title: 'Temporarily blocked',
    intro: () => 'Requests from your network kept arriving after this website asked them to slow down. You do not need to do anything.',
    wait: retry => `Access resumes automatically in about ${duration(retry)}`,
    note: ['Why this can happen', 'Offices, campuses, VPNs and mobile carriers put many people behind one address. Another device or an automated tool on your network may have caused this. Repeated blocks last longer.'] },
  ai_agent: { mark: 'bot', tone: 'danger', title: 'AI agents are not allowed here',
    intro: () => 'This website is for people reading it themselves. AI agents, assistants and AI crawlers cannot access it.',
    note: ['If you are a person', 'Open this page in your own browser, without an AI assistant or agent acting for you.'] },
  automation_detected: { mark: 'bot', tone: 'danger', title: 'Automated browser detected',
    intro: () => 'This browser appears to be controlled by automation software or an AI agent, so the human check cannot pass. If you have developer tools open, close them and reload.' },
  sandbox_detected: { mark: 'server', tone: 'danger', title: 'Server browser detected',
    intro: () => 'This browser appears to be running on a server or in a virtual machine, not on a personal device.' },
  automation_declared: { mark: 'bot', tone: 'danger', title: 'Automated access is restricted',
    intro: () => 'This browser reported an automation signal. If you are browsing yourself or use assistive tools, contact this website’s operator for help.' },
};
const PAUSED = { mark: 'clock', tone: 'warning', title: 'Access paused', intro: () => 'This website’s access limit has been reached. It resets on its own.',
  wait: retry => `Wait at least ${duration(retry)} before trying again` };
const UNKNOWN = { mark: 'alert', tone: 'neutral', title: 'This request could not be completed', intro: () => 'Something went wrong while opening this page. It is often temporary, so try again in a moment.' };

export function denialPage({ status, reason, retryAfter, requestID, site }) {
  // Say exactly when access returns. An unexplained block looks like the site is down.
  const notice = status === 429 && reason !== 'temporarily_blocked' ? PAUSED : DENIALS[reason] ?? UNKNOWN;
  const wait = notice.wait ? `<p class="wait">${icon('clock')}<span>${notice.wait(retryAfter)}</span></p>` : '';
  const note = notice.note ? `<div class="note"><h2>${notice.note[0]}</h2><p>${notice.note[1]}</p></div>` : '';
  // No retry button while a wait is running: reloading early only spends the network's budget and can extend a block.
  const retry = status === 429 ? '' : '<a class="button secondary" href="">Try again</a>';
  return page({ title: notice.title, intro: notice.intro(retryAfter), tone: notice.tone, marks: icon(notice.mark), requestID, site,
    body: `${wait}${note}${retry}<p class="help">If this keeps happening, contact this website’s operator and include the reference below.</p>` });
}

// No puzzles: the browser spends a moment of computation, then the original page reloads.
export function challengePage({ retryAfter, requestID, site }) {
  return page({ title: 'Checking your browser', headingID: 'challenge-heading', state: 'working', tone: 'accent', requestID, site, marks: STATE_MARKS,
    intro: 'This website is receiving a lot of traffic from your network. Your browser is doing a short automatic check, and the page reloads when it finishes.',
    body: `<div class="progress" aria-hidden="true"></div><p id="status" role="status" aria-live="polite">Starting the check.</p>${RETRY}`
      + `<noscript><p class="help">This check needs JavaScript. Otherwise, wait about ${duration(retryAfter)} and reload this page.</p></noscript>`,
    head: '<script type="module" src="/_gate/challenge.js"></script>' });
}

// A plainly labelled human check. Mainstream AI agents are built to stop at these and hand control to the person.
export function humanPage({ recheck, requestID, passSeconds, site }) {
  return page({ title: recheck ? 'Still you?' : 'Confirm you are human', headingID: 'human-heading', state: 'loading', tone: 'accent', requestID, site, marks: STATE_MARKS,
    intro: recheck ? 'This browser has opened a lot of pages, or opened them faster than people usually read. Confirm once more to keep browsing.'
      : `This website is for people. AI agents and automated browsers are not allowed. Confirm once to keep browsing for up to ${duration(passSeconds)} on this browser.`,
    body: '<button id="hold" type="button" disabled aria-describedby="status hint"><span>Press and hold</span><span class="hold-fill" aria-hidden="true"></span></button>'
      + `<p id="status" role="status" aria-live="polite">Loading the check…</p>${RETRY}`
      + '<p id="hint" class="help">Hold the button until it fills. You can also focus it and hold Space or Enter.</p>'
      + '<noscript><p class="help">This check needs JavaScript. Turn it on and reload this page.</p></noscript>',
    head: '<script type="module" src="/_gate/human.js"></script>' });
}
