const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

export function duration(seconds) {
  const s = Math.max(1, Math.ceil(seconds));
  if (s < 90) return `${s} seconds`;
  if (s < 5400) return `${Math.round(s / 60)} minutes`;
  return `${Math.round(s / 3600)} hours`;
}

function page(title, eyebrow, intro, card, head = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · Human Gate</title><link rel="stylesheet" href="/_gate/style.css">${head}</head><body><header><a class="brand" href="/">HUMAN GATE</a></header><main><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p class="intro">${intro}</p><section class="card">${card}</section></main></body></html>`;
}

export function denialPage(status, reason, retryAfter, requestID) {
  const automation = reason === 'automation_declared';
  // Say exactly when access returns. An unexplained block looks like the site is down.
  if (reason === 'temporarily_blocked') {
    return page('Temporarily blocked.', `ACCESS NOTICE / ${status}`,
      `Requests from your network kept arriving after this website asked them to slow down. Access resumes automatically in about ${duration(retryAfter)}. You do not need to do anything.`,
      `<div class="tiny">WHY THIS CAN HAPPEN</div><h2>Shared networks count together.</h2><p>Offices, campuses, VPNs and mobile carriers put many people behind one address. Another device or an automated tool on your network may have caused this. Repeated blocks last longer.</p><p class="reference">Reference: ${escape(requestID)}</p>`);
  }
  if (reason === 'ai_agent') {
    return page('AI agents are not allowed here.', `ACCESS NOTICE / ${status}`,
      'This website is for people reading it themselves. AI agents, assistants and AI crawlers cannot access it.',
      `<div class="tiny">IF YOU ARE A PERSON</div><h2>Open it yourself.</h2><p>Visit this page in your own browser, without an AI assistant or agent acting for you.</p><p class="reference">Reference: ${escape(requestID)}</p>`);
  }
  const title = status === 429 ? 'Access paused.' : automation ? 'Automated access is restricted.'
    : reason === 'automation_detected' ? 'Automated browser detected.'
    : reason === 'sandbox_detected' ? 'Server browser detected.' : 'This request could not be completed.';
  const message = status === 429 ? `This website’s access limit has been reached. Wait at least ${duration(retryAfter)} before trying again.`
    : automation ? 'This browser reported an automation signal. If you are browsing yourself or use assistive tools, contact this website’s operator for help.'
    : reason === 'automation_detected' ? 'This browser appears to be controlled by automation software or an AI agent, so the human check cannot pass. If you have developer tools open, close them and reload. If you are browsing yourself, contact this website’s operator.'
    : reason === 'sandbox_detected' ? 'This browser appears to be running on a server or in a virtual machine, not on a personal device. If you are browsing yourself, contact this website’s operator.'
    : 'Try again later or contact this website’s operator with the reference below.';
  return page(title, `ACCESS NOTICE / ${status}`, message,
    `<div class="tiny">WHAT YOU CAN DO</div><h2>Contact the operator.</h2><p>They can review the access policy and help if this restriction is unexpected.</p><a class="notice-link" href="">Try this request again →</a><p class="reference">Reference: ${escape(requestID)}</p>`);
}

// No puzzles: the browser spends a moment of computation, then the original page reloads.
export function challengePage(retryAfter, requestID) {
  return page('Checking your browser.', 'ACCESS NOTICE / 429',
    'This website is receiving a lot of traffic from your network. Your browser is doing a short automatic check. The page will reload when it finishes.',
    `<div class="tiny">NO PUZZLES</div><h2 id="challenge-heading">Working…</h2><p id="status" role="status" aria-live="polite">Starting the check.</p><noscript><p>This check needs JavaScript. Otherwise, wait about ${duration(retryAfter)} and reload this page.</p></noscript><p class="reference">Reference: ${escape(requestID)}</p>`,
    '<script type="module" src="/_gate/challenge.js"></script>');
}

// A plainly labelled human check. Mainstream AI agents are built to stop at these and hand control to the person.
export function humanPage(recheck, requestID, passSeconds) {
  return page(recheck ? 'Still you?' : 'Confirm you are human.', 'HUMAN CHECK',
    recheck ? 'This browser has opened a lot of pages, or opened them faster than people usually read. Confirm once more to keep browsing.'
      : `This website is for people. AI agents and automated browsers are not allowed. Confirm once to keep browsing for up to ${duration(passSeconds)} on this browser.`,
    `<div class="tiny">HUMAN VERIFICATION</div><h2 id="human-heading">Press and hold.</h2><p>Hold the button until it fills. You can also focus it and hold Space or Enter.</p><button id="hold" type="button" disabled aria-describedby="status"><span>Press and hold</span><span class="hold-fill" aria-hidden="true"></span></button><p id="status" role="status" aria-live="polite">Loading the check…</p><noscript><p>This check needs JavaScript. Turn it on and reload this page.</p></noscript><p class="reference">Reference: ${escape(requestID)}</p>`,
    '<script type="module" src="/_gate/human.js"></script>');
}
