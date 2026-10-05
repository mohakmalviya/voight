const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

export function denialPage(status, reason, retryAfter, requestID) {
  const automation = reason === 'automation_declared';
  const title = status === 429 ? 'Access paused.' : automation ? 'Automated access is restricted.' : 'This request could not be completed.';
  const message = status === 429 ? `This website’s access limit has been reached. Wait at least ${Math.max(1, Math.ceil(retryAfter))} seconds before trying again. Signing in again will not reset the limit.`
    : automation ? 'This browser reported an automation signal. If you are browsing yourself or use assistive tools, contact this website’s operator for help.'
    : 'Try again later or contact this website’s operator with the reference below.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · Human Gate</title><link rel="stylesheet" href="/_gate/style.css"></head><body><header><a class="brand" href="/_gate/index.html"><span class="logo">H</span> HUMAN GATE</a></header><main><div class="eyebrow">ACCESS NOTICE / ${status}</div><h1>${title}</h1><p class="intro">${message}</p><section class="card"><div class="tiny">WHAT YOU CAN DO</div><h2>Contact the operator.</h2><p>They can review the access policy and help if this restriction is unexpected.</p><a class="notice-link" href="">Try this request again →</a><p class="reference">Reference: ${escape(requestID)}</p></section></main></body></html>`;
}
