// What happened, read back from the decision log (`npm run stats`): how many requests reached the site, got the human
// check or were refused and why; how many checks were shown and answered, and per platform and input how many passed,
// failed or were refused, and by which signals. It answers "does a rule refuse
// people on one system?" without anything that tells visitors apart: the log has no addresses or user agents.

// Coarse platform from the user agent, noted on every check answer (`platform:<name>`).
export function platform(userAgent = '') {
  if (/Android/.test(userAgent)) return 'android';
  if (/iPhone|iPad|iPod/.test(userAgent)) return 'ios';
  if (/CrOS/.test(userAgent)) return 'chromeos';
  if (/Windows NT/.test(userAgent)) return 'windows';
  // iPads asking for desktop sites say Macintosh too.
  if (/Macintosh/.test(userAgent)) return 'mac';
  if (/Linux|X11/.test(userAgent)) return 'linux';
  return 'other';
}

const OUTCOMES = { human_pass_issued: 'passed', human_check_failed: 'failed', automation_detected: 'automation', sandbox_detected: 'sandbox' };
const COLUMNS = ['passed', 'short', 'failed', 'automation', 'sandbox', 'other'];
const CHECK_PAGES = new Set(['human_check_required', 'human_recheck']);

export function createStats() {
  const rows = new Map(), flags = new Map(), scores = new Map(), refused = new Map();
  let shown = 0, issued = 0, first = null, last = null, requests = 0, through = 0, from = null, to = null;
  const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
  return {
    add(event) {
      if (!event || typeof event !== 'object' || typeof event.reason !== 'string') return;
      requests++;
      if (typeof event.at === 'string') { from ??= event.at; to = event.at; }
      if (event.reason === 'admitted') through++;
      // Check pages are counted as shown below; every other answer of 400 or more is a refusal.
      else if (!CHECK_PAGES.has(event.reason) && Number(event.status) >= 400) bump(refused, event.reason);
      if (event.reason === 'human_check_required') shown++;
      if (event.reason === 'human_check_issued') issued++;
      const notes = Array.isArray(event.automationSignals) ? event.automationSignals.map(String) : [];
      const value = name => notes.find(note => note.startsWith(`${name}:`))?.slice(name.length + 1);
      // Only answers to a check carry the platform note.
      const system = value('platform');
      if (!system) return;
      if (typeof event.at === 'string') { first ??= event.at; last = event.at; }
      const key = `${system}/${value('pointer') ?? 'none'}`;
      const row = rows.get(key) ?? Object.fromEntries(COLUMNS.map(column => [column, 0]));
      const outcome = OUTCOMES[event.reason] ?? 'other';
      row[outcome]++;
      const score = Number(value('sandbox'));
      // A pass shortened to an hour by some sandbox signals.
      if (outcome === 'passed' && score >= 2) row.short++;
      rows.set(key, row);
      if (outcome === 'passed' && Number.isFinite(score)) bump(scores, score);
      // Flags are the notes without a value after a colon.
      if (outcome !== 'passed') for (const note of new Set(notes.filter(note => !note.includes(':')))) bump(flags, `${outcome}: ${note}`);
    },
    summary() {
      return { requests, through, refused: Object.fromEntries([...refused].sort((a, b) => b[1] - a[1])), from, to, shown, issued, first, last, rows: Object.fromEntries([...rows].sort()), flags: Object.fromEntries([...flags].sort((a, b) => b[1] - a[1])), scores: Object.fromEntries([...scores].sort((a, b) => a[0] - b[0])) };
    },
    render() {
      const { requests, through, refused, from, to, shown, issued, first, last, rows, flags, scores } = this.summary();
      const blocked = Object.values(refused).reduce((sum, count) => sum + count, 0);
      const lines = [`Requests ${from ? `from ${from} to ${to}` : '(none in this log)'}: ${requests}`,
        `  ${through} reached the site, ${shown} got the human check, ${blocked} were refused${blocked ? ` (${Object.entries(refused).map(([reason, count]) => `${reason} ${count}`).join(', ')})` : ''}`, '',
        `Human checks ${first ? `from ${first} to ${last}` : '(no answers in this log)'}`, `Shown ${shown}, started ${issued}, answered ${Object.values(rows).reduce((total, row) => total + COLUMNS.filter(column => column !== 'short').reduce((sum, column) => sum + row[column], 0), 0)}`, ''];
      const width = Math.max(14, ...Object.keys(rows).map(key => key.length));
      lines.push(['platform/input'.padEnd(width), ...COLUMNS.map(column => column.padStart(11))].join(''));
      for (const [key, row] of Object.entries(rows)) lines.push([key.padEnd(width), ...COLUMNS.map(column => String(row[column]).padStart(11))].join(''));
      lines.push('', '"short" passes are included in "passed": some sandbox signals, so the pass lasts an hour.');
      if (Object.keys(flags).length) lines.push('', 'Signals on answers that did not pass:', ...Object.entries(flags).map(([flag, count]) => `  ${flag} ${count}`));
      if (Object.keys(scores).length) lines.push('', `Sandbox score of passes: ${Object.entries(scores).map(([score, count]) => `${score}: ${count}`).join(', ')}`);
      return lines.join('\n');
    },
  };
}
