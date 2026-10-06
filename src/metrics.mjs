import http from 'node:http';

// Prometheus counters (METRICS_PORT), built from the same decisions the log records: requests by status and reason,
// and how often each automation or sandbox signal was seen. Nothing about a visitor is kept.
export function createMetrics() {
  const requests = new Map(), signals = new Map(), bytes = { total: 0 };
  const bump = (map, key, by = 1) => map.set(key, (map.get(key) ?? 0) + by);
  return {
    record(event) {
      bump(requests, `${event.status}|${event.reason}`);
      bytes.total += event.chargedBytes ?? 0;
      // Notes carry a value after a colon (moves:40, devtools:1.20); only the name is counted.
      for (const signal of new Set((event.automationSignals ?? []).map(note => String(note).split(':')[0]))) {
        if (/^[a-z_-]{1,40}$/.test(signal)) bump(signals, signal);
      }
    },
    render() {
      const lines = ['# HELP human_gate_requests_total Requests by response status and decision reason.', '# TYPE human_gate_requests_total counter'];
      for (const [key, count] of [...requests].sort()) {
        const [status, reason] = key.split('|');
        lines.push(`human_gate_requests_total{status="${status}",reason="${reason.replace(/[^a-z0-9_]/gi, '_')}"} ${count}`);
      }
      lines.push('# HELP human_gate_signals_total Requests on which each automation or sandbox signal was noted.', '# TYPE human_gate_signals_total counter');
      for (const [signal, count] of [...signals].sort()) lines.push(`human_gate_signals_total{signal="${signal}"} ${count}`);
      lines.push('# HELP human_gate_charged_bytes_total Decoded response bytes charged to budgets.', '# TYPE human_gate_charged_bytes_total counter', `human_gate_charged_bytes_total ${bytes.total}`);
      return `${lines.join('\n')}\n`;
    },
  };
}

// Listens on loopback only: the counters are for the operator's own monitoring.
export function metricsServer(metrics) {
  return http.createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/metrics') { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    res.end(metrics.render());
  });
}
