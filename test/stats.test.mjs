import test from 'node:test';
import assert from 'node:assert/strict';
import { platform, createStats } from '../src/stats.mjs';

test('the platform note names only the operating system family', () => {
  const cases = {
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36': 'windows',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15': 'mac',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36': 'linux',
    'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36': 'chromeos',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36': 'android',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1': 'ios',
    'curl/8.9.1': 'other',
  };
  for (const [userAgent, name] of Object.entries(cases)) assert.equal(platform(userAgent), name, userAgent);
  assert.equal(platform(), 'other');
});

test('stats count check answers per platform and input, and the signals on those that did not pass', () => {
  const stats = createStats();
  const answer = (reason, ...notes) => stats.add({ at: '2026-10-07T10:00:00.000Z', status: reason === 'human_pass_issued' ? 200 : 403, reason, automationSignals: notes });
  for (let i = 0; i < 3; i++) stats.add({ reason: 'human_check_required', automationSignals: [] });
  for (let i = 0; i < 2; i++) stats.add({ reason: 'human_check_issued', automationSignals: [] });
  answer('human_pass_issued', 'platform:windows', 'pointer:mouse', 'moves:40', 'sandbox:0');
  answer('human_pass_issued', 'platform:windows', 'pointer:mouse', 'datacenter', 'sandbox:2');
  answer('human_pass_issued', 'platform:linux', 'pointer:mouse', 'no_voices', 'sandbox:1');
  answer('human_check_failed', 'platform:android', 'pointer:touch', 'moves:0', 'sandbox:0', 'short_hold');
  answer('sandbox_detected', 'platform:android', 'pointer:touch', 'emulator_gpu', 'sandbox:4');
  answer('automation_detected', 'platform:linux', 'pointer:mouse', 'no_predicted_input', 'predicted:1/42', 'no_webgl', 'sandbox:4');
  answer('invalid_solution', 'platform:other');
  // Not answers to a check, or not log lines at all.
  stats.add({ reason: 'admitted', automationSignals: ['webdriver'] });
  for (const junk of [null, 'junk', 7, { automationSignals: 'platform:windows' }]) stats.add(junk);
  const summary = stats.summary();
  assert.equal(summary.shown, 3); assert.equal(summary.issued, 2);
  assert.deepEqual(summary.rows, {
    'android/touch': { passed: 0, short: 0, failed: 1, automation: 0, sandbox: 1, other: 0 },
    'linux/mouse': { passed: 1, short: 0, failed: 0, automation: 1, sandbox: 0, other: 0 },
    'other/none': { passed: 0, short: 0, failed: 0, automation: 0, sandbox: 0, other: 1 },
    'windows/mouse': { passed: 2, short: 1, failed: 0, automation: 0, sandbox: 0, other: 0 },
  });
  assert.deepEqual(summary.flags, { 'failed: short_hold': 1, 'sandbox: emulator_gpu': 1, 'automation: no_predicted_input': 1, 'automation: no_webgl': 1 });
  assert.deepEqual(summary.scores, { 0: 1, 1: 1, 2: 1 });
  const text = stats.render();
  assert.match(text, /Shown 3, started 2, answered 7/);
  assert.match(text, /android\/touch +0 +0 +1 +0 +1 +0/);
  assert.match(text, /Sandbox score of passes: 0: 1, 1: 1, 2: 1/);
  assert.match(createStats().render(), /no answers in this log/);
});
