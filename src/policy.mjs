import { readFile } from 'node:fs/promises';
import { parseAddress, parseCIDR, inRanges } from './network.mjs';

// The operator's own rules (POLICY_FILE), checked in order before anything else; the first rule whose conditions all
// match decides. `allow` skips the human check and the AI-agent refusal, `check` always asks for the human check, and
// `deny` refuses. Budgets and blocks apply whatever a rule says.
const ACTIONS = new Set(['allow', 'deny', 'check']);
const CONDITIONS = new Set(['path', 'userAgent', 'headers', 'cidr']);

function pattern(value, where) {
  if (typeof value !== 'string' || !value || value.length > 512) throw new Error(`Invalid POLICY_FILE ${where}`);
  try { return new RegExp(value); } catch { throw new Error(`Invalid POLICY_FILE ${where}: not a regular expression`); }
}

export function parsePolicy(value) {
  const rules = Array.isArray(value) ? value : value?.rules;
  if (!Array.isArray(rules) || rules.length > 1000) throw new Error('POLICY_FILE must be a list of rules');
  return rules.map((rule, i) => {
    const name = rule?.name;
    if (typeof name !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(name)) throw new Error(`POLICY_FILE rule ${i + 1} needs a name of letters, digits, dots, dashes or underscores`);
    if (!ACTIONS.has(rule.action)) throw new Error(`POLICY_FILE rule ${name}: action must be allow, deny or check`);
    const unknown = Object.keys(rule).filter(key => !['name', 'action', ...CONDITIONS].includes(key));
    if (unknown.length) throw new Error(`POLICY_FILE rule ${name}: unknown field ${unknown[0]}`);
    if (![...CONDITIONS].some(key => rule[key] !== undefined)) throw new Error(`POLICY_FILE rule ${name} needs at least one of path, userAgent, headers or cidr`);
    const parsed = { name, action: rule.action };
    if (rule.path !== undefined) parsed.path = pattern(rule.path, `rule ${name} path`);
    if (rule.userAgent !== undefined) parsed.userAgent = pattern(rule.userAgent, `rule ${name} userAgent`);
    if (rule.headers !== undefined) {
      if (!rule.headers || typeof rule.headers !== 'object' || Array.isArray(rule.headers) || !Object.keys(rule.headers).length) throw new Error(`POLICY_FILE rule ${name}: headers must map header names to patterns`);
      parsed.headers = Object.entries(rule.headers).map(([header, value]) => {
        if (!/^[A-Za-z0-9-]{1,64}$/.test(header)) throw new Error(`POLICY_FILE rule ${name}: invalid header name ${header}`);
        return [header.toLowerCase(), pattern(value, `rule ${name} header ${header}`)];
      });
    }
    if (rule.cidr !== undefined) {
      if (!Array.isArray(rule.cidr) || !rule.cidr.length) throw new Error(`POLICY_FILE rule ${name}: cidr must be a list`);
      parsed.cidr = rule.cidr.map(entry => { try { return parseCIDR(entry); } catch { throw new Error(`POLICY_FILE rule ${name}: invalid cidr ${entry}`); } });
    }
    return parsed;
  });
}

export async function loadPolicy(file) {
  let text;
  try { text = await readFile(file, 'utf8'); } catch { throw new Error(`Cannot read POLICY_FILE ${file}`); }
  let value;
  try { value = JSON.parse(text); } catch { throw new Error(`POLICY_FILE ${file} is not valid JSON`); }
  return parsePolicy(value);
}

// A missing header matches as an empty string, so "^$" means absent or empty.
export function matchPolicy(rules, { path, userAgent, headers, ip }) {
  const address = parseAddress(ip);
  return rules.find(rule => (!rule.path || rule.path.test(path))
    && (!rule.userAgent || rule.userAgent.test(userAgent))
    && (!rule.headers || rule.headers.every(([name, value]) => value.test(String(headers[name] ?? ''))))
    && (!rule.cidr || (address !== null && inRanges(address, rule.cidr)))) ?? null;
}
