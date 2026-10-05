import { promises as dns } from 'node:dns';

// AI crawlers and assistants that name themselves. Agents driving an ordinary browser do not appear here;
// the human check exists for them.
const AI_AGENT_TOKENS = [
  'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'Claude-Web', 'anthropic-ai',
  'PerplexityBot', 'Perplexity-User', 'CCBot', 'Bytespider', 'TikTokSpider', 'meta-externalagent', 'meta-externalfetcher',
  'Amazonbot', 'cohere-ai', 'cohere-training-data-crawler', 'Diffbot', 'YouBot', 'MistralAI-User', 'DuckAssistBot',
  'Google-CloudVertexBot', 'AI2Bot', 'Ai2Bot-Dolma', 'Timpibot', 'ImagesiftBot', 'Kangaroo Bot',
];
// Tokens are plain words, hyphens and spaces, so they are safe inside the pattern.
const aiAgentUA = new RegExp(`(?:^|[^a-z0-9-])(?:${AI_AGENT_TOKENS.join('|')})(?:[^a-z0-9-]|$)`, 'i');

// Desktop AI apps whose built-in browser names the app, such as the Claude app's browser pane ("Claude/2.1 Chrome/...").
const aiBrowserApp = /(?:^|[\s(;])Claude\/[0-9]/;

// Signed agents (Web Bot Auth, RFC 9421), such as ChatGPT agent, announce themselves with Signature-Agent.
// Blocking needs no signature check: a forged header only shuts out the client that sent it.
export function declaredAIAgent(headers) {
  if (aiAgentUA.test(headers['user-agent'] ?? '')) return 'user_agent';
  if (aiBrowserApp.test(headers['user-agent'] ?? '')) return 'ai_browser';
  if (headers['signature-agent'] || /tag="web-bot-auth"/i.test(headers['signature-input'] ?? '')) return 'signed_agent';
  return null;
}

// Search engines publish how to verify their crawlers: the address must reverse-resolve into their domain,
// and that name must resolve back to the same address. A user agent alone proves nothing.
export const CRAWLERS = {
  googlebot: { ua: /\bGooglebot\b/i, domains: ['googlebot.com', 'google.com'] },
  bingbot: { ua: /\bbingbot\b/i, domains: ['search.msn.com'] },
  applebot: { ua: /\bApplebot\b/i, domains: ['applebot.apple.com'] },
  yandexbot: { ua: /\bYandex(?:Bot|Images)\b/i, domains: ['yandex.ru', 'yandex.net', 'yandex.com'] },
};

const withTimeout = (promise, ms) => Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error('dns_timeout')), ms).unref())]);

export function crawlerVerifier(names, resolver = dns, { cacheSize = 10000, cacheMs = 3600000, timeoutMs = 2000 } = {}) {
  const enabled = names.map(name => [name, CRAWLERS[name]]);
  const cache = new Map();
  return async function verify(ip, userAgent, now = Date.now()) {
    const claimed = enabled.find(([, crawler]) => crawler.ua.test(userAgent ?? ''));
    if (!claimed) return null;
    const [name, crawler] = claimed, key = `${name}|${ip}`;
    const cached = cache.get(key);
    if (cached && cached.expires > now) return cached.ok ? name : null;
    let ok = false;
    try {
      const hosts = await withTimeout(resolver.reverse(ip), timeoutMs);
      for (const host of hosts) {
        const name = host.toLowerCase().replace(/\.$/, '');
        if (!crawler.domains.some(domain => name.endsWith(`.${domain}`))) continue;
        const addresses = await withTimeout(resolver.lookup(name, { all: true }), timeoutMs);
        if (addresses.some(entry => entry.address === ip)) { ok = true; break; }
      }
    } catch { ok = false; }
    if (cache.size >= cacheSize) cache.clear();
    cache.set(key, { ok, expires: now + cacheMs });
    return ok ? name : null;
  };
}
