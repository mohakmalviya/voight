// Link previews (OPEN_GRAPH=on). Chat and social apps fetch a shared link with their own clients, which cannot pass the
// human check. The check page they get carries the page's own preview tags instead (title, description, image), read
// from the origin and cached, so a shared link still shows a card while the page itself stays behind the check.
const MAX_HEAD_BYTES = 256 * 1024, MAX_TAGS = 32, MAX_CONTENT = 1000, MAX_ENTRIES = 1000;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
const decode = text => text.replace(/&(?:#(\d{1,7})|#x([0-9a-f]{1,6})|([a-z]+));/gi, (all, dec, hex, name) => {
  const code = dec ? Number(dec) : hex ? parseInt(hex, 16) : null;
  if (code !== null) return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
  return ENTITIES[name.toLowerCase()] ?? all;
});

// The preview tags in a page's head, as [attribute, key, content]: og:*, twitter:* and description, plus the title as
// og:title when the page has none (otherwise the card would show the check page's own title).
export function previewTags(html) {
  const end = html.search(/<\/head\s*>/i);
  const head = end === -1 ? html : html.slice(0, end);
  const tags = [];
  for (const [tag] of head.matchAll(/<meta\b[^>]*>/gi)) {
    const attrs = {};
    for (const match of tag.matchAll(/([a-zA-Z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[match[1].toLowerCase()] = match[2] ?? match[3];
    const attribute = attrs.property !== undefined ? 'property' : 'name';
    const key = (attrs[attribute] ?? '').trim().toLowerCase();
    if (!/^(?:og:[a-z:_]{1,40}|twitter:[a-z:_]{1,40}|description)$/.test(key) || typeof attrs.content !== 'string') continue;
    const content = decode(attrs.content).trim().slice(0, MAX_CONTENT);
    if (content && tags.length < MAX_TAGS) tags.push([attribute, key, content]);
  }
  const title = /<title\b[^>]*>([^<]{1,1000})<\/title>/i.exec(head);
  if (title && !tags.some(([, key]) => key === 'og:title')) tags.unshift(['property', 'og:title', decode(title[1]).trim().slice(0, MAX_CONTENT)]);
  return tags.filter(([, , content]) => content);
}

// Reads and caches each page's preview tags. Images the tags point to on this site become readable without the check,
// so the card can show them; nothing else does.
// Reads the gateway's settings at each call (the origin, the upstream, OPEN_GRAPH_SECONDS).
export function previewReader({ config, fetchImpl = fetch, now = Date.now }) {
  const cache = new Map(), images = new Set();
  async function read(pathAndQuery) {
    const target = new URL(config.upstream); const page = new URL(pathAndQuery, config.origin);
    target.pathname = page.pathname; target.search = page.search;
    const response = await fetchImpl(target, { redirect: 'manual', headers: { accept: 'text/html', 'user-agent': 'HumanGate/0.10' }, signal: AbortSignal.timeout(3000) });
    if (response.status !== 200 || !/text\/html|application\/xhtml/i.test(response.headers.get('content-type') ?? '')) { await response.body?.cancel(); return []; }
    let html = '', bytes = 0; const decoder = new TextDecoder();
    for await (const chunk of response.body) {
      bytes += chunk.length; html += decoder.decode(chunk, { stream: true });
      if (bytes >= MAX_HEAD_BYTES || /<\/head\s*>/i.test(html)) break;
    }
    return previewTags(html.slice(0, MAX_HEAD_BYTES));
  }
  return {
    async tags(pathAndQuery) {
      const cached = cache.get(pathAndQuery);
      if (cached && cached.expires > now()) return cached.tags;
      let tags = [];
      try { tags = await read(pathAndQuery); } catch { tags = []; }
      // Preview clients want whole URLs; pages often give paths.
      tags = tags.map(([attribute, key, content]) => {
        if (!/^(?:og:url|og:image(?::url|:secure_url)?|twitter:image(?::src)?)$/.test(key)) return [attribute, key, content];
        try { return [attribute, key, new URL(content, config.origin).href]; } catch { return [attribute, key, content]; }
      });
      if (cache.size >= MAX_ENTRIES) cache.clear();
      cache.set(pathAndQuery, { tags, expires: now() + config.openGraphSeconds * 1000 });
      for (const [, key, content] of tags) {
        if (!/^(?:og:image(?::url|:secure_url)?|twitter:image(?::src)?)$/.test(key)) continue;
        try {
          const image = new URL(content, config.origin);
          if (image.origin !== config.origin) continue;
          if (images.size >= MAX_ENTRIES) images.clear();
          images.add(image.pathname);
        } catch { /* not a URL */ }
      }
      return tags;
    },
    isImage: path => images.has(path),
  };
}
