// Part of the human check: times cached fetches from a shared worker, outside the page, for the request timing in
// probe.template.js. A DevTools client that intercepts the page's requests does not reach shared workers; an extension
// that watches requests sees both alike.
onconnect = event => {
  const port = event.ports[0];
  port.onmessage = async ({ data }) => {
    try {
      const [path, count] = data, url = new URL(path, location.href).href, start = performance.now();
      for (let i = 0; i < count; i++) await (await fetch(url, { cache: 'force-cache' })).arrayBuffer();
      const took = performance.now() - start;
      // Only cache hits compare: a fetch that went to the network timed the connection.
      port.postMessage(performance.getEntriesByName(url).slice(-count).every(entry => entry.transferSize === 0) ? took : null);
    } catch { port.postMessage(null); }
  };
};
