import { fileURLToPath } from 'node:url';
// Keep downloaded browsers inside the checkout unless the operator supplies a path.
process.env.PLAYWRIGHT_BROWSERS_PATH ??= fileURLToPath(new URL('../.cache/playwright/', import.meta.url));
export const { chromium } = await import('playwright');
