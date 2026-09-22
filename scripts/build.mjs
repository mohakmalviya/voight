import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
await mkdir(new URL('../dist/', import.meta.url), { recursive: true });
for (const file of ['index.html', 'style.css']) await copyFile(new URL(`../web/${file}`, import.meta.url), new URL(`../dist/${file}`, import.meta.url));
await build({ entryPoints: [fileURLToPath(new URL('../web/client.mjs', import.meta.url))], outfile: fileURLToPath(new URL('../dist/client.js', import.meta.url)), bundle: true, format: 'esm', minify: true, target: 'es2022' });
