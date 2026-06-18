// Post-build fixup for the dual ESM+CJS layout.
//
// The root package.json declares "type": "module", so every .js file is ESM by
// default — which is correct for dist/esm/. But the CJS build (tsc module:CommonJS)
// also emits .js files into dist/cjs/, and Node would mis-read those as ESM. The
// standard fix is to drop a tiny package.json with "type": "commonjs" into the CJS
// output dir, scoping that subtree back to CommonJS. (Symmetrically we mark dist/esm
// as "module" for clarity, though it inherits that from the root already.)
import { writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');

const targets = [
  ['cjs', '{"type":"commonjs"}\n'],
  ['esm', '{"type":"module"}\n'],
];

for (const [sub, contents] of targets) {
  const dir = join(dist, sub);
  if (!existsSync(dir)) {
    throw new Error(`expected build output at ${dir} — did the tsc step run?`);
  }
  writeFileSync(join(dir, 'package.json'), contents);
}

console.log('fixup-cjs: wrote dist/cjs/package.json + dist/esm/package.json');
