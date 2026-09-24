import { build } from 'esbuild';
import { chmodSync, rmSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });

// Bundled ESM still contains CommonJS dependencies that call `require` for Node built-ins.
const requireShim = "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);";

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  legalComments: 'none',
  logLevel: 'info',
};

await build({ ...common, entryPoints: ['src/action/main.ts'], outfile: 'dist/index.mjs', banner: { js: requireShim } });
await build({ ...common, entryPoints: ['src/cli.ts'], outfile: 'dist/cli.mjs', banner: { js: `#!/usr/bin/env node\n${requireShim}` } });
chmodSync('dist/cli.mjs', 0o755);
