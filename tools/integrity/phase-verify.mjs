#!/usr/bin/env node

/**
 * Bootstrap Phase Verifier Runner
 * Directly executable with plain Node:
 *   node tools/integrity/phase-verify.mjs <PROMPT_ID>
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const promptId = process.argv[2] || 'P00A';
const tsScript = path.join(__dirname, 'phase-verifier.ts');

const result = spawnSync('npx', ['tsx', tsScript, promptId], {
  stdio: 'inherit',
  shell: true
});

process.exit(result.status ?? 1);
