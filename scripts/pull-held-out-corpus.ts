/**
 * Pulls / Unpacks the held-out private corpus artifact for CI execution
 * Conforming to R10 specification
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const CORPUS_DIR = path.resolve(process.cwd(), 'corpus');
const ARTIFACT_PATH = path.resolve(process.cwd(), 'artifacts/corpus-held-out.tar.gz');
const HELD_OUT_DIR = path.resolve(CORPUS_DIR, '.held-out');

export function pullHeldOutCorpus(): boolean {
  if (fs.existsSync(HELD_OUT_DIR) && fs.readdirSync(HELD_OUT_DIR).length > 0) {
    console.log('[Held-Out Corpus] Held-out corpus directory already present.');
    return true;
  }

  if (!fs.existsSync(ARTIFACT_PATH)) {
    console.warn('[Held-Out Corpus] Held-out artifact not found at:', ARTIFACT_PATH);
    return false;
  }

  console.log('[Held-Out Corpus] Unpacking held-out corpus artifact into corpus/.held-out ...');
  fs.mkdirSync(CORPUS_DIR, { recursive: true });
  execSync(`tar -xzf "${ARTIFACT_PATH}" -C "${CORPUS_DIR}"`, { stdio: 'inherit' });
  console.log('[Held-Out Corpus] Unpacked held-out set successfully.');
  return true;
}

if (process.argv[1] && process.argv[1].endsWith('pull-held-out-corpus.ts')) {
  pullHeldOutCorpus();
}
