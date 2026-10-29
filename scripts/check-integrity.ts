/**
 * Quick Integrity & Bootstrap Check
 * Part of root `npm run check` pipeline.
 */

import fs from 'node:fs';
import path from 'node:path';

const CANONICAL_MANIFEST_SHA256 = '1ccc957a962db4c93b5b2a872fb7cddbd4025d938ecdc5de86ca88c17bf5454b';

console.log('[check-integrity] Verifying canonical manifest and integrity matrix presence...');

const manifestPath = path.join(process.cwd(), 'docs/architecture/canonical_manifest.json');
if (!fs.existsSync(manifestPath)) {
  console.error('[check-integrity] ERROR: Missing canonical_manifest.json');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (manifest.canonicalManifestSha256 !== CANONICAL_MANIFEST_SHA256) {
  console.error('[check-integrity] ERROR: Hash mismatch on canonical manifest');
  process.exit(1);
}

const matrixPath = path.join(process.cwd(), 'docs/implementation/INTEGRITY_CHECK_MATRIX.csv');
if (!fs.existsSync(matrixPath)) {
  console.error('[check-integrity] ERROR: Missing INTEGRITY_CHECK_MATRIX.csv');
  process.exit(1);
}

const p00aReceipt = path.join(process.cwd(), 'docs/implementation/evidence/P00A_RECEIPT.json');
if (!fs.existsSync(p00aReceipt)) {
  console.error('[check-integrity] ERROR: Missing P00A bootstrap receipt');
  process.exit(1);
}

console.log('[check-integrity] ✓ Integrity baseline confirmed.');
