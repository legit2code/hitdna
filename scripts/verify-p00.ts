/**
 * P00 Bootstrap Verification Script
 * Validates the materialization of the canonical 66-engine architecture baseline,
 * checkpoints, and required source of truth files.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

console.log('[verify-p00] Starting P00 Architecture Baseline Verification...');

// 1. Verify canonical manifest
const manifestPath = path.join(process.cwd(), 'docs/architecture/canonical_manifest.json');
assert.ok(fs.existsSync(manifestPath), 'canonical_manifest.json must exist');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
assert.equal(manifest.architectureVersion, '5.0.0');
assert.equal(manifest.packVersion, '6.0.0');
assert.equal(manifest.domainCount, 7);
assert.equal(manifest.engineCount, 66);
assert.equal(manifest.moduleCount, 670);
console.log('  ✓ canonical_manifest.json verified (v5.0.0, 7 domains, 66 engines, 670 modules)');

// 2. Verify ENGINE_RESPONSIBILITY_MATRIX.csv
const matrixPath = path.join(process.cwd(), 'docs/architecture/ENGINE_RESPONSIBILITY_MATRIX.csv');
assert.ok(fs.existsSync(matrixPath), 'ENGINE_RESPONSIBILITY_MATRIX.csv must exist');
const matrixLines = fs.readFileSync(matrixPath, 'utf8').trim().split('\n');
assert.equal(matrixLines.length - 1, 66, 'Matrix must have exactly 66 engine rows');
console.log('  ✓ ENGINE_RESPONSIBILITY_MATRIX.csv verified (exactly 66 engine rows)');

// 3. Verify ENGINE_COVERAGE.csv
const coveragePath = path.join(process.cwd(), 'docs/implementation/ENGINE_COVERAGE.csv');
assert.ok(fs.existsSync(coveragePath), 'ENGINE_COVERAGE.csv must exist');
const coverageLines = fs.readFileSync(coveragePath, 'utf8').trim().split('\n');
assert.equal(coverageLines.length - 1, 66, 'Coverage must have exactly 66 engine rows');
console.log('  ✓ ENGINE_COVERAGE.csv verified (exactly 66 engine rows)');

// 4. Verify REQUIREMENT_COVERAGE.csv
const reqPath = path.join(process.cwd(), 'docs/implementation/REQUIREMENT_COVERAGE.csv');
assert.ok(fs.existsSync(reqPath), 'REQUIREMENT_COVERAGE.csv must exist');
console.log('  ✓ REQUIREMENT_COVERAGE.csv verified');

// 5. Verify Architecture Docs
const requiredDocs = [
  'MASTER_PRODUCT_ARCHITECTURE.md',
  'CORE_MUSIC_GENRE_SCHEMA.md',
  'CONTINUOUS_RESEARCH.md',
  'HIT_DNA_ANALYTICS_METHODOLOGY.md',
  'MODERN_LANGUAGE_INTELLIGENCE.md',
  'MUSICAL_PATTERN_INTELLIGENCE.md',
  'GENERATION_ARCHITECTURE.md',
  'SECURITY_AND_SECRETS.md',
  'IMPLEMENTATION_ROADMAP.md',
];

for (const doc of requiredDocs) {
  const docPath = path.join(process.cwd(), 'docs/architecture', doc);
  assert.ok(fs.existsSync(docPath), `Architecture doc ${doc} must exist`);
}
console.log('  ✓ All 9 architecture specification documents verified');

// 6. Verify Checkpoint files
const checkpointDocs = ['KNOWN_GAPS.md', 'DECISIONS_PENDING.md', 'BUILD_STATE.md', 'BUILD_STATE.json'];
for (const cp of checkpointDocs) {
  const cpPath = path.join(process.cwd(), 'docs/implementation', cp);
  assert.ok(fs.existsSync(cpPath), `Checkpoint doc ${cp} must exist`);
}
console.log('  ✓ All 4 checkpoint documents verified');

console.log('[verify-p00] ALL P00 VERIFICATION CHECKS PASSED.');
