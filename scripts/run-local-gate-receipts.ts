/**
 * CAIM Local Gate Execution & Authentic Receipt Generator
 * Architecture P103 — Secure Runner Engine
 */

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createAndSaveRunnerReceipt } from '../src/certification/receipt-generator.ts';
import { GateId } from '../src/certification/gate-schema.ts';

interface RunGateOptions {
  gateId: GateId;
  command: string;
  outputPath: string;
  logPath: string;
}

function runAndProduceReceipt(opts: RunGateOptions): void {
  console.log(`[Runner] Executing ${opts.gateId}: ${opts.command}`);
  const startTime = Date.now();
  let exitCode = 0;
  let stdout = '';
  let errorMsg = '';

  try {
    const rawOut = execSync(opts.command, {
      cwd: process.cwd(),
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 120000,
    });
    stdout = rawOut;
  } catch (err: any) {
    exitCode = err.status || 1;
    stdout = err.stdout?.toString() || '';
    errorMsg = err.stderr?.toString() || err.message;
  }

  const durationMs = Date.now() - startTime;
  fs.mkdirSync(path.dirname(opts.logPath), { recursive: true });
  fs.writeFileSync(opts.logPath, `=== ${opts.gateId} EXECUTION LOG ===\nCOMMAND: ${opts.command}\nEXIT_CODE: ${exitCode}\nDURATION: ${durationMs}ms\n\nSTDOUT:\n${stdout}\n\nSTDERR:\n${errorMsg}\n`, 'utf-8');

  // Derive test counts from stdout if vitest
  let passed = 0;
  let failed = 0;
  let skipped = 0;
  let total = 0;

  if (opts.command.includes('vitest')) {
    const matchPassed = stdout.match(/(\d+)\s+passed/);
    const matchFailed = stdout.match(/(\d+)\s+failed/);
    const matchSkipped = stdout.match(/(\d+)\s+skipped/);

    if (matchPassed) passed = parseInt(matchPassed[1], 10);
    if (matchFailed) failed = parseInt(matchFailed[1], 10);
    if (matchSkipped) skipped = parseInt(matchSkipped[1], 10);
    total = passed + failed + skipped;
  } else {
    // Non-test commands (typecheck, install, scan)
    passed = exitCode === 0 ? 1 : 0;
    failed = exitCode === 0 ? 0 : 1;
    total = 1;
  }

  const status = exitCode === 0 ? 'EXECUTED — PASS' : 'EXECUTED — FAIL';
  const blockers = exitCode === 0 ? [] : [errorMsg.trim() || `Command failed with exit code ${exitCode}`];

  createAndSaveRunnerReceipt({
    gateId: opts.gateId,
    providerType: 'REAL',
    command: opts.command,
    exitCode,
    durationMs,
    stdout,
    logPointer: opts.logPath,
    testCounts: { total, passed, failed, skipped },
    status,
    blockers,
    outputPath: opts.outputPath,
  });

  console.log(`[Runner] ${opts.gateId}: ${status} (${durationMs}ms, exit: ${exitCode}, tests: ${passed}/${total})`);
}

async function runAllLocalGates() {
  const receiptsDir = path.resolve(process.cwd(), 'docs/certification');
  const logsDir = path.resolve(process.cwd(), 'docs/certification/logs');

  // L01 Toolchain
  runAndProduceReceipt({
    gateId: 'GATE_L01_TOOLCHAIN',
    command: 'pnpm install --frozen-lockfile',
    outputPath: path.join(receiptsDir, 'gate-l01-toolchain-receipt.json'),
    logPath: path.join(logsDir, 'l01-toolchain.log'),
  });

  // L02 Types
  runAndProduceReceipt({
    gateId: 'GATE_L02_TYPES',
    command: 'pnpm run typecheck',
    outputPath: path.join(receiptsDir, 'gate-l02-types-receipt.json'),
    logPath: path.join(logsDir, 'l02-types.log'),
  });

  // L03 Sandbox Security
  runAndProduceReceipt({
    gateId: 'GATE_L03_SANDBOX_SECURITY',
    command: 'pnpm exec vitest run src/__tests__/p19_sandbox_runtime_evasion.test.ts',
    outputPath: path.join(receiptsDir, 'gate-l03-sandbox-security-receipt.json'),
    logPath: path.join(logsDir, 'l03-sandbox-security.log'),
  });

  // L04 Shipping Truth States
  runAndProduceReceipt({
    gateId: 'GATE_L04_SHIPPING_TRUTH',
    command: 'pnpm exec vitest run tests/prompt02-shipping-truth-states.test.ts',
    outputPath: path.join(receiptsDir, 'gate-l04-shipping-truth-receipt.json'),
    logPath: path.join(logsDir, 'l04-shipping-truth.log'),
  });

  // L05 Slow Suite Invariants
  runAndProduceReceipt({
    gateId: 'GATE_L05_SLOW_SUITE',
    command: 'pnpm exec vitest run tests/p03-slow-suite-alignment.test.ts',
    outputPath: path.join(receiptsDir, 'gate-l05-slow-suite-receipt.json'),
    logPath: path.join(logsDir, 'l05-slow-suite.log'),
  });

  // L10 Git Secret Scan
  const hasGit = fs.existsSync(path.resolve(process.cwd(), '.git'));
  if (hasGit) {
    runAndProduceReceipt({
      gateId: 'GATE_L10_GIT_SECRET_SCAN',
      command: 'pnpm run scan:secrets',
      outputPath: path.join(receiptsDir, 'gate-l10-git-secret-scan-receipt.json'),
      logPath: path.join(logsDir, 'l10-git-secrets.log'),
    });
  } else {
    // Ephemeral container environment blocked
    const logPath = path.join(logsDir, 'l10-git-secrets.log');
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.writeFileSync(logPath, 'BLOCKED: No .git directory present in studio container runtime. Complete git history scan requires CI runner with fetch-depth: 0.\n', 'utf-8');
    createAndSaveRunnerReceipt({
      gateId: 'GATE_L10_GIT_SECRET_SCAN',
      providerType: 'REAL',
      command: 'git log -p | pnpm run scan:secrets',
      exitCode: 1,
      durationMs: 5,
      stdout: 'ENVIRONMENT BLOCKED: .git directory absent',
      logPointer: logPath,
      testCounts: { total: 0, passed: 0, failed: 0, skipped: 0 },
      status: 'ENVIRONMENT BLOCKED',
      blockers: ['No prior Git commit history exists in the ephemeral studio container (fetch-depth: 0 required in CI).'],
      outputPath: path.join(receiptsDir, 'gate-l10-git-secret-scan-receipt.json'),
    });
    console.log('[Runner] GATE_L10_GIT_SECRET_SCAN: ENVIRONMENT BLOCKED (.git absent)');
  }
}

void runAllLocalGates();
