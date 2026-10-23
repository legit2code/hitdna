import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

export interface AuditWaiver {
  affectedDependency: string;
  approver: string;
  reason: string;
  expiration: string; // ISO date string: YYYY-MM-DD
  vulnerabilityId?: string;
  ticket?: string;
  approvedAt?: string;
}

export interface WaiverValidationResult {
  valid: boolean;
  waiver: AuditWaiver;
  error?: string;
}

export interface AuditFinding {
  name: string;
  severity: 'low' | 'moderate' | 'high' | 'critical';
  title?: string;
  url?: string;
  range?: string;
  via?: Array<string | { name: string; title: string; url: string; severity: string }>;
  isDirect?: boolean;
  effects?: string[];
}

export interface AuditEvaluationResult {
  totalFindings: number;
  findingsAtOrAboveLevel: number;
  waivedCount: number;
  unwaivedCount: number;
  expiredWaiversCount: number;
  unwaivedFindings: AuditFinding[];
  waivedFindings: Array<{ finding: AuditFinding; waiver: AuditWaiver }>;
  waiverValidationErrors: string[];
  passed: boolean;
  summary: string;
}

const SEVERITY_RANKS: Record<string, number> = {
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

export function validateWaiver(waiver: any, currentDate = new Date()): WaiverValidationResult {
  if (!waiver || typeof waiver !== 'object') {
    return { valid: false, waiver, error: 'Waiver must be an object' };
  }

  const { affectedDependency, approver, reason, expiration } = waiver;

  if (!affectedDependency || typeof affectedDependency !== 'string' || affectedDependency.trim() === '') {
    return { valid: false, waiver, error: 'Missing or empty required field: affectedDependency' };
  }

  if (!approver || typeof approver !== 'string' || approver.trim() === '') {
    return { valid: false, waiver, error: `Waiver for "${affectedDependency}" is missing required field: approver` };
  }

  if (!reason || typeof reason !== 'string' || reason.trim() === '') {
    return { valid: false, waiver, error: `Waiver for "${affectedDependency}" is missing required field: reason` };
  }

  if (!expiration || typeof expiration !== 'string' || expiration.trim() === '') {
    return { valid: false, waiver, error: `Waiver for "${affectedDependency}" is missing required field: expiration date` };
  }

  const expDate = new Date(expiration);
  if (isNaN(expDate.getTime())) {
    return { valid: false, waiver, error: `Waiver for "${affectedDependency}" has invalid expiration date: ${expiration}` };
  }

  if (expDate.getTime() <= currentDate.getTime()) {
    return {
      valid: false,
      waiver,
      error: `Waiver for "${affectedDependency}" EXPIRED on ${expiration}. Approver: ${approver}. Renewal required.`,
    };
  }

  return { valid: true, waiver };
}

export function loadWaivers(waiverFilePath: string, currentDate = new Date()): {
  validWaivers: AuditWaiver[];
  errors: string[];
} {
  if (!fs.existsSync(waiverFilePath)) {
    return { validWaivers: [], errors: [] };
  }

  try {
    const rawContent = fs.readFileSync(waiverFilePath, 'utf-8');
    const parsed = JSON.parse(rawContent);
    const waiverList: any[] = Array.isArray(parsed) ? parsed : (parsed.waivers || []);

    const validWaivers: AuditWaiver[] = [];
    const errors: string[] = [];

    for (const item of waiverList) {
      const validation = validateWaiver(item, currentDate);
      if (validation.valid) {
        validWaivers.push(validation.waiver);
      } else {
        errors.push(validation.error!);
      }
    }

    return { validWaivers, errors };
  } catch (err: any) {
    return { validWaivers: [], errors: [`Failed to parse waiver file ${waiverFilePath}: ${err.message}`] };
  }
}

export function evaluateAuditReport(
  auditJson: any,
  waivers: AuditWaiver[],
  auditLevel = 'high',
  waiverErrors: string[] = []
): AuditEvaluationResult {
  const minRank = SEVERITY_RANKS[auditLevel.toLowerCase()] ?? SEVERITY_RANKS['high'];
  const vulnerabilities: Record<string, any> = auditJson.vulnerabilities || {};

  const unwaivedFindings: AuditFinding[] = [];
  const waivedFindings: Array<{ finding: AuditFinding; waiver: AuditWaiver }> = [];

  let totalFindings = 0;
  let findingsAtOrAboveLevel = 0;

  for (const [pkgName, vulnData] of Object.entries(vulnerabilities)) {
    totalFindings++;
    const severity = (vulnData.severity || 'low').toLowerCase();
    const rank = SEVERITY_RANKS[severity] ?? 0;

    if (rank >= minRank) {
      findingsAtOrAboveLevel++;

      const finding: AuditFinding = {
        name: pkgName,
        severity: severity as any,
        title: vulnData.via?.[0]?.title || (typeof vulnData.via?.[0] === 'string' ? vulnData.via[0] : 'Vulnerability detected'),
        url: vulnData.via?.[0]?.url,
        range: vulnData.range,
        via: vulnData.via,
        isDirect: vulnData.isDirect,
        effects: vulnData.effects,
      };

      // Match against active waivers
      const matchingWaiver = waivers.find(
        (w) => w.affectedDependency.toLowerCase() === pkgName.toLowerCase()
      );

      if (matchingWaiver) {
        waivedFindings.push({ finding, waiver: matchingWaiver });
      } else {
        unwaivedFindings.push(finding);
      }
    }
  }

  const passed = unwaivedFindings.length === 0 && waiverErrors.length === 0;

  let summary = '';
  if (passed) {
    summary = `PASS: 0 unwaived vulnerabilities at or above level "${auditLevel}". (${waivedFindings.length} waived, ${totalFindings} total dependencies analyzed)`;
  } else {
    summary = `FAIL: ${unwaivedFindings.length} unwaived vulnerabilities at or above level "${auditLevel}". ${waiverErrors.length} waiver errors detected.`;
  }

  return {
    totalFindings,
    findingsAtOrAboveLevel,
    waivedCount: waivedFindings.length,
    unwaivedCount: unwaivedFindings.length,
    expiredWaiversCount: waiverErrors.length,
    unwaivedFindings,
    waivedFindings,
    waiverValidationErrors: waiverErrors,
    passed,
    summary,
  };
}

export function runAuditWithWaivers(options?: {
  auditLevel?: string;
  waiverFile?: string;
  cwd?: string;
}): AuditEvaluationResult {
  const auditLevel = options?.auditLevel || 'high';
  const waiverPath = options?.waiverFile || path.resolve(process.cwd(), 'audit-waivers.json');
  const cwd = options?.cwd || process.cwd();

  console.log('===============================================================');
  console.log(`🛡️  DEPENDENCY VULNERABILITY AUDIT (Gate Level: ${auditLevel.toUpperCase()})`);
  console.log(`📋 Waiver Configuration: ${path.basename(waiverPath)}`);
  console.log('===============================================================\n');

  const { validWaivers, errors: waiverErrors } = loadWaivers(waiverPath);

  if (waiverErrors.length > 0) {
    console.error('❌ INVALID OR EXPIRED WAIVER ENTRIES DETECTED:');
    for (const err of waiverErrors) {
      console.error(`   - ${err}`);
    }
    console.log();
  }

  let auditRaw = '';
  try {
    auditRaw = execSync('npm audit --json', {
      cwd,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (err: any) {
    // npm audit exits with code 1 if any vulnerabilities are detected.
    // The JSON output is in stdout.
    auditRaw = err.stdout || '';
  }

  let auditJson: any = {};
  try {
    auditJson = JSON.parse(auditRaw);
  } catch (err: any) {
    console.error(`Failed to parse npm audit output as JSON: ${err.message}`);
    auditJson = { vulnerabilities: {} };
  }

  const evalResult = evaluateAuditReport(auditJson, validWaivers, auditLevel, waiverErrors);

  if (evalResult.waivedFindings.length > 0) {
    console.log('🟡 ACTIVE WAIVERS APPLIED:');
    for (const { finding, waiver } of evalResult.waivedFindings) {
      console.log(`   - [WAIVED] ${finding.name} (${finding.severity.toUpperCase()}): ${finding.title}`);
      console.log(`     Approver:   ${waiver.approver}`);
      console.log(`     Reason:     ${waiver.reason}`);
      console.log(`     Expires:    ${waiver.expiration}`);
    }
    console.log();
  }

  if (evalResult.unwaivedFindings.length > 0) {
    console.error('🔴 UNWAIVED VULNERABILITIES DETECTED:');
    for (const finding of evalResult.unwaivedFindings) {
      console.error(`   - [${finding.severity.toUpperCase()}] ${finding.name}`);
      console.error(`     Title: ${finding.title}`);
      if (finding.url) console.error(`     Advisory: ${finding.url}`);
      if (finding.range) console.error(`     Affected versions: ${finding.range}`);
    }
    console.error('\nTo temporarily waive a vulnerability pending patch/upstream fix, add an entry to audit-waivers.json');
    console.error('with: affectedDependency, approver, reason, and an unexpired expiration date.');
    console.log();
  }

  console.log(`📊 Audit Result: ${evalResult.summary}\n`);

  return evalResult;
}

// CLI Execution Entry Point
if (process.argv[1] && process.argv[1].endsWith('audit-with-waivers.ts')) {
  const args = process.argv.slice(2);
  let auditLevel = 'high';
  let waiverFile = path.resolve(process.cwd(), 'audit-waivers.json');

  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--audit-level=')) {
      auditLevel = args[i].split('=')[1];
    } else if (args[i] === '--audit-level' && args[i + 1]) {
      auditLevel = args[++i];
    } else if (args[i].startsWith('--waivers=')) {
      waiverFile = path.resolve(process.cwd(), args[i].split('=')[1]);
    } else if (args[i] === '--waivers' && args[i + 1]) {
      waiverFile = path.resolve(process.cwd(), args[++i]);
    }
  }

  const result = runAuditWithWaivers({ auditLevel, waiverFile });
  if (!result.passed) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}
