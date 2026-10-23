/**
 * Secret & Credential Leak Scanner
 * P32 — Zero-Leak Credential & Token Scanning Engine
 */

import fs from 'fs';
import path from 'path';

export interface SecretFinding {
  file: string;
  line: number;
  patternName: string;
  matchedSnippet: string;
  severity: 'HIGH' | 'CRITICAL';
}

export interface SecretScanResult {
  passed: boolean;
  totalFilesScanned: number;
  findings: SecretFinding[];
  durationMs: number;
}

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; severity: 'HIGH' | 'CRITICAL' }> = [
  {
    name: 'Google Cloud / Gemini API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{30,40}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Generic AWS / S3 Access Key ID',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Supabase Service Role JWT (Unredacted)',
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/,
    severity: 'CRITICAL',
  },
  {
    name: 'Hardcoded Private Key Header',
    regex: /-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/,
    severity: 'CRITICAL',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'OpenAI / Live API Secret Token Key',
    regex: /\bsk-(?:live|proj|admin)[-_][0-9A-Za-z]{16,}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Generic Hardcoded Token Assignment',
    regex: /(api_key|apikey|secret_key|secretkey|private_key|privatekey|auth_token|authtoken|client_secret|clientsecret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{24,}['"]/i,
    severity: 'HIGH',
  },
  {
    name: 'Hardcoded CI / PostgreSQL Fixed Credentials',
    regex: /caim_ci_secure_password_2026/i,
    severity: 'CRITICAL',
  },
];

// Directories and files to ignore in global repo scan
// Note: tests/ and __tests__/ are NOT ignored. All test files must be scanned for secrets.
const IGNORED_DIRS = ['node_modules', '.git', 'dist', 'coverage', '.cache'];
const IGNORED_EXTS = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico'];

// Reviewed allowlist for harmless fixture snippets (exact files only)
interface AllowlistEntry {
  path: string;
  owner: string;
  reason: string;
  expires: string;
}

const REVIEWED_ALLOWLIST: AllowlistEntry[] = [
  {
    path: 'scripts/secret-scanner.ts',
    owner: 'security-team',
    reason: 'Contains regex pattern definitions for scanning',
    expires: '2030-01-01',
  },
  {
    path: '.gitleaks.toml',
    owner: 'security-team',
    reason: 'Gitleaks rule definition file',
    expires: '2030-01-01',
  },
  {
    path: 'src/__tests__/p15_static_analysis.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test fixture testing static detection of hardcoded credential leaks',
    expires: '2027-12-31',
  },
  {
    path: 'src/__tests__/p19_sandbox_runtime_evasion.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test suite verifying SecretSanitizer redaction of Gemini and Supabase keys',
    expires: '2027-12-31',
  },
  {
    path: 'src/__tests__/p32_ci_migration_dr_release.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test suite verifying secret scanner detection of AWS and Gemini keys',
    expires: '2027-12-31',
  },
  {
    path: 'src/__tests__/p35_production_hardening_rc.test.ts',
    owner: 'appsec-engineering',
    reason: 'Negative test validating fail-closed behavior on mock API keys',
    expires: '2027-12-31',
  },
  {
    path: 'src/__tests__/p42_audit_durability_and_fail_secure.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test verifying that audit logs do not leak raw API keys or private RSA keys',
    expires: '2027-12-31',
  },
  {
    path: 'tests/p37_security_infrastructure.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test verifying secret stripping across security infrastructure boundaries',
    expires: '2027-12-31',
  },
  {
    path: 'tests/production-mock-fixture-contamination.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test verifying mock fixtures and development keys are rejected in production',
    expires: '2027-12-31',
  },
  {
    path: 'tests/prompt01r-policy-readiness-auth.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test verifying sandbox policy enforcement and token sanitization',
    expires: '2027-12-31',
  },
  {
    path: 'src/__tests__/p16_taint_analysis.test.ts',
    owner: 'appsec-engineering',
    reason: 'Test verifying taint analysis tracking of token sinks',
    expires: '2027-12-31',
  },
  {
    path: 'tests/release-gate-strictness.test.ts',
    owner: 'appsec-engineering',
    reason: 'Negative test validating bundle secret scanner detection',
    expires: '2027-12-31',
  },
];

export function isAllowlisted(filePath: string): boolean {
  return REVIEWED_ALLOWLIST.some(entry => filePath === entry.path || filePath.endsWith(entry.path));
}

export function scanFileForSecrets(filePath: string, content: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments or explicit test mock markers (e.g. FAKE / test-only-dummy)
    if (
      line.includes('// redacting') || 
      line.includes('// mock') || 
      line.includes('SIMULATED_') || 
      line.includes('test-only-dummy') ||
      line.includes('// secret-scan:ignore') ||
      line.includes('FAKE_') ||
      line.includes('sk-test-FAKE')
    ) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(line)) {
        // Redact matching token for safe reporting
        const match = line.match(pattern.regex);
        const raw = match ? match[0] : 'MATCH';
        const redacted = raw.length > 8 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';

        findings.push({
          file: filePath,
          line: i + 1,
          patternName: pattern.name,
          matchedSnippet: line.replace(raw, redacted).trim(),
          severity: pattern.severity,
        });
      }
    }
  }

  return findings;
}

export function runSecretScan(rootDir: string = process.cwd()): SecretScanResult {
  const startTime = performance.now();
  const findings: SecretFinding[] = [];
  let totalFilesScanned = 0;

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.includes(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (IGNORED_EXTS.includes(ext)) continue;
        if (isAllowlisted(relativePath)) continue;

        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          totalFilesScanned++;
          const fileFindings = scanFileForSecrets(relativePath, content);
          findings.push(...fileFindings);
        } catch {
          // Skip binary or unreadable files
        }
      }
    }
  }

  walk(rootDir);
  const durationMs = Math.round(performance.now() - startTime);

  return {
    passed: findings.length === 0,
    totalFilesScanned,
    findings,
    durationMs,
  };
}

/**
 * Scans generated client and server bundles in dist/ directory.
 * Ensures no server-only secrets or private tokens are leaked into production artifacts.
 */
export function scanBundleDirectory(distDir: string = path.resolve(process.cwd(), 'dist')): {
  passed: boolean;
  totalBundlesScanned: number;
  findings: SecretFinding[];
  clientBundleClean: boolean;
  serverBundleClean: boolean;
  error?: string;
} {
  const findings: SecretFinding[] = [];
  let totalBundlesScanned = 0;
  let clientBundleClean = true;
  let serverBundleClean = true;

  if (!fs.existsSync(distDir)) {
    return {
      passed: false,
      totalBundlesScanned: 0,
      findings: [],
      clientBundleClean: false,
      serverBundleClean: false,
      error: `Bundle scan failed: distribution directory '${distDir}' does not exist. Run 'pnpm run build' before scanning.`,
    };
  }

  function walkDist(dir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkDist(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (['.js', '.cjs', '.mjs', '.html', '.css', '.json'].includes(ext)) {
          totalBundlesScanned++;
          const content = fs.readFileSync(fullPath, 'utf-8');
          const fileFindings = scanFileForSecrets(path.relative(process.cwd(), fullPath), content);
          if (fileFindings.length > 0) {
            findings.push(...fileFindings);
            if (fullPath.includes('/dist/assets') || fullPath.endsWith('.html')) {
              clientBundleClean = false;
            } else {
              serverBundleClean = false;
            }
          }
        }
      }
    }
  }

  walkDist(distDir);

  if (totalBundlesScanned === 0) {
    return {
      passed: false,
      totalBundlesScanned: 0,
      findings: [],
      clientBundleClean: false,
      serverBundleClean: false,
      error: `Bundle scan failed: zero eligible bundle files found in '${distDir}'.`,
    };
  }

  return {
    passed: findings.length === 0,
    totalBundlesScanned,
    findings,
    clientBundleClean,
    serverBundleClean,
  };
}

// CLI Execution Entry Point
if (process.argv[1] && process.argv[1].endsWith('secret-scanner.ts')) {
  const result = runSecretScan();
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) {
    process.exit(1);
  }
  process.exit(0);
}
