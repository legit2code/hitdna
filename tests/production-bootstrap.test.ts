import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { AuthService } from '@caim/auth/service.ts';
import { ProductionBootstrapManager } from '@caim/auth/bootstrap.ts';

describe('Production Administrator Bootstrap & Migration Invariants', () => {
  let authService: AuthService;
  const testCredentialsPath = '/tmp/test-caim-bootstrap-credentials.json';
  const testTokenPath = '/tmp/test-caim-bootstrap-token.txt';

  beforeEach(() => {
    AuthService.clearInMemoryPrincipals();
    ProductionBootstrapManager.invalidateEnrollmentToken();
    process.env.BOOTSTRAP_TOKEN_FILE = testTokenPath;
    process.env.BOOTSTRAP_CREDENTIALS_FILE = testCredentialsPath;

    if (fs.existsSync(testCredentialsPath)) {
      try { fs.unlinkSync(testCredentialsPath); } catch {}
    }
    if (fs.existsSync(testTokenPath)) {
      try { fs.unlinkSync(testTokenPath); } catch {}
    }
  });

  it('1. Migrations audit: verifies migration 20260823000016 contains no password seeding or ON CONFLICT reset', () => {
    const migrationPath = path.join(process.cwd(), 'supabase/migrations/20260823000016_p06_seed_admin_principal.sql');
    expect(fs.existsSync(migrationPath)).toBe(true);

    const content = fs.readFileSync(migrationPath, 'utf8');

    // Remove SQL comments for structural check
    const uncommented = content.replace(/--.*$/gm, '');

    expect(uncommented).not.toContain('INSERT INTO security.principals');
    expect(uncommented).not.toContain('hashed_password');
    expect(uncommented).not.toContain('ON CONFLICT (email) DO UPDATE');
    expect(uncommented).not.toContain('EXCLUDED.hashed_password');
    expect(uncommented).not.toContain('EXCLUDED.roles');
  });

  it('2. Codebase audit: confirms NO migration contains an ON CONFLICT ... DO UPDATE pattern touching hashed_password or roles', () => {
    const migrationsDir = path.join(process.cwd(), 'supabase/migrations');
    const files = fs.readdirSync(migrationsDir).filter((f) => f.endsWith('.sql'));

    for (const file of files) {
      const fullPath = path.join(migrationsDir, file);
      const content = fs.readFileSync(fullPath, 'utf8');
      const uncommented = content.replace(/--.*$/gm, '');

      // Check for ON CONFLICT ... DO UPDATE clauses
      const updateMatches = uncommented.match(/ON\s+CONFLICT[\s\S]*?DO\s+UPDATE\s+SET[\s\S]*?;/gi);
      if (updateMatches) {
        for (const match of updateMatches) {
          expect(match).not.toMatch(/hashed_password\s*=/i);
          expect(match).not.toMatch(/roles\s*=/i);
        }
      }
    }
  });

  it('3. Bootstrap Status: detects unbootstrapped state and reflects admin count accurately', async () => {
    authService = new AuthService();

    // Clean state: no admin
    const initialStatus = await ProductionBootstrapManager.checkBootstrapStatus(authService);
    expect(initialStatus.requires_bootstrap).toBe(true);
    expect(initialStatus.admin_count).toBe(0);
    expect(initialStatus.enrollment_enabled).toBe(true);

    // Register a standard user
    await authService.registerPrincipal({
      email: 'regular.user@caim.internal',
      password: 'RegularUser#2026!Sec',
    });

    // Still requires bootstrap (only standard user exists)
    const afterUserStatus = await ProductionBootstrapManager.checkBootstrapStatus(authService);
    expect(afterUserStatus.requires_bootstrap).toBe(true);
    expect(afterUserStatus.admin_count).toBe(0);
  });

  it('4. Deploy-time bootstrap: generates high-entropy random secret, delivers out-of-band, and succeeds authentication', async () => {
    authService = new AuthService();

    const bootResult = await ProductionBootstrapManager.executeDeployTimeBootstrap(authService, {
      adminEmail: 'root-admin@caim.internal',
      credentialsFilePath: testCredentialsPath,
      forceOneTimeSecret: true,
    });

    expect(bootResult.bootstrapped).toBe(true);
    expect(bootResult.method).toBe('random_secret_out_of_band');
    expect(bootResult.email).toBe('root-admin@caim.internal');
    // Invariant: Application code NEVER holds or returns the plaintext secret in response
    expect((bootResult as any).oneTimeSecret).toBeUndefined();
    expect(bootResult.credentialsFilePath).toBe(testCredentialsPath);

    // Verify out-of-band credential file exists and has restrictive permissions (mode 0600)
    expect(fs.existsSync(testCredentialsPath)).toBe(true);
    const fileStat = fs.statSync(testCredentialsPath);
    // 0o600 on POSIX is 33152 in decimal mode & 0o777 === 0o600
    expect((fileStat.mode & 0o777)).toBe(0o600);

    const fileContent = JSON.parse(fs.readFileSync(testCredentialsPath, 'utf8'));
    expect(fileContent.email).toBe('root-admin@caim.internal');
    expect(fileContent.one_time_secret).toBeDefined();

    const secret = fileContent.one_time_secret;
    // Secret must pass complexity validation
    const validation = AuthService.validatePasswordStrength(secret);
    expect(validation.valid).toBe(true);

    // Verify administrator can successfully authenticate with this one-time secret
    const loginRes = await authService.loginWithPassword({
      email: 'root-admin@caim.internal',
      password: secret,
    });
    expect(loginRes.access_token).toBeDefined();
    expect(loginRes.principal.roles).toContain('admin');

    // CRITICAL IDEMPOTENCY TEST:
    // Future bootstrap or migration run MUST NOT reset password!
    const secondBootResult = await ProductionBootstrapManager.executeDeployTimeBootstrap(authService, {
      adminEmail: 'root-admin@caim.internal',
      password: 'AttackerSecurePass#2026!Sec',
    });

    expect(secondBootResult.bootstrapped).toBe(false);
    expect(secondBootResult.method).toBe('skipped_admin_exists');

    // Verify original password STILL WORKS and was NOT reset
    const reLogin = await authService.loginWithPassword({
      email: 'root-admin@caim.internal',
      password: secret,
    });
    expect(reLogin.access_token).toBeDefined();

    // Verify attacker injected password fails
    await expect(
      authService.loginWithPassword({
        email: 'root-admin@caim.internal',
        password: 'AttackerSecurePass#2026!Sec',
      })
    ).rejects.toThrow(/Invalid credentials/);
  });

  it('5. First-run enrollment flow: enforces single-use token, creates admin, and permanently closes enrollment', async () => {
    authService = new AuthService();

    const token = ProductionBootstrapManager.getOrCreateEnrollmentToken();
    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThanOrEqual(32);

    // 1. Invalid token attempt rejected
    await expect(
      ProductionBootstrapManager.enrollFirstRunAdmin(authService, {
        email: 'first-admin@caim.internal',
        password: 'EnrollPassword#2026!Sec',
        enrollment_token: 'invalid_forged_token_12345678901234567890',
      })
    ).rejects.toThrow(/Invalid bootstrap enrollment token/);

    // 2. Valid enrollment succeeds
    const enrolled = await ProductionBootstrapManager.enrollFirstRunAdmin(authService, {
      email: 'first-admin@caim.internal',
      password: 'EnrollPassword#2026!Sec',
      enrollment_token: token,
    });

    expect(enrolled.status).toBe('enrolled');
    expect(enrolled.email).toBe('first-admin@caim.internal');
    expect(enrolled.roles).toContain('admin');

    // 3. Admin can authenticate
    const login = await authService.loginWithPassword({
      email: 'first-admin@caim.internal',
      password: 'EnrollPassword#2026!Sec',
    });
    expect(login.access_token).toBeDefined();

    // 4. Token is destroyed and enrollment is permanently closed
    await expect(
      ProductionBootstrapManager.enrollFirstRunAdmin(authService, {
        email: 'second-admin@caim.internal',
        password: 'AnotherPassword#2026!Sec',
        enrollment_token: token,
      })
    ).rejects.toThrow(/closed/);
  });
});
