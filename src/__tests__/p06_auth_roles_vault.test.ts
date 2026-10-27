import { describe, it, expect } from 'vitest';
import { 
  resolvePrincipalClaims, 
  resolveClassificationClearance, 
  SecurityClassificationRank,
  computeDerivedClassification,
  validateClassificationDerivation,
  filterVaultRecords,
  readVaultItem,
  requireAuth,
  requireRole,
  requireClassification,
  requireScope,
  requireServiceIdentity,
  requireGrant,
  executeWithAuditedOverride,
  UnauthorizedAccessError,
  UnauthorizedVaultAccessError,
  ScopeBoundaryViolationError,
  createBrowserAuthClient,
  createServerAuthHelper,
  hashPassword,
  verifyPassword,
  signAccessToken,
  verifyAccessToken,
  AuthService,
  BusinessRole,
  ServiceIdentity
} from '@caim/auth';
import { createTestDb } from '@caim/db/migrator.ts';
import { Repository } from '@caim/db/repositories.ts';

describe('P06 — Authentication, Roles, RLS & Vault Boundaries Matrix Tests', () => {
  const PLATFORM_SCOPE = '00000000-0000-0000-0000-000000000001';
  const TENANT_A_SCOPE = '00000000-0000-0000-0000-000000000002';
  const TENANT_B_SCOPE = '00000000-0000-0000-0000-000000000003';

  // 1. Role and Claim Matrix Resolution
  describe('1. Role & Claim Resolution Matrix', () => {
    it('resolves ANONYMOUS principal with PUBLIC_METADATA clearance only', () => {
      const context = resolvePrincipalClaims({ principal_id: undefined });
      expect(context.is_authenticated).toBe(false);
      expect(context.roles).toEqual(['anonymous']);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.PUBLIC_METADATA);
    });

    it('resolves USER principal with INTERNAL clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_standard_1', roles: ['user'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.roles).toContain('user');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.INTERNAL);
    });

    it('resolves ANALYST principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_analyst_1', roles: ['analyst'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves REVIEWER principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_reviewer_1', roles: ['reviewer'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves RELEASE_APPROVER principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_approver_1', roles: ['release_approver'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves AUDITOR principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_auditor_1', roles: ['auditor'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves OPERATOR principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_operator_1', roles: ['operator'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves VAULT_READER principal with VAULT_RESTRICTED clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_vault_1', roles: ['vault_reader'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves ADMIN principal with VAULT_RESTRICTED clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_admin_1', roles: ['admin'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves SERVICE-ANALYSIS worker with service identity', () => {
      const context = resolvePrincipalClaims({ 
        principal_id: 'service:service-analysis', 
        is_service: true, 
        service_name: 'service-analysis' 
      });
      expect(context.is_service).toBe(true);
      expect(context.service_name).toBe('service-analysis');
      expect(context.roles).toContain('admin');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves SERVICE-KNOWLEDGE worker with service identity', () => {
      const context = resolvePrincipalClaims({ 
        principal_id: 'service:service-knowledge', 
        is_service: true, 
        service_name: 'service-knowledge' 
      });
      expect(context.is_service).toBe(true);
      expect(context.service_name).toBe('service-knowledge');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });
  });

  // 2. Vault Boundaries & Forbidden Reads / Writes Matrix
  describe('2. Vault Boundaries & Zero Unauthorized Retrieval Gate', () => {
    const mockDataStore = [
      { id: '1', title: 'Public Catalog', security_classification_rank: SecurityClassificationRank.PUBLIC_METADATA },
      { id: '2', title: 'Internal Score Config', security_classification_rank: SecurityClassificationRank.INTERNAL },
      { id: '3', title: 'Static Finding AST', security_classification_rank: SecurityClassificationRank.SENSITIVE },
      { id: '4', title: 'Taint Flow & Secret Leak', security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED },
      { id: '5', title: 'Signing Private Key Ref', security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED },
    ];

    it('GATE: Anonymous user retrieves ZERO non-public records and ZERO vault records', () => {
      const anon = resolvePrincipalClaims({});
      const filtered = filterVaultRecords(anon, mockDataStore);
      expect(filtered.length).toBe(1);
      expect(filtered[0].id).toBe('1');
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
    });

    it('GATE: Standard User retrieves ZERO vault records', () => {
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      const filtered = filterVaultRecords(user, mockDataStore);
      expect(filtered.length).toBe(2);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.SENSITIVE)).toBe(false);
    });

    it('GATE: Analyst retrieves ZERO vault records', () => {
      const analyst = resolvePrincipalClaims({ principal_id: 'a1', roles: ['analyst'] });
      const filtered = filterVaultRecords(analyst, mockDataStore);
      expect(filtered.length).toBe(3);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
    });

    it('GATE: Vault Reader retrieves ALL records including VAULT_RESTRICTED', () => {
      const vaultReader = resolvePrincipalClaims({ principal_id: 'vr1', roles: ['vault_reader'] });
      const filtered = filterVaultRecords(vaultReader, mockDataStore);
      expect(filtered.length).toBe(5);
      expect(filtered.filter(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED).length).toBe(2);
    });

    it('GATE: Admin retrieves ALL records including VAULT_RESTRICTED', () => {
      const admin = resolvePrincipalClaims({ principal_id: 'adm1', roles: ['admin'] });
      const filtered = filterVaultRecords(admin, mockDataStore);
      expect(filtered.length).toBe(5);
    });

    it('GATE: Direct read of Vault item throws UnauthorizedVaultAccessError for non-vault reader', () => {
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      expect(() => {
        readVaultItem(user, {
          id: 'vault_item_1',
          data: { secret: 'super_secret' },
          security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
        });
      }).toThrow(UnauthorizedVaultAccessError);
    });

    it('GATE: Direct read of Vault item succeeds for Vault Reader and Admin', () => {
      const vaultReader = resolvePrincipalClaims({ principal_id: 'vr1', roles: ['vault_reader'] });
      const item = readVaultItem(vaultReader, {
        id: 'vault_item_1',
        data: { secret: 'super_secret' },
        security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
      });
      expect(item.data.secret).toBe('super_secret');
    });
  });

  // 3. Authorization Guards & Forbidden Operations Matrix
  describe('3. Authorization Guards & Role Gating', () => {
    it('enforces requireAuth on anonymous principals', () => {
      const anon = resolvePrincipalClaims({});
      expect(() => requireAuth(anon)).toThrow(UnauthorizedAccessError);
    });

    it('enforces requireRole correctly across matrix', () => {
      const analyst = resolvePrincipalClaims({ principal_id: 'a1', roles: ['analyst'] });
      const approver = resolvePrincipalClaims({ principal_id: 'ap1', roles: ['release_approver'] });
      const admin = resolvePrincipalClaims({ principal_id: 'adm1', roles: ['admin'] });

      // Analyst cannot approve release
      expect(() => requireRole(analyst, ['release_approver'])).toThrow(UnauthorizedAccessError);

      // Approver can approve release
      expect(() => requireRole(approver, ['release_approver'])).not.toThrow();

      // Admin has universal role clearance
      expect(() => requireRole(admin, ['release_approver'])).not.toThrow();
      expect(() => requireRole(admin, ['auditor'])).not.toThrow();
    });

    it('enforces requireServiceIdentity strictly to authorized worker names', () => {
      const serviceAnalysis = resolvePrincipalClaims({ 
        principal_id: 'svc:analysis', 
        is_service: true, 
        service_name: 'service-analysis' 
      });
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });

      expect(() => requireServiceIdentity(serviceAnalysis, ['service-analysis'])).not.toThrow();
      expect(() => requireServiceIdentity(serviceAnalysis, ['service-knowledge'])).toThrow(UnauthorizedAccessError);
      expect(() => requireServiceIdentity(user, ['service-analysis'])).toThrow(UnauthorizedAccessError);
    });

    it('enforces requireScope against cross-tenant access', () => {
      const tenantAUser = resolvePrincipalClaims({ 
        principal_id: 'u_tenantA', 
        roles: ['user'],
        accessible_scope_ids: [PLATFORM_SCOPE, TENANT_A_SCOPE]
      });

      // Allowed on Tenant A
      expect(() => requireScope(tenantAUser, TENANT_A_SCOPE)).not.toThrow();

      // Forbidden on Tenant B (cross-tenant violation)
      expect(() => requireScope(tenantAUser, TENANT_B_SCOPE)).toThrow(ScopeBoundaryViolationError);
    });

    it('enforces requireGrant for granular permissions', () => {
      const userWithoutGrant = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      const userWithGrant = resolvePrincipalClaims({ 
        principal_id: 'u2', 
        roles: ['user'], 
        grants: ['package_shipper'] 
      });

      expect(() => requireGrant(userWithoutGrant, 'package_shipper')).toThrow(UnauthorizedAccessError);
      expect(() => requireGrant(userWithGrant, 'package_shipper')).not.toThrow();
    });
  });

  // 4. Security Classification Propagation & Derivation
  describe('4. Security Classification Monotonic Propagation', () => {
    it('computes output_classification >= max(input_classifications)', () => {
      const inputs = [
        SecurityClassificationRank.PUBLIC_METADATA,
        SecurityClassificationRank.INTERNAL,
        SecurityClassificationRank.SENSITIVE,
      ];
      const maxRank = computeDerivedClassification(inputs);
      expect(maxRank).toBe(SecurityClassificationRank.SENSITIVE);

      // Adding VAULT_RESTRICTED escalates derived output rank
      const inputsWithVault = [...inputs, SecurityClassificationRank.VAULT_RESTRICTED];
      expect(computeDerivedClassification(inputsWithVault)).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('rejects declassification without authorized approval', () => {
      const inputs = [SecurityClassificationRank.SENSITIVE];
      
      // Attempting to output INTERNAL from SENSITIVE input fails
      expect(() => {
        validateClassificationDerivation(inputs, SecurityClassificationRank.INTERNAL, false);
      }).toThrow(UnauthorizedAccessError);

      // With authorized declassification flag, it passes
      expect(validateClassificationDerivation(inputs, SecurityClassificationRank.INTERNAL, true)).toBe(true);
    });
  });

  // 5. Audited Override (Break-Glass) Authorization
  describe('5. Audited Break-Glass Override', () => {
    it('requires min 10 char justification and records immutable audit event on execution', async () => {
      const user = resolvePrincipalClaims({ principal_id: 'usr_operator', roles: ['operator'] });
      const loggedEvents: any[] = [];
      const mockAuditSink = {
        logAuditEvent: (event: any) => {
          loggedEvents.push(event);
        },
      };

      // Rejects empty or too short justification
      await expect(
        executeWithAuditedOverride(
          user,
          {
            actor_id: user.principal_id,
            action: 'EMERGENCY_DECRYPTION',
            target_resource_id: 'vault_res_99',
            target_resource_type: 'VAULT_SECRET',
            justification: 'too short',
            correlation_id: 'corr_123',
          },
          mockAuditSink,
          async () => 'ok'
        )
      ).rejects.toThrow(UnauthorizedAccessError);

      // Valid break-glass execution
      const result = await executeWithAuditedOverride(
        user,
        {
          actor_id: user.principal_id,
          action: 'EMERGENCY_DECRYPTION',
          target_resource_id: 'vault_res_99',
          target_resource_type: 'VAULT_SECRET',
          justification: 'Incident #4092: Emergency production incident mitigation authorized by SecOps',
          correlation_id: 'corr_123',
        },
        mockAuditSink,
        async (elevatedContext) => {
          expect(elevatedContext.is_override_active).toBe(true);
          expect(elevatedContext.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
          return { decrypted: true };
        }
      );

      expect(result.decrypted).toBe(true);
      expect(loggedEvents.length).toBe(1);
      expect(loggedEvents[0].outcome).toBe('SUCCESS');
      expect(loggedEvents[0].action).toBe('AUDITED_OVERRIDE:EMERGENCY_DECRYPTION');
      expect(loggedEvents[0].metadata.justification).toContain('Incident #4092');
    });
  });

  // 6. Client Bundle Secret Boundary Gate
  describe('6. Client Secret Isolation Gate', () => {
    it('GATE: Browser client helper refuses service_role or secret keys', () => {
      expect(() => {
        createBrowserAuthClient({
          supabaseAnonKey: 'service_role_secret_elevated_key_do_not_leak',
        });
      }).toThrow(/FATAL SECURITY VIOLATION/);
    });

    it('GATE: Browser client helper works with public anon key', () => {
      const client = createBrowserAuthClient({
        supabaseAnonKey: 'public-anon-key-safe-for-browsers',
      });
      expect(client.isClientSafe()).toBe(true);
    });
  });

  // 7. Database Security & Tenant Repository Operations
  describe('7. Security Repository & Roles in DB', () => {
    it('manages roles, user_roles, and access_grants in PostgreSQL', async () => {
      const db = createTestDb({ applyMigrations: true, applySeed: true });
      const repo = new Repository(db);

      const allRoles = await repo.getAllRoles();
      expect(allRoles.length).toBeGreaterThanOrEqual(5);

      const analystRole = await repo.getRoleByKey('analyst');
      expect(analystRole).not.toBeNull();

      // Assign user role
      const assigned = await repo.assignUserRole({
        user_role_id: '00000000-0000-0000-0000-111111111111',
        principal_id: 'test_user_01',
        role_id: analystRole!.role_id,
        granted_by: 'test_admin',
      });
      expect(assigned.principal_id).toBe('test_user_01');

      const userRoles = await repo.getUserRoles('test_user_01');
      expect(userRoles.length).toBe(1);

      // Create access grant
      const grant = await repo.createAccessGrant({
        access_grant_id: '00000000-0000-0000-0000-222222222222',
        principal_id: 'test_user_01',
        grant_type: 'vault_reader',
        target_scope: null,
        granted_by: 'test_admin',
        expires_at: null,
      });
      expect(grant.grant_type).toBe('vault_reader');

      const grants = await repo.getAccessGrantsForPrincipal('test_user_01');
      expect(grants.length).toBe(1);
    });
  });

  // 8. Real Authentication, JWT Cryptographic Verification & Header Forgery Rejection
  describe('8. Real Authentication & Header Forgery Rejection Matrix', () => {
    const runtimeJwtSecret = 'test_jwt_sec_' + crypto.randomUUID();
    const serviceMeshSecret = 'test-service-mesh-shared-secret-p06';
    const authHelper = createServerAuthHelper({
      jwtSecret: runtimeJwtSecret,
      serviceSecret: serviceMeshSecret,
      serviceTenantScopes: {
        'service-analysis': ['*'],
      },
    });

    it('GATE: Bcrypt hashes passwords and securely rejects plain or incorrect matches', async () => {
      const plaintext = 'SuperSecret123!';
      const hash = await hashPassword(plaintext);
      
      expect(hash).not.toBe(plaintext);
      expect(hash.startsWith('$2') || hash.startsWith('$argon2')).toBe(true);

      const isMatch = await verifyPassword(plaintext, hash);
      expect(isMatch).toBe(true);

      const isWrongMatch = await verifyPassword('WrongPassword', hash);
      expect(isWrongMatch).toBe(false);
    });

    it('GATE: Forged role headers (x-user-role / x-roles) are STRICTLY IGNORED and resolve to anonymous', async () => {
      // Attacker attempts to forge admin role via client headers without a signed JWT
      const forgedHeaders = {
        'x-roles': 'admin,vault_reader',
        'x-user-role': 'admin',
        'x-role': 'admin',
        'x-tenant-id': TENANT_A_SCOPE,
      };

      const principal = await authHelper.authenticateRequest(forgedHeaders);
      
      expect(principal.is_authenticated).toBe(false);
      expect(principal.roles).toEqual(['anonymous']);
      expect(principal.principal_id).toBe('anonymous');
      expect(principal.max_classification_rank).toBe(SecurityClassificationRank.PUBLIC_METADATA);

      // Attempting protected operations with this principal must fail
      expect(() => requireAuth(principal)).toThrow(UnauthorizedAccessError);
      expect(() => requireRole(principal, ['admin'])).toThrow(UnauthorizedAccessError);
    });

    it('GATE: Forged or tampered JWT tokens are cryptographically rejected', async () => {
      // Token signed with wrong secret key
      const forgedToken = signAccessToken(
        {
          principal_id: 'attacker_1',
          email: 'attacker@evil.com',
          roles: ['admin', 'vault_reader'],
        },
        { secret: 'wrong-malicious-attacker-secret-key' }
      );

      const headers = {
        'authorization': `Bearer ${forgedToken}`,
      };

      const principal = await authHelper.authenticateRequest(headers);
      
      expect(principal.is_authenticated).toBe(false);
      expect(principal.roles).toEqual(['anonymous']);
      expect(() => requireAuth(principal)).toThrow(UnauthorizedAccessError);
    });

    it('GATE: Forged x-service-identity without valid shared secret is REJECTED', async () => {
      // Attacker passes x-service-identity without the matching secret
      const forgedServiceHeaders = {
        'x-service-identity': 'service-analysis',
        // Missing or invalid x-service-secret
        'x-service-secret': 'invalid-attacker-secret',
      };

      const principal = await authHelper.authenticateRequest(forgedServiceHeaders);
      
      expect(principal.is_authenticated).toBe(false);
      expect(principal.is_service).toBe(false);
      expect(principal.roles).toEqual(['anonymous']);
      expect(() => requireServiceIdentity(principal, ['service-analysis'])).toThrow(UnauthorizedAccessError);
    });

    it('GATE: Valid verified service credentials successfully authenticate service worker', async () => {
      const verifiedServiceHeaders = {
        'x-service-identity': 'service-analysis',
        'x-service-secret': 'test-service-mesh-shared-secret-p06',
        'x-tenant-id': TENANT_A_SCOPE,
      };

      const principal = await authHelper.authenticateRequest(verifiedServiceHeaders);
      
      expect(principal.is_authenticated).toBe(true);
      expect(principal.is_service).toBe(true);
      expect(principal.service_name).toBe('service-analysis');
      expect(principal.tenant_id).toBe(TENANT_A_SCOPE);
      expect(() => requireServiceIdentity(principal, ['service-analysis'])).not.toThrow();
    });

    it('GATE: Valid signed JWT securely resolves principal identity and roles', async () => {
      const validToken = signAccessToken(
        {
          principal_id: 'usr_verified_analyst_01',
          email: 'analyst@caim.internal',
          roles: ['analyst'],
          tenant_id: TENANT_A_SCOPE,
        },
        { secret: runtimeJwtSecret }
      );

      const headers = {
        'authorization': `Bearer ${validToken}`,
      };

      const principal = await authHelper.authenticateRequest(headers);
      
      expect(principal.is_authenticated).toBe(true);
      expect(principal.principal_id).toBe('usr_verified_analyst_01');
      expect(principal.roles).toContain('analyst');
      expect(principal.tenant_id).toBe(TENANT_A_SCOPE);
      expect(() => requireAuth(principal)).not.toThrow();
      expect(() => requireRole(principal, ['analyst'])).not.toThrow();
      // Cannot execute admin functions
      expect(() => requireRole(principal, ['admin'])).toThrow(UnauthorizedAccessError);
    });

    it('GATE: Fresh AuthService has zero working default logins until explicitly seeded in dev', async () => {
      AuthService.clearInMemoryPrincipals();
      const freshAuth = new AuthService();

      // Zero working default logins on fresh start
      await expect(
        freshAuth.loginWithPassword({
          email: 'admin@caim.internal',
          password: 'Admin#2026$RotatedRootKey!8472',
        })
      ).rejects.toThrow(/Invalid credentials/);

      // seedDevelopmentPrincipals() fails closed in production
      const prevEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        expect(() => freshAuth.seedDevelopmentPrincipals()).toThrow(/strictly prohibited in production mode/);
      } finally {
        if (prevEnv === undefined) {
          delete process.env.NODE_ENV;
        } else {
          process.env.NODE_ENV = prevEnv;
        }
      }
    });

    it('GATE: AuthService executes full password login, JWT issuance, and refresh token rotation', async () => {
      const authService = new AuthService();
      authService.seedDevelopmentPrincipals();
      
      // 1. Login with seeded admin credentials
      const loginRes = await authService.loginWithPassword({
        email: 'admin@caim.internal',
        password: 'Admin#2026$RotatedRootKey!8472',
      });

      expect(loginRes.token_type).toBe('Bearer');
      expect(loginRes.expires_in).toBe(900); // 15m
      expect(loginRes.access_token).toBeDefined();
      expect(loginRes.refresh_token).toBeDefined();
      expect(loginRes.principal.roles).toContain('admin');

      // 2. Verify issued access token
      const claims = verifyAccessToken(loginRes.access_token);
      expect(claims.sub).toBe(loginRes.principal.principal_id);
      expect(claims.email).toBe('admin@caim.internal');
      expect(claims.roles).toContain('admin');

      // 3. Refresh token rotation
      const refreshRes = await authService.refreshAccessToken(loginRes.refresh_token);
      expect(refreshRes.access_token).toBeDefined();
      expect(refreshRes.refresh_token).toBeDefined();
      expect(refreshRes.refresh_token).not.toBe(loginRes.refresh_token); // Rotated!

      // 4. Old refresh token cannot be reused
      await expect(authService.refreshAccessToken(loginRes.refresh_token)).rejects.toThrow(
        /Invalid, revoked, or expired refresh token/
      );

      // 5. Logout / revoke session
      const revoked = await authService.revokeSession(refreshRes.refresh_token);
      expect(revoked).toBe(true);
      await expect(authService.refreshAccessToken(refreshRes.refresh_token)).rejects.toThrow(
        /Invalid, revoked, or expired refresh token/
      );
    });

    it('GATE: Admin password is rotated away from old credentials and fallback bypass is eliminated', async () => {
      const authService = new AuthService();
      authService.seedDevelopmentPrincipals();

      // 1. Old shared password fails
      await expect(
        authService.loginWithPassword({
          email: 'admin@caim.internal',
          password: 'Admin2026!SecureRoot#',
        })
      ).rejects.toThrow(/Invalid credentials/);

      // 2. Old auditor password for admin fails (no bypass)
      await expect(
        authService.loginWithPassword({
          email: 'admin@caim.internal',
          password: 'Admin123!Secure',
        })
      ).rejects.toThrow(/Invalid credentials/);

      // 3. Rotated high-entropy password succeeds
      const adminLogin = await authService.loginWithPassword({
        email: 'admin@caim.internal',
        password: 'Admin#2026$RotatedRootKey!8472',
      });
      expect(adminLogin.access_token).toBeDefined();
      expect(adminLogin.principal.email).toBe('admin@caim.internal');
    });

    it('GATE: validatePasswordStrength enforces 12+ chars, complexity, and blocks known breached passwords', () => {
      // 1. Too short (< 12)
      expect(AuthService.validatePasswordStrength('Short1!').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('Short1!').error).toContain('at least 12 characters');

      // 2. Missing uppercase
      expect(AuthService.validatePasswordStrength('lowercaseonly123!@#').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('lowercaseonly123!@#').error).toContain('uppercase letter');

      // 3. Missing lowercase
      expect(AuthService.validatePasswordStrength('UPPERCASEONLY123!@#').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('UPPERCASEONLY123!@#').error).toContain('lowercase letter');

      // 4. Missing number
      expect(AuthService.validatePasswordStrength('NoNumbersIncluded!@#$').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('NoNumbersIncluded!@#$').error).toContain('numerical digit');

      // 5. Missing special character
      expect(AuthService.validatePasswordStrength('NoSpecialCharacters1234').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('NoSpecialCharacters1234').error).toContain('special character');

      // 6. Known breached password
      expect(AuthService.validatePasswordStrength('Admin2026!SecureRoot#').valid).toBe(false);
      expect(AuthService.validatePasswordStrength('Admin2026!SecureRoot#').error).toContain('known-compromised');

      // 7. Strong valid password
      expect(AuthService.validatePasswordStrength('Secure#Rotated2026!Key$77').valid).toBe(true);
    });

    it('GATE: AuthService.changePassword updates bcrypt hash and invalidates all existing refresh tokens', async () => {
      const authService = new AuthService();

      // 1. Log in auditor to create an active session
      const login1 = await authService.loginWithPassword({
        email: 'auditor@caim.internal',
        password: 'Admin123!Secure',
      });
      const principalId = login1.principal.principal_id;
      const initialRefreshToken = login1.refresh_token;

      // 2. Log in a second session for the same principal
      const login2 = await authService.loginWithPassword({
        email: 'auditor@caim.internal',
        password: 'Admin123!Secure',
      });
      const secondRefreshToken = login2.refresh_token;

      // 3. Re-verification failure with incorrect current password
      await expect(
        authService.changePassword({
          principalId,
          currentPassword: 'WrongCurrentPassword!123',
          newPassword: 'BrandNew#SecurePassword2026!',
        })
      ).rejects.toThrow(/Incorrect current password/);

      // 4. Rejection when new password is same as current password
      await expect(
        authService.changePassword({
          principalId,
          currentPassword: 'Admin123!Secure',
          newPassword: 'Admin123!Secure',
        })
      ).rejects.toThrow(/New password cannot be identical/);

      // 5. Rejection when new password is weak or breached
      await expect(
        authService.changePassword({
          principalId,
          currentPassword: 'Admin123!Secure',
          newPassword: 'weak',
        })
      ).rejects.toThrow(/at least 12 characters/);

      // 6. Successful password rotation
      const result = await authService.changePassword({
        principalId,
        currentPassword: 'Admin123!Secure',
        newPassword: 'BrandNew#SecurePassword2026!',
      });
      expect(result.success).toBe(true);
      expect(result.invalidatedSessionsCount).toBeGreaterThanOrEqual(2);

      // 7. Old password no longer works
      await expect(
        authService.loginWithPassword({
          email: 'auditor@caim.internal',
          password: 'Admin123!Secure',
        })
      ).rejects.toThrow(/Invalid credentials/);

      // 8. New password works successfully
      const newLogin = await authService.loginWithPassword({
        email: 'auditor@caim.internal',
        password: 'BrandNew#SecurePassword2026!',
      });
      expect(newLogin.access_token).toBeDefined();

      // 9. Prior refresh tokens (sessions created before password change) are completely invalidated
      await expect(authService.refreshAccessToken(initialRefreshToken)).rejects.toThrow(
        /Invalid, revoked, or expired refresh token/
      );
      await expect(authService.refreshAccessToken(secondRefreshToken)).rejects.toThrow(
        /Invalid, revoked, or expired refresh token/
      );

      // 10. Newly issued refresh token after rotation works normally
      const refreshedNew = await authService.refreshAccessToken(newLogin.refresh_token);
      expect(refreshedNew.access_token).toBeDefined();
    });
  });
});

