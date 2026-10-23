import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import {
  TenantInvitationManager,
  DEFAULT_JWT_SECRET,
  getJwtSecret,
  getInvitationSigningSecret,
  AuthService,
} from '@caim/auth';
import { ProductionConfigValidator } from '@caim/config';

describe('P1 Defects Regression Suite', () => {
  // Test A: Seeded tokens must be rejected
  it('rejects old seeded tokens (inv_enterprise_tok123, inv_partner_tok456, inv_tenant_acme_corp)', () => {
    const manager = TenantInvitationManager.getInstance();
    const seededTokens = ['inv_enterprise_tok123', 'inv_partner_tok456', 'inv_tenant_acme_corp'];

    for (const tok of seededTokens) {
      expect(() => {
        manager.validateInvitation(tok);
      }).toThrow(/Forged or unrecognized invitation token/);
    }
  });

  // Test B: Forging a token with the old literal secret must be rejected
  it('rejects invitation token forged with old literal secret', () => {
    const manager = TenantInvitationManager.getInstance();
    const oldSecret = 'caim-ephemeral-jwt-signing-secret-default-2026';
    const forgedToken = jwt.sign(
      {
        invitation_id: 'forged_001',
        tenant_id: 'tenant_victim_corp',
        intended_role: 'admin',
      },
      oldSecret,
      {
        algorithm: 'HS256',
        issuer: 'caim-invitation-service',
        audience: 'caim-platform',
        expiresIn: '1h',
      }
    );

    expect(() => {
      manager.validateInvitation(forgedToken);
    }).toThrow(/Forged or invalid cryptographic invitation token/);
  });

  // Test C: In NODE_ENV=production, missing, short, or default secret throws
  it('getJwtSecret() throws in NODE_ENV=production when missing or weak', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalJwtSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.JWT_SECRET;
      expect(() => getJwtSecret()).toThrow();

      process.env.JWT_SECRET = 'short-secret';
      expect(() => getJwtSecret()).toThrow();

      process.env.JWT_SECRET = 'caim-ephemeral-jwt-signing-secret-default-2026';
      expect(() => getJwtSecret()).toThrow();
    } finally {
      process.env.NODE_ENV = originalEnv;
      if (originalJwtSecret !== undefined) process.env.JWT_SECRET = originalJwtSecret;
      else delete process.env.JWT_SECRET;
    }
  });

  it('getInvitationSigningSecret() throws in NODE_ENV=production when missing, weak, or equals JWT_SECRET', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalInvSecret = process.env.INVITATION_SIGNING_SECRET;
    const originalJwtSecret = process.env.JWT_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.INVITATION_SIGNING_SECRET;
      expect(() => getInvitationSigningSecret()).toThrow();

      process.env.INVITATION_SIGNING_SECRET = 'short';
      expect(() => getInvitationSigningSecret()).toThrow();

      // Cannot reuse JWT_SECRET
      const strongSecret = 'a-very-strong-secret-that-is-over-32-characters-long';
      process.env.JWT_SECRET = strongSecret;
      process.env.INVITATION_SIGNING_SECRET = strongSecret;
      expect(() => getInvitationSigningSecret()).toThrow();
    } finally {
      process.env.NODE_ENV = originalEnv;
      if (originalInvSecret !== undefined) process.env.INVITATION_SIGNING_SECRET = originalInvSecret;
      else delete process.env.INVITATION_SIGNING_SECRET;
      if (originalJwtSecret !== undefined) process.env.JWT_SECRET = originalJwtSecret;
      else delete process.env.JWT_SECRET;
    }
  });

  // Test D: Production validator fails when only supabaseServiceKey is set
  it('ProductionConfigValidator fails when only supabaseServiceKey is present without JWT_SECRET and INVITATION_SIGNING_SECRET', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalJwt = process.env.JWT_SECRET;
    const originalInv = process.env.INVITATION_SIGNING_SECRET;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.JWT_SECRET;
      delete process.env.INVITATION_SIGNING_SECRET;

      const report = ProductionConfigValidator.validate({
        environment: 'production',
        auth: {} as any,
        providers: {
          supabaseServiceKey: 'ey-some-valid-supabase-service-key-token-here-1234567890',
        } as any,
      } as any);

      const jwtFinding = report.findings.find(f => f.key === 'JWT_SECRET');
      const invFinding = report.findings.find(f => f.key === 'INVITATION_SIGNING_SECRET');

      expect(jwtFinding?.passed).toBe(false);
      expect(invFinding?.passed).toBe(false);
    } finally {
      process.env.NODE_ENV = originalEnv;
      if (originalJwt) process.env.JWT_SECRET = originalJwt;
      else delete process.env.JWT_SECRET;
      if (originalInv) process.env.INVITATION_SIGNING_SECRET = originalInv;
      else delete process.env.INVITATION_SIGNING_SECRET;
    }
  });

  // Test E: Role cap: admin invitation created by non-admin is rejected
  it('rejects creation of an admin invitation by a non-admin creator', () => {
    const manager = TenantInvitationManager.getInstance();
    expect(() => {
      manager.createOpaqueInvitation({
        tenant_id: 'tenant_acme_corp',
        intended_role: 'admin',
        created_by: 'user@acme.com',
        creator: {
          principal_id: 'user_001',
          email: 'user@acme.com',
          roles: ['user'],
          is_authenticated: true,
        } as any,
      });
    }).toThrow(/Cannot create an invitation granting role 'admin'/);
  });

  // Test F: Domain-based tenant mapping stays in NULL-tenant pending state until email verified
  it('keeps self-registered principal in NULL-tenant pending state until email is verified', async () => {
    AuthService.clearInMemoryPrincipals();
    const authService = new AuthService();

    const registered = await authService.registerPrincipal({
      email: 'employee@corporate-domain.com',
      password: 'StrongPassword2026!Valid',
      is_admin_action: false,
    });

    // Invariant: Unverified user must NOT have active tenant membership
    expect(registered.email_verified).toBe(false);
    expect(registered.tenant_id).toBeNull();

    // After email verification, tenant is activated
    const token = (registered as any).email_verification_token || 
      (AuthService as any).inMemoryPrincipals.get('employee@corporate-domain.com')?.email_verification_token;
    if (token) {
      await authService.verifyEmail(token, 'employee@corporate-domain.com');
      const verified = (AuthService as any).inMemoryPrincipals.get('employee@corporate-domain.com');
      expect(verified?.email_verified).toBe(true);
      expect(verified?.tenant_id).toBe('tenant_corporate_domain_com');
    }
  });
});
