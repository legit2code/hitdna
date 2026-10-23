import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express, { Request, Response, NextFunction } from 'express';
import { Server } from 'http';
import { 
  AuthService, 
  CapabilityGrantService, 
  requireCapabilityGrant, 
  createServerAuthHelper,
  PlatformAuditService,
  UnauthorizedAccessError 
} from '@caim/auth';

describe('Auth Registration & RBAC Hardening', () => {
  let app: express.Application;
  let server: Server;
  let baseUrl: string;
  let authService: AuthService;
  let capabilityGrantService: CapabilityGrantService;
  let platformAuditService: PlatformAuditService;

  beforeEach(async () => {
    AuthService.clearInMemoryPrincipals();
    AuthService.seedDevelopmentPrincipals();

    authService = new AuthService();
    capabilityGrantService = new CapabilityGrantService();
    platformAuditService = new PlatformAuditService();
    const authHelper = createServerAuthHelper();

    app = express();
    app.use(express.json());

    // Middleware to extract principal
    app.use(async (req: Request, _res: Response, next: NextFunction) => {
      try {
        (req as any).principal = await authHelper.authenticateRequest(req.headers as any);
      } catch {
        (req as any).principal = {
          principal_id: 'anonymous',
          is_authenticated: false,
          is_service: false,
          roles: ['anonymous'],
          tenant_id: null,
          accessible_scope_ids: [],
          max_classification_rank: 0,
          is_override_active: false,
          grants: [],
        };
      }
      next();
    });

    // Public Registration Endpoint
    app.post('/api/auth/register', async (req: Request, res: Response) => {
      try {
        const { email, password, invitation_token, invitationToken } = req.body || {};
        if (!email || !password) {
          return res.status(400).json({ error: 'Missing required fields: email and password.' });
        }
        // Public registration: caller-supplied roles and tenant_id are STRICTLY IGNORED
        const newPrincipal = await authService.registerPrincipal({
          email,
          password,
          invitation_token: invitation_token || invitationToken,
          is_admin_action: false,
        });

        return res.status(201).json({ status: 'created', principal: newPrincipal });
      } catch (err: any) {
        return res.status(400).json({ error: err.message || 'Registration failed.' });
      }
    });

    // Dedicated Authenticated-Admin-Only Endpoint
    app.post(['/api/admin/principals', '/api/auth/admin/register'], async (req: Request, res: Response) => {
      try {
        const principal = (req as any).principal;
        if (!principal || !principal.is_authenticated || principal.principal_id === 'anonymous') {
          return res.status(401).json({
            error: 'Unauthorized: Valid authenticated session token required.',
            authenticated: false,
          });
        }

        await requireCapabilityGrant(principal, ['admin:manage_principals', 'composer:full_access'], {
          grantService: capabilityGrantService,
        });

        const { email, password, roles, tenant_id, external_identity_provider_id } = req.body || {};
        if (!email || !password) {
          return res.status(400).json({ error: 'Missing required fields: email and password.' });
        }

        const newPrincipal = await authService.registerPrincipal({
          email,
          password,
          roles: roles && Array.isArray(roles) && roles.length > 0 ? roles : undefined,
          tenant_id: tenant_id || undefined,
          external_identity_provider_id,
          caller: principal,
          allowElevatedRoles: true,
          is_admin_action: true,
        });

        return res.status(201).json({ status: 'created', principal: newPrincipal });
      } catch (err: any) {
        if (err instanceof UnauthorizedAccessError) {
          return res.status(403).json({ error: err.message, authenticated: true });
        }
        return res.status(400).json({ error: err.message || 'Failed to create principal.' });
      }
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const port = (server.address() as any).port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('POST /api/auth/register with {"roles": ["admin"]} assigns role ["user"] and NOT admin', async () => {
    const maliciousPayload = {
      email: 'attacker@evilcorp.com',
      password: 'HackerAuth_2026!Key',
      roles: ['admin'],
      tenant_id: 'injected_tenant_root',
    };

    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(maliciousPayload),
    });

    expect(res.status).toBe(201);
    const body = await res.json();

    expect(body.status).toBe('created');
    expect(body.principal).toBeDefined();
    expect(body.principal.email).toBe('attacker@evilcorp.com');

    // CRITICAL ASSERTION: The resulting principal has role ['user'], NOT admin
    expect(body.principal.roles).toEqual(['user']);
    expect(body.principal.roles).not.toContain('admin');

    // CRITICAL ASSERTION: tenant_id was not accepted from the caller
    expect(body.principal.tenant_id).not.toBe('injected_tenant_root');
    expect(body.principal.tenant_id).toBe('tenant_evilcorp_com');
  });

  it('registerPrincipal() directly ignores caller roles and tenant_id when is_admin_action is false or omitted', async () => {
    const unauthenticatedAttempt = await authService.registerPrincipal({
      email: 'direct-caller@gmail.com',
      password: 'SecretVault_2026!Key',
      roles: ['admin', 'operator', 'auditor'],
      tenant_id: 'forged_tenant_id',
      // is_admin_action is intentionally omitted
    });

    expect(unauthenticatedAttempt.roles).toEqual(['user']);
    expect(unauthenticatedAttempt.roles).not.toContain('admin');
    expect(unauthenticatedAttempt.tenant_id).toBeNull();
  });

  it('registerPrincipal() resolves server-side tenant from valid invitation token', async () => {
    const invitedUser = await authService.registerPrincipal({
      email: 'invited@randommail.com',
      password: 'InvitedUser_2026!Key',
      invitation_token: 'inv_tenant_acme_corp',
    });

    expect(invitedUser.roles).toEqual(['user']);
    expect(invitedUser.tenant_id).toBe('tenant_acme_corp');
  });

  it('unauthenticated caller to /api/admin/principals is rejected with 401', async () => {
    const res = await fetch(`${baseUrl}/api/admin/principals`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'newadmin@caim.internal',
        password: 'AdminPassword123!',
        roles: ['admin'],
      }),
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain('Unauthorized');
  });

  it('authenticated non-admin user to /api/admin/principals is rejected with 403', async () => {
    // Regular user logs in
    const userLogin = await authService.loginWithPassword({
      email: 'user@caim.internal',
      password: 'User123!Secure',
    });

    const res = await fetch(`${baseUrl}/api/admin/principals`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userLogin.access_token}`,
      },
      body: JSON.stringify({
        email: 'privileged@caim.internal',
        password: 'AdminPassword123!',
        roles: ['admin'],
      }),
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toMatch(/lacks active|does not have an active capability grant/);
  });

  it('authenticated admin with capability grant can create principal with elevated roles and specific tenant', async () => {
    // Admin logs in
    const adminLogin = await authService.loginWithPassword({
      email: 'admin@caim.internal',
      password: 'Admin#2026$RotatedRootKey!8472',
    });

    const res = await fetch(`${baseUrl}/api/admin/principals`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminLogin.access_token}`,
      },
      body: JSON.stringify({
        email: 'security-engineer@caim.internal',
        password: 'ComplexAdmin_2026!Key',
        roles: ['admin', 'operator', 'auditor'],
        tenant_id: 'tenant_platform_core',
      }),
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.status).toBe('created');
    expect(body.principal.email).toBe('security-engineer@caim.internal');
    expect(body.principal.roles).toEqual(['admin', 'operator', 'auditor']);
    expect(body.principal.tenant_id).toBe('tenant_platform_core');
  });
});
