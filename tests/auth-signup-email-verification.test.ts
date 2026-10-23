import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express, { Request, Response } from 'express';
import { Server } from 'http';
import { 
  AuthService, 
  getStubEmailSender, 
  resetEmailSender, 
  InMemoryEmailSender,
  createServerAuthHelper
} from '@caim/auth';

describe('End-to-End Signup & Email Verification Flow', () => {
  let app: express.Application;
  let server: Server;
  let baseUrl: string;
  let authService: AuthService;
  let emailSender: InMemoryEmailSender;

  beforeEach(async () => {
    AuthService.clearInMemoryPrincipals();
    AuthService.seedDevelopmentPrincipals();
    resetEmailSender();
    emailSender = getStubEmailSender();

    authService = new AuthService(undefined, emailSender);

    app = express();
    app.use(express.json());

    // Public Registration Endpoint
    app.post('/api/auth/register', async (req: Request, res: Response) => {
      try {
        const { email, password, terms_accepted } = req.body || {};
        if (!email || !password) {
          return res.status(400).json({ error: 'Missing required fields: email and password.' });
        }
        if (terms_accepted !== true) {
          return res.status(400).json({ error: 'Terms of service and privacy policy must be accepted.' });
        }

        // Public registration ignores any supplied roles or tenant_id
        const newPrincipal = await authService.registerPrincipal({
          email,
          password,
          is_admin_action: false,
        });

        return res.status(201).json({
          status: 'created',
          message: 'Account created. Please check your email to verify your address.',
          principal: newPrincipal,
        });
      } catch (err: any) {
        return res.status(400).json({ error: err.message || 'Registration failed.' });
      }
    });

    // Verification endpoint
    app.post('/api/auth/verify-email', async (req: Request, res: Response) => {
      try {
        const { token, email } = req.body || {};
        if (!token) {
          return res.status(400).json({ error: 'Verification token is required.' });
        }
        const result = await authService.verifyEmail(token, email);
        return res.json({
          status: 'verified',
          message: 'Email address verified successfully.',
          email: result.email,
        });
      } catch (err: any) {
        return res.status(400).json({ error: err.message || 'Verification failed.' });
      }
    });

    // Resend verification endpoint
    app.post('/api/auth/resend-verification', async (req: Request, res: Response) => {
      try {
        const { email } = req.body || {};
        if (!email) {
          return res.status(400).json({ error: 'Email is required.' });
        }
        await authService.resendEmailVerification(email);
        return res.json({
          status: 'sent',
          message: 'If the email exists and is unverified, a new verification link has been sent.',
        });
      } catch (err: any) {
        return res.status(400).json({ error: err.message || 'Failed to resend verification.' });
      }
    });

    // Login endpoint
    app.post('/api/auth/login', async (req: Request, res: Response) => {
      try {
        const { email, password } = req.body || {};
        if (!email || !password) {
          return res.status(400).json({ error: 'Email and password required.' });
        }
        const session = await authService.loginWithPassword({ email, password });
        return res.json({
          status: 'authenticated',
          access_token: session.access_token,
          principal: session.principal,
        });
      } catch (err: any) {
        return res.status(401).json({ error: err.message || 'Login failed.' });
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

  it('demonstrates the complete signup -> unverified check -> token verify -> authenticated login flow', async () => {
    const signupEmail = 'analyst.jane@defense-research.org';
    const strongPassword = 'JaneSecure2026!Password';

    // 1. Attempt signup with attempted privilege escalation (roles: ['admin', 'superadmin'], tenant_id: 'root_override')
    const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        password: strongPassword,
        terms_accepted: true,
        roles: ['admin', 'superadmin'],
        tenant_id: 'root_override',
      }),
    });

    expect(registerRes.status).toBe(201);
    const registerBody = await registerRes.json();
    expect(registerBody.status).toBe('created');
    expect(registerBody.principal.email).toBe(signupEmail);

    // CRITICAL RBAC ASSERTIONS:
    // Roles MUST be strictly ['user'], never elevated
    expect(registerBody.principal.roles).toEqual(['user']);
    expect(registerBody.principal.roles).not.toContain('admin');
    // Tenant ID MUST NOT be accepted from client body
    expect(registerBody.principal.tenant_id).not.toBe('root_override');
    expect(registerBody.principal.tenant_id).toBe('tenant_defense_research_org');
    // Verification flag MUST be false upon initial self-registration
    expect(registerBody.principal.email_verified).toBe(false);

    // 2. Verify an email was sent via the EmailSender abstraction
    const sentMessages = emailSender.getSentEmails();
    expect(sentMessages.length).toBe(1);
    expect(sentMessages[0].to).toBe(signupEmail);
    expect(sentMessages[0].subject).toContain('Verify your CAIM account email address');

    // Extract the verification token from the email body
    const tokenMatch = sentMessages[0].text.match(/verification code: ([a-zA-Z0-9_-]+)/i) || 
                       sentMessages[0].text.match(/token=([a-zA-Z0-9_-]+)/i);
    expect(tokenMatch).not.toBeNull();
    const verificationToken = tokenMatch![1];
    expect(verificationToken.length).toBeGreaterThanOrEqual(16);

    // 3. Attempt to login before verifying email - MUST BE REJECTED
    const preVerifyLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        password: strongPassword,
      }),
    });

    expect(preVerifyLoginRes.status).toBe(401);
    const preVerifyLoginBody = await preVerifyLoginRes.json();
    expect(preVerifyLoginBody.error).toMatch(/Email not verified/i);

    // 4. Test invalid token rejection
    const invalidTokenRes = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        token: 'invalid-token-12345',
      }),
    });

    expect(invalidTokenRes.status).toBe(400);
    const invalidTokenBody = await invalidTokenRes.json();
    expect(invalidTokenBody.error).toMatch(/invalid or expired/i);

    // 5. Submit valid verification token
    const verifyRes = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        token: verificationToken,
      }),
    });

    expect(verifyRes.status).toBe(200);
    const verifyBody = await verifyRes.json();
    expect(verifyBody.status).toBe('verified');
    expect(verifyBody.email).toBe(signupEmail);

    // 6. Token replay protection: submitting the same token a second time should fail
    const replayRes = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        token: verificationToken,
      }),
    });
    expect(replayRes.status).toBe(400);

    // 7. Login now succeeds!
    const postVerifyLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        password: strongPassword,
      }),
    });

    expect(postVerifyLoginRes.status).toBe(200);
    const postVerifyLoginBody = await postVerifyLoginRes.json();
    expect(postVerifyLoginBody.status).toBe('authenticated');
    expect(postVerifyLoginBody.access_token).toBeDefined();
    expect(postVerifyLoginBody.principal.email).toBe(signupEmail);
    expect(postVerifyLoginBody.principal.email_verified).toBe(true);
    expect(postVerifyLoginBody.principal.roles).toEqual(['user']);
    expect(postVerifyLoginBody.principal.roles).not.toContain('admin');
  });

  it('resend verification code dispatches a new token when previous token is unused', async () => {
    const signupEmail = 'resend.test@corp.com';
    const strongPassword = 'CorpSecure2026!Key';

    await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: signupEmail,
        password: strongPassword,
        terms_accepted: true,
      }),
    });

    expect(emailSender.getSentEmails().length).toBe(1);

    // Trigger resend
    const resendRes = await fetch(`${baseUrl}/api/auth/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: signupEmail }),
    });

    expect(resendRes.status).toBe(200);
    expect(emailSender.getSentEmails().length).toBe(2);

    const latestEmail = emailSender.getSentEmails()[1];
    const match = latestEmail.text.match(/verification code: ([a-zA-Z0-9_-]+)/i) || 
                  latestEmail.text.match(/token=([a-zA-Z0-9_-]+)/i);
    expect(match).not.toBeNull();
    const newToken = match![1];

    // Verify using the newly resent token
    const verifyRes = await fetch(`${baseUrl}/api/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: signupEmail, token: newToken }),
    });
    expect(verifyRes.status).toBe(200);
  });
});
