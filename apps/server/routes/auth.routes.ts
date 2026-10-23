import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { parseCookies, requireAuthenticatedPrincipal } from "../middleware/security.ts";
import { ProductionBootstrapManager, UnauthorizedAccessError } from "@caim/auth";

export function registerAuthRoutes(app: Express, container: ServiceContainer) {
  const { authService, platformAuditService, rateLimiterEngine, csrfProtectionEngine, config } = container;

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      const { email, password, username } = req.body || {};
      const userEmail = email || username;
      if (!userEmail || !password) {
        return res.status(400).json({ error: "Missing required fields: email and password." });
      }
      const authResult = await authService.loginWithPassword({ email: userEmail, password });

      // Move refresh token to an httpOnly, Secure, SameSite cookie set by the server
      res.cookie('refresh_token', authResult.refresh_token, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: authResult.principal.principal_id,
        action: 'AUTHENTICATION_LOGIN',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: authResult.principal.principal_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { email: authResult.principal.email, roles: authResult.principal.roles },
      });

      return res.json(authResult);
    } catch (err: any) {
      return res.status(401).json({ error: err.message || "Invalid credentials." });
    }
  });

  app.post("/api/auth/refresh", async (req: Request, res: Response) => {
    try {
      const cookies = (req as any).cookies || parseCookies(req.headers.cookie);
      const refreshToken = cookies['refresh_token'] || cookies['caim_refresh_token'] || req.body?.refresh_token;
      if (!refreshToken) {
        return res.status(400).json({ error: "Missing refresh_token in cookie or request body." });
      }
      const refreshed = await authService.refreshAccessToken(refreshToken);

      // Rotate / refresh httpOnly cookie
      if (refreshed.refresh_token) {
        res.cookie('refresh_token', refreshed.refresh_token, {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          path: '/',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
      }

      return res.json(refreshed);
    } catch (err: any) {
      return res.status(401).json({ error: err.message || "Invalid or expired refresh token." });
    }
  });

  app.post("/api/auth/logout", async (req: Request, res: Response) => {
    try {
      const cookies = (req as any).cookies || parseCookies(req.headers.cookie);
      const refreshToken = cookies['refresh_token'] || cookies['caim_refresh_token'] || req.body?.refresh_token;
      if (refreshToken) {
        await authService.revokeSession(refreshToken);
      }
      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
      });
      return res.json({ status: "logged_out", success: true });
    } catch {
      res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
      });
      return res.json({ status: "logged_out", success: true });
    }
  });

  // Public self-registration
  // Caller-supplied roles and tenant_id are validated against authorization rules (Prompt 5 Sections 12 & 13):
  // Client cannot choose privileged roles or uninvited tenants.
  // Invariant: CLIENT REQUESTS ROLE != ROLE IS AUTHORIZED
  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const { 
        email, 
        password, 
        invitation_token, 
        invitationToken, 
        terms_accepted, 
        termsAccepted,
        role,
        roles,
        tenant_id,
        tenantId,
      } = req.body || {};
      if (!email || !password) {
        return res.status(400).json({ error: "Missing required fields: email and password." });
      }

      if (terms_accepted === false || termsAccepted === false) {
        return res.status(400).json({ error: "You must accept the Terms of Service and Privacy Policy to create an account." });
      }

      const requestedRoles = roles && Array.isArray(roles) && roles.length > 0 
        ? roles 
        : role 
        ? [role] 
        : undefined;

      const requestedTenant =
        tenant_id ||
        tenantId ||
        (req.headers["x-tenant-id"] as string) ||
        (req.query?.tenant_id as string) ||
        (req.query?.tenantId as string) ||
        undefined;

      const newPrincipal = await authService.registerPrincipal({
        email,
        password,
        invitation_token: invitation_token || invitationToken,
        roles: requestedRoles,
        tenant_id: requestedTenant,
        is_admin_action: false,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: newPrincipal.principal_id,
        action: 'AUTHENTICATION_REGISTER_PUBLIC',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: newPrincipal.principal_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { 
          email: newPrincipal.email, 
          roles: newPrincipal.roles, 
          tenant_id: newPrincipal.tenant_id,
          email_verified: (newPrincipal as any).email_verified ?? false,
        },
      });

      return res.status(201).json({ 
        status: "created", 
        principal: newPrincipal,
        email_verification_required: !(newPrincipal as any).email_verified,
        message: (newPrincipal as any).email_verified 
          ? "Account registered successfully."
          : "Account created. A verification code has been dispatched to your email. Please verify your email before logging in."
      });
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: 'anonymous',
        action: 'AUTHENTICATION_REGISTER_PUBLIC',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: req.body?.email || 'unknown',
        outcome: 'DENIED',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      const status = err instanceof UnauthorizedAccessError ? 403 : 400;
      return res.status(status).json({ error: err.message || "Registration failed." });
    }
  });

  // Email verification confirmation endpoint
  app.post("/api/auth/verify-email", async (req: Request, res: Response) => {
    try {
      const { token, code, email } = req.body || {};
      const verificationToken = token || code;
      if (!verificationToken) {
        return res.status(400).json({ error: "Verification token or code is required." });
      }

      const result = await authService.verifyEmail({ token: String(verificationToken), email });

      await platformAuditService.recordAuditEntry({
        principal_id: 'anonymous',
        action: 'AUTHENTICATION_EMAIL_VERIFIED',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: result.email,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { email: result.email },
      });

      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: err.message || "Email verification failed." });
    }
  });

  // Resend email verification endpoint
  app.post("/api/auth/resend-verification", async (req: Request, res: Response) => {
    try {
      const { email } = req.body || {};
      if (!email) {
        return res.status(400).json({ error: "Email is required to resend verification." });
      }
      const result = await authService.resendVerification(email);
      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: err.message || "Failed to resend verification email." });
    }
  });

  // Dev & Test email verification helper to inspect stubbed sent emails
  if (process.env.NODE_ENV !== 'production') {
    app.get("/api/auth/dev-sent-emails", async (req: Request, res: Response) => {
      const sender = authService.getEmailSender();
      if ('getSentEmails' in sender) {
        const emails = (sender as any).getSentEmails();
        const emailFilter = req.query.email as string | undefined;
        if (emailFilter) {
          return res.json({ emails: emails.filter((e: any) => e.to.toLowerCase() === emailFilter.toLowerCase()) });
        }
        return res.json({ emails });
      }
      return res.json({ emails: [] });
    });
  }

  // Dedicated authenticated-admin-only endpoint for creating a principal with elevated roles or a specific tenant.
  // Requires caller to already hold requireCapabilityGrant-level admin access ('admin:manage_principals' or 'composer:full_access'),
  // strictly unreachable by an anonymous request.


  app.get("/api/auth/bootstrap/status", async (_req: Request, res: Response) => {
    try {
      const status = await ProductionBootstrapManager.checkBootstrapStatus(authService);
      return res.json(status);
    } catch (err: any) {
      return res.status(500).json({ error: err.message || "Failed to determine bootstrap status." });
    }
  });

  // Production Bootstrap First-Run Enrollment Endpoint
  // Enrolls root authoritative administrator on clean systems. Requires single-use out-of-band enrollment token.
  app.post("/api/auth/bootstrap/enroll", async (req: Request, res: Response) => {
    try {
      const { email, password, enrollment_token } = req.body || {};
      if (!email || !password || !enrollment_token) {
        return res.status(400).json({
          error: "Missing required enrollment fields: email, password, and enrollment_token.",
        });
      }

      const result = await ProductionBootstrapManager.enrollFirstRunAdmin(authService, {
        email,
        password,
        enrollment_token,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: result.principal_id,
        action: 'BOOTSTRAP_FIRST_RUN_ENROLLMENT',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: result.principal_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          enrolled_email: result.email,
          roles: result.roles,
        },
      });

      return res.status(201).json(result);
    } catch (err: any) {
      if (err.message && err.message.includes('closed')) {
        return res.status(409).json({ error: err.message });
      }
      if (err.message && err.message.includes('Invalid bootstrap enrollment token')) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(400).json({ error: err.message || "Failed to complete first-run enrollment." });
    }
  });

  app.post("/api/auth/change-password", async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles.includes('anonymous')) {
        return res.status(401).json({
          error: "Unauthorized: Valid authenticated session token required (Authorization: Bearer <token>).",
          authenticated: false,
        });
      }

      const { currentPassword, newPassword, current_password, new_password } = req.body || {};
      const currentPass = currentPassword || current_password;
      const newPass = newPassword || new_password;

      if (!currentPass || !newPass) {
        return res.status(400).json({
          error: "Missing required fields: current_password and new_password.",
        });
      }

      const result = await authService.changePassword({
        principalId: req.principal.principal_id,
        currentPassword: currentPass,
        newPassword: newPass,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'AUTHENTICATION_PASSWORD_CHANGED',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: req.principal.principal_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          invalidated_sessions_count: result.invalidatedSessionsCount,
          reason: 'Self-service cryptographic password rotation',
        },
      });

      return res.json(result);
    } catch (err: any) {
      const errorMessage = err.message || "Failed to change password.";
      const status = errorMessage.includes("Incorrect current password") || errorMessage.includes("Unauthorized")
        ? 401
        : 400;
      return res.status(status).json({ error: errorMessage });
    }
  });

  // Seeded Quick-Login Accounts for Dev/Test Environments (Emails only, strictly disabled in production)
  app.get("/api/auth/dev-seed-accounts", (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(404).json({ error: "Endpoint disabled in production environment.", accounts: [] });
    }
    return res.json({
      accounts: [
        {
          email: "admin@caim.internal",
          role: "admin",
          label: "Admin Account",
          description: "Platform Administration"
        },
        {
          email: "auditor@caim.internal",
          role: "auditor",
          label: "Auditor Account",
          description: "Security & Assurance Auditing"
        }
      ]
    });
  });

  // Explicit dev-seed endpoint (strictly disabled and unreachable in production)
  app.post("/api/auth/dev-seed", (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Forbidden: Principal seeding is strictly prohibited in production environments." });
    }
    try {
      authService.seedDevelopmentPrincipals();
      return res.json({ status: "seeded", message: "Development principals explicitly seeded for development testing." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });


  app.get("/api/auth/me", (req, res) => {
    res.json({
      principal: req.principal,
      status: req.principal?.is_authenticated ? "authenticated" : "anonymous",
    });
  });


}
