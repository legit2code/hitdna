import { Request, Response, NextFunction } from "express";
import {
  PrincipalContext,
  createAnonymousPrincipal,
  SupabaseServerAuth,
  CsrfProtectionEngine,
  createCsrfProtectionMiddleware,
  RateLimiterEngine,
  createRateLimiterMiddleware,
  resolveAuthorizedTenant,
} from "@caim/auth";

declare global {
  namespace Express {
    interface Request {
      principal?: PrincipalContext;
    }
  }
}

export function parseCookies(cookieHeader?: string): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx < 0) continue;
    const key = pair.substring(0, idx).trim();
    const val = pair.substring(idx + 1).trim();
    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  }
  return cookies;
}

export function createAuthPrincipalMiddleware(authHelper?: SupabaseServerAuth) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (authHelper && typeof authHelper.authenticateRequest === 'function') {
        const principal = await authHelper.authenticateRequest(req.headers as any);
        req.principal = principal || createAnonymousPrincipal();
      } else {
        req.principal = createAnonymousPrincipal();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.debug('[AUTH_PRINCIPAL_RESOLVE_ANONYMOUS]', { reason: msg });
      req.principal = createAnonymousPrincipal();
    }
    // Invariant: never leave req.principal undefined
    if (!req.principal) {
      req.principal = createAnonymousPrincipal();
    }
    next();
  };
}

export const requireDiagnosticAccess = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({
      error: "Unauthorized: Authentication required to access Diagnostic Console.",
      authenticated: false,
    });
  }

  const allowedRoles = ["admin", "operator", "auditor", "system_engineer"];
  const userRoles = req.principal?.roles || [];
  const hasAllowedRole = userRoles.some((r) => allowedRoles.includes(r as any));
  if (!hasAllowedRole) {
    console.debug('[AUTH_ACCESS_DENIED]', { required_roles: allowedRoles, current_roles: userRoles });
    return res.status(403).json({
      error: "Access Denied: Internal Engineering Console requires operator, admin, or auditor role.",
      authenticated: true,
    });
  }
  next();
};

export const requireWorkerManagementAccess = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
    return res.status(401).json({
      error: "Unauthorized: Verified authentication required to manage background workers.",
      authenticated: false,
    });
  }

  const userRoles = req.principal.roles || [];
  const userCapabilities = req.principal.capabilities || [];
  const userGrants = req.principal.grants || [];

  // Check narrow capability first
  const hasNarrowCapability =
    userCapabilities.includes("worker.manage") ||
    userCapabilities.includes("worker:manage") ||
    userGrants.includes("worker.manage") ||
    userGrants.includes("worker:manage");

  // Check operator or admin role
  const hasPrivilegedRole =
    userRoles.includes("operator") ||
    userRoles.includes("admin") ||
    userRoles.includes("system_admin" as any);

  if (!hasNarrowCapability && !hasPrivilegedRole) {
    console.debug('[AUTH_ACCESS_DENIED]', { required_capability: "worker.manage", current_roles: userRoles });
    return res.status(403).json({
      error: "Access Denied: Worker management requires 'worker.manage' capability or operator/admin role.",
      required_capability: "worker.manage",
      authenticated: true,
    });
  }

  next();
};

export const requireProductUserAccess = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({
      error: "Unauthorized: Valid authenticated session token required.",
      authenticated: false,
    });
  }

  const allowedRoles = [
    "user",
    "analyst",
    "developer",
    "reviewer",
    "release_approver",
    "product_user",
    "operator",
    "admin",
    "auditor",
    "system_engineer",
  ];
  const userRoles = req.principal?.roles || [];
  const hasAllowedRole = userRoles.some((r) => allowedRoles.includes(r as any));
  if (!hasAllowedRole) {
    console.debug('[AUTH_ACCESS_DENIED]', { required_roles: allowedRoles, current_roles: userRoles });
    return res.status(403).json({
      error: "Access Denied: Product User capabilities require an authorized role.",
      authenticated: true,
    });
  }
  next();
};

export const requireAuthenticatedPrincipal = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
    return res.status(401).json({
      error: "Unauthorized: Verified authentication required.",
      authenticated: false,
    });
  }
  next();
};

export const requireTenantContext = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes("anonymous")) {
    return res.status(401).json({
      error: "NO AUTHENTICATED PRINCIPAL: Authentication required for tenant operations.",
      authenticated: false,
    });
  }

  const requestedTenant = (req.headers["x-tenant-id"] as string)
    || (req.params?.tenantId as string)
    || (req.query?.tenant_id as string)
    || (req.query?.tenantId as string)
    || (req.body?.tenant_id as string)
    || (req.body?.tenantId as string);

  try {
    const authorizedTenantId = resolveAuthorizedTenant(req.principal, requestedTenant);
    req.principal.tenant_id = authorizedTenantId;
    req.principal.tenantId = authorizedTenantId;
    next();
  } catch (err: any) {
    const status = err.name === 'UnauthorizedAccessError' ? 401 : 403;
    return res.status(status).json({
      error: err.message || "NO AUTHORIZED TENANT CONTEXT: Access denied for requested tenant.",
      authenticated: true,
    });
  }
};

export const requireDiscoveryServiceAuth = (req: Request, res: Response, next: NextFunction) => {
  if (
    req.principal?.is_authenticated &&
    (req.principal.is_service ||
      req.principal.service_name === "service-discovery" ||
      req.principal.roles?.includes("operator") ||
      req.principal.roles?.includes("admin"))
  ) {
    return next();
  }

  return res.status(401).json({
    error: "Unauthorized: Valid service token or service-identity required to report discovery cycles.",
    authenticated: false,
  });
};


export const requireAdminRole = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({ error: "Unauthorized: Authentication required.", authenticated: false });
  }
  if (!req.principal.roles?.includes("admin")) {
    return res.status(403).json({ error: "Access Denied: Admin role required.", authenticated: true });
  }
  next();
};

export const requireSecurityOfficerOrAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({ error: "Unauthorized: Authentication required.", authenticated: false });
  }
  const allowed = ["admin", "security_officer"];
  if (!req.principal.roles?.some((r) => allowed.includes(r as any))) {
    return res.status(403).json({ error: "Access Denied: Security officer or admin role required.", authenticated: true });
  }
  next();
};

export const requireTopSecretOrAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({ error: "Unauthorized: Authentication required.", authenticated: false });
  }
  if (!req.principal.roles?.includes("admin") && (req.principal.max_classification_rank || 0) < 3) {
    return res.status(403).json({ error: "Access Denied: Top Secret clearance or admin role required.", authenticated: true });
  }
  next();
};

export const requireRestrictedOrAdmin = (req: Request, res: Response, next: NextFunction) => {
  if (!req.principal || !req.principal.is_authenticated) {
    return res.status(401).json({ error: "Unauthorized: Authentication required.", authenticated: false });
  }
  if (!req.principal.roles?.includes("admin") && (req.principal.max_classification_rank || 0) < 4) {
    return res.status(403).json({ error: "Access Denied: Vault Restricted clearance or admin role required.", authenticated: true });
  }
  next();
};

export { createCsrfProtectionMiddleware, createRateLimiterMiddleware };
