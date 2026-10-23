import { requireCapabilityGrant, requireClassification, SecurityClassificationRank } from "@caim/auth";
import { Express, Request, Response, NextFunction } from "express";
import { ServiceContainer } from "../services/container.ts";
import {
  requireAdminRole,
  requireSecurityOfficerOrAdmin,
  requireTopSecretOrAdmin,
  requireRestrictedOrAdmin,
} from "../middleware/security.ts";
import {
  executeWithAuditedOverride,
  UnauthorizedAccessError,
  UnauthorizedVaultAccessError,
} from "@caim/auth";

export function registerAdminRoutes(app: Express, container: ServiceContainer) {
  const { authService, platformAuditService, capabilityGrantService } = container;

  app.post(["/api/admin/principals", "/api/auth/admin/register"], async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.principal_id === 'anonymous') {
        return res.status(401).json({
          error: "Unauthorized: Valid authenticated session token required (Authorization: Bearer <token>).",
          authenticated: false,
        });
      }

      await requireCapabilityGrant(req.principal, ['admin:manage_principals', 'composer:full_access'], {
        grantService: capabilityGrantService,
      });

      const { email, password, roles, tenant_id, external_identity_provider_id } = req.body || {};
      if (!email || !password) {
        return res.status(400).json({ error: "Missing required fields: email and password." });
      }

      const newPrincipal = await authService.registerPrincipal({
        email,
        password,
        roles: roles && Array.isArray(roles) && roles.length > 0 ? roles : undefined,
        tenant_id: tenant_id || undefined,
        external_identity_provider_id,
        caller: req.principal,
        allowElevatedRoles: true,
        is_admin_action: true,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'ADMIN_CREATE_PRINCIPAL',
        target_entity_type: 'PRINCIPAL',
        target_entity_id: newPrincipal.principal_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          created_email: newPrincipal.email,
          assigned_roles: newPrincipal.roles,
          assigned_tenant: newPrincipal.tenant_id,
        },
      });

      return res.status(201).json({ status: "created", principal: newPrincipal });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message, authenticated: true });
      }
      return res.status(400).json({ error: err.message || "Failed to create principal." });
    }
  });

  // Production Bootstrap Status Endpoint


  app.get("/api/v1/vault/credentials", (req, res) => {
    try {
      if (!req.principal || !req.principal.is_authenticated || req.principal.roles?.includes('anonymous')) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      requireClassification(req.principal, SecurityClassificationRank.VAULT_RESTRICTED);
      return res.json({
        status: "success",
        vault_items: [
          {
            id: "vault_cred_001",
            type: "CREDENTIAL_REFERENCE",
            locator: "vault://tenants/primary/keys/production-signing",
            security_classification: "VAULT_RESTRICTED",
          }
        ]
      });
    } catch (err: any) {
      if (err instanceof UnauthorizedVaultAccessError || err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // Audited Override (Break-Glass) Gated Execution
  app.post("/api/v1/audit/override", async (req, res) => {
    try {
      // PART A: Reject unauthenticated or anonymous principals immediately
      if (
        !req.principal || 
        !req.principal.is_authenticated || 
        req.principal.roles?.includes('anonymous') || 
        req.principal.principal_id === 'anonymous' ||
        req.principal.principalType === 'anonymous'
      ) {
        await platformAuditService.recordAuditEntry({
          principal_id: 'anonymous',
          action: 'POLICY_OVERRIDDEN',
          target_entity_type: 'VAULT_SECRET',
          target_entity_id: req.body?.target_resource_id || 'res_vault_override',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: 'Unauthorized: Anonymous or unauthenticated principal rejected' },
        });
        return res.status(401).json({ error: "Unauthorized: Verified authentication required." });
      }

      // PART A: Require specific privileged capability or role
      const privilegedRoles = ['admin', 'operator', 'security_officer', 'system_admin'];
      const privilegedCapabilities = ['break_glass', 'security.break_glass', 'override.execute', 'vault.override', 'security.override'];
      const hasPrivilegedRole = req.principal.roles?.some((r: any) => privilegedRoles.includes(r));
      const hasPrivilegedCap = 
        (req.principal.capabilities || []).some((c: string) => privilegedCapabilities.includes(c)) ||
        (req.principal.grants || []).some((g: string) => privilegedCapabilities.includes(g));

      if (!hasPrivilegedRole && !hasPrivilegedCap) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal.principal_id,
          action: 'POLICY_OVERRIDDEN',
          target_entity_type: req.body?.target_resource_type || 'VAULT_SECRET',
          target_entity_id: req.body?.target_resource_id || 'res_vault_override',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: 'Access Denied: Principal lacks break-glass capability or role' },
        });
        return res.status(403).json({ 
          error: "Access Denied: Break-glass operation requires operator or admin role or break_glass capability." 
        });
      }

      const { justification, target_resource_id, action, target_resource_type } = req.body;

      // Real audit sink delegating to platformAuditService
      const overrideAuditSink = {
        logAuditEvent: async (event: any) => {
          await platformAuditService.recordAuditEntry({
            principal_id: event.principal_or_service_id,
            action: event.action,
            target_entity_type: event.metadata?.target_resource_type || target_resource_type || 'VAULT_SECRET',
            target_entity_id: event.target_entity_ref_id || target_resource_id || 'res_vault_override',
            outcome: event.outcome === 'SUCCESS' ? 'SUCCESS' : 'REFUSED',
            client_ip: req.ip,
            user_agent: req.headers['user-agent'] as string,
            details: {
              ...event.metadata,
              correlation_id: event.correlation_id,
            },
          });
        },
      };

      const result = await executeWithAuditedOverride(
        req.principal,
        {
          actor_id: req.principal.principal_id,
          action: action || "MANUAL_INSPECTION",
          target_resource_id: target_resource_id || "res_vault_override",
          target_resource_type: target_resource_type || "VAULT_SECRET",
          justification: justification || "",
          correlation_id: `corr_${Date.now()}`,
        },
        overrideAuditSink,
        async (elevated) => {
          return {
            status: "OVERRIDE_EXECUTED",
            elevated_actor: elevated.principal_id,
            resource_accessed: target_resource_id,
            operation_status: "OPERATION_STUBBED_SAFE_INSPECTION",
            underlying_vault_operation: "NOT_EXECUTED_STUB",
          };
        }
      );

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'POLICY_OVERRIDDEN',
        target_entity_type: target_resource_type || 'VAULT_SECRET',
        target_entity_id: target_resource_id || 'res_vault_override',
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          action: action || 'MANUAL_INSPECTION',
          justification: justification || '',
          target_resource_type: target_resource_type || 'VAULT_SECRET',
          mfa_status: 'NOT_IMPLEMENTED_BY_PLATFORM',
          operation_mode: 'STUBBED_SAFE_INSPECTION',
          underlying_vault_operation: 'NOT_EXECUTED_STUB',
        },
      });

      return res.json({
        ...result,
        mfa_report: {
          mfa_supported: false,
          mfa_enforced: false,
          mfa_status: 'NOT_IMPLEMENTED_BY_PLATFORM',
          strongest_control_enforced: 'AUTHENTICATED_PRIVILEGED_ROLE_AND_AUDITED_JUSTIFICATION',
          note: 'Multi-factor authentication (MFA) step-up is not implemented by the platform. Enforcing strict cryptographic principal authentication, least-privilege role/capability validation, and immutable audit logging.',
        },
      });
    } catch (err: any) {
      const isForbidden = err instanceof UnauthorizedAccessError && req.principal?.is_authenticated;
      const isUnauthorized = !req.principal || !req.principal.is_authenticated;
      const status = isUnauthorized ? 401 : isForbidden ? 403 : 400;

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'POLICY_OVERRIDDEN',
        target_entity_type: req.body?.target_resource_type || 'VAULT_SECRET',
        target_entity_id: req.body?.target_resource_id || 'unknown',
        outcome: 'REFUSED',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      return res.status(status).json({ error: err.message });
    }
  });


}
