import { UnauthorizedAccessError } from "@caim/auth";
import { SyntheticTargetService } from "../../../workers/sandbox-orchestrator/security/synthetic-target.ts";
import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireProductUserAccess, requireAdminRole } from "../middleware/security.ts";
import { requireCapabilityGrant } from "@caim/auth";
import { ALL_TECHNIQUE_CATEGORIES, TechniqueCategory } from "../../../workers/composer/index.ts";

export function registerComposerRoutes(app: Express, container: ServiceContainer) {
  const { capabilityGrantService, composerEngine, syntheticTargetService, dbClient, platformAuditService } = container;

  // 1. My Capabilities endpoint (returns active capabilities & allowed technique categories for current caller)
  app.get("/api/composer/my-capabilities", async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated) {
        return res.json({
          authenticated: false,
          capabilities: [],
          tier: 'none',
          allowed_technique_categories: [],
          all_technique_categories: ALL_TECHNIQUE_CATEGORIES,
        });
      }
      const grants = await capabilityGrantService.getActiveGrantsForPrincipal(req.principal.principal_id);
      const isFull = grants.some(g => g.capability_key === 'composer:full_access');
      const restricted = grants.find(g => g.capability_key === 'composer:restricted_access');

      let tier: 'full' | 'restricted' | 'none' = 'none';
      let allowedCategories: string[] = [];

      if (isFull) {
        tier = 'full';
        allowedCategories = [...ALL_TECHNIQUE_CATEGORIES];
      } else if (restricted) {
        tier = 'restricted';
        allowedCategories = restricted.scope_limitations && restricted.scope_limitations.length > 0 && !restricted.scope_limitations.includes('*')
          ? restricted.scope_limitations
          : [...ALL_TECHNIQUE_CATEGORIES];
      }

      return res.json({
        authenticated: true,
        principal_id: req.principal.principal_id,
        tier,
        grants,
        allowed_technique_categories: allowedCategories,
        all_technique_categories: ALL_TECHNIQUE_CATEGORIES,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // 2. List all capability grants (Admin/Owner - gated strictly by 'composer:full_access', NOT admin role alone)
  app.get("/api/composer/grants", async (req: Request, res: Response) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      await requireCapabilityGrant(req.principal, 'composer:full_access', { grantService: capabilityGrantService });
      const grants = await capabilityGrantService.listGrants();
      return res.json({ status: "success", grants });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: err.message });
    }
  });

  // 3. Grant capability to principal (Gated strictly by 'composer:full_access')
  app.post("/api/composer/grants", async (req: Request, res: Response) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      await requireCapabilityGrant(req.principal, 'composer:full_access', { grantService: capabilityGrantService });

      const { capability_key, principal_id, justification, scope_limitations } = req.body || {};
      if (!capability_key || !principal_id || !justification) {
        return res.status(400).json({ error: "Missing required fields: capability_key, principal_id, justification." });
      }

      const grant = await capabilityGrantService.grantCapability({
        capability_key,
        principal_id,
        granted_by: req.principal.principal_id,
        justification,
        scope_limitations: Array.isArray(scope_limitations) ? scope_limitations : null,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'CAPABILITY_GRANTED',
        target_entity_type: 'CAPABILITY_GRANT',
        target_entity_id: grant.grant_id,
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { capability_key, granted_to: principal_id, justification },
      });

      return res.status(201).json({ status: "created", grant });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: err.message });
    }
  });

  // 4. Revoke capability grant (Gated strictly by 'composer:full_access')
  app.post("/api/composer/grants/:grantId/revoke", async (req: Request, res: Response) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      await requireCapabilityGrant(req.principal, 'composer:full_access', { grantService: capabilityGrantService });

      const grant = await capabilityGrantService.revokeCapability({
        grant_id: req.params.grantId,
        revoked_by: req.principal.principal_id,
      });

      return res.json({ status: "revoked", grant });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: err.message });
    }
  });

  // 5. Generate agent / tool via Composer Engine
  app.post("/api/composer/generate", async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated) {
        await platformAuditService.recordAuditEntry({
          principal_id: 'anonymous',
          action: 'COMPOSER_GENERATION_TRIGGERED',
          target_entity_type: 'COMPOSER_ARTIFACT',
          target_entity_id: 'unauthenticated',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: 'Authentication required' },
        });
        return res.status(401).json({ error: "Authentication required." });
      }

      const { technique_category, prompt, target_name, target_language, parameters } = req.body || {};
      if (!technique_category || !prompt) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal.principal_id,
          action: 'COMPOSER_GENERATION_TRIGGERED',
          target_entity_type: 'COMPOSER_ARTIFACT',
          target_entity_id: 'invalid_params',
          outcome: 'REFUSED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: 'Missing required fields: technique_category and prompt.' },
        });
        return res.status(400).json({ error: "Missing required fields: technique_category and prompt." });
      }

      // Check capability grant for technique_category
      await requireCapabilityGrant(
        req.principal,
        ['composer:full_access', 'composer:restricted_access'],
        {
          techniqueCategory: technique_category,
          grantService: capabilityGrantService,
        }
      );

      const result = await composerEngine.generate({
        principal_id: req.principal.principal_id,
        technique_category: technique_category as TechniqueCategory,
        prompt,
        target_name,
        target_language,
        parameters,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'COMPOSER_GENERATION_TRIGGERED',
        target_entity_type: 'COMPOSER_ARTIFACT',
        target_entity_id: result.artifact_id || 'generation_refused',
        outcome: result.status === 'SUCCESS' ? 'SUCCESS' : 'REFUSED',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          technique_category,
          target_language,
          refusal_reason: result.refusal_reason,
          status: result.status,
        },
      });

      if (result.status === 'REFUSED') {
        return res.status(400).json({
          status: 'REFUSED',
          error: result.refusal_reason,
          result,
        });
      }

      return res.json({
        status: 'SUCCESS',
        result,
      });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'anonymous',
          action: 'COMPOSER_GENERATION_TRIGGERED',
          target_entity_type: 'COMPOSER_ARTIFACT',
          target_entity_id: 'unauthorized_capability',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: err.message },
        });
        return res.status(403).json({ error: err.message });
      }
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'COMPOSER_GENERATION_TRIGGERED',
        target_entity_type: 'COMPOSER_ARTIFACT',
        target_entity_id: 'error',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      return res.status(500).json({ error: err.message });
    }
  });

  // 6. View Composer generation audit logs (Gated strictly by 'composer:full_access')
  app.get("/api/composer/logs", async (req: Request, res: Response) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      await requireCapabilityGrant(req.principal, 'composer:full_access', { grantService: capabilityGrantService });

      const logs = await composerEngine.listLogs();
      return res.json({ status: "success", logs });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: err.message });
    }
  });

  // 7. Synthetic target test execution endpoint (Sandbox network validation)
  app.post("/api/composer/synthetic-target/simulate", async (req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Synthetic target simulation endpoint is strictly disabled in production mode." });
    }
    try {
      const { destination_host, port, request_path, method } = req.body || {};
      if (destination_host) {
        const egressEval = SyntheticTargetService.evaluateEgress(destination_host, port || 443);
        return res.json({ status: "evaluated", egress: egressEval });
      }

      const simResponse = SyntheticTargetService.handleSyntheticRequest({
        path: request_path || '/api/v1/health',
        method: method || 'GET',
        body: req.body,
      });
      return res.json({ status: "success", response: simResponse });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // 8. Execute Composer-synthesized artifact in isolated Sandbox MicroVM
  // Bound strictly to SyntheticTargetService under strict DEFAULT_DENY network policy
  app.post("/api/composer/execute", async (req: Request, res: Response) => {
    try {
      if (!req.principal || !req.principal.is_authenticated) {
        await platformAuditService.recordAuditEntry({
          principal_id: 'anonymous',
          action: 'COMPOSER_EXECUTION_TRIGGERED',
          target_entity_type: 'COMPOSER_ARTIFACT',
          target_entity_id: 'unauthenticated',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: 'Authentication required' },
        });
        return res.status(401).json({ error: "Authentication required." });
      }

      const {
        artifact_id,
        technique_category,
        files,
        code,
        synthetic_target_domain,
        provider_type,
        input_payload,
        target_port,
      } = req.body || {};

      const category = (technique_category as TechniqueCategory) || 'TOOL_SYNTHESIS';

      // Check capability grant for technique_category
      await requireCapabilityGrant(
        req.principal,
        ['composer:full_access', 'composer:restricted_access'],
        {
          techniqueCategory: category,
          grantService: capabilityGrantService,
        }
      );

      const result = await composerEngine.execute({
        principal_id: req.principal.principal_id,
        artifact_id,
        technique_category: category,
        files,
        code,
        synthetic_target_domain,
        provider_type,
        input_payload,
        target_port,
      });

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal.principal_id,
        action: 'COMPOSER_EXECUTION_TRIGGERED',
        target_entity_type: 'COMPOSER_ARTIFACT',
        target_entity_id: artifact_id || 'unknown_artifact',
        outcome: result.status === 'COMPLETED' ? 'SUCCESS' : result.status === 'REFUSED' ? 'REFUSED' : 'FAILURE',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          technique_category: category,
          provider_type,
          status: result.status,
          network_violations: result.execution_output?.network_violations_detected || 0,
        },
      });

      if (result.status === 'REFUSED') {
        return res.status(400).json({
          status: 'REFUSED',
          error: result.refusal_reason,
          result,
        });
      }

      return res.json({
        status: 'SUCCESS',
        result,
      });
    } catch (err: any) {
      if (err instanceof UnauthorizedAccessError) {
        await platformAuditService.recordAuditEntry({
          principal_id: req.principal?.principal_id || 'anonymous',
          action: 'COMPOSER_EXECUTION_TRIGGERED',
          target_entity_type: 'COMPOSER_ARTIFACT',
          target_entity_id: 'unauthorized_capability',
          outcome: 'DENIED',
          client_ip: req.ip,
          user_agent: req.headers['user-agent'] as string,
          details: { error: err.message },
        });
        return res.status(403).json({ error: err.message });
      }
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || 'anonymous',
        action: 'COMPOSER_EXECUTION_TRIGGERED',
        target_entity_type: 'COMPOSER_ARTIFACT',
        target_entity_id: 'error',
        outcome: 'ERROR',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err) },
      });
      return res.status(500).json({ error: err.message });
    }
  });


}
