import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";
import {
  DecisionOrchestrationEngine,
  ScoreModelRegistry,
  PolicyRegistry,
  PolicyOverrideManager,
  RecommendationEngine,
  UseCaseEngine,
  USE_CASE_PROFILE_V1,
} from "../../../workers/decision/index.ts";

export function registerDecisionRoutes(app: Express, container: ServiceContainer) {
  const { platformAuditService } = container;
  app.get("/api/dev/decision/scoring-models", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ScoreModelRegistry.listModels());
  });

  app.get("/api/dev/decision/policies", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PolicyRegistry.listPolicies());
  });

  app.post("/api/dev/decision/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const result = await DecisionOrchestrationEngine.runDecisionSuite(req.body);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/decision/overrides/:analysisRunId", requireDiagnosticAccess, (req: Request, res: Response) => {
    const history = PolicyOverrideManager.getOverrideHistory(req.params.analysisRunId);
    const active = PolicyOverrideManager.getActiveOverride(req.params.analysisRunId);
    res.json({ active, history });
  });

  app.post("/api/dev/decision/overrides", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const override = PolicyOverrideManager.applyOverride(req.body);

      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || override.approver_id || 'operator',
        action: 'SCORING_OVERRIDDEN',
        target_entity_type: 'POLICY_DECISION',
        target_entity_id: override.analysis_run_id || req.body?.analysisRunId || req.body?.analysis_run_id || 'analysis-run',
        outcome: 'SUCCESS',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: {
          override_id: override.override_id,
          original_outcome: override.original_outcome,
          overridden_outcome: override.overridden_outcome,
          reason: override.reason,
          justification_details: override.justification_details,
          approver_id: override.approver_id,
          approver_role: override.approver_role,
        },
      });

      res.json(override);
    } catch (err: any) {
      await platformAuditService.recordAuditEntry({
        principal_id: req.principal?.principal_id || req.body?.approver_id || 'operator',
        action: 'SCORING_OVERRIDDEN',
        target_entity_type: 'POLICY_DECISION',
        target_entity_id: req.body?.analysisRunId || req.body?.analysis_run_id || 'analysis-run',
        outcome: 'REFUSED',
        client_ip: req.ip,
        user_agent: req.headers['user-agent'] as string,
        details: { error: err.message || String(err), payload: req.body },
      });
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/dev/decision/overrides/revoke", requireDiagnosticAccess, async (req: Request, res: Response) => {
    const { overrideId, revokerId } = req.body;
    const success = PolicyOverrideManager.revokeOverride(overrideId, revokerId);

    await platformAuditService.recordAuditEntry({
      principal_id: req.principal?.principal_id || revokerId || 'operator',
      action: 'POLICY_OVERRIDDEN',
      target_entity_type: 'POLICY_DECISION',
      target_entity_id: overrideId || 'override-target',
      outcome: success ? 'SUCCESS' : 'FAILURE',
      client_ip: req.ip,
      user_agent: req.headers['user-agent'] as string,
      details: {
        revoked_override_id: overrideId,
        revoker: revokerId,
        success,
      },
    });

    res.json({ success });
  });


}
