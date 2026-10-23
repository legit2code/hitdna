import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";
import {
  SandboxOrchestrationEngine,
  ScenarioRegistry,
  SandboxLifecycleManager,
  StaticDynamicComparator,
} from "../../../workers/sandbox-orchestrator/index.ts";

export function registerSandboxRoutes(app: Express, _container: ServiceContainer) {
  app.get("/api/dev/sandbox/scenarios", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ScenarioRegistry.listScenarios());
  });

  app.get("/api/dev/sandbox/active-sessions", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      activeCount: SandboxLifecycleManager.getActiveSessionCount(),
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/api/dev/sandbox/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { scenarioId, scenario, providerType, files, envVars, resourceLimits, networkPolicy, staticFindings, staticReport } = req.body || {};

      // 1. Explicit provider requirement: Disallow silent default to SIMULATED
      if (!providerType) {
        return res.status(400).json({
          error: "Explicit providerType ('E2B' or 'SIMULATED') is required. Dynamic sandbox runs cannot default to simulation.",
          code: "PROVIDER_TYPE_REQUIRED",
          truth_state: "NOT_CONFIGURED",
          status: "NOT_CONFIGURED",
        });
      }

      if (providerType !== 'E2B' && providerType !== 'SIMULATED' && providerType !== 'DOCKER_ISOLATED') {
        return res.status(400).json({
          error: `Invalid providerType '${providerType}'. Must be 'E2B' or 'SIMULATED'.`,
          code: "INVALID_PROVIDER_TYPE",
        });
      }

      // 2. Reject attempted truth_state mutation if client attempts to pass truth_state=OBSERVED with SIMULATED provider
      if (providerType === 'SIMULATED' && (req.body?.truth_state === 'OBSERVED' || req.body?.truthState === 'OBSERVED')) {
        return res.status(400).json({
          error: "Invalid truth state transition: Cannot promote SIMULATED execution to OBSERVED truth state.",
          code: "ILLEGAL_TRUTH_STATE_MUTATION",
        });
      }

      // 3. Explicit E2B requirement: fail closed if E2B is absent (no fallback to simulation)
      if (providerType === 'E2B') {
        const isE2BAvailable = Boolean(process.env.E2B_API_KEY && process.env.E2B_API_KEY.trim().length > 0);
        if (!isE2BAvailable) {
          return res.status(503).json({
            error: "E2B provider is not configured (E2B_API_KEY absent). Cannot perform real sandbox observation.",
            code: "PROVIDER_UNAVAILABLE",
            truth_state: "NOT_CONFIGURED",
            execution_mode: "PROVIDER_UNAVAILABLE",
            actual_provider: "NONE",
            requested_provider: "E2B",
            status: "PROVIDER_UNAVAILABLE",
          });
        }
      }

      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId,
        scenario,
        providerType,
        requireRealSandbox: providerType === 'E2B',
        files,
        envVars,
        resourceLimits,
        networkPolicy,
      });

      // If execution resulted in PROVIDER_UNAVAILABLE, return 503 without fallback
      if (result.status === 'PROVIDER_UNAVAILABLE' || result.actual_provider === 'NONE') {
        return res.status(503).json({
          error: result.fallback_reason || "Sandbox provider unavailable for requested observation.",
          code: "PROVIDER_UNAVAILABLE",
          ...result,
        });
      }

      let comparison = null;
      if (staticFindings || staticReport) {
        comparison = StaticDynamicComparator.compare(staticFindings || staticReport, result);
      }

      res.json({
        ...result,
        comparison,
      });
    } catch (err: any) {
      if (err?.name === 'SandboxProviderUnavailableError' || err?.message?.includes('PROVIDER_UNAVAILABLE')) {
        return res.status(503).json({
          error: err.message,
          code: "PROVIDER_UNAVAILABLE",
          truth_state: "NOT_CONFIGURED",
          execution_mode: "PROVIDER_UNAVAILABLE",
          actual_provider: "NONE",
          requested_provider: req.body?.providerType || "E2B",
          status: "PROVIDER_UNAVAILABLE",
        });
      }
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/sandbox/compare", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { staticFindings, staticReport, dynamicResult } = req.body || {};
      if (!dynamicResult) {
        return res.status(400).json({ error: "dynamicResult is required for comparison" });
      }

      // Check attempted status mutation: if dynamicResult is simulated but claimed OBSERVED
      if (
        (dynamicResult.actual_provider === 'SIMULATED' || dynamicResult.provider_type === 'SIMULATED' || dynamicResult.execution_mode === 'SIMULATED') &&
        (dynamicResult.truth_state === 'OBSERVED' || req.body?.truth_state === 'OBSERVED')
      ) {
        return res.status(400).json({
          error: "Invalid truth state transition: Cannot promote SIMULATED execution to OBSERVED truth state.",
          code: "ILLEGAL_TRUTH_STATE_MUTATION",
        });
      }

      const comparison = StaticDynamicComparator.compare(staticFindings || staticReport || [], dynamicResult);
      res.json(comparison);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 20. P21 — Risk, Scoring Models, Policies, Overrides & Use-Case Endpoints

}
