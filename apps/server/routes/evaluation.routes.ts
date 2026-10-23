import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";
import {
  GOLDEN_CORPUS_FIXTURES,
  PRODUCTION_REGRESSION_THRESHOLDS,
} from "@caim/contracts/evaluation.ts";
import {
  runEvaluationVerificationTests,
} from "@caim/workflow/evaluation.ts";

export function registerEvaluationRoutes(app: Express, container: ServiceContainer) {
  const { globalEvaluationEngine } = container;

  app.get("/api/dev/evaluation/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Fixture endpoints are strictly disabled in production mode." });
    }
    res.json(GOLDEN_CORPUS_FIXTURES);
  });

  app.get("/api/dev/evaluation/thresholds", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PRODUCTION_REGRESSION_THRESHOLDS);
  });

  app.get("/api/dev/evaluation/runs", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(globalEvaluationEngine.getAllRuns());
  });

  app.post("/api/dev/evaluation/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Evaluation simulation endpoints are strictly disabled in production mode." });
    }
    const { engineVersion, isConclusionChanging, simulateRegression, baselineEngineVersion } = req.body;
    const run = await globalEvaluationEngine.evaluateEngineVersion({
      engineVersion: engineVersion || 'v2.1.0-candidate',
      baselineEngineVersion: baselineEngineVersion || 'v2.0.1-certified',
      isConclusionChanging: isConclusionChanging !== undefined ? isConclusionChanging : true,
      simulateRegression: Boolean(simulateRegression),
      evaluatorActorId: (req as any).principal?.actorId || 'ci-runner@caim.internal'
    });
    const decision = globalEvaluationEngine.getReleaseGateDecision(run);
    res.json({ run, decision });
  });

  app.post("/api/dev/evaluation/verify", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Evaluation verification test endpoints are strictly disabled in production mode." });
    }
    const testResult = runEvaluationVerificationTests();
    res.json(testResult);
  });

  // ---------------------------------------------------------------------------
  // P34 REQUIREMENTS TRACEABILITY MATRIX & DEFINITION-OF-DONE AUDIT
  // ---------------------------------------------------------------------------

}
