import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";
import {
  AUTHORITATIVE_REQUIREMENTS_MATRIX,
  MANDATORY_ACCEPTANCE_PATHS,
  LineageResolverEngine,
  QualityTargetsAuditor,
  runPlatformDefinitionOfDoneAudit,
} from "@caim/workflow/traceability.ts";

export function registerTraceabilityRoutes(app: Express, _container: ServiceContainer) {
  app.get("/api/dev/traceability/requirements", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(AUTHORITATIVE_REQUIREMENTS_MATRIX);
  });

  app.get("/api/dev/traceability/acceptance-paths", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(MANDATORY_ACCEPTANCE_PATHS);
  });

  app.get("/api/dev/traceability/lineage/conclusion/:id?", requireDiagnosticAccess, (req: Request, res: Response) => {
    const conclusionId = req.params.id || 'dec-quarantine-rce-001';
    const resolution = LineageResolverEngine.resolveConclusionLineage(conclusionId);
    res.json(resolution);
  });

  app.get("/api/dev/traceability/lineage/observation/:id?", requireDiagnosticAccess, (req: Request, res: Response) => {
    const observationId = req.params.id || 'obs-github-repo-001';
    const resolution = LineageResolverEngine.resolveObservationToOntologyLineage(observationId);
    res.json(resolution);
  });

  app.get("/api/dev/traceability/quality-targets", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const targets = QualityTargetsAuditor.evaluateQualityTargets();
    res.json(targets);
  });

  app.post("/api/dev/traceability/audit-run", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const auditReport = runPlatformDefinitionOfDoneAudit();
    res.json(auditReport);
  });


}
