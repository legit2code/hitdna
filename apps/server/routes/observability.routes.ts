import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess, requireProductUserAccess } from "../middleware/security.ts";
import { GoldenCorpusEvaluationEngine } from "@caim/workflow/evaluation.ts";
import {
  OpenTelemetryTracer,
  AuditLogEngine,
  PlatformTelemetryEngine,
  TraceResolver,
  SecretRedactor,
  runObservabilityVerificationTests,
} from "@caim/workflow/observability.ts";

export function registerObservabilityRoutes(app: Express, container: ServiceContainer) {
  const { platformAuditService, csrfProtectionEngine, discoveryLineageService, globalAuditEngine, globalTracer } = container;

  app.get("/api/dev/observability/metrics", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const discMetrics = await discoveryLineageService.getDiscoveryMetrics();
      PlatformTelemetryEngine.setDiscoveryMetrics(discMetrics);
    } catch (_e) {}
    res.json(PlatformTelemetryEngine.getMetricsSnapshot());
  });

  app.get("/api/dev/observability/discovery-metrics", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const discMetrics = await discoveryLineageService.getDiscoveryMetrics();
      PlatformTelemetryEngine.setDiscoveryMetrics(discMetrics);
      res.json(discMetrics);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve discovery metrics" });
    }
  });



  app.get("/api/dev/observability/capacity", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PlatformTelemetryEngine.getCapacityMetrics());
  });

  app.get("/api/dev/observability/cost", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      breakdown: PlatformTelemetryEngine.getCostAttributionBreakdown(),
      summary: PlatformTelemetryEngine.getMetricsSnapshot().geminiAi
    });
  });

  app.get("/api/dev/observability/alerts", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PlatformTelemetryEngine.getAlertConditions());
  });

  app.get("/api/dev/observability/audit", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { actorId, action, targetId } = req.query;
    res.json(globalAuditEngine.getEvents({
      actorId: actorId as string,
      action: action as string,
      targetId: targetId as string
    }));
  });

  app.post("/api/dev/observability/trace/e2e", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const trace = TraceResolver.createSyntheticE2ETrace(globalTracer, globalAuditEngine);
    res.json(trace);
  });

  app.post("/api/dev/observability/redact", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { text, payload } = req.body;
    if (text) {
      res.json(SecretRedactor.redactString(text));
    } else if (payload) {
      res.json({ sanitizedPayload: SecretRedactor.redactObject(payload) });
    } else {
      res.status(400).json({ error: 'Provide text or payload parameter' });
    }
  });

  app.post("/api/dev/observability/verify", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const testResult = runObservabilityVerificationTests();
    res.json(testResult);
  });

  // ---------------------------------------------------------------------------
  // P31 GOLDEN CORPUS, EVALUATION & REGRESSION RELEASE GATES
  // ---------------------------------------------------------------------------
  const globalEvaluationEngine = new GoldenCorpusEvaluationEngine();

  // Run baseline evaluation on server start asynchronously
  void globalEvaluationEngine.evaluateEngineVersion({
    engineVersion: 'v2.0.1-certified',
    baselineEngineVersion: 'v2.0.0-gold',
    isConclusionChanging: false,
    simulateRegression: false,
    evaluatorActorId: 'release-gatekeeper@caim.internal'
  }).catch(() => {});


  app.get("/api/audit/logs", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      const { principal_id, action, target_entity_type, target_entity_id, outcome, from_timestamp, to_timestamp, limit, offset } = req.query;
      const result = await platformAuditService.queryAuditLogs({
        principal_id: principal_id as string,
        action: action as string,
        target_entity_type: target_entity_type as string,
        target_entity_id: target_entity_id as string,
        outcome: outcome as string,
        from_timestamp: from_timestamp as string,
        to_timestamp: to_timestamp as string,
        limit: limit ? parseInt(limit as string, 10) : 50,
        offset: offset ? parseInt(offset as string, 10) : 0,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/audit/stats", requireProductUserAccess, async (_req: Request, res: Response) => {
    try {
      const stats = await platformAuditService.getAuditStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/audit/csrf-report", (_req: Request, res: Response) => {
    res.json(csrfProtectionEngine.getCsrfSecurityReport());
  });

  app.get("/api/dev/audit/logs", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { principal_id, action, target_entity_type, target_entity_id, outcome, limit, offset } = req.query;
      const result = await platformAuditService.queryAuditLogs({
        principal_id: principal_id as string,
        action: action as string,
        target_entity_type: target_entity_type as string,
        target_entity_id: target_entity_id as string,
        outcome: outcome as string,
        limit: limit ? parseInt(limit as string, 10) : 50,
        offset: offset ? parseInt(offset as string, 10) : 0,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

}
