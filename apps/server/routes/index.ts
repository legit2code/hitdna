import { Express } from "express";
import { ServiceContainer } from "../services/container.ts";
import { registerHealthRoutes } from "./health.routes.ts";
import { registerAuthRoutes } from "./auth.routes.ts";
import { registerAdminRoutes } from "./admin.routes.ts";
import { registerDiagnosticRoutes } from "./diagnostic.routes.ts";
import { registerSyntaxRoutes } from "./syntax.routes.ts";
import { registerAnalysisRoutes } from "./analysis.routes.ts";
import { registerSandboxRoutes } from "./sandbox.routes.ts";
import { registerDecisionRoutes } from "./decision.routes.ts";
import { registerKnowledgeRoutes } from "./knowledge.routes.ts";
import { registerComposerRoutes } from "./composer.routes.ts";
import { registerPackagingRoutes } from "./packaging.routes.ts";
import { registerObservabilityRoutes } from "./observability.routes.ts";
import { registerEvaluationRoutes } from "./evaluation.routes.ts";
import { registerTraceabilityRoutes } from "./traceability.routes.ts";
import { registerIngestionRoutes } from "./ingestion.routes.ts";
import { registerDiscoveryRoutes } from "./discovery.routes.ts";
import { registerWorkersRoutes } from "./workers.routes.ts";

export function registerAllRoutes(app: Express, container: ServiceContainer) {
  registerHealthRoutes(app, container);
  registerAuthRoutes(app, container);
  registerAdminRoutes(app, container);
  registerDiagnosticRoutes(app, container);
  registerIngestionRoutes(app, container);
  registerDiscoveryRoutes(app, container);
  registerSyntaxRoutes(app, container);
  registerAnalysisRoutes(app, container);
  registerSandboxRoutes(app, container);
  registerDecisionRoutes(app, container);
  registerKnowledgeRoutes(app, container);
  registerComposerRoutes(app, container);
  registerPackagingRoutes(app, container);
  registerObservabilityRoutes(app, container);
  registerEvaluationRoutes(app, container);
  registerTraceabilityRoutes(app, container);
  registerWorkersRoutes(app, container);
}
