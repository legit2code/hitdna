import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess } from "../middleware/security.ts";

export function registerDiagnosticRoutes(app: Express, container: ServiceContainer) {
  const { diagnosticService, config } = container;

  app.get("/api/dev/system", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const systemHealth = await diagnosticService.getSystemHealth(config.env);
      res.json(systemHealth);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve system diagnostic health" });
    }
  });

  // 2. WorkflowRuns List
  app.get("/api/dev/workflows", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const workflows = await diagnosticService.listWorkflowRuns();
      res.json(workflows);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list workflow runs" });
    }
  });

  // 2a. WorkflowRun Detail
  app.get("/api/dev/workflows/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const workflow = await diagnosticService.getWorkflowRunDetails(req.params.id);
      if (!workflow) {
        return res.status(404).json({ error: `WorkflowRun not found for ID: ${req.params.id}` });
      }
      res.json(workflow);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get workflow run details" });
    }
  });

  // 3. Jobs & Leases List
  app.get("/api/dev/jobs", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { status, queueKey, workflowRunId, limit } = req.query;
      const jobs = await diagnosticService.listJobs({
        status: status as string,
        queueKey: queueKey as string,
        workflowRunId: workflowRunId as string,
        limit: limit ? parseInt(limit as string, 10) : 50,
      });
      res.json(jobs);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list jobs" });
    }
  });

  // 3a. Job Detail with Attempt History
  app.get("/api/dev/jobs/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const job = await diagnosticService.getJobDetails(req.params.id);
      if (!job) {
        return res.status(404).json({ error: `Job not found for ID: ${req.params.id}` });
      }
      res.json(job);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get job details" });
    }
  });

  // 4. Dead-Letter Queue (DLQ) List
  app.get("/api/dev/dlq", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const dlqEntries = await diagnosticService.listDeadLetterJobs();
      res.json(dlqEntries);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list dead letter queue entries" });
    }
  });

  // 4a. DLQ Detail
  app.get("/api/dev/dlq/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const dlqDetail = await diagnosticService.getDeadLetterJobDetails(req.params.id);
      if (!dlqDetail) {
        return res.status(404).json({ error: `Dead letter job entry not found for ID: ${req.params.id}` });
      }
      res.json(dlqDetail);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get dead letter entry details" });
    }
  });

  // Seed or Reset Sample Diagnostic Records
  app.post("/api/dev/seed-sample", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Sample diagnostic data seeding is strictly prohibited in production mode." });
    }
    try {
      await diagnosticService.seedSampleDiagnosticData();
      res.json({ status: "success", message: "Sample diagnostic records verified" });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });


}
