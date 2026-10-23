import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireProductUserAccess, requireWorkerManagementAccess } from "../middleware/security.ts";

export function registerWorkersRoutes(app: Express, container: ServiceContainer) {
  const { autonomousWorker, scheduledWorkerMap } = container;

  app.get("/api/workers/status", requireProductUserAccess, (_req: Request, res: Response) => {
    res.json({
      discovery_worker: autonomousWorker.getStatus(),
      scheduled_workers: Array.from(scheduledWorkerMap.values()).map(w => w.getStatus()),
    });
  });

  // Get status of specific background worker
  app.get("/api/workers/:workerId/status", requireProductUserAccess, (req: Request, res: Response) => {
    const worker = scheduledWorkerMap.get(req.params.workerId);
    if (!worker) {
      return res.status(404).json({ error: `Worker not found: ${req.params.workerId}` });
    }
    res.json(worker.getStatus());
  });

  // Start specific background worker with optional intervalMs
  app.post("/api/workers/:workerId/start", requireWorkerManagementAccess, (req: Request, res: Response) => {
    const worker = scheduledWorkerMap.get(req.params.workerId);
    if (!worker) {
      return res.status(404).json({ error: `Worker not found: ${req.params.workerId}` });
    }
    const { intervalMs } = req.body || {};
    worker.start(intervalMs ? Number(intervalMs) : undefined);
    res.json({ success: true, message: `Started worker ${worker.name}`, status: worker.getStatus() });
  });

  // Stop specific background worker
  app.post("/api/workers/:workerId/stop", requireWorkerManagementAccess, (req: Request, res: Response) => {
    const worker = scheduledWorkerMap.get(req.params.workerId);
    if (!worker) {
      return res.status(404).json({ error: `Worker not found: ${req.params.workerId}` });
    }
    worker.stop();
    res.json({ success: true, message: `Stopped worker ${worker.name}`, status: worker.getStatus() });
  });

  // Trigger immediate cycle for specific background worker
  app.post("/api/workers/:workerId/run-now", requireWorkerManagementAccess, async (req: Request, res: Response) => {
    const worker = scheduledWorkerMap.get(req.params.workerId);
    if (!worker) {
      return res.status(404).json({ error: `Worker not found: ${req.params.workerId}` });
    }
    try {
      const result = await worker.runCycle();
      res.json({ success: true, result, status: worker.getStatus() });
    } catch (err: any) {
      res.status(500).json({ error: err.message || `Failed to run cycle for ${worker.name}` });
    }
  });

  // Start all workers
  app.post("/api/workers/start-all", requireWorkerManagementAccess, (req: Request, res: Response) => {
    const { intervalMs } = req.body || {};
    for (const worker of scheduledWorkerMap.values()) {
      worker.start(intervalMs ? Number(intervalMs) : undefined);
    }
    res.json({
      success: true,
      message: "Started all scheduled background workers",
      workers: Array.from(scheduledWorkerMap.values()).map(w => w.getStatus()),
    });
  });

  // Stop all workers
  app.post("/api/workers/stop-all", requireWorkerManagementAccess, (_req: Request, res: Response) => {
    for (const worker of scheduledWorkerMap.values()) {
      worker.stop();
    }
    res.json({
      success: true,
      message: "Stopped all scheduled background workers",
      workers: Array.from(scheduledWorkerMap.values()).map(w => w.getStatus()),
    });
  });

  // Browsable Library of Pre-Analyzed & Discovered Agents

}
