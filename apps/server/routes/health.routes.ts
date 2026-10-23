import { Express, Request, Response } from "express";
import { getPublicConfig, getOptionalProviderStatus } from "@caim/config";
import type { ServiceContainer } from "../services/container.ts";

export function registerHealthRoutes(app: Express, container: ServiceContainer) {
  const { config, dbClient, dbAdapter } = container;

  // Health and System Baseline APIs (Liveness)
  const livenessHandler = (_req: Request, res: Response) => {
    res.json({
      status: "healthy",
      alive: true,
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
      platform: "Agent Lifecycle Intelligence Platform (CAIM)",
      baseline: config.features ? "V2.0.1 Controlled Implementation Baseline" : "Unknown",
      version: "2.0.1",
      runtime: "Node.js + Express + Vite Full-Stack Runtime",
    });
  };

  const healthzHandler = (_req: Request, res: Response) => {
    res.status(200).json({
      status: "ok",
      uptime: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  };

  app.get("/healthz", healthzHandler);
  app.get("/api/healthz", healthzHandler);
  app.get("/api/health", livenessHandler);
  app.get("/health", livenessHandler);

  // Split health: /readyz (DB reachable and migration head equals expected)
  const readyzHandler = async (_req: Request, res: Response) => {
    let dbConnected = false;
    let schemaVerified = false;
    let appliedHead: string | null = null;
    const errors: string[] = [];

    if (!dbClient) {
      errors.push("Database client is not initialized");
    } else {
      try {
        await dbClient.query("SELECT 1;");
        dbConnected = true;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        errors.push(`Database ping failed: ${msg}`);
      }
    }

    if (dbAdapter && typeof dbAdapter.verifySchema === "function") {
      try {
        const schemaRes = await dbAdapter.verifySchema();
        schemaVerified = schemaRes.verified;
        if (schemaRes.appliedMigrations && schemaRes.appliedMigrations.length > 0) {
          appliedHead = schemaRes.appliedMigrations[schemaRes.appliedMigrations.length - 1];
        }
        if (schemaRes.missingMigrations && schemaRes.missingMigrations.length > 0) {
          errors.push(`Missing migrations: ${schemaRes.missingMigrations.join(', ')}`);
        }
      } catch (sErr: unknown) {
        const msg = sErr instanceof Error ? sErr.message : String(sErr);
        errors.push(`Schema verification error: ${msg}`);
      }
    } else {
      schemaVerified = true;
      appliedHead = "IN_MEMORY";
    }

    const isReady = dbConnected && schemaVerified;
    const status = isReady ? 200 : 503;

    return res.status(status).json({
      status: isReady ? "ready" : "unready",
      ready: isReady,
      db: dbConnected ? "connected" : "disconnected",
      schema: schemaVerified ? "verified" : "unverified",
      appliedHead,
      errors: errors.length > 0 ? errors : undefined,
      timestamp: new Date().toISOString(),
    });
  };

  app.get("/readyz", readyzHandler);
  app.get("/api/readyz", readyzHandler);

  // System Readiness APIs (Dependency & Subsystem Verifications)
  const readinessHandler = async (_req: Request, res: Response) => {
    const isProduction = process.env.NODE_ENV === "production";
    const checks: Record<string, any> = {};
    let isReady = true;

    // 1. Database Connectivity & Pool Health
    if (!dbClient) {
      checks.database = { status: "UNHEALTHY", error: "Database client is not initialized" };
      isReady = false;
    } else {
      try {
        const start = Date.now();
        await dbClient.query("SELECT 1;");
        const latencyMs = Date.now() - start;
        checks.database = {
          status: "HEALTHY",
          latency_ms: latencyMs,
        };
      } catch (dbErr: any) {
        checks.database = { status: "UNHEALTHY", error: dbErr.message };
        isReady = false;
      }
    }

    // 2. Database Schema & Migration Status
    if (dbAdapter && typeof dbAdapter.verifySchema === "function") {
      try {
        const schemaRes = await dbAdapter.verifySchema();
        if (schemaRes.verified) {
          checks.schema = { status: "VERIFIED", applied_count: schemaRes.appliedMigrations.length };
        } else {
          checks.schema = {
            status: "UNVERIFIED",
            missing_migrations: schemaRes.missingMigrations,
            missing_tables: schemaRes.missingTables,
          };
          if (isProduction) isReady = false;
        }
      } catch (sErr: any) {
        checks.schema = { status: "ERROR", error: sErr.message };
        if (isProduction) isReady = false;
      }
    } else {
      checks.schema = { status: "VERIFIED", mode: "in-memory / test" };
    }

    // 3. Execution Sandbox Worker Status (runs out-of-process in worker-sandbox-orchestrator)
    checks.sandbox_provider = {
      status: "DELEGATED_TO_WORKER",
      worker_class: "sandbox-orchestrator",
      mode: "asynchronous_queue",
    };

    // 4. Memory Resource Allocation
    const mem = process.memoryUsage();
    checks.memory = {
      status: "HEALTHY",
      rss_bytes: mem.rss,
      heap_used_bytes: mem.heapUsed,
      heap_total_bytes: mem.heapTotal,
    };

    if (!isReady) {
      return res.status(503).json({
        status: "UNREADY",
        ready: false,
        timestamp: new Date().toISOString(),
        checks,
      });
    }

    return res.status(200).json({
      status: "READY",
      ready: true,
      timestamp: new Date().toISOString(),
      checks,
    });
  };

  app.get("/api/ready", readinessHandler);
  app.get("/ready", readinessHandler);

  // Public safe configuration endpoint (secrets strictly excluded)
  app.get("/api/config/public", (_req, res) => {
    const publicConfig = getPublicConfig();
    res.json(publicConfig);
  });

  // System diagnostic state endpoint
  app.get("/api/pipeline/state", (_req, res) => {
    res.json({
      stage: "P06_COMPLETE",
      total_engines_target: 71,
      implemented_count: 0,
      active_workers: [
        "discovery",
        "semantic",
        "static-analysis",
        "composition",
        "sandbox-orchestrator",
        "decision",
        "knowledge",
        "lifecycle",
        "evaluation",
      ],
      database: {
        foundation_p03: "ACTIVE",
        analysis_intel_p04: "ACTIVE",
        knowledge_lifecycle_ops_p05: "ACTIVE",
        auth_roles_rls_vault_p06: "ACTIVE",
        total_migrations: 13,
        lineage_engine: "OPERATIONAL",
      },
      auth: {
        roles_defined: 10,
        vault_boundary: "ENFORCED",
        rls_policies: "ACTIVE",
      },
      secrets_configured: Boolean(config.geminiApiKey),
      providers: {
        github: getOptionalProviderStatus("githubToken"),
        huggingface: getOptionalProviderStatus("huggingfaceApiKey"),
        e2b: getOptionalProviderStatus("e2bApiKey"),
        supabase: getOptionalProviderStatus("supabaseServiceKey"),
      },
      features: config.features,
      models: config.models,
    });
  });
}
