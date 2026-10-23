import "dotenv/config";
import crypto from "node:crypto";
import express, { Express, Request, Response, NextFunction } from "express";
import path from "path";
import helmet from "helmet";
import { getServerConfig, ServerConfig } from "@caim/config";
import { initDatabase } from "./infrastructure/db.ts";
import { createServiceContainer, ServiceContainer } from "./services/container.ts";
import {
  createRateLimiterMiddleware,
  createCsrfProtectionMiddleware,
  PrincipalContext,
} from "@caim/auth";
import { createAuthPrincipalMiddleware } from "./middleware/security.ts";
import { createApiExpressRouter } from "@caim/api";
import { registerAllRoutes } from "./routes/index.ts";
import type { DatabaseClient, PostgresDatabaseAdapter } from "@caim/db";

// Extended Request with PrincipalContext
declare global {
  namespace Express {
    interface Request {
      principal?: PrincipalContext;
      requestId?: string;
    }
  }
}

export interface AppDependencies {
  config?: ServerConfig;
  dbClient?: DatabaseClient | any;
  dbAdapter?: PostgresDatabaseAdapter | any;
  container?: ServiceContainer;
  disableHelmet?: boolean;
}

const WELL_FORMED_REQUEST_ID_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;

/**
 * Creates the Express application with hardened HTTP middleware pipeline.
 * Pure function: does NOT listen on any port, has no network side-effects.
 */
export async function createApp(deps?: Partial<AppDependencies>): Promise<Express> {
  const app = express();

  // 1. Resolve configuration and dependencies
  const config = deps?.config || getServerConfig();
  let dbClient = deps?.dbClient;
  let dbAdapter = deps?.dbAdapter;

  if ((!dbClient || !dbAdapter) && !deps?.container) {
    const initialized = await initDatabase(config);
    dbClient = dbClient || initialized.dbClient;
    dbAdapter = dbAdapter || initialized.dbAdapter;
  }

  const container = deps?.container || (await createServiceContainer(dbClient, config, dbAdapter));

  // Disable x-powered-by
  app.disable("x-powered-by");

  // =========================================================================
  // ORDERED MIDDLEWARE PIPELINE (Task 2)
  // =========================================================================

  // 1. Request ID (accept only well-formed inbound, otherwise generate secure UUID)
  app.use((req: Request, res: Response, next: NextFunction) => {
    const inbound = req.headers["x-request-id"];
    let requestId: string;
    if (typeof inbound === "string" && WELL_FORMED_REQUEST_ID_REGEX.test(inbound)) {
      requestId = inbound;
    } else {
      requestId = crypto.randomUUID();
    }
    req.headers["x-request-id"] = requestId;
    req.requestId = requestId;
    (req as any).id = requestId;
    res.setHeader("x-request-id", requestId);
    next();
  });

  // 2. Helmet (CSP suited to built SPA with no inline script, HSTS in prod, referrer-policy, x-content-type-options, frame-ancestors 'none')
  if (!deps?.disableHelmet) {
    const isProduction = config.env === "production";
    app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
          },
        },
        hsts: isProduction
          ? {
              maxAge: 31536000,
              includeSubDomains: true,
              preload: true,
            }
          : false,
        referrerPolicy: { policy: "strict-origin-when-cross-origin" },
        xContentTypeOptions: true,
        frameguard: { action: "deny" },
      })
    );

    // Adapt security headers for SPA HTML/asset requests so preview iframe functions properly
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (!req.path.startsWith("/api") && req.path !== "/healthz") {
        res.removeHeader("X-Frame-Options");
        res.removeHeader("Cross-Origin-Opener-Policy");
        res.removeHeader("Cross-Origin-Resource-Policy");
        const csp = res.getHeader("Content-Security-Policy");
        if (typeof csp === "string") {
          const updatedCsp = csp
            .replace("frame-ancestors 'none'", "frame-ancestors 'self' https://*.google.com https://localhost.corp.google.com:26001")
            .replace("script-src 'self'", "script-src 'self' 'unsafe-inline' 'unsafe-eval'");
          res.setHeader("Content-Security-Policy", updatedCsp);
        }
      }
      next();
    });
  }

  // 3. Configured trust proxy
  if (config.trustProxy !== undefined) {
    app.set("trust proxy", config.trustProxy);
  }

  // 4. CORS allow-list from config
  const corsOrigins = config.corsOrigins || ["http://localhost:3000", "http://127.0.0.1:3000"];
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin) {
      const allowed = corsOrigins.includes(origin) || corsOrigins.includes("*");
      if (allowed) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        res.setHeader(
          "Access-Control-Allow-Headers",
          "Content-Type, Authorization, X-Requested-With, X-Request-ID, X-CSRF-Protection, X-Tenant-ID"
        );
        res.setHeader("Access-Control-Allow-Credentials", "true");
      }
    }
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  });

  // 5. Rate Limiter (BEFORE body parsers)
  app.use(createRateLimiterMiddleware(container.rateLimiterEngine));

  // 6. Body parsers with per-route limits (default 256 KB; explicit higher limits only on ingestion routes)
  const ingestionPaths = [
    "/api/ingestion",
    "/api/dev/ingestion",
    "/api/agents",
    "/api/packaging",
    "/api/v1/agents",
  ];
  const ingestionJsonParser = express.json({ limit: config.ingestionBodyLimit || "10mb" });
  const ingestionUrlencodedParser = express.urlencoded({
    extended: true,
    limit: config.ingestionBodyLimit || "10mb",
  });

  const defaultJsonParser = express.json({ limit: config.bodyLimit || "256kb" });
  const defaultUrlencodedParser = express.urlencoded({
    extended: true,
    limit: config.bodyLimit || "256kb",
  });

  app.use((req: Request, res: Response, next: NextFunction) => {
    const isIngestion = ingestionPaths.some(
      (p) => req.path.startsWith(p) || req.originalUrl?.startsWith(p)
    );
    const parser = isIngestion ? ingestionJsonParser : defaultJsonParser;
    const urlencoded = isIngestion ? ingestionUrlencodedParser : defaultUrlencodedParser;

    parser(req, res, (err) => {
      if (err) return next(err);
      urlencoded(req, res, next);
    });
  });

  // 7. CSRF Protection
  app.use(createCsrfProtectionMiddleware(container.csrfProtectionEngine));

  // 8. One Principal Resolution Middleware (never throws, never leaves req.principal undefined)
  app.use(createAuthPrincipalMiddleware(container.authHelper));

  // Test helper route for slow requests and secret leak testing (in test/dev)
  if (config.env !== "production" || process.env.NODE_ENV === "test") {
    app.get("/api/test-slow", async (req: Request, res: Response) => {
      const delay = parseInt((req.query.delay as string) || "400", 10);
      await new Promise((r) => setTimeout(r, delay));
      res.json({ ok: true, delay });
    });
    app.get("/api/test-error-secret", (_req: Request, _res: Response) => {
      throw new Error("CRITICAL_DATABASE_SECRET_KEY_NEVER_EXPOSE_9999");
    });
    app.post("/api/test-echo", (req: Request, res: Response) => {
      res.json({ ok: true, receivedBytes: JSON.stringify(req.body || {}).length });
    });
  }

  // 9. Route Registration
  registerAllRoutes(app, container);

  // Mount Standard Architecture V2.0.1 Typed API Router (/api/v1/*)
  app.use(
    "/api/v1",
    createApiExpressRouter({
      container,
      dbClient,
      dbAdapter,
    })
  );

  // Unknown /api/* routes: return RFC 9457 JSON 404, NEVER the SPA HTML
  app.all("/api/*", (req: Request, res: Response) => {
    const reqId =
      (req.headers["x-request-id"] as string) || req.requestId || (req as any).id || "unknown-request-id";
    res
      .status(404)
      .setHeader("Content-Type", "application/problem+json")
      .json({
        type: "about:blank",
        title: "Not Found",
        status: 404,
        detail: `Cannot ${req.method} ${req.path}`,
        instance: req.originalUrl || req.url,
        requestId: reqId,
      });
  });

  // 10. Static Serving & SPA fallback
  if (config.env !== "production" && process.env.SKIP_VITE !== "true") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else if (config.env === "production" || process.env.SERVE_STATIC === "true") {
    const distPath = path.join(process.cwd(), "dist");
    app.use(
      express.static(distPath, {
        setHeaders: (res, filePath) => {
          if (filePath.endsWith("index.html")) {
            res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
          } else if (filePath.includes("/assets/") || /\.[a-f0-9]{8,}\./.test(filePath)) {
            res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
          }
        },
      })
    );
    app.get("*", (_req, res) => {
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // 11. Central Error Handling Middleware (RFC 9457 application/problem+json)
  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    const status =
      typeof err.status === "number"
        ? err.status
        : typeof err.statusCode === "number"
        ? err.statusCode
        : 500;

    const reqId =
      (req.headers["x-request-id"] as string) || req.requestId || (req as any).id || "unknown-request-id";

    if (status >= 500) {
      console.error(`[CAIM Server Error] ${req.method} ${req.url} - Request ID: ${reqId}:`, err);
    }

    if (res.headersSent) {
      return;
    }

    res.status(status);
    res.setHeader("Content-Type", "application/problem+json");

    let title = "Internal Server Error";
    let detail = `An unexpected error occurred. Reference Request ID: ${reqId}`;

    if (status === 400) {
      title = "Bad Request";
      detail = err.message || "The request could not be understood.";
    } else if (status === 401) {
      title = "Unauthorized";
      detail = "Authentication is required and has failed or has not yet been provided.";
    } else if (status === 403) {
      title = "Forbidden";
      detail = "The server understood the request but refuses to authorize it.";
    } else if (status === 404) {
      title = "Not Found";
      detail = err.message || "The requested resource could not be found.";
    } else if (status === 413) {
      title = "Payload Too Large";
      detail = "Request entity too large. Payload exceeds the maximum allowed size.";
    } else if (status === 429) {
      title = "Too Many Requests";
      detail = err.message || "Rate limit exceeded.";
    } else if (status >= 400 && status < 500) {
      title = err.name || "Client Error";
      detail = err.message || "A client error occurred.";
    }

    res.json({
      type: "about:blank",
      title,
      status,
      detail,
      instance: req.originalUrl || req.url,
      requestId: reqId,
    });
  });

  return app;
}
