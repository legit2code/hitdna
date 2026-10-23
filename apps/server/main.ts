import "dotenv/config";
import { getServerConfig } from "@caim/config";
import { initDatabase } from "./infrastructure/db.ts";
import { createServiceContainer } from "./services/container.ts";
import { createApp, AppDependencies } from "./index.ts";

export async function startServer(deps?: Partial<AppDependencies>) {
  const config = deps?.config || getServerConfig();
  const { dbClient, dbAdapter } =
    deps?.dbClient && deps?.dbAdapter
      ? { dbClient: deps.dbClient, dbAdapter: deps.dbAdapter }
      : await initDatabase(config);
  const container = deps?.container || (await createServiceContainer(dbClient, config, dbAdapter));

  const app = await createApp({ config, dbClient, dbAdapter, container });

  const argvPort = (() => {
    const idx = process.argv.indexOf("--port");
    if (idx !== -1 && process.argv[idx + 1]) {
      const p = parseInt(process.argv[idx + 1], 10);
      if (!isNaN(p)) return p;
    }
    return null;
  })();
  const argvHost = (() => {
    const idx = process.argv.indexOf("--host");
    if (idx !== -1 && process.argv[idx + 1]) {
      return process.argv[idx + 1];
    }
    return null;
  })();

  const port = argvPort ?? config.port;
  const host = argvHost ?? config.host;

  const server = app.listen(port, host, () => {
    console.log(`[CAIM Platform] Server running on http://${host}:${port} [Env: ${config.env}]`);
  });

  const timeoutMs = config.shutdownTimeoutMs || 10000;
  let isShuttingDown = false;

  const shutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`[CAIM Platform] Received ${signal}, starting graceful shutdown...`);

    const forceTimer = setTimeout(() => {
      console.error(`[CAIM Platform] Graceful shutdown timed out after ${timeoutMs}ms. Forcing exit.`);
      process.exit(1);
    }, timeoutMs);
    forceTimer.unref();

    try {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      if (dbAdapter) {
        await dbAdapter.close().catch((err: any) => {
          console.error("[CAIM Platform] Error closing dbAdapter:", err);
        });
      }

      clearTimeout(forceTimer);
      console.log(`[CAIM Platform] Graceful shutdown completed cleanly.`);
      process.exit(0);
    } catch (err) {
      console.error("[CAIM Platform] Error during graceful shutdown:", err);
      clearTimeout(forceTimer);
      process.exit(1);
    }
  };

  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));

  process.on("unhandledRejection", (reason: unknown) => {
    console.error("[FATAL] Unhandled Promise Rejection:", reason);
    process.exit(1);
  });

  process.on("uncaughtException", (err: Error) => {
    console.error("[FATAL] Uncaught Exception:", err);
    process.exit(1);
  });

  return { app, server, container, shutdown };
}

// Auto-run if executed directly as entrypoint
const isMain =
  typeof process !== "undefined" &&
  Boolean(
    process.argv[1] &&
      (process.argv[1].endsWith("apps/server/main.ts") ||
        process.argv[1].endsWith("apps/server/main.js"))
  );

if (isMain) {
  startServer().catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
  });
}
