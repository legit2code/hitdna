# apps/server — Bounded API Server

Node.js / Express bounded API server.

## Architecture & Boundaries
- Bootstrapped by `apps/server/index.ts` binding to port 3000.
- Serves `/api/health`, `/api/config/public`, and pipeline execution routes.
- Accesses server-side configuration exclusively via `packages/config`.
- Dispatches asynchronous tasks to independent worker queues rather than executing heavy analysis inside the HTTP request loop.
