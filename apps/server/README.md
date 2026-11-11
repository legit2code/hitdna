# Server Application

The server application is CAIM's HTTP and trust boundary. The root `server.ts` entrypoint loads the runtime prelude and invokes `startServer()` from `apps/server/main.ts`. The startup module initializes configuration, PostgreSQL access, the service container, the Express app, and the network listener.

## Main responsibilities

- Load typed configuration and secret material from the server environment.
- Initialize PostgreSQL and verify the production schema before accepting traffic.
- Construct shared authentication, persistence, discovery, analysis, knowledge, packaging, audit, and operations services.
- Apply request IDs, security headers, CORS, rate limiting, request-size limits, CSRF protection, and principal resolution.
- Register domain API routes and the typed `/api/v1` router.
- Serve Vite middleware during development or compiled static assets in production.
- Shut down the HTTP server and database adapter gracefully on SIGTERM/SIGINT.

## Important files

| File | Responsibility |
|---|---|
| `../../server.ts` | Process entrypoint. |
| `main.ts` | Listener lifecycle and graceful shutdown. |
| `index.ts` | Express app factory, middleware and route mounting. |
| `infrastructure/db.ts` | PostgreSQL initialization, migration verification and dev/test fallback. |
| `services/container.ts` | Shared service and worker dependency construction. |
| `middleware/security.ts` | Principal/authentication middleware. |
| `routes/index.ts` | Central route registration. |
| `../../packages/api` | Typed API router, envelopes, errors and adapters. |

## Run locally

From the repository root:

```bash
corepack enable
pnpm install --frozen-lockfile
cp .env.example .env
pnpm run dev
```

The application defaults to port 3000. Port and host configuration are parsed in `packages/config/src/loaders.ts`; command-line `--port` and `--host` arguments are also supported by `apps/server/main.ts`.

## Database behavior

Production requires a configured PostgreSQL connection URL (`DATABASE_URL`, `SUPABASE_DB_URL`, or `POSTGRES_URL`). Startup checks database health and verifies that required migrations and tables are present. Production startup fails closed if the connection or schema verification fails, and does not run DDL migrations automatically.

The in-memory `pg-mem` fallback is limited to development/test. Do not use it as evidence of durable persistence, production RLS, backup, or failover behavior.

## Security boundaries

The server owns authentication, tenant context, role/capability checks, CSRF, rate limiting, audit persistence, and access to private provider credentials. Do not move these checks into the browser or expose service credentials in public configuration. Keep worker and privileged packages out of the web bundle.
