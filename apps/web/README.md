# Web Application

The web application is CAIM's React 19 single-page console. It provides the user-facing workflow screens for agent discovery, analysis, evidence, risk, governance, knowledge, modification, packaging, observability, operations, and release verification.

## Structure

- `App.tsx` defines the main navigation and composes the workflow views.
- `src/components/views/` contains the domain workflow screens.
- `src/components/dev/` contains the engineering diagnostic console.
- `src/components/auth/` contains login, signup, email verification, and password-change views.
- `src/context/` contains React authentication context.
- `src/lib/` contains authenticated API helpers.
- `src/main.tsx` mounts the application into the document root.

## Development

Run the full application from the repository root:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run dev
```

Vite is mounted as Express middleware during development. For a production client build, run `pnpm run build`; the browser assets are emitted under `dist/` and served by the production Express process.

## Client/server boundary

The browser is not a trusted execution environment. All privileged actions and analysis pipelines are called through bounded `/api/*` endpoints. Do not import `workers/*`, server-only secrets, Node crypto, or packaging/signing implementations into client components. The Vite isolation plugin rejects these imports, and architecture tests cover bundle boundaries.

Authorization and tenant scope must be enforced by the server and database; hiding a button or route in React is not an authorization control.
