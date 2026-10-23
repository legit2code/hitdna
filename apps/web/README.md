# apps/web — Client Web Application

The frontend React client application entrypoint.

## Architecture & Boundaries
- Uses standard React 18+ and Tailwind CSS.
- Served by the preview server during development and compiled to `dist/` for production.
- **Strict Invariant**: Web bundle NEVER directly imports worker code (`workers/*`) or server-only secret configuration. All communication with analysis pipelines is routed via bounded `/api/*` endpoints.
