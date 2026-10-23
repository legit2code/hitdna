import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../../apps/server/index.ts';
import { getServerConfig } from '@caim/config';

describe('HTTP Security Headers (R03 Task 2)', () => {
  it('enforces CSP, nosniff, frame-ancestors, and removes x-powered-by in standard environment', async () => {
    const config = { ...getServerConfig(), env: 'development' as const };
    const app = await createApp({ config });

    const res = await request(app).get('/healthz');

    expect(res.status).toBe(200);

    // 1. Content Security Policy
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("'unsafe-eval'");

    // 2. X-Content-Type-Options: nosniff
    expect(res.headers['x-content-type-options']).toBe('nosniff');

    // 3. Frame-Ancestors / X-Frame-Options
    expect(res.headers['x-frame-options']).toBe('DENY');

    // 4. X-Powered-By is disabled
    expect(res.headers['x-powered-by']).toBeUndefined();

    // 5. In non-production, HSTS is disabled by default
    expect(res.headers['strict-transport-security']).toBeUndefined();
  });

  it('enforces HSTS header when running in production environment', async () => {
    const prodConfig = { ...getServerConfig(), env: 'production' as const };
    const mockDbClient = { query: async () => ({ rows: [] }) };
    const mockDbAdapter = {
      close: async () => {},
      verifySchema: async () => ({ verified: true, appliedMigrations: [] }),
    } as any;

    const app = await createApp({
      config: prodConfig,
      dbClient: mockDbClient,
      dbAdapter: mockDbAdapter,
    });

    const res = await request(app).get('/healthz');

    expect(res.status).toBe(200);
    const hsts = res.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).toContain('max-age=31536000');
    expect(hsts).toContain('includeSubDomains');
  });

  it('fails security header assertions when helmet is removed (negative control verification)', async () => {
    // Negative control: when helmet is omitted/disabled, CSP and nosniff headers are missing
    const appWithoutHelmet = await createApp({ disableHelmet: true });

    const res = await request(appWithoutHelmet).get('/healthz');

    expect(res.headers['content-security-policy']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBeUndefined();
    expect(res.headers['x-frame-options']).toBeUndefined();
  });
});
