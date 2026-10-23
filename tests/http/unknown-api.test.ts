import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../../apps/server/index.ts';

describe('Unknown API Routes (R03 Task 4)', () => {
  it('returns RFC 9457 JSON 404 for unknown /api/* routes, never SPA HTML', async () => {
    const app = await createApp();

    const res = await request(app)
      .get('/api/nope')
      .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');

    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toContain('application/problem+json');

    // Body must be JSON problem details
    expect(res.body).toBeDefined();
    expect(res.body.status).toBe(404);
    expect(res.body.title).toBe('Not Found');
    expect(res.body.detail).toContain('Cannot GET /api/nope');

    // Never return SPA HTML
    expect(res.text).not.toContain('<!DOCTYPE html>');
    expect(res.text).not.toContain('<html');
  });

  it('returns JSON 404 for deeply nested unknown /api/v1/unknown/endpoint routes', async () => {
    const app = await createApp();

    const res = await request(app).post('/api/v1/unknown/nonexistent-action');

    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toContain('application/problem+json');
    expect(res.body.status).toBe(404);
  });
});
