import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../../apps/server/index.ts';
import { getServerConfig } from '@caim/config';

describe('HTTP Body Limits (R03 Task 2)', () => {
  it('rejects a 2 MB JSON body to a default route with 413 and RFC 9457 problem details', async () => {
    const config = { ...getServerConfig(), bodyLimit: '256kb', ingestionBodyLimit: '10mb' };
    const app = await createApp({ config });

    // Generate ~2 MB payload (2 * 1024 * 1024 characters)
    const largePayload = {
      title: 'Oversized payload',
      data: 'A'.repeat(2 * 1024 * 1024),
    };

    const res = await request(app)
      .post('/api/test-echo')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify(largePayload));

    // Must return 413 Payload Too Large
    expect(res.status).toBe(413);
    expect(res.headers['content-type']).toContain('application/problem+json');
    expect(res.body.status).toBe(413);
    expect(res.body.title).toBe('Payload Too Large');
    expect(res.body.detail).toContain('exceeds the maximum allowed size');
  });

  it('allows ingestion routes to accept payloads up to their configured maximum (>256 KB)', async () => {
    const config = { ...getServerConfig(), bodyLimit: '256kb', ingestionBodyLimit: '10mb' };
    const app = await createApp({ config });

    // Payload of ~600 KB: well over the 256 KB default limit, but within the 10 MB ingestion limit
    const ingestionPayload = {
      canonicalName: 'large-agent-test',
      sourceLocator: 'github.com/caim-org/large-agent',
      manifestContent: 'B'.repeat(600 * 1024),
    };

    const res = await request(app)
      .post('/api/ingestion/submit')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify(ingestionPayload));

    // The parser MUST NOT reject this with 413 (it may return 401 unauthenticated or 200, but NOT 413)
    expect(res.status).not.toBe(413);
  });
});
