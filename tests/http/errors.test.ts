import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../../apps/server/index.ts';

describe('HTTP Central Error Handling (R03 Task 4)', () => {
  it('ensures a thrown error with a secret in its message never leaks in a 500 response body', async () => {
    const app = await createApp();
    const secretSubstring = 'CRITICAL_DATABASE_SECRET_KEY_NEVER_EXPOSE_9999';

    const res = await request(app)
      .get('/api/test-error-secret')
      .set('x-request-id', 'req-test-error-handling-12345');

    // Must be status 500
    expect(res.status).toBe(500);

    // Must return RFC 9457 application/problem+json
    expect(res.headers['content-type']).toContain('application/problem+json');

    // Secret string MUST NOT appear anywhere in the body or text response
    expect(res.text).not.toContain(secretSubstring);
    expect(JSON.stringify(res.body)).not.toContain(secretSubstring);

    // Must not leak stack trace
    expect(res.body.stack).toBeUndefined();
    expect(res.text).not.toContain('at createApp');

    // Must return the request ID
    expect(res.body.requestId).toBe('req-test-error-handling-12345');
    expect(res.body.title).toBe('Internal Server Error');
    expect(res.body.status).toBe(500);
    expect(res.body.detail).toContain('req-test-error-handling-12345');
  });
});
