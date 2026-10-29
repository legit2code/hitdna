/**
 * Integration Tests: HTTP Routes & System Contracts (PF-02.M07)
 * Tests client/server contracts, health, and error envelopes without external keys.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Server } from 'node:http';
import { createExpressApp } from '../../server/app.ts';
import { SuccessEnvelope, ErrorEnvelope, SystemHealth, ReadinessState } from '../../contracts/system.ts';

describe('Server HTTP API Integration Tests', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    const app = createExpressApp();
    await new Promise<void>((resolve) => {
      // Bind to port 0 to choose an available ephemeral port
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (typeof addr === 'object' && addr !== null) {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  test('GET /api/health returns 200 and valid SuccessEnvelope<SystemHealth>', async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<SystemHealth>;
    assert.equal(json.success, true);
    assert.equal(json.data.status, 'healthy');
    assert.equal(json.data.architectureVersion, '5.0.0');
    assert.equal(json.data.checks.server, true);
    assert.equal(json.meta?.phase, 'P03');
  });

  test('GET /api/ready returns 200 and valid SuccessEnvelope<ReadinessState>', async () => {
    const res = await fetch(`${baseUrl}/api/ready`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<ReadinessState>;
    assert.equal(json.success, true);
    assert.equal(json.data.ready, true);
    assert.equal(json.data.phase, 'P03');
    assert.equal(json.data.engineId, 'PF-04');
  });

  test('GET /api/diag returns 200 and diagnostic information for active engines', async () => {
    const res = await fetch(`${baseUrl}/api/diag`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<Record<string, unknown>>;
    assert.equal(json.success, true);
    assert.equal(json.data.engineId, 'PF-04');
    assert.equal(json.meta?.phase, 'P03');
  });

  test('GET /api/config returns 200 and safe public client config without secrets', async () => {
    const res = await fetch(`${baseUrl}/api/config`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<{ client: Record<string, unknown>; features: Record<string, unknown> }>;
    assert.equal(json.success, true);
    assert.equal(json.data.client.currentPhase, 'P03');
    assert.equal(json.data.client.architectureVersion, '5.0.0');
    assert.equal(typeof json.data.features.enableArtistSafetyGuard, 'boolean');

    // Verify no secret leakage
    const bodyStr = JSON.stringify(json);
    assert.equal(bodyStr.includes('GEMINI_API_KEY'), false);
    assert.equal(bodyStr.includes('SPOTIFY_CLIENT_SECRET'), false);
  });

  test('GET /api/taxonomy/genres returns controlled canonical genre vocabulary', async () => {
    const res = await fetch(`${baseUrl}/api/taxonomy/genres`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<Array<{ genreId: string; name: string; nodeType: string }>>;
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data));
    assert.ok(json.data.length >= 10);
    assert.ok(json.data.some(g => g.name === 'Hip-Hop' && g.nodeType === 'ROOT_FAMILY'));
    assert.ok(json.data.some(g => g.name === 'Trap' && g.nodeType === 'SUBGENRE'));
    assert.ok(json.data.some(g => g.name === 'Country Rap' && g.nodeType === 'HYBRID_LABEL'));
  });

  test('GET /api/taxonomy/graph returns taxonomy structural summary', async () => {
    const res = await fetch(`${baseUrl}/api/taxonomy/graph`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<{
      taxonomyVersion: string;
      nodeCount: number;
      edgeCount: number;
      rootFamilies: Array<{ id: string; name: string }>;
    }>;
    assert.equal(json.success, true);
    assert.equal(json.data.taxonomyVersion, '5.0.0');
    assert.ok(json.data.nodeCount >= 10);
    assert.ok(json.data.edgeCount >= 10);
    assert.ok(json.data.rootFamilies.length >= 5);
  });

  test('GET /api/registries/language-sources returns permitted and non-permitted source rules', async () => {
    const res = await fetch(`${baseUrl}/api/registries/language-sources`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<Record<string, { permitted: boolean }>>;
    assert.equal(json.success, true);
    assert.equal(json.data.LYRICS_ANNOTATION.permitted, true);
    assert.equal(json.data.UNAUTHORIZED_SCRAPING.permitted, false);
  });

  test('GET /api/registries/pattern-extractors returns deterministic extractors', async () => {
    const res = await fetch(`${baseUrl}/api/registries/pattern-extractors`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<Record<string, { determinismGuarantee: string }>>;
    assert.equal(json.success, true);
    assert.equal(json.data.CHORD_PROGRESSION_EXTRACTOR.determinismGuarantee, 'STRICT_DETERMINISTIC');
  });

  test('GET /api/providers returns 200 with masked provider states and zero secrets', async () => {
    const res = await fetch(`${baseUrl}/api/providers`);
    assert.equal(res.status, 200);

    const json = (await res.json()) as SuccessEnvelope<Array<{ name: string; status: string; liveVerificationPerformed: boolean }>>;
    assert.equal(json.success, true);
    assert.ok(Array.isArray(json.data));
    assert.ok(json.data.length >= 4);

    for (const provider of json.data) {
      assert.notEqual(provider.status, 'AVAILABLE');
      assert.equal(provider.liveVerificationPerformed, false);
    }
  });

  test('GET /api/unknown-endpoint returns 404 with structured ErrorEnvelope', async () => {
    const res = await fetch(`${baseUrl}/api/unknown-endpoint`);
    assert.equal(res.status, 404);

    const json = (await res.json()) as ErrorEnvelope;
    assert.equal(json.success, false);
    assert.equal(json.error.code, 'ROUTE_NOT_FOUND');
    assert.equal(json.error.phase, 'P03');
  });
});
