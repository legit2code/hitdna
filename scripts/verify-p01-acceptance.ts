import { createApp } from '../apps/server/index.ts';
import { signAccessToken } from '../packages/auth/src/index.ts';
import request from 'supertest';

async function main() {
  console.log('=== P01 Acceptance Verification ===');
  const app = await createApp();
  const adminToken = signAccessToken({
    principal_id: 'admin-p01-test',
    email: 'admin@hitdna.internal',
    roles: ['admin'],
    capabilities: ['admin:diagnostic'],
  });

  // Test 1: POST with payload { "scenarioId": "SCN-BENIGN-01" } (omitted providerType)
  console.log('\n--- Test 1: Omitted providerType payload ---');
  const payload1 = { scenarioId: 'SCN-BENIGN-01' };
  const res1 = await request(app)
    .post('/api/dev/sandbox/run')
    .set('Authorization', `Bearer ${adminToken}`)
    .send(payload1);

  console.log(`HTTP Status: ${res1.status}`);
  console.log('HTTP Body:', JSON.stringify(res1.body, null, 2));

  if (res1.status !== 400 || res1.body.code !== 'PROVIDER_TYPE_REQUIRED' || res1.body.truth_state !== 'NOT_CONFIGURED') {
    throw new Error(`Test 1 Failed: Expected status 400 and PROVIDER_TYPE_REQUIRED, got ${res1.status}`);
  }
  console.log('✓ PASS: Omitted provider request rejected with 400 and NOT_CONFIGURED code.');

  // Test 2: POST with explicit providerType = 'SIMULATED'
  console.log('\n--- Test 2: Explicit SIMULATED provider ---');
  const payload2 = { scenarioId: 'SCN-BENIGN-01', providerType: 'SIMULATED' };
  const res2 = await request(app)
    .post('/api/dev/sandbox/run')
    .set('Authorization', `Bearer ${adminToken}`)
    .send(payload2);

  console.log(`HTTP Status: ${res2.status}`);
  console.log('HTTP Body (summary):', {
    actual_provider: res2.body.actual_provider,
    requested_provider: res2.body.requested_provider,
    execution_mode: res2.body.execution_mode,
    truth_state: res2.body.truth_state,
    status: res2.body.status,
  });

  if (res2.status !== 200 || res2.body.actual_provider !== 'SIMULATED' || res2.body.truth_state !== 'SIMULATED' || res2.body.execution_mode !== 'SIMULATED') {
    throw new Error(`Test 2 Failed: Expected simulated truth_state and execution_mode, got actual_provider=${res2.body.actual_provider}`);
  }
  console.log('✓ PASS: Explicit SIMULATED provider runs clearly as SIMULATED; never promoted to OBSERVED.');

  // Test 3: POST with explicit providerType = 'E2B' with missing credentials
  console.log('\n--- Test 3: Explicit E2B provider with missing credentials ---');
  const prevKey = process.env.E2B_API_KEY;
  delete process.env.E2B_API_KEY;

  try {
    const payload3 = { scenarioId: 'SCN-BENIGN-01', providerType: 'E2B' };
    const res3 = await request(app)
      .post('/api/dev/sandbox/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send(payload3);

    console.log(`HTTP Status: ${res3.status}`);
    console.log('HTTP Body:', JSON.stringify(res3.body, null, 2));

    if (res3.status !== 503 || res3.body.code !== 'PROVIDER_UNAVAILABLE' || res3.body.actual_provider !== 'NONE') {
      throw new Error(`Test 3 Failed: Expected status 503 and PROVIDER_UNAVAILABLE, got ${res3.status}`);
    }
    console.log('✓ PASS: Explicit E2B with missing credentials fails closed without simulation fallback.');
  } finally {
    if (prevKey !== undefined) {
      process.env.E2B_API_KEY = prevKey;
    }
  }

  // Test 4: Attempted status mutation (SIMULATED provider with truth_state: OBSERVED)
  console.log('\n--- Test 4: Attempted status mutation ---');
  const payload4 = { scenarioId: 'SCN-BENIGN-01', providerType: 'SIMULATED', truth_state: 'OBSERVED' };
  const res4 = await request(app)
    .post('/api/dev/sandbox/run')
    .set('Authorization', `Bearer ${adminToken}`)
    .send(payload4);

  console.log(`HTTP Status: ${res4.status}`);
  console.log('HTTP Body:', JSON.stringify(res4.body, null, 2));

  if (res4.status !== 400 || res4.body.code !== 'ILLEGAL_TRUTH_STATE_MUTATION') {
    throw new Error(`Test 4 Failed: Expected status 400 and ILLEGAL_TRUTH_STATE_MUTATION, got ${res4.status}`);
  }
  console.log('✓ PASS: Attempted status mutation from SIMULATED to OBSERVED rejected.');

  console.log('\n=== All P01 Acceptance Criteria Verified Successfully ===');
  process.exit(0);
}

main().catch((err) => {
  console.error('P01 Verification Failed:', err);
  process.exit(1);
});
