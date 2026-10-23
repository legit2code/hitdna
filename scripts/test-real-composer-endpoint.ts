async function testRealComposerEndpoint() {
  console.log('=== TESTING REAL POST /api/composer/execute ENDPOINT ===');
  console.log('Client process.env.E2B_API_KEY present:', Boolean(process.env.E2B_API_KEY));

  // 1. Authenticate as admin
  const loginRes = await fetch('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'admin@caim.internal',
      password: 'Admin#2026$RotatedRootKey!8472',
    }),
  });

  if (!loginRes.ok) {
    throw new Error(`Login failed with status ${loginRes.status}: ${await loginRes.text()}`);
  }

  const loginData: any = await loginRes.json();
  const token = loginData.access_token;
  const principalId = loginData.principal.principal_id;
  console.log(`[1] Authenticated as principal: ${principalId}`);

  // 2. Ensure composer:full_access grant exists
  const statusRes = await fetch('http://localhost:3000/api/composer/my-capabilities', {
    headers: { Authorization: `Bearer ${token}` },
  });
  const statusData: any = await statusRes.json();
  console.log(`[2] Composer status: tier=${statusData.tier}`);

  if (statusData.tier !== 'full') {
    console.log('[2.1] Granting composer:full_access to admin...');
    const grantRes = await fetch('http://localhost:3000/api/composer/grants', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        capability_key: 'composer:full_access',
        principal_id: principalId,
        justification: 'Automated test suite verification of live endpoint execution',
      }),
    });
    console.log(`Grant response status: ${grantRes.status}`);
  }

  // 3. Generate a benign artifact
  console.log('\n[3] Calling POST /api/composer/generate...');
  const genRes = await fetch('http://localhost:3000/api/composer/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      prompt: 'Build synthetic token entropy auditor for http://synthetic-target.local/auth',
      technique_category: 'TOOL_SYNTHESIS',
      target_name: 'SyntheticTokenEntropyAuditor',
    }),
  });

  const genData: any = await genRes.json();
  console.log('Generate response status:', genRes.status);
  const artifactId = genData.artifact?.artifact_id || genData.result?.artifact_id;
  console.log('Generated Artifact ID:', artifactId);

  // 4. Test POST /api/composer/execute WITHOUT passing provider_type (auto-resolution)
  console.log('\n[4] Calling POST /api/composer/execute (auto-resolved provider_type)...');
  const execRes1 = await fetch('http://localhost:3000/api/composer/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      artifact_id: artifactId,
      technique_category: 'TOOL_SYNTHESIS',
      synthetic_target_domain: 'synthetic-target.local',
      input_payload: { probe_id: 'probe-001' },
    }),
  });

  console.log('Execute 1 HTTP status:', execRes1.status);
  const execData1: any = await execRes1.json();
  console.log('\n--- RAW RESPONSE JSON 1 (Auto-resolved provider) ---');
  console.log(JSON.stringify(execData1, null, 2));

  // 5. Test POST /api/composer/execute WITH explicit provider_type: 'E2B'
  console.log('\n[5] Calling POST /api/composer/execute (explicit provider_type: "E2B")...');
  const execRes2 = await fetch('http://localhost:3000/api/composer/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      artifact_id: artifactId,
      technique_category: 'TOOL_SYNTHESIS',
      synthetic_target_domain: 'synthetic-target.local',
      provider_type: 'E2B',
      input_payload: { probe_id: 'probe-002' },
    }),
  });

  console.log('Execute 2 HTTP status:', execRes2.status);
  const execData2: any = await execRes2.json();
  console.log('\n--- RAW RESPONSE JSON 2 (Explicit E2B) ---');
  console.log(JSON.stringify(execData2, null, 2));
}

testRealComposerEndpoint().catch(console.error);
