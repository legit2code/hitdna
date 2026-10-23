async function main() {
  // Login
  const loginRes = await fetch('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'admin@caim.internal',
      password: 'Admin#2026$RotatedRootKey!8472',
    }),
  });
  const loginData: any = await loginRes.json();
  const token = loginData.access_token;

  // Generate artifact
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
  const artifactId = genData.artifact?.artifact_id || genData.result?.artifact_id;

  // Execute WITHOUT specifying provider_type
  const execRes = await fetch('http://localhost:3000/api/composer/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      artifact_id: artifactId,
      technique_category: 'TOOL_SYNTHESIS',
      synthetic_target_domain: 'synthetic-target.local',
      input_payload: { probe_id: 'probe-live-e2b-verification' },
    }),
  });

  const execData: any = await execRes.json();
  console.log('=== EXACT RESPONSE FROM POST /api/composer/execute (OMITTING provider_type) ===');
  console.log('HTTP Status:', execRes.status);
  console.log('provider_type:', execData.provider_type || execData.result?.provider_type);
  console.log('session_id:', execData.session_id || execData.result?.session_id);
  console.log('run_id:', execData.run_id || execData.result?.run_id);
  console.log('status:', execData.status || execData.result?.status);
  console.log('\nFULL_JSON_START');
  console.log(JSON.stringify(execData, null, 2));
  console.log('FULL_JSON_END');
}

main().catch(console.error);
