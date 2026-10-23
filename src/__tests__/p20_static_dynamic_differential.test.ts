/**
 * P20 — Static vs Dynamic Behavioral Differential Engine Test Suite
 * Comprehensive verification of discrepancy detection, concordance evaluation,
 * target-specific matching, and differential status classification.
 */

import { describe, it, expect } from 'vitest';
import { 
  StaticDynamicComparator,
  DynamicSandboxRunResult,
  RuntimeEvent,
} from '../../workers/sandbox-orchestrator/index.ts';
import { StaticFinding } from '../../workers/static-analysis/types.ts';

function createMockStaticFinding(overrides: Partial<StaticFinding>): StaticFinding {
  return {
    finding_id: overrides.finding_id || `sf-${Math.random().toString(36).substring(2, 7)}`,
    rule_id: overrides.rule_id || 'SA-GEN-001',
    ruleset_version: '1.0.0',
    category: overrides.category || 'NETWORK',
    severity: overrides.severity || 'HIGH',
    confidence: overrides.confidence ?? 0.90,
    title: overrides.title || 'Static Analysis Risk Finding',
    description: overrides.description || 'Static analysis detected suspicious behavioral pattern.',
    rationale: overrides.rationale || 'Code inspection identified potential security issue.',
    source_span: overrides.source_span || {
      file_path: 'src/agent.ts',
      start_line: 1,
      start_col: 1,
      end_line: 1,
      end_col: 40,
      byte_offset_start: 0,
      byte_offset_end: 40,
    },
    stage_run: overrides.stage_run || {
      stage_run_id: 'sr-mock-1',
      stage_name: 'STATIC_ANALYSIS',
      artifact_id: 'art-diff-test',
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      status: 'COMPLETED',
      engine_key: 'static-analysis-engine',
      engine_version: '1.0.0',
      ruleset_version: '1.0.0',
    },
    ...overrides,
  };
}

function createMockDynamicRunResult(overrides: Partial<DynamicSandboxRunResult>): DynamicSandboxRunResult {
  const provider = overrides.provider_type || 'SIMULATED';
  return {
    run_id: overrides.run_id || `dyn-${Math.random().toString(36).substring(2, 7)}`,
    artifact_id: overrides.artifact_id || 'art-diff-test',
    scenario_id: overrides.scenario_id || 'SCN-DIFF-01',
    scenario_version: '1.0.0',
    provider_type: provider,
    requested_provider: overrides.requested_provider || provider,
    actual_provider: overrides.actual_provider || provider,
    execution_mode: overrides.execution_mode || (provider === 'SIMULATED' ? 'SIMULATED' : 'LIVE'),
    fallback_reason: overrides.fallback_reason,
    session_id: overrides.session_id || 'sess-diff-01',
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    duration_ms: 120,
    status: overrides.status || 'PASSED',
    resource_quota: {
      maxDurationMs: 5000,
      maxMemoryMb: 256,
      maxCpuPercentage: 50,
      maxProcessCount: 5,
      maxOutputSizeBytes: 10240,
    },
    network_policy: {
      type: 'DEFAULT_DENY',
      allowedDomains: [],
      allowedPorts: [],
      allowDns: false,
      interceptEgress: true,
    },
    canaries_injected: overrides.canaries_injected || [],
    canaries_tripped: overrides.canaries_tripped || [],
    sanitization_audit: {
      forbidden_secrets_found_in_payload: 0,
      sanitized: true,
    },
    runtime_events: overrides.runtime_events || [],
    raw_traces: overrides.raw_traces || [],
    behavior_sequences: overrides.behavior_sequences || [],
    evasion_indicators: overrides.evasion_indicators || [],
    evasion_risk_score: overrides.evasion_risk_score ?? 0.0,
    anti_analysis_detected: overrides.anti_analysis_detected ?? false,
    teardown: {
      session_id: overrides.session_id || 'sess-diff-01',
      final_status: 'TERMINATED',
      started_at: new Date().toISOString(),
      destroyed_at: new Date().toISOString(),
      duration_ms: 120,
      resources_released: true,
      processes_killed: 0,
      ephemeral_files_cleaned: true,
      guaranteed_clean: true,
    },
    ...overrides,
  };
}

describe('P20 — Static vs Dynamic Behavioral Differential Suite', () => {

  describe('1. DYNAMIC_CONFIRMED: Static Risk Confirmed by Runtime Reproduction', () => {
    it('confirms static process execution risk when dynamic sandbox reproduces process spawn', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-proc-01',
          rule_id: 'SA-PROC-001',
          category: 'PROCESS_EXECUTION',
          severity: 'HIGH',
          title: 'Direct Shell / Command Execution',
          description: 'Spawns child process using /bin/sh or exec.',
        }),
      ];

      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-proc-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-01',
          scenario_version: '1.0.0',
          category: 'PROCESS',
          action: 'PROCESS_SPAWNED',
          target: '/bin/sh -c whoami',
          status: 'ALLOWED',
          severity: 'HIGH',
          metadata: { pid: 1042, command: '/bin/sh', args: ['-c', 'whoami'] },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(1);
      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.summary.contradicted_matches_count).toBe(0);
      expect(report.summary.untriggered_static_count).toBe(0);
      expect(report.summary.unpredicted_dynamic_count).toBe(0);

      expect(report.confirmed_matches.length).toBe(1);
      const match = report.confirmed_matches[0];
      expect(match.finding_id).toBe('sf-proc-01');
      expect(match.rule_id).toBe('SA-PROC-001');
      expect(match.concordance).toBe('CONFIRMED');
      expect(match.differential_status).toBe('DYNAMIC_CONFIRMED');
      expect(match.dynamic_evidence.matched_event_ids).toContain('ev-proc-01');
      expect(match.dynamic_evidence.events.length).toBe(1);
      expect(report.summary.risk_assessment_delta).toBe('CONFIRMED_HIGH');
      expect(report.narrative_report).toContain('DYNAMIC_CONFIRMED');
    });

    it('confirms static outbound network risk when dynamic execution performs matching egress', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-net-01',
          rule_id: 'SA-NET-001',
          category: 'NETWORK',
          severity: 'HIGH',
          title: 'Outbound HTTP Connection',
          description: 'Connects to remote host api.external-service.com via fetch/https.',
        }),
      ];

      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-net-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-01',
          scenario_version: '1.0.0',
          category: 'NETWORK',
          action: 'HTTP_REQUEST_OUTBOUND',
          target: 'api.external-service.com',
          status: 'ALLOWED',
          severity: 'HIGH',
          metadata: { method: 'POST', port: 443 },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);
      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.confirmed_matches[0].differential_status).toBe('DYNAMIC_CONFIRMED');
      expect(report.confirmed_matches[0].concordance).toBe('CONFIRMED');
    });
  });

  describe('2. DYNAMIC_CONTRADICTED: Static Risk Actively Disproven / Blocked by Policy', () => {
    it('classifies finding as DYNAMIC_CONTRADICTED when flagged unrestricted network egress is blocked by policy', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-net-egress-01',
          rule_id: 'SA-NET-EXFIL',
          category: 'NETWORK',
          severity: 'CRITICAL',
          title: 'Unrestricted Data Egress Sink',
          description: 'Static analysis flagged potential unrestricted network egress to rogue-c2.attacker.com',
        }),
      ];

      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-net-blocked-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-02',
          scenario_version: '1.0.0',
          category: 'NETWORK',
          action: 'EGRESS_BLOCKED',
          target: 'rogue-c2.attacker.com',
          status: 'BLOCKED',
          severity: 'HIGH',
          metadata: { 
            policy_enforced: true, 
            ruleMatched: 'DEFAULT_DENY_RULE',
            blocked: true,
          },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        scenario_id: 'SCN-DIFF-02',
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(1);
      expect(report.summary.contradicted_matches_count).toBe(1);
      expect(report.summary.unpredicted_dynamic_count).toBe(0);

      expect(report.contradicted_matches.length).toBe(1);
      const contradictedMatch = report.contradicted_matches[0];
      expect(contradictedMatch.finding_id).toBe('sf-net-egress-01');
      expect(contradictedMatch.rule_id).toBe('SA-NET-EXFIL');
      expect(contradictedMatch.concordance).toBe('CONTRADICTED');
      expect(contradictedMatch.differential_status).toBe('DYNAMIC_CONTRADICTED');
      expect(contradictedMatch.dynamic_evidence.summary).toContain('BLOCKED');
      expect(report.summary.risk_assessment_delta).toBe('CONTRADICTED_MITIGATED');
      expect(report.narrative_report).toContain('DYNAMIC_CONTRADICTED');
    });

    it('handles contradiction where runtime policy blocks DNS resolution predicted statically', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-dns-01',
          rule_id: 'SA-DNS-001',
          category: 'NETWORK',
          severity: 'HIGH',
          title: 'Unrestricted Domain Resolution',
          description: 'DNS query to evil-exfil.com flagged as potential data exfiltration channel.',
        }),
      ];

      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-dns-blocked-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-02',
          scenario_version: '1.0.0',
          category: 'NETWORK',
          action: 'DNS_BLOCKED',
          target: 'evil-exfil.com',
          status: 'BLOCKED',
          severity: 'HIGH',
          metadata: { ruleMatched: 'DNS_RESTRICTION' },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);
      expect(report.summary.contradicted_matches_count).toBe(1);
      expect(report.contradicted_matches[0].differential_status).toBe('DYNAMIC_CONTRADICTED');
      expect(report.contradicted_matches[0].concordance).toBe('CONTRADICTED');
    });
  });

  describe('3. UNTRIGGERED_STATIC: Static Risk Never Exercised at Runtime (Dormant / Suppressed)', () => {
    it('classifies finding as UNTRIGGERED_STATIC with DORMANT_BRANCH when dynamic run never reaches the code', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-fs-dormant-01',
          rule_id: 'SA-FS-WRITE-01',
          category: 'FILESYSTEM',
          severity: 'MEDIUM',
          title: 'Dormant File Write in Error Branch',
          description: 'Writes debug logs to /tmp/debug.log on error condition.',
        }),
      ];

      // Dynamic execution has no filesystem events
      const dynamicRun = createMockDynamicRunResult({
        runtime_events: [],
        evasion_risk_score: 0.0,
        anti_analysis_detected: false,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(1);
      expect(report.summary.confirmed_matches_count).toBe(0);
      expect(report.summary.contradicted_matches_count).toBe(0);
      expect(report.summary.untriggered_static_count).toBe(1);
      expect(report.summary.unpredicted_dynamic_count).toBe(0);

      expect(report.untriggered_static_findings.length).toBe(1);
      const untriggered = report.untriggered_static_findings[0];
      expect(untriggered.finding_id).toBe('sf-fs-dormant-01');
      expect(untriggered.rule_id).toBe('SA-FS-WRITE-01');
      expect(untriggered.differential_status).toBe('UNTRIGGERED_STATIC');
      expect(untriggered.reason_not_triggered).toBe('DORMANT_BRANCH');
    });

    it('classifies finding as UNTRIGGERED_STATIC with EVASION_SUPPRESSED when anti-analysis is detected', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-evaded-01',
          rule_id: 'SA-PROC-EVAL',
          category: 'PROCESS_EXECUTION',
          severity: 'HIGH',
          title: 'Delayed Dynamic Eval / Process Spawn',
          description: 'Conditional eval executed after anti-analysis VM checks.',
        }),
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: [],
        evasion_risk_score: 0.85,
        anti_analysis_detected: true,
        evasion_indicators: [
          {
            indicator_id: 'ind-01',
            type: 'ENVIRONMENT_FINGERPRINTING',
            name: 'Sandbox Artifact Probe',
            detected: true,
            confidence: 0.95,
            description: 'Detected /proc/cpuinfo hypervisor check.',
            evidence: [{ timestamp: new Date().toISOString(), detail: 'Checked hypervisor flags' }],
          },
        ],
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.untriggered_static_count).toBe(1);
      const untriggered = report.untriggered_static_findings[0];
      expect(untriggered.differential_status).toBe('UNTRIGGERED_STATIC');
      expect(untriggered.reason_not_triggered).toBe('EVASION_SUPPRESSED');
      expect(report.summary.risk_assessment_delta).toBe('INDETERMINATE_EVASION');
    });
  });

  describe('4. UNPREDICTED_DYNAMIC: Live Behavior Discovered at Runtime Not Flagged by Static Analysis', () => {
    it('surfaces high-severity unpredicted dynamic event as UNPREDICTED_DYNAMIC', () => {
      // Static findings contain only unrelated low-severity filesystem observation
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-fs-safe-01',
          rule_id: 'SA-FS-READ-01',
          category: 'FILESYSTEM',
          severity: 'LOW',
          title: 'Read Static Config File',
          description: 'Reads local application configuration file /app/config.json',
        }),
      ];

      // Dynamic sandbox surfaces an unpredicted dynamic eval & canary harvest
      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-fs-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-04',
          scenario_version: '1.0.0',
          category: 'FILESYSTEM',
          action: 'FILE_READ',
          target: '/app/config.json',
          status: 'ALLOWED',
          severity: 'LOW',
          metadata: { path: '/app/config.json' },
        },
        {
          event_id: 'ev-unpred-canary-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-04',
          scenario_version: '1.0.0',
          category: 'CANARY',
          action: 'CANARY_HARVEST_ATTEMPT',
          target: 'STRIPE_SECRET_KEY',
          status: 'FLAGGED',
          severity: 'CRITICAL',
          metadata: { secret: 'sk-canary-prod-live-99deadbeef' },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
        canaries_tripped: [
          {
            canary_id: 'can-01',
            name: 'Stripe Secret',
            type: 'API_KEY',
            synthetic_value: 'sk-canary-prod-live-99deadbeef',
            location: 'ENV_VAR',
            target_key_name: 'STRIPE_SECRET_KEY',
            tripped: true,
          },
        ],
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(1);
      expect(report.summary.confirmed_matches_count).toBe(1); // fs-01 confirmed
      expect(report.summary.unpredicted_dynamic_count).toBe(1); // canary harvest unpredicted

      expect(report.unpredicted_dynamic_behaviors.length).toBe(1);
      const unpredicted = report.unpredicted_dynamic_behaviors[0];
      expect(unpredicted.differential_status).toBe('UNPREDICTED_DYNAMIC');
      expect(unpredicted.category).toBe('CANARY');
      expect(unpredicted.observed_action).toBe('CANARY_HARVEST_ATTEMPT');
      expect(unpredicted.severity).toBe('CRITICAL');
      expect(unpredicted.possible_cause).toBe('CANARY_HARVEST');
      expect(report.summary.risk_assessment_delta).toBe('ELEVATED_BY_DYNAMIC');
    });

    it('identifies unpredicted dynamic obfuscated code execution (eval fuzzing)', () => {
      const staticFindings: StaticFinding[] = []; // No static findings at all

      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-eval-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-04',
          scenario_version: '1.0.0',
          category: 'SECURITY',
          action: 'DYNAMIC_CODE_EVAL_DETECTED',
          target: 'eval(Buffer.from(...))',
          status: 'FLAGGED',
          severity: 'HIGH',
          metadata: { payload: 'base64_hidden' },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.unpredicted_dynamic_count).toBe(1);
      const unpredicted = report.unpredicted_dynamic_behaviors[0];
      expect(unpredicted.differential_status).toBe('UNPREDICTED_DYNAMIC');
      expect(unpredicted.possible_cause).toBe('DYNAMIC_CODE_EVAL');
      expect(report.summary.risk_assessment_delta).toBe('ELEVATED_BY_DYNAMIC');
    });
  });

  describe('5. Zero Static Findings & Clean Dynamic Run (No Fabricated Matches)', () => {
    it('confirms the comparator does not fabricate matches when both static and dynamic runs are completely clean', () => {
      const staticFindings: StaticFinding[] = [];
      const dynamicRun = createMockDynamicRunResult({
        runtime_events: [
          {
            event_id: 'ev-benign-init',
            timestamp: new Date().toISOString(),
            scenario_id: 'SCN-BENIGN-01',
            scenario_version: '1.0.0',
            category: 'PROCESS',
            action: 'INITIALIZE_RUNTIME',
            target: 'node runtime',
            status: 'ALLOWED',
            severity: 'INFO',
            metadata: {},
          },
        ],
        canaries_tripped: [],
        evasion_risk_score: 0.0,
        anti_analysis_detected: false,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(0);
      expect(report.summary.confirmed_matches_count).toBe(0);
      expect(report.summary.contradicted_matches_count).toBe(0);
      expect(report.summary.untriggered_static_count).toBe(0);
      expect(report.summary.unpredicted_dynamic_count).toBe(0);
      expect(report.summary.evasion_divergences_count).toBe(0);
      expect(report.summary.overall_concordance_rate).toBe(1.0);
      expect(report.summary.risk_assessment_delta).toBe('CONCORDANT_BENIGN');

      expect(report.confirmed_matches).toEqual([]);
      expect(report.contradicted_matches).toEqual([]);
      expect(report.untriggered_static_findings).toEqual([]);
      expect(report.unpredicted_dynamic_behaviors).toEqual([]);
      expect(report.evasion_divergences).toEqual([]);
      expect(report.narrative_report).toContain('CONCORDANT_BENIGN');
    });
  });

  describe('6. Multiple Findings in the Same Category: Target-Specific Matching Without Cross-Contamination', () => {
    it('does not cross-match unrelated findings that share the same category (NETWORK)', () => {
      // 3 static findings all in the NETWORK category, targeting different hosts
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-net-target-a',
          rule_id: 'SA-NET-C2-001',
          category: 'NETWORK',
          severity: 'HIGH',
          title: 'C2 Beacon Egress to attacker-c2.example.com',
          description: 'Outbound network connection to attacker-c2.example.com detected statically.',
        }),
        createMockStaticFinding({
          finding_id: 'sf-net-target-b',
          rule_id: 'SA-NET-SSRF-002',
          category: 'NETWORK',
          severity: 'HIGH',
          title: 'Internal Vault SSRF to internal-vault.corp.local',
          description: 'Potential SSRF request targeting internal-vault.corp.local.',
        }),
        createMockStaticFinding({
          finding_id: 'sf-net-target-c',
          rule_id: 'SA-NET-TELEMETRY-003',
          category: 'NETWORK',
          severity: 'LOW',
          title: 'Dormant Telemetry Egress to metrics.analytics.io',
          description: 'Dormant metric ping to metrics.analytics.io.',
        }),
      ];

      // Dynamic execution ONLY connects to attacker-c2.example.com
      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-net-target-a',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-06',
          scenario_version: '1.0.0',
          category: 'NETWORK',
          action: 'HTTP_EGRESS_OUTBOUND',
          target: 'attacker-c2.example.com',
          status: 'ALLOWED',
          severity: 'HIGH',
          metadata: { host: 'attacker-c2.example.com', port: 443 },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.total_static_findings).toBe(3);
      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.summary.untriggered_static_count).toBe(2);
      expect(report.summary.unpredicted_dynamic_count).toBe(0);

      // Only finding A should be confirmed
      expect(report.confirmed_matches.length).toBe(1);
      expect(report.confirmed_matches[0].finding_id).toBe('sf-net-target-a');
      expect(report.confirmed_matches[0].rule_id).toBe('SA-NET-C2-001');
      expect(report.confirmed_matches[0].differential_status).toBe('DYNAMIC_CONFIRMED');

      // Findings B and C MUST be untriggered, NOT falsely matched with Finding A's event
      expect(report.untriggered_static_findings.length).toBe(2);
      const untriggeredIds = report.untriggered_static_findings.map(f => f.finding_id);
      expect(untriggeredIds).toContain('sf-net-target-b');
      expect(untriggeredIds).toContain('sf-net-target-c');

      for (const untriggered of report.untriggered_static_findings) {
        expect(untriggered.differential_status).toBe('UNTRIGGERED_STATIC');
        expect(untriggered.reason_not_triggered).toBe('DORMANT_BRANCH');
      }
    });

    it('does not cross-match filesystem findings targeting different file paths', () => {
      const staticFindings = [
        createMockStaticFinding({
          finding_id: 'sf-fs-shadow',
          rule_id: 'SA-FS-SENSITIVE-01',
          category: 'FILESYSTEM',
          severity: 'CRITICAL',
          title: 'Read /etc/shadow or /etc/passwd',
          description: 'Attempts to read sensitive system file /etc/shadow.',
        }),
        createMockStaticFinding({
          finding_id: 'sf-fs-cache',
          rule_id: 'SA-FS-CACHE-02',
          category: 'FILESYSTEM',
          severity: 'LOW',
          title: 'Cache File Creation in /var/tmp/cache',
          description: 'Writes temporary cache files to /var/tmp/cache.',
        }),
      ];

      // Dynamic run only reads /etc/shadow
      const runtimeEvents: RuntimeEvent[] = [
        {
          event_id: 'ev-fs-shadow',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-DIFF-06',
          scenario_version: '1.0.0',
          category: 'FILESYSTEM',
          action: 'FILE_READ_SENSITIVE',
          target: '/etc/shadow',
          status: 'ALLOWED',
          severity: 'CRITICAL',
          metadata: { path: '/etc/shadow' },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.confirmed_matches[0].finding_id).toBe('sf-fs-shadow');
      expect(report.confirmed_matches[0].differential_status).toBe('DYNAMIC_CONFIRMED');

      expect(report.summary.untriggered_static_count).toBe(1);
      expect(report.untriggered_static_findings[0].finding_id).toBe('sf-fs-cache');
      expect(report.untriggered_static_findings[0].differential_status).toBe('UNTRIGGERED_STATIC');
    });
  });

  describe('7. Comprehensive Multi-Category Differential Scenario', () => {
    it('evaluates a full spectrum scenario with CONFIRMED, CONTRADICTED, UNTRIGGERED, and UNPREDICTED simultaneously', () => {
      const staticFindings = [
        // 1. Will be DYNAMIC_CONFIRMED
        createMockStaticFinding({
          finding_id: 'sf-proc-confirmed',
          rule_id: 'SA-PROC-001',
          category: 'PROCESS_EXECUTION',
          severity: 'HIGH',
          title: 'Command Execution',
          description: 'Executes child process command.',
        }),
        // 2. Will be DYNAMIC_CONTRADICTED
        createMockStaticFinding({
          finding_id: 'sf-net-contradicted',
          rule_id: 'SA-NET-002',
          category: 'NETWORK',
          severity: 'HIGH',
          title: 'Unrestricted Data Egress to darkweb-drop.onion',
          description: 'Flagged unrestricted egress to darkweb-drop.onion',
        }),
        // 3. Will be UNTRIGGERED_STATIC
        createMockStaticFinding({
          finding_id: 'sf-dormant',
          rule_id: 'SA-FILE-003',
          category: 'FILESYSTEM',
          severity: 'MEDIUM',
          title: 'Dormant Persistence File Write to /etc/cron.d/job',
          description: 'Attempts persistence via cron table.',
        }),
      ];

      const runtimeEvents: RuntimeEvent[] = [
        // Confirms sf-proc-confirmed
        {
          event_id: 'ev-proc-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-FULL-01',
          scenario_version: '1.0.0',
          category: 'PROCESS',
          action: 'PROCESS_SPAWNED',
          target: 'sh -c id',
          status: 'ALLOWED',
          severity: 'HIGH',
          metadata: {},
        },
        // Contradicts sf-net-contradicted
        {
          event_id: 'ev-net-blocked-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-FULL-01',
          scenario_version: '1.0.0',
          category: 'NETWORK',
          action: 'EGRESS_BLOCKED',
          target: 'darkweb-drop.onion',
          status: 'BLOCKED',
          severity: 'HIGH',
          metadata: { blocked: true },
        },
        // Unpredicted dynamic canary trip
        {
          event_id: 'ev-canary-trip-01',
          timestamp: new Date().toISOString(),
          scenario_id: 'SCN-FULL-01',
          scenario_version: '1.0.0',
          category: 'CANARY',
          action: 'CANARY_SECRET_READ',
          target: 'AWS_SECRET_ACCESS_KEY',
          status: 'FLAGGED',
          severity: 'CRITICAL',
          metadata: { secret: 'canary-aws-key' },
        },
      ];

      const dynamicRun = createMockDynamicRunResult({
        scenario_id: 'SCN-FULL-01',
        runtime_events: runtimeEvents,
      });

      const report = StaticDynamicComparator.compare(staticFindings, dynamicRun);

      // Verify counts
      expect(report.summary.total_static_findings).toBe(3);
      expect(report.summary.confirmed_matches_count).toBe(1);
      expect(report.summary.contradicted_matches_count).toBe(1);
      expect(report.summary.untriggered_static_count).toBe(1);
      expect(report.summary.unpredicted_dynamic_count).toBe(1);

      // Verify specific records
      expect(report.confirmed_matches.find(m => m.finding_id === 'sf-proc-confirmed')?.differential_status).toBe('DYNAMIC_CONFIRMED');
      expect(report.contradicted_matches.find(m => m.finding_id === 'sf-net-contradicted')?.differential_status).toBe('DYNAMIC_CONTRADICTED');
      expect(report.untriggered_static_findings.find(m => m.finding_id === 'sf-dormant')?.differential_status).toBe('UNTRIGGERED_STATIC');
      expect(report.unpredicted_dynamic_behaviors.find(b => b.category === 'CANARY')?.differential_status).toBe('UNPREDICTED_DYNAMIC');

      // Verify narrative report format
      expect(report.narrative_report).toContain('Static vs Dynamic Analysis Correlation Report');
      expect(report.narrative_report).toContain('[1. Static Predictions vs Dynamic Confirmation]');
      expect(report.narrative_report).toContain('[2. Dynamic Anomalies Not Predicted Statically]');
    });
  });
});
