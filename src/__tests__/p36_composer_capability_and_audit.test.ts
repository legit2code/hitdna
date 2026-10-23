import { describe, it, expect, beforeEach } from 'vitest';
import { 
  CapabilityGrantService, 
  requireCapabilityGrant, 
  UnauthorizedAccessError,
  PrincipalContext,
  SecurityClassificationRank
} from '@caim/auth';
import { 
  AgentComposerEngine, 
  ComposerTargetValidator, 
  ALL_TECHNIQUE_CATEGORIES 
} from '../../workers/composer/index.ts';
import { SyntheticTargetService } from '../../workers/sandbox-orchestrator/security/synthetic-target.ts';
import { KnowledgeCorpusManager } from '../../workers/knowledge/reindex/scheduler.ts';
import { HybridRetrievalService } from '../../workers/knowledge/retrieval/service.ts';
import { GeminiEmbeddingProvider } from '../../workers/knowledge/embeddings/provider.ts';

import { AuditLogEngine } from '@caim/workflow/observability.ts';
import crypto from 'node:crypto';

describe('P36 — Composer Capability, Access Control, RAG Risk Filtering & Sandbox Isolation', () => {
  let grantService: CapabilityGrantService;
  let corpusManager: KnowledgeCorpusManager;
  let retrievalService: HybridRetrievalService;
  let composerEngine: AgentComposerEngine;

  const ADMIN_PRINCIPAL_ID = '00000000-0000-0000-0001-000000000001';
  const ENGINEER_PRINCIPAL_ID = '00000000-0000-0000-0001-000000000002';
  const UNAUTHORIZED_PRINCIPAL_ID = '00000000-0000-0000-0001-000000000099';

  beforeEach(async () => {
    grantService = new CapabilityGrantService();
    corpusManager = new KnowledgeCorpusManager(new GeminiEmbeddingProvider());
    retrievalService = new HybridRetrievalService(corpusManager, new GeminiEmbeddingProvider());

    // Populate test projections with mixed risk bands
    corpusManager.getProjections().set('agent-low-risk-001', {
      knowledge_projection_id: 'proj-001',
      knowledge_object_id: 'kobj-001',
      entity_ref_id: 'agent-low-risk-001',
      agent_id: 'agent-low-risk-001',
      object_type: 'agent',
      projection_type: 'AGENT_CANONICAL',
      projection_version: '1',
      security_classification: 'INTERNAL',
      security_classification_rank: SecurityClassificationRank.INTERNAL,
      vault_restricted: false,
      document_text: 'Defensive Credential Evaluator: Evaluates password entropy against NIST SP 800-63B standards',
      summary: 'Evaluates password entropy against NIST SP 800-63B standards',
      payload: {},
      exact_keywords: {
        agent_id: 'agent-low-risk-001',
        risk_band: 'LOW_RISK',
        lifecycle_status: 'APPROVED',
      },
      content_hash: 'hash-001',
      stale: false,
      indexed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    corpusManager.getProjections().set('agent-high-risk-quarantine-002', {
      knowledge_projection_id: 'proj-002',
      knowledge_object_id: 'kobj-002',
      entity_ref_id: 'agent-high-risk-quarantine-002',
      agent_id: 'agent-high-risk-quarantine-002',
      object_type: 'agent',
      projection_type: 'AGENT_CANONICAL',
      projection_version: '1',
      security_classification: 'INTERNAL',
      security_classification_rank: SecurityClassificationRank.INTERNAL,
      vault_restricted: false,
      document_text: 'Unrestricted Offensive Credential Dumper: Aggressive LSASS memory dumper extracted from external exploit package',
      summary: 'Aggressive LSASS memory dumper extracted from external exploit package',
      payload: {},
      exact_keywords: {
        agent_id: 'agent-high-risk-quarantine-002',
        risk_band: 'HIGH_RISK',
        lifecycle_status: 'QUARANTINED',
      },
      content_hash: 'hash-002',
      stale: false,
      indexed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    composerEngine = new AgentComposerEngine({
      grantService,
      corpusManager,
      retrievalService,
    });
  });

  describe('1. Per-Principal Restricted Capability Grants (Non-Role Based)', () => {
    it('seeds authoritative composer:full_access grant for platform owner', async () => {
      const grants = await grantService.getActiveGrantsForPrincipal(ADMIN_PRINCIPAL_ID);
      expect(grants.length).toBeGreaterThanOrEqual(1);
      
      const adminGrant = grants.find(g => g.capability_key === 'composer:full_access');
      expect(adminGrant).toBeDefined();
      expect(adminGrant?.principal_id).toBe(ADMIN_PRINCIPAL_ID);
      expect(adminGrant?.justification).toContain('Platform owner');
      expect(adminGrant?.revoked_at).toBeNull();
    });

    it('denies access (403 / UnauthorizedAccessError) to principals without active capability grant', async () => {
      const unauthorizedContext: PrincipalContext = {
        principal_id: UNAUTHORIZED_PRINCIPAL_ID,
        is_authenticated: true,
        is_service: false,
        roles: ['admin'], // Even with admin role, lacks capability grant!
        tenant_id: 'tenant-1',
        accessible_scope_ids: ['tenant-1'],
        max_classification_rank: SecurityClassificationRank.INTERNAL,
        grants: [],
      };

      await expect(
        requireCapabilityGrant(unauthorizedContext, 'composer:full_access', { grantService })
      ).rejects.toThrow(UnauthorizedAccessError);
    });

    it('supports provisioning and revoking composer:restricted_access tier with scope limitations', async () => {
      // 1. Owner grants restricted capability to second engineer
      const grant = await grantService.grantCapability({
        capability_key: 'composer:restricted_access',
        principal_id: ENGINEER_PRINCIPAL_ID,
        granted_by: ADMIN_PRINCIPAL_ID,
        justification: 'Designated defensive tooling engineer - limited to extraction & tool synthesis',
        scope_limitations: ['DATA_EXTRACTION', 'TOOL_SYNTHESIS'],
      });

      expect(grant.grant_id).toBeDefined();
      expect(grant.capability_key).toBe('composer:restricted_access');
      expect(grant.scope_limitations).toEqual(['DATA_EXTRACTION', 'TOOL_SYNTHESIS']);

      // 2. Access check for authorized category passes
      const accessAllowed = await grantService.checkComposerAccess(ENGINEER_PRINCIPAL_ID, 'DATA_EXTRACTION');
      expect(accessAllowed.allowed).toBe(true);
      expect(accessAllowed.tier).toBe('restricted');

      // 3. Access check for out-of-scope category is refused
      const accessDenied = await grantService.checkComposerAccess(ENGINEER_PRINCIPAL_ID, 'SECURITY_VALIDATION');
      expect(accessDenied.allowed).toBe(false);
      expect(accessDenied.reason).toContain('not authorized for restricted capability grant');

      // 4. Revocation
      const revoked = await grantService.revokeCapability({
        grant_id: grant.grant_id,
        revoked_by: ADMIN_PRINCIPAL_ID,
      });
      expect(revoked.revoked_at).not.toBeNull();

      const accessPostRevocation = await grantService.checkComposerAccess(ENGINEER_PRINCIPAL_ID, 'DATA_EXTRACTION');
      expect(accessPostRevocation.allowed).toBe(false);
    });
  });

  describe('2. Composer Generation Engine, Target Refusal & RAG Risk Filtering', () => {
    it('refuses generation requests targeting real-world systems, domains, or public IPs', async () => {
      const requestWithRealDomain = {
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS' as const,
        prompt: 'Build an automated testing tool against target login service at https://auth.corporate-bank.com/api',
      };

      const result = await composerEngine.generate(requestWithRealDomain);
      expect(result.success).toBe(false);
      expect(result.status).toBe('REFUSED');
      expect(result.refusal_reason).toContain('Real-world target infrastructure detected');
      expect(result.refusal_reason).toContain('corporate-bank.com');
    });

    it('generates benign tooling with RAG filtering strictly excluding HIGH_RISK / QUARANTINED agents and runs StaticAnalysis pass', async () => {
      const benignRequest = {
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS' as const,
        prompt: 'Build a synthetic defensive password strength testing tool evaluating entropy on http://synthetic-target.local/auth',
        target_name: 'PasswordEntropyValidatorAgent',
      };

      const result = await composerEngine.generate(benignRequest);
      expect(result.success).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(result.technique_category).toBe('TOOL_SYNTHESIS');
      expect(result.generated_code).toContain('class PasswordEntropyValidatorAgent');
      expect(result.generated_code).toContain('synthetic-target.local');

      // Verify RAG retrieved source agents excluded high-risk
      expect(result.source_agents_retrieved).not.toContain('agent-high-risk-quarantine-002');

      // Verify static analysis ran
      expect(result.static_analysis).toBeDefined();
      expect(result.static_analysis?.findings).toBeDefined();
    });

    it('refuses generated code containing unconstrained runtime CLI flags (--target, --host, argv)', () => {
      const codeWithCliFlag = `
        import { parseArgs } from 'util';
        export class ProbeAgent {
          async run() {
            const args = process.argv.slice(2);
            const target = args[0] || '--target';
            return fetch(target);
          }
        }
      `;
      const validation = ComposerTargetValidator.validateGeneratedCode(codeWithCliFlag);
      expect(validation.allowed).toBe(false);
      expect(validation.validation_pass).toBe('GENERATED_CODE');
      expect(validation.refusal_reason).toContain('CLI argument/flag');
      expect(validation.refusal_reason).toContain('unconstrained target parameter');
    });

    it('refuses generated code containing unconstrained environment variables for target host/url', () => {
      const codeWithEnvVar = `
        export class RemoteAgent {
          async execute() {
            const endpoint = process.env.TARGET_HOST;
            return fetch('https://' + endpoint);
          }
        }
      `;
      const validation = ComposerTargetValidator.validateGeneratedCode(codeWithEnvVar);
      expect(validation.allowed).toBe(false);
      expect(validation.validation_pass).toBe('GENERATED_CODE');
      expect(validation.refusal_reason).toContain('Runtime env var');
    });

    it('refuses generated code containing unconstrained function/constructor target parameters', () => {
      const codeWithOpenParam = `
        export class ScannerTool {
          constructor(private targetHost: string) {}
          async scan() {
            return fetch('http://' + this.targetHost);
          }
        }
      `;
      const validation = ComposerTargetValidator.validateGeneratedCode(codeWithOpenParam);
      expect(validation.allowed).toBe(false);
      expect(validation.validation_pass).toBe('GENERATED_CODE');
      expect(validation.refusal_reason).toContain('Unconstrained target parameter');
    });

    it('refuses generated code with hardcoded real-world domains even if prompt was benign', () => {
      const codeWithRealDomain = `
        export class ExtractorTool {
          private apiUrl = 'https://api.github.com/v3';
          async fetchInfo() { return fetch(this.apiUrl); }
        }
      `;
      const validation = ComposerTargetValidator.validateGeneratedCode(codeWithRealDomain);
      expect(validation.allowed).toBe(false);
      expect(validation.validation_pass).toBe('GENERATED_CODE');
      expect(validation.refusal_reason).toContain('real-world target infrastructure');
      expect(validation.refusal_reason).toContain('github.com');
    });
  });

  describe('3. Sandbox MicroVM Execution Path & Network Policy Enforcement (/api/composer/execute)', () => {
    it('allows synthetic sandbox hostnames under strict whitelist policy', () => {
      const synthCheck = SyntheticTargetService.evaluateEgress('synthetic-target.local', 443);
      expect(synthCheck.allowed).toBe(true);
      expect(synthCheck.event.status).toBe('ALLOWED');
    });

    it('strictly blocks real-world external hostnames and IPs under DEFAULT_DENY network policy', () => {
      const realTargetCheck = SyntheticTargetService.evaluateEgress('api.github.com', 443);
      expect(realTargetCheck.allowed).toBe(false);
      expect(realTargetCheck.event.status).toBe('BLOCKED');
      expect(realTargetCheck.reason).toContain('not in the whitelist');

      const ipCheck = SyntheticTargetService.evaluateEgress('142.250.190.46', 443);
      expect(ipCheck.allowed).toBe(false);
      expect(ipCheck.event.status).toBe('BLOCKED');
    });

    it('refuses execution if principal lacks capability grant', async () => {
      const execResult = await composerEngine.execute({
        principal_id: UNAUTHORIZED_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS',
        provider_type: 'SIMULATED',
      });

      expect(execResult.success).toBe(false);
      expect(execResult.status).toBe('REFUSED');
      expect(execResult.refusal_reason).toContain('capability grant');
    });

    it('refuses execution if code payload contains unconstrained target parameters or real-world domains', async () => {
      const execResult = await composerEngine.execute({
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS',
        code: `export class BadTool { constructor(private targetHost: string) {} }`,
        provider_type: 'SIMULATED',
      });

      expect(execResult.success).toBe(false);
      expect(execResult.status).toBe('REFUSED');
      expect(execResult.refusal_reason).toContain('Unconstrained target parameter');
    });

    it('refuses execution if requested synthetic target domain is a real-world host', async () => {
      const execResult = await composerEngine.execute({
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS',
        synthetic_target_domain: 'api.github.com',
        provider_type: 'SIMULATED',
      });

      expect(execResult.success).toBe(false);
      expect(execResult.status).toBe('REFUSED');
      expect(execResult.refusal_reason).toContain('not a permitted synthetic sandbox target');
    });

    it('executes generated tool in sandbox microVM, applying single synthetic target whitelist and verifying external blocking', async () => {
      // 1. Generate artifact first
      const genResult = await composerEngine.generate({
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS',
        prompt: 'Build synthetic entropy auditor for http://synthetic-target.local/auth',
        target_name: 'SyntheticAuditorAgent',
      });

      expect(genResult.success).toBe(true);
      expect(genResult.artifact_id).toBeDefined();

      // 2. Execute artifact via composerEngine.execute()
      const execResult = await composerEngine.execute({
        principal_id: ADMIN_PRINCIPAL_ID,
        artifact_id: genResult.artifact_id,
        technique_category: 'TOOL_SYNTHESIS',
        synthetic_target_domain: 'synthetic-target.local',
        provider_type: 'SIMULATED',
        input_payload: { test_user: 'demo-audit-user' },
      });

      expect(execResult.success).toBe(true);
      expect(execResult.status).toBe('COMPLETED');
      expect(execResult.run_id).toBeDefined();
      expect(execResult.session_id).toBeDefined();

      // 3. Confirm network policy strictly applies single-target whitelist
      expect(execResult.network_policy_applied.type).toBe('WHITELIST_ONLY');
      expect(execResult.network_policy_applied.allowedDomains).toEqual(['synthetic-target.local']);

      // 4. Confirm egress evaluations show synthetic target is allowed and external hosts are blocked
      const synthEgress = execResult.egress_evaluations.find(e => e.destination.includes('synthetic-target.local'));
      expect(synthEgress?.allowed).toBe(true);

      const githubEgress = execResult.egress_evaluations.find(e => e.destination.includes('github.com'));
      expect(githubEgress?.allowed).toBe(false);

      const ipEgress = execResult.egress_evaluations.find(e => e.destination.includes('142.250.190.46'));
      expect(ipEgress?.allowed).toBe(false);

      // 5. Confirm execution traces contain synthetic perimeter boundary logs
      expect(execResult.raw_traces.some(t => t.includes('WHITELIST_ONLY'))).toBe(true);
      expect(execResult.raw_traces.some(t => t.includes('synthetic'))).toBe(true);

      // 6. Confirm execution_output reflects real tool execution results
      expect(execResult.execution_output.status).toBe('COMPLETED');
      expect(execResult.execution_output.success).toBe(true);
      expect(execResult.execution_output.result).toBeDefined();
    });

    it('actually executes generated tool code in sandbox and captures deterministic tool execution failures', async () => {
      // Create a tool that passes static validation (safe synthetic target) but deterministically fails at runtime
      const failingToolCode = `
        export class DeterministicFailingAgent {
          private targetUrl: string;
          constructor(targetUrl: string = 'http://synthetic-target.local/api/v1') {
            this.targetUrl = targetUrl;
          }
          async execute(context: any) {
            const res = await fetch(this.targetUrl + '/metrics');
            const data = await res.json();
            if (!data.enterprise_quota_token) {
              throw new Error('Deterministic failure: synthetic target response missing enterprise_quota_token');
            }
            return data;
          }
        }
      `;

      const execResult = await composerEngine.execute({
        principal_id: ADMIN_PRINCIPAL_ID,
        technique_category: 'TOOL_SYNTHESIS',
        code: failingToolCode,
        synthetic_target_domain: 'synthetic-target.local',
        provider_type: 'SIMULATED',
        input_payload: { probe_id: 'probe-991' },
      });

      // Confirm execution is not reported as fake success
      expect(execResult.success).toBe(false);
      expect(execResult.status).toBe('FAILED');
      expect(execResult.execution_output).toBeDefined();
      expect(execResult.execution_output.success).toBe(false);
      expect(execResult.execution_output.status).toBe('FAILED');
      expect(execResult.execution_output.error).toContain('Deterministic failure: synthetic target response missing enterprise_quota_token');
      expect(execResult.raw_traces.some(t => t.includes('Deterministic failure'))).toBe(true);
    });
  });

  describe('4. Dedicated Composer Audit Trail', () => {
    it('GATE: AuditLogEngine produces genuine 64-character hex SHA-256 signatures, not 32-bit rolling hashes', () => {
      const engine = new AuditLogEngine();
      const event = engine.recordEvent({
        actorType: 'SYSTEM',
        actorId: 'audit-actor-test',
        action: 'POLICY_OVERRIDE_REQUESTED',
        targetType: 'ARTIFACT',
        targetId: 'art-hash-test-01',
        correlation: {
          traceId: 'trc-01',
          spanId: 'spn-01',
          requestId: 'req-01',
        },
        details: { sample: 'payload_for_hashing_verification' },
      });

      expect(event.signatureSha256).toMatch(/^sha256:[a-f0-9]{64}$/);

      // Verify exact hash calculation
      const expectedSha256 = 'sha256:' + crypto.createHash('sha256').update(event.auditId + event.timestamp + 'audit-actor-test' + 'POLICY_OVERRIDE_REQUESTED').digest('hex');
      expect(event.signatureSha256).toBe(expectedSha256);
    });

    it('records all generation attempts including refusals and successful passes into audit log', async () => {
      const logs = await composerEngine.listLogs();
      expect(logs.length).toBeGreaterThanOrEqual(2);

      const refusedLog = logs.find(l => l.status === 'REFUSED');
      expect(refusedLog).toBeDefined();
      expect(refusedLog?.refusal_reason).toBeDefined();

      const successLog = logs.find(l => l.status === 'SUCCESS');
      expect(successLog).toBeDefined();
      expect(successLog?.generated_artifact_id).toBeDefined();
      expect(successLog?.static_analysis_result_summary).toBeDefined();
    });
  });
});
