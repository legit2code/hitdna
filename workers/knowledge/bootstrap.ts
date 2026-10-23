import { KnowledgeCorpusManager } from './reindex/scheduler.ts';
import { GeminiEmbeddingProvider, DeterministicMockEmbeddingProvider } from './embeddings/provider.ts';
import { HybridRetrievalService } from './retrieval/service.ts';
import { SecurityClassificationCode } from '@caim/auth/types.ts';

export interface KnowledgeInitOptions {
  seedDemoCorpus?: boolean;
  reset?: boolean;
}

let corpusManagerInstance: KnowledgeCorpusManager | null = null;
let retrievalServiceInstance: HybridRetrievalService | null = null;

export function resetKnowledgeInstancesForTesting(): void {
  corpusManagerInstance = null;
  retrievalServiceInstance = null;
}

export async function initializeKnowledgeAndRetrieval(
  apiKey?: string,
  dbClient?: any,
  options?: KnowledgeInitOptions
): Promise<{ corpus: KnowledgeCorpusManager; retrieval: HybridRetrievalService }> {
  if (options?.reset) {
    resetKnowledgeInstancesForTesting();
  }

  if (corpusManagerInstance && retrievalServiceInstance) {
    return { corpus: corpusManagerInstance, retrieval: retrievalServiceInstance };
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const effectiveKey = apiKey || process.env.GEMINI_API_KEY;

  if (isProduction && !effectiveKey) {
    throw new Error('[FATAL PRODUCTION ERROR] GEMINI_API_KEY is required in production mode. Fallback mock embeddings are strictly prohibited in production.');
  }

  if (isProduction && options?.seedDemoCorpus === true) {
    throw new Error('[FATAL SECURITY VIOLATION] seedDemoCorpus is strictly prohibited in production mode.');
  }

  const provider = effectiveKey
    ? new GeminiEmbeddingProvider(effectiveKey)
    : new DeterministicMockEmbeddingProvider();

  const corpus = new KnowledgeCorpusManager(provider, dbClient);
  const retrieval = new HybridRetrievalService(corpus, provider);

  // Production runtime must NEVER automatically seed fictional or demo intelligence
  const shouldSeed = !isProduction && (
    options?.seedDemoCorpus === true ||
    ((process.env.NODE_ENV === 'test' || Boolean(process.env.VITEST)) && options?.seedDemoCorpus !== false) ||
    process.env.CAIM_SEED_DEMO_KNOWLEDGE === 'true'
  );

  if (shouldSeed) {
    await seedCanonicalKnowledgeCorpus(corpus);
  }

  corpusManagerInstance = corpus;
  retrievalServiceInstance = retrieval;

  return { corpus, retrieval };
}

export async function seedCanonicalKnowledgeCorpus(corpus: KnowledgeCorpusManager): Promise<void> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[FATAL SECURITY VIOLATION] seedCanonicalKnowledgeCorpus() is strictly prohibited in production mode.');
  }

  // 1. Agents & Versions
  await corpus.indexAuthoritativeEntity('agent', 'agent-sentinel-core', {
    agent_id: 'agent-sentinel-core',
    name: 'SentinelCore Autonomous Worker',
    namespace: 'sentinel',
    vendor: 'Antigravity Cyber Systems',
    framework: 'LangChain-TS',
    description: 'Autonomous multi-tool orchestration agent specialized in code analysis and dependency graph traversal.',
    capabilities: ['tool_calling', 'sandbox_execution', 'vault_access'],
    architecture_tier: 'Core-Autonomous',
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('version', 'ver-sentinel-2.4.1', {
    agent_id: 'agent-sentinel-core',
    agent_version_id: 'ver-sentinel-2.4.1',
    version_number: '2.4.1',
    version_tag: 'stable-prod',
    git_commit_sha: 'a89c31f94d01b1e7c534c0429f4a98403328e100',
    lifecycle_state: 'ACTIVE_PRODUCTION',
    release_notes: 'Integrated secure sandbox and fine-grained AST reachability checks.',
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('version', 'ver-sentinel-2.3.0', {
    agent_id: 'agent-sentinel-core',
    agent_version_id: 'ver-sentinel-2.3.0',
    version_number: '2.3.0',
    version_tag: 'deprecated-legacy',
    git_commit_sha: 'b12c88f94d01b1e7c534c0429f4a98403328e222',
    lifecycle_state: 'DEPRECATED',
    release_notes: 'Initial release with unparameterized shell executor.',
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('agent', 'agent-security-analyst-v1', {
    agent_id: 'agent-security-analyst-v1',
    name: 'Security Analyst Agent V1',
    namespace: 'sentinel',
    vendor: 'Antigravity Cyber Systems',
    framework: 'LangChain-TS',
    description: 'Security testing and code analysis agent.',
    capabilities: ['tool_calling', 'sandbox_execution'],
    architecture_tier: 'Core-Autonomous',
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('agent', 'agent-vault-governor', {
    agent_id: 'agent-vault-governor',
    name: 'Vault Governor AI',
    namespace: 'security-vault',
    vendor: 'CAIM Defense Systems',
    framework: 'Custom-Lisp',
    description: 'Strict confidential agent handling encrypted key rotation and hardware security enclave telemetry.',
    capabilities: ['vault_encryption', 'hardware_key_rotation'],
    architecture_tier: 'Restricted-Vault',
    security_classification: 'VAULT_RESTRICTED' as SecurityClassificationCode,
  });

  // 2. Ontology Taxonomy Concepts (Multi-hop support)
  await corpus.indexAuthoritativeEntity('ontology', 'concept-direct-injection', {
    concept_name: 'Direct Prompt & Code Injection',
    category: 'VULNERABILITY_TAXONOMY',
    definition: 'Untrusted user input interpolated directly into execution contexts or LLM meta-prompts causing privilege escalation.',
    taxonomy_code: 'CAIM-VULN-001',
    parent_concepts: ['Adversarial Evasion', 'Taint Flow Failure'],
    security_classification: 'PUBLIC_METADATA' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('ontology', 'concept-honeytoken-detection', {
    concept_name: 'Honeytoken Trap Trigger',
    category: 'BEHAVIORAL_TELEMETRY',
    definition: 'Synthetic canary credentials placed in mock environments to identify active unauthorized reconnaissance and exfiltration.',
    taxonomy_code: 'CAIM-TELEMETRY-042',
    parent_concepts: ['Dynamic Sandbox', 'Deception Technology'],
    security_classification: 'PUBLIC_METADATA' as SecurityClassificationCode,
  });

  // 3. Vulnerabilities & Dependencies
  await corpus.indexAuthoritativeEntity('vulnerability', 'CVE-2026-44012', {
    cve_id: 'CVE-2026-44012',
    package_name: 'lodash',
    severity: 'HIGH',
    cvss_score: 8.8,
    fixed_version: '4.17.22',
    summary: 'Prototype pollution in lodash.template allows remote code execution via constructor payload.',
    security_classification: 'PUBLIC_METADATA' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('dependency', 'dep-lodash-4.17.21', {
    package_name: 'lodash',
    ecosystem: 'npm',
    version: '4.17.21',
    license: 'MIT',
    reachable_sinks: ['eval', 'vm.runInContext'],
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  // 4. Analysis Run, Finding & Claim-Evidence Lineage
  const runId = 'run-sentinel-audit-901';
  await corpus.indexAuthoritativeEntity('run', runId, {
    analysis_run_id: runId,
    agent_id: 'agent-sentinel-core',
    agent_version_id: 'ver-sentinel-2.4.1',
    run_type: 'STATIC_AND_BEHAVIORAL',
    status: 'COMPLETED',
    confidence_score: 0.98,
    duration_ms: 1420,
    trigger_source: 'CI_CD_PIPELINE',
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  await corpus.indexAuthoritativeEntity('finding', 'find-taint-source-eval', {
    rule_id: 'RULE-STATIC-TAINT-001',
    title: 'Unsanitized user prompt flows into child_process.exec',
    category: 'VULNERABILITY',
    severity: 'CRITICAL',
    file_path: 'src/tools/shell_executor.ts',
    line_number: 84,
    code_snippet: 'const res = child_process.execSync(userSuppliedCmd);',
    remediation_advice: 'Use parameterized spawn with strict allowlists.',
    security_classification: 'SENSITIVE' as SecurityClassificationCode,
  }, { agent_id: 'agent-sentinel-core', agent_version_id: 'ver-sentinel-2.4.1', analysis_run_id: runId });

  await corpus.indexAuthoritativeEntity('evidence', 'ev-ast-dataflow-sink', {
    evidence_id: 'ev-ast-dataflow-sink',
    evidence_type: 'STATIC_AST_FLOW',
    evidence_class: 'DIRECT_OBSERVATION',
    epistemic_state: 'OBSERVED_FACT',
    confidence: 1.0,
    source_locator: 'src/tools/shell_executor.ts#84',
    observation: 'AST Node CallExpression invokes child_process.execSync with parameter untrustedInput',
    security_classification: 'SENSITIVE' as SecurityClassificationCode,
  }, { agent_id: 'agent-sentinel-core', analysis_run_id: runId });

  await corpus.indexAuthoritativeEntity('claim', 'claim-rce-vulnerability-verified', {
    claim_id: 'claim-rce-vulnerability-verified',
    claim_type: 'SECURITY_POSTURE',
    claim_state: 'SUPPORTED',
    confidence: 0.99,
    statement: 'Agent SentinelCore version 2.4.1 contains verified critical Remote Code Execution vulnerability in tool execution module.',
    evidence_links: [{ evidence_id: 'ev-ast-dataflow-sink' }],
    security_classification: 'SENSITIVE' as SecurityClassificationCode,
  }, { agent_id: 'agent-sentinel-core', agent_version_id: 'ver-sentinel-2.4.1', analysis_run_id: runId });

  // 5. Policy & Risk Decision
  await corpus.indexAuthoritativeEntity('risk', 'risk-critical-rce-exposure', {
    risk_id: 'risk-critical-rce-exposure',
    risk_type: 'EXECUTION_ESCAPE',
    severity: 'CRITICAL',
    risk_score: 9.4,
    title: 'Critical RCE via unescaped shell tool',
    description: 'Possibility of host container compromise during tool calling phase.',
    mitigated: false,
    security_classification: 'SENSITIVE' as SecurityClassificationCode,
  }, { agent_id: 'agent-sentinel-core', analysis_run_id: runId });

  await corpus.indexAuthoritativeEntity('policy', 'pol-deploy-quarantine-block', {
    policy_key: 'POL-BLOCK-CRITICAL-UNMITIGATED',
    outcome: 'BLOCK_DEPLOYMENT',
    reasons: ['Unmitigated CRITICAL risk: risk-critical-rce-exposure (score 9.4 > 8.0 threshold)'],
    override_applied: false,
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  }, { agent_id: 'agent-sentinel-core', analysis_run_id: runId });

  await corpus.indexAuthoritativeEntity('recommendation', 'rec-fix-parameterized-spawn', {
    recommendation_id: 'rec-fix-parameterized-spawn',
    priority: 'P0',
    recommendation_type: 'REMEDIATION',
    title: 'Replace execSync with isolated child_process.spawn inside gVisor sandbox',
    risk_id: 'risk-critical-rce-exposure',
    action_steps: [
      'Refactor shell_executor.ts to import spawn from child_process',
      'Pass arguments array without shell expansion',
      'Attach sandbox containment profile'
    ],
    security_classification: 'INTERNAL' as SecurityClassificationCode,
  });

  // 6. Vault-Only Restricted Document (For P23 Authorization Gate Verification)
  await corpus.indexAuthoritativeEntity('agent', 'vault-classified-payload-007', {
    entity_ref_id: 'vault-classified-payload-007',
    name: 'Top Secret Quantum Enclave Encryption Master Key Blueprint',
    vendor: 'NSA/GCHQ Joint Research',
    description: 'Hardware master entropy seed and physical vault decryption coordinates.',
    is_vault: true,
    security_classification: 'VAULT_RESTRICTED' as SecurityClassificationCode,
  });
}
