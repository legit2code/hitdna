import { describe, it, expect } from 'vitest';
import { 
  CAIM_SPEC_VERSION,
  createEmptyCaimManifest,
  validateCaimManifest,
  assertAgentVersionIsNotAnalysisRun,
  assertPermissionNotCapabilityNotBehavior,
  SemanticInvariantViolationError,
  CaimAgentVersionSchema,
  CaimCapabilityInstanceSchema,
  CaimPermissionSchema,
  CaimBehaviorObservedSchema,
  getCaimManifestJsonSchema,
  isCaimPermission,
  isCaimCapability,
  isCaimBehaviorObserved
} from '@caim/caim';

import { 
  ONTOLOGY_SPEC_VERSION,
  STANDARD_CONCEPTS,
  getConceptByCanonicalKey,
  getConceptsByNamespace,
  createOntologyRelationship,
  createMappingRule,
  createInferenceRule,
  recordInferenceProvenance,
  validateOntologyVersionRef,
  validateOntologyDeprecation,
  CURRENT_ONTOLOGY_VERSION_REF,
  OntologyConceptSchema,
  OntologyRelationshipSchema
} from '@caim/ontology';

import { 
  asAgentId,
  asAgentVersionId,
  asAnalysisRunId,
  asScopeId,
  isValidUuid,
  wrapInIntelligenceEnvelope,
  createIntelligenceEnvelopeSchema,
  getIntelligenceEnvelopeJsonSchema,
  FindingContractSchema,
  EvidenceContractSchema,
  AssertionContractSchema,
  ClaimContractSchema,
  assertAgentVersionNotAnalysisRun,
  assertDistinctIntelligenceHierarchy,
  deserializeEpistemicState,
  InvariantViolationError,
  EpistemicTransitionError,
  INTELLIGENCE_ENVELOPE_VERSION
} from '@caim/contracts';

describe('P07 — CAIM, Ontology & Shared Contract Packages', () => {

  describe('1. CAIM Specification & Semantic Schemas', () => {
    it('creates and validates a complete CAIM manifest', () => {
      const manifest = createEmptyCaimManifest({
        agent_id: 'a0000000-0000-0000-0000-000000000001',
        canonical_name: 'SecurityAnalyzerAgent',
        agent_version_id: 'b0000000-0000-0000-0000-000000000001',
        content_fingerprint: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        version_label: '1.0.0',
      });

      expect(manifest.caim_version).toBe(CAIM_SPEC_VERSION);
      expect(manifest.agent.canonical_name).toBe('SecurityAnalyzerAgent');
      expect(manifest.version.agent_version_id).toBe('b0000000-0000-0000-0000-000000000001');

      const validated = validateCaimManifest(manifest);
      expect(validated.caim_version).toBe('2.0.1');
    });

    it('generates valid JSON Schema for CAIM manifest', () => {
      const jsonSchema = getCaimManifestJsonSchema();
      expect(jsonSchema.title).toBe('CaimManifest');
      expect(jsonSchema.type).toBe('object');
      expect((jsonSchema.required as string[])).toContain('caim_version');
      expect((jsonSchema.required as string[])).toContain('agent');
      expect((jsonSchema.required as string[])).toContain('version');
    });
  });

  describe('2. Required Invariant Tests: AgentVersion != AnalysisRun', () => {
    it('enforces AgentVersion is strictly static content identity without AnalysisRun execution properties', () => {
      const validVersion = {
        _entity_kind: 'AGENT_VERSION',
        agent_version_id: 'b0000000-0000-0000-0000-000000000001',
        agent_id: 'a0000000-0000-0000-0000-000000000001',
        content_fingerprint: 'sha256:abc123',
      };
      expect(() => assertAgentVersionIsNotAnalysisRun(validVersion)).not.toThrow();
      expect(() => assertAgentVersionNotAnalysisRun(validVersion)).not.toThrow();

      const invalidVersionWithRun = {
        _entity_kind: 'AGENT_VERSION',
        agent_version_id: 'b0000000-0000-0000-0000-000000000001',
        agent_id: 'a0000000-0000-0000-0000-000000000001',
        analysis_run_id: 'c0000000-0000-0000-0000-000000000001', // ILLEGAL CONFLATION
        content_fingerprint: 'sha256:abc123',
      };
      expect(() => assertAgentVersionIsNotAnalysisRun(invalidVersionWithRun)).toThrow(SemanticInvariantViolationError);
      expect(() => assertAgentVersionNotAnalysisRun(invalidVersionWithRun)).toThrow(InvariantViolationError);
    });

    it('rejects pipeline execution metadata attached directly to AgentVersion', () => {
      const versionWithPipeline = {
        _entity_kind: 'AGENT_VERSION',
        agent_version_id: 'b0000000-0000-0000-0000-000000000001',
        agent_id: 'a0000000-0000-0000-0000-000000000001',
        pipeline_version: '2.0.1', // ILLEGAL CONFLATION
        content_fingerprint: 'sha256:abc123',
      };
      expect(() => assertAgentVersionIsNotAnalysisRun(versionWithPipeline)).toThrow(SemanticInvariantViolationError);
    });
  });

  describe('3. Required Invariant Tests: Permission != Capability != BehaviorObserved', () => {
    it('distinguishes Permission (authorization) vs Capability (functional potential) vs BehaviorObserved (runtime event)', () => {
      const permission = {
        _entity_kind: 'PERMISSION',
        permission_id: '00000000-0000-0000-0000-000000000001',
        agent_version_id: '00000000-0000-0000-0000-000000000002',
        permission_concept_id: 'permission.fs.write',
        declared_state: 'REQUESTED',
        confidence: 1.0,
      };
      expect(isCaimPermission(permission)).toBe(true);
      expect(isCaimCapability(permission)).toBe(false);
      expect(isCaimBehaviorObserved(permission)).toBe(false);
      expect(() => assertPermissionNotCapabilityNotBehavior(permission)).not.toThrow();

      const capability = {
        _entity_kind: 'CAPABILITY',
        capability_id: '00000000-0000-0000-0000-000000000003',
        agent_version_id: '00000000-0000-0000-0000-000000000002',
        capability_concept_id: 'capability.tools.exec',
        canonical_key: 'capability.tools.exec',
        declaration_state: 'INFERRED_STATIC',
        source_type: 'CODE_AST',
        confidence: 0.95,
      };
      expect(isCaimCapability(capability)).toBe(true);
      expect(isCaimPermission(capability)).toBe(false);
      expect(() => assertPermissionNotCapabilityNotBehavior(capability)).not.toThrow();

      const behavior = {
        _entity_kind: 'BEHAVIOR_OBSERVED',
        behavior_observation_id: '00000000-0000-0000-0000-000000000004',
        behavior_concept_id: 'behavior.evasion.obfuscation',
        runtime_event_id: '00000000-0000-0000-0000-000000000005',
        occurred_at: new Date().toISOString(),
        observed_action: 'eval(Buffer.from(...))',
        target_resource: '/tmp/payload',
        confidence: 1.0,
      };
      expect(isCaimBehaviorObserved(behavior)).toBe(true);
      expect(() => assertPermissionNotCapabilityNotBehavior(behavior)).not.toThrow();
    });

    it('rejects cross-conflation of Permission with empirical BehaviorObserved fields', () => {
      const contaminatedPermission = {
        _entity_kind: 'PERMISSION',
        permission_id: '00000000-0000-0000-0000-000000000001',
        agent_version_id: '00000000-0000-0000-0000-000000000002',
        permission_concept_id: 'permission.fs.write',
        declared_state: 'REQUESTED',
        observed_action: 'unlinkSync(/etc/passwd)', // ILLEGAL FIELD ON PERMISSION
        confidence: 1.0,
      };
      expect(() => assertPermissionNotCapabilityNotBehavior(contaminatedPermission)).toThrow(SemanticInvariantViolationError);
    });

    it('rejects cross-conflation of Capability with Permission declared_state', () => {
      const contaminatedCapability = {
        _entity_kind: 'CAPABILITY',
        capability_id: '00000000-0000-0000-0000-000000000003',
        agent_version_id: '00000000-0000-0000-0000-000000000002',
        capability_concept_id: 'capability.tools.exec',
        canonical_key: 'capability.tools.exec',
        declared_state: 'GRANTED', // ILLEGAL FIELD ON CAPABILITY
        source_type: 'CODE_AST',
        confidence: 0.95,
      };
      expect(() => assertPermissionNotCapabilityNotBehavior(contaminatedCapability)).toThrow(SemanticInvariantViolationError);
    });
  });

  describe('4. Required Invariant Tests: Finding != Evidence != Assertion != Claim', () => {
    it('validates distinct schemas and hierarchy constraints across the 4 epistemic layers', () => {
      const finding = FindingContractSchema.parse({
        finding_id: 'f0000000-0000-0000-0000-000000000001',
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        rule_id: 'RULE_CHILD_PROCESS_SPAWN',
        severity: 'HIGH',
        message: 'Direct child_process.spawn invocation detected',
        source_span: {
          file_path: 'src/index.ts',
          start_line: 12,
          start_col: 1,
          end_line: 12,
          end_col: 35,
        },
      });
      expect(finding._contract_type).toBe('FINDING');
      expect(() => assertDistinctIntelligenceHierarchy(finding)).not.toThrow();

      const evidence = EvidenceContractSchema.parse({
        evidence_id: 'e0000000-0000-0000-0000-000000000001',
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        scope_id: '00000000-0000-0000-0000-000000000001',
        evidence_type: 'STATIC_CODE',
        evidence_class: 'STRUCTURAL_EXTRACTION',
        static_finding_id: finding.finding_id,
        description: 'Extracted AST subtree showing unconstrained spawn call',
        confidence: 0.98,
        weight: 0.85,
      });
      expect(evidence._contract_type).toBe('EVIDENCE');
      expect(() => assertDistinctIntelligenceHierarchy(evidence)).not.toThrow();

      const assertion = AssertionContractSchema.parse({
        assertion_id: 'a5000000-0000-0000-0000-000000000001',
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        scope_id: '00000000-0000-0000-0000-000000000001',
        assertion_key: 'capability.tools.exec',
        concept_id: 'capability.tools.exec',
        predicate: 'IS_A',
        epistemic_state: 'DERIVED_ASSERTION',
        evidence_ids: [evidence.evidence_id],
        confidence: 0.95,
        engine_key: 'static_analysis_engine',
      });
      expect(assertion._contract_type).toBe('ASSERTION');
      expect(() => assertDistinctIntelligenceHierarchy(assertion)).not.toThrow();

      const claim = ClaimContractSchema.parse({
        claim_id: 'c1000000-0000-0000-0000-000000000001',
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        scope_id: '00000000-0000-0000-0000-000000000001',
        claim_type: 'SECURITY_POSTURE',
        claim_text: 'Agent requires sandbox isolation due to unconstrained process execution',
        state: 'SUPPORTED',
        assertion_ids: [assertion.assertion_id],
        confidence: 0.92,
      });
      expect(claim._contract_type).toBe('CLAIM');
      expect(() => assertDistinctIntelligenceHierarchy(claim)).not.toThrow();
    });

    it('rejects mixing Finding attributes into Assertion contracts', () => {
      const contaminatedAssertion = {
        _contract_type: 'ASSERTION',
        assertion_id: 'a5000000-0000-0000-0000-000000000001',
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        scope_id: '00000000-0000-0000-0000-000000000001',
        assertion_key: 'capability.tools.exec',
        epistemic_state: 'DERIVED_ASSERTION',
        severity: 'CRITICAL', // ILLEGAL: severity belongs on Finding, not Assertion
        confidence: 0.95,
        engine_key: 'static_analysis_engine',
      };
      expect(() => assertDistinctIntelligenceHierarchy(contaminatedAssertion)).toThrow(InvariantViolationError);
    });
  });

  describe('5. Required Invariant Tests: Inferred State Cannot Deserialize as Observed Without Evidence Class Change', () => {
    it('blocks deserialization of DERIVED_INFERENCE or HEURISTIC_ESTIMATE into OBSERVED_FACT without empirical proof', () => {
      expect(() => deserializeEpistemicState({
        intended_epistemic_state: 'OBSERVED_FACT',
        source_evidence_class: 'DERIVED_INFERENCE',
        has_direct_observation_proof: false,
      })).toThrow(EpistemicTransitionError);

      expect(() => deserializeEpistemicState({
        intended_epistemic_state: 'OBSERVED_FACT',
        source_evidence_class: 'HEURISTIC_ESTIMATE',
        has_direct_observation_proof: false,
      })).toThrow(EpistemicTransitionError);
    });

    it('allows deserialization into OBSERVED_FACT when backed by DIRECT_OBSERVATION or explicit verified empirical proof', () => {
      const state = deserializeEpistemicState({
        intended_epistemic_state: 'OBSERVED_FACT',
        source_evidence_class: 'DIRECT_OBSERVATION',
        has_direct_observation_proof: true,
      });
      expect(state).toBe('OBSERVED_FACT');
    });

    it('allows deserialization of DERIVED_INFERENCE into DERIVED_ASSERTION or HYPOTHESIS', () => {
      const derivedState = deserializeEpistemicState({
        intended_epistemic_state: 'DERIVED_ASSERTION',
        source_evidence_class: 'DERIVED_INFERENCE',
        has_direct_observation_proof: false,
      });
      expect(derivedState).toBe('DERIVED_ASSERTION');
    });
  });

  describe('6. Shared Durable Intelligence Envelope', () => {
    it('wraps and validates intelligence payload in standardized envelope', () => {
      const envelope = wrapInIntelligenceEnvelope({
        analysis_run_id: 'a0000000-0000-0000-0000-000000000001',
        agent_version_id: 'b0000000-0000-0000-0000-000000000001',
        scope_id: '00000000-0000-0000-0000-000000000001',
        pipeline_version: '2.0.1',
        security_classification: 'INTERNAL',
        producer: {
          engine_key: 'static_analysis',
          engine_version: '2.0.1',
          ruleset_version: '2026.08',
        },
        payload: {
          findings_count: 5,
          top_risk: 'risk.supply_chain.untrusted_dep',
        },
        provenance: {
          provenance_id: 'p0000000-0000-0000-0000-000000000001',
          source_spans: [],
          input_hashes: ['sha256:abcdef'],
          derived_at: new Date().toISOString(),
          engine_signature: 'static_analysis_v2',
          transformation_type: 'CALIBRATED_INFERENCE',
          confidence: 0.95,
        },
      });

      expect(envelope.envelope_version).toBe(INTELLIGENCE_ENVELOPE_VERSION);
      expect(envelope.producer.engine_key).toBe('static_analysis');
      expect(envelope.security_classification).toBe('INTERNAL');

      const jsonSchema = getIntelligenceEnvelopeJsonSchema();
      expect(jsonSchema.title).toBe('IntelligenceEnvelope');
    });
  });

  describe('7. Ontology Controlled Vocabulary & Provenance Rules', () => {
    it('provides standard controlled concepts with namespace mappings', () => {
      const execConcept = getConceptByCanonicalKey('capability.tools.exec');
      expect(execConcept).toBeDefined();
      expect(execConcept?.namespace).toBe('capability');

      const capabilities = getConceptsByNamespace('capability');
      expect(capabilities.length).toBeGreaterThanOrEqual(4);

      const risks = getConceptsByNamespace('risk');
      expect(risks.length).toBeGreaterThanOrEqual(2);
    });

    it('creates and validates ontology relationships', () => {
      const rel = createOntologyRelationship({
        subject_concept_id: 'capability.tools.exec',
        predicate: 'REQUIRES',
        object_concept_id: 'permission.process.spawn',
        confidence: 0.99,
      });

      expect(rel.predicate).toBe('REQUIRES');
      expect(rel.confidence).toBe(0.99);
      expect(isValidUuid(rel.relationship_id)).toBe(true);
    });

    it('records mapping rules, inference rules, and inference provenance', () => {
      const mapRule = createMappingRule({
        rule_name: 'Map Node Child Process Exec',
        source_ecosystem: 'npm',
        source_pattern: 'child_process.exec',
        target_concept_id: 'capability.tools.exec',
        mapping_type: 'EXACT',
        confidence: 1.0,
        mapping_version: '2.0.1',
      });
      expect(mapRule.source_pattern).toBe('child_process.exec');

      const infRule = createInferenceRule({
        rule_name: 'Infer Process Spawn Permission Requirement',
        antecedent_concept_ids: ['capability.tools.exec'],
        consequent_concept_id: 'permission.process.spawn',
        predicate: 'REQUIRES',
        calibration_version: '2.0.1',
        minimum_confidence: 0.9,
      });
      expect(infRule.predicate).toBe('REQUIRES');

      const provenance = recordInferenceProvenance({
        inference_rule_id: infRule.inference_rule_id,
        engine_key: 'semantic_inference_engine',
        engine_version: '2.0.1',
        input_entity_ref_ids: ['00000000-0000-0000-0000-000000000001'],
        derived_concept_id: 'permission.process.spawn',
        confidence: 0.95,
      });
      expect(provenance.engine_key).toBe('semantic_inference_engine');
      expect(isValidUuid(provenance.provenance_id)).toBe(true);
    });

    it('validates ontology version reference and deprecations', () => {
      expect(CURRENT_ONTOLOGY_VERSION_REF.version_label).toBe(ONTOLOGY_SPEC_VERSION);
      const validatedRef = validateOntologyVersionRef(CURRENT_ONTOLOGY_VERSION_REF);
      expect(validatedRef.status).toBe('ACTIVE');

      const deprecation = validateOntologyDeprecation({
        deprecation_id: '00000000-0000-0000-0000-000000000001',
        deprecated_concept_id: 'capability.legacy.shell',
        superseded_by_concept_id: 'capability.tools.exec',
        reason: 'Consolidated into unified process execution capability',
        effective_version: '2.0.0',
      });
      expect(deprecation.superseded_by_concept_id).toBe('capability.tools.exec');
    });
  });

  describe('8. Common Platform Branded IDs', () => {
    it('validates and brands UUID identifiers', () => {
      const validUuid = '12345678-1234-4234-8234-123456789abc';
      expect(isValidUuid(validUuid)).toBe(true);
      expect(asAgentId(validUuid)).toBe(validUuid);
      expect(asAgentVersionId(validUuid)).toBe(validUuid);
      expect(asAnalysisRunId(validUuid)).toBe(validUuid);
      expect(asScopeId(validUuid)).toBe(validUuid);

      expect(isValidUuid('invalid-uuid-string')).toBe(false);
      expect(() => asAgentId('not-a-uuid')).toThrow();
    });
  });

});
