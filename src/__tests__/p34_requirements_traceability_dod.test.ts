/**
 * P34 — Requirements Traceability & Platform Definition-of-Done Audit Test Suite
 * Conforming strictly to Architecture V2.0.1 and P00 Build Constitution.
 */

import { describe, it, expect } from 'vitest';
import {
  AUTHORITATIVE_REQUIREMENTS_MATRIX,
  MANDATORY_ACCEPTANCE_PATHS,
  LineageResolverEngine,
  QualityTargetsAuditor,
  runPlatformDefinitionOfDoneAudit
} from '@caim/workflow/traceability.js';

describe('P34 — Requirements Traceability & Platform Definition-of-Done Audit', () => {

  // =========================================================================
  // 1. Authoritative Requirements Mapping & RTM Coverage
  // =========================================================================
  describe('1. Authoritative Requirements Mapping & Traceability Coverage', () => {
    it('should maintain authoritative requirement records adhering to standard schema', () => {
      expect(AUTHORITATIVE_REQUIREMENTS_MATRIX.length).toBeGreaterThanOrEqual(25);

      for (const req of AUTHORITATIVE_REQUIREMENTS_MATRIX) {
        expect(req.requirementId).toBeDefined();
        expect(req.requirementId.length).toBeGreaterThan(3);
        expect(req.category).toBeDefined();
        expect(req.title).toBeDefined();
        expect(['NOT_STARTED', 'IN_PROGRESS', 'IMPLEMENTED', 'VERIFIED', 'BLOCKED', 'NOT_APPLICABLE']).toContain(req.implementationStatus);
        expect(Array.isArray(req.codeRefs)).toBe(true);
        expect(req.codeRefs.length).toBeGreaterThan(0);
        expect(Array.isArray(req.dataObjects)).toBe(true);
        expect(req.dataObjects.length).toBeGreaterThan(0);
        expect(Array.isArray(req.apiEventQueueRefs)).toBe(true);
        expect(req.apiEventQueueRefs.length).toBeGreaterThan(0);
        expect(Array.isArray(req.testRefs)).toBe(true);
        expect(req.testRefs.length).toBeGreaterThan(0);
        expect(Array.isArray(req.evaluationRefs)).toBe(true);
        expect(req.evaluationRefs.length).toBeGreaterThan(0);
        expect(['PASS', 'FAIL', 'PENDING']).toContain(req.latestResult);
        expect(typeof req.releaseBlocking).toBe('boolean');
        expect(typeof req.dodChecklistMet).toBe('boolean');
        expect(req.notes).toBeDefined();
      }
    });

    it('should have 100% VERIFIED status and PASS results for all release-blocking requirements', () => {
      const releaseBlockingReqs = AUTHORITATIVE_REQUIREMENTS_MATRIX.filter(r => r.releaseBlocking);
      expect(releaseBlockingReqs.length).toBeGreaterThanOrEqual(20);

      const failedOrUnverified = releaseBlockingReqs.filter(
        r => r.implementationStatus !== 'VERIFIED' || r.latestResult !== 'PASS' || !r.dodChecklistMet
      );
      expect(failedOrUnverified).toHaveLength(0);
    });

    it('should cover all key architectural domains without gaps', () => {
      const categories = new Set(AUTHORITATIVE_REQUIREMENTS_MATRIX.map(r => r.category));
      expect(categories.has('Architecture & Multi-Tenancy')).toBe(true);
      expect(categories.has('Security NFR')).toBe(true);
      expect(categories.has('Data & Schema')).toBe(true);
      expect(categories.has('Epistemic Intelligence')).toBe(true);
      expect(categories.has('Discovery & Ingestion')).toBe(true);
      expect(categories.has('Static Analysis')).toBe(true);
      expect(categories.has('Composition & SBOM')).toBe(true);
      expect(categories.has('Dynamic Sandbox')).toBe(true);
      expect(categories.has('Decision & Risk')).toBe(true);
      expect(categories.has('Knowledge & RAG')).toBe(true);
      expect(categories.has('Lifecycle & State')).toBe(true);
      expect(categories.has('Operations & Outbox')).toBe(true);
      expect(categories.has('Evaluation & Golden Corpus')).toBe(true);
    });
  });

  // =========================================================================
  // 2. Mandatory Epistemic Acceptance Paths (11 Distinct Paths)
  // =========================================================================
  describe('2. Mandatory Epistemic Acceptance Paths', () => {
    const requiredPaths = [
      'STATIC_EVIDENCE',
      'INFERENCE',
      'RUNTIME_OBSERVATION',
      'SIMULATION',
      'EXTERNAL_INTELLIGENCE',
      'DIFFERENTIAL',
      'RISK',
      'EXPLANATION',
      'RECOMMENDATION',
      'VALIDATION',
      'UNCERTAINTY'
    ];

    it('should define and prove all 11 epistemic acceptance paths', () => {
      for (const pathKey of requiredPaths) {
        const path = MANDATORY_ACCEPTANCE_PATHS[pathKey];
        expect(path).toBeDefined();
        expect(path.pathType).toBe(pathKey);
        expect(path.title).toBeDefined();
        expect(path.coreQuestion).toBeDefined();
        expect(path.sampleInput).toBeDefined();
        expect(path.deducedOutput).toBeDefined();
        expect(path.lineageLinks).toBeDefined();
        expect(path.lineageLinks.sourceRef).toBeDefined();
        expect(path.lineageLinks.targetRef).toBeDefined();
        expect(path.provenTruthfully).toBe(true);
      }
    });

    it('should enforce strict epistemic class boundaries (OBSERVED_FACT vs DERIVED_ASSERTION vs UNKNOWN)', () => {
      // Static Evidence, Runtime Observation, Simulation, External Intel, Validation must be OBSERVED_FACT
      expect(MANDATORY_ACCEPTANCE_PATHS.STATIC_EVIDENCE.epistemicState).toBe('OBSERVED_FACT');
      expect(MANDATORY_ACCEPTANCE_PATHS.RUNTIME_OBSERVATION.epistemicState).toBe('OBSERVED_FACT');
      expect(MANDATORY_ACCEPTANCE_PATHS.SIMULATION.epistemicState).toBe('OBSERVED_FACT');
      expect(MANDATORY_ACCEPTANCE_PATHS.EXTERNAL_INTELLIGENCE.epistemicState).toBe('OBSERVED_FACT');
      expect(MANDATORY_ACCEPTANCE_PATHS.VALIDATION.epistemicState).toBe('OBSERVED_FACT');

      // Inference, Differential, Risk, Explanation, Recommendation must be DERIVED_ASSERTION
      expect(MANDATORY_ACCEPTANCE_PATHS.INFERENCE.epistemicState).toBe('DERIVED_ASSERTION');
      expect(MANDATORY_ACCEPTANCE_PATHS.DIFFERENTIAL.epistemicState).toBe('DERIVED_ASSERTION');
      expect(MANDATORY_ACCEPTANCE_PATHS.RISK.epistemicState).toBe('DERIVED_ASSERTION');
      expect(MANDATORY_ACCEPTANCE_PATHS.EXPLANATION.epistemicState).toBe('DERIVED_ASSERTION');
      expect(MANDATORY_ACCEPTANCE_PATHS.RECOMMENDATION.epistemicState).toBe('DERIVED_ASSERTION');

      // Uncertainty must be UNKNOWN
      expect(MANDATORY_ACCEPTANCE_PATHS.UNCERTAINTY.epistemicState).toBe('UNKNOWN');
      expect(MANDATORY_ACCEPTANCE_PATHS.UNCERTAINTY.uncertaintyScore).toBeGreaterThan(0.5);
    });
  });

  // =========================================================================
  // 3. Mandatory Lineage Test: Conclusion -> Source (8 Hops)
  // =========================================================================
  describe('3. Mandatory Lineage Test: Conclusion to Source (8 Hops)', () => {
    it('should resolve full 8-hop lineage from published conclusion to root agent version', () => {
      const resolution = LineageResolverEngine.resolveConclusionLineage('dec-quarantine-rce-001');

      expect(resolution.resolutionStatus).toBe('COMPLETE');
      expect(resolution.hopCount).toBe(8);
      expect(resolution.completenessRatio).toBe(1.0);
      expect(resolution.chain).toHaveLength(8);

      // Verify each hop in the required order:
      // Hop 1: Conclusion/Policy/Recommendation
      expect(resolution.chain[0].level).toBe(1);
      expect(resolution.chain[0].hopName).toContain('Conclusion');
      expect(resolution.chain[0].entityType).toBe('intel.policy_decisions');

      // Hop 2: Risk/Claim
      expect(resolution.chain[1].level).toBe(2);
      expect(resolution.chain[1].hopName).toContain('Risk');
      expect(resolution.chain[1].entityType).toBe('intel.claims');

      // Hop 3: Assertion
      expect(resolution.chain[2].level).toBe(3);
      expect(resolution.chain[2].hopName).toContain('Assertion');
      expect(resolution.chain[2].entityType).toBe('intel.assertions');

      // Hop 4: Evidence
      expect(resolution.chain[3].level).toBe(4);
      expect(resolution.chain[3].hopName).toContain('Evidence');
      expect(resolution.chain[3].entityType).toBe('intel.evidence');

      // Hop 5: Finding/RuntimeEvent/ExternalIntel
      expect(resolution.chain[4].level).toBe(5);
      expect(resolution.chain[4].hopName).toContain('Finding');
      expect(resolution.chain[4].entityType).toBe('analysis.static_findings');

      // Hop 6: SourceSpan/Artifact/SandboxTrace
      expect(resolution.chain[5].level).toBe(6);
      expect(resolution.chain[5].hopName).toContain('Source Span');
      expect(resolution.chain[5].entityType).toBe('source.source_spans');

      // Hop 7: AnalysisStageRun
      expect(resolution.chain[6].level).toBe(7);
      expect(resolution.chain[6].hopName).toContain('Analysis Stage Run');
      expect(resolution.chain[6].entityType).toBe('ops.stage_runs');

      // Hop 8: AnalysisRun -> AgentVersion
      expect(resolution.chain[7].level).toBe(8);
      expect(resolution.chain[7].hopName).toContain('Analysis Run & Agent Version');
      expect(resolution.chain[7].entityType).toContain('caim.agent_versions');

      // Verify all nodes are verified
      expect(resolution.chain.every(n => n.verified)).toBe(true);
    });
  });

  // =========================================================================
  // 4. Mandatory Lineage Test: Observation -> Ontology (6 Hops)
  // =========================================================================
  describe('4. Mandatory Lineage Test: Source Observation to Ontology (6 Hops)', () => {
    it('should resolve full 6-hop lineage from source observation to ontology concept', () => {
      const resolution = LineageResolverEngine.resolveObservationToOntologyLineage('obs-github-repo-001');

      expect(resolution.resolutionStatus).toBe('COMPLETE');
      expect(resolution.hopCount).toBe(6);
      expect(resolution.completenessRatio).toBe(1.0);
      expect(resolution.chain).toHaveLength(6);

      // Verify each hop in the required order:
      // Hop 1: SourceObservation
      expect(resolution.chain[0].level).toBe(1);
      expect(resolution.chain[0].hopName).toContain('Source Observation');
      expect(resolution.chain[0].entityType).toBe('source.observations');

      // Hop 2: Artifact
      expect(resolution.chain[1].level).toBe(2);
      expect(resolution.chain[1].hopName).toContain('Artifact');
      expect(resolution.chain[1].entityType).toBe('source.artifacts');

      // Hop 3: Parsed/Normalized Fact
      expect(resolution.chain[2].level).toBe(3);
      expect(resolution.chain[2].hopName).toContain('Parsed / Normalized Fact');
      expect(resolution.chain[2].entityType).toBe('semantic.facts');

      // Hop 4: CANE Mapping
      expect(resolution.chain[3].level).toBe(4);
      expect(resolution.chain[3].hopName).toContain('CANE Mapping');
      expect(resolution.chain[3].entityType).toBe('caim.cane_manifests');

      // Hop 5: CAIM Entity
      expect(resolution.chain[4].level).toBe(5);
      expect(resolution.chain[4].hopName).toContain('CAIM Entity');
      expect(resolution.chain[4].entityType).toBe('caim.canonical_agents');

      // Hop 6: Ontology Concept
      expect(resolution.chain[5].level).toBe(6);
      expect(resolution.chain[5].hopName).toContain('Ontology Concept');
      expect(resolution.chain[5].entityType).toBe('ontology.concepts');

      expect(resolution.chain.every(n => n.verified)).toBe(true);
    });
  });

  // =========================================================================
  // 5. Quality Targets Invariants
  // =========================================================================
  describe('5. Platform Quality Targets & Non-Negotiable Invariants', () => {
    it('should meet all 5 platform quality targets with 0 tolerance for violations', () => {
      const qualityReport = QualityTargetsAuditor.evaluateQualityTargets();

      expect(qualityReport.allTargetsMet).toBe(true);
      expect(qualityReport.publishedTestConclusionLineageCompleteness).toBe(1.0);
      expect(qualityReport.unauthorizedVaultRetrievalCount).toBe(0);
      expect(qualityReport.unsupportedSubstantiveRagClaimsCount).toBe(0);
      expect(qualityReport.policyHardBlockBypassByScoreCount).toBe(0);
      expect(qualityReport.inferenceMislabeledObservedCount).toBe(0);

      for (const item of qualityReport.breakdown) {
        expect(item.passed).toBe(true);
      }
    });
  });

  // =========================================================================
  // 6. Platform Definition-of-Done (DoD) Full Audit Execution
  // =========================================================================
  describe('6. Platform Definition-of-Done (DoD) Audit Verdict', () => {
    it('should evaluate full platform DoD and return APPROVED_FOR_RELEASE with signed attestation', () => {
      const auditReport = runPlatformDefinitionOfDoneAudit();

      expect(auditReport.auditId).toBeDefined();
      expect(auditReport.architectureVersion).toBe('2.0.1');
      expect(auditReport.verdict).toBe('APPROVED_FOR_RELEASE');
      expect(auditReport.requirementsAudit.releaseBlockingPassRate).toBe(1.0);
      expect(auditReport.acceptancePathsAudit.passedPaths).toBe(11);
      expect(auditReport.lineageAudit.conclusionLineageVerified).toBe(true);
      expect(auditReport.lineageAudit.observationOntologyVerified).toBe(true);
      expect(auditReport.lineageAudit.completenessPercentage).toBe(100.0);
      expect(auditReport.qualityTargetsAudit.allTargetsMet).toBe(true);

      for (const check of auditReport.dodChecklist) {
        expect(check.status).toBe('PASSED');
      }

      expect(auditReport.signedAttestationSha256).toMatch(/^sha256:[a-f0-9]{64}$/);
    });
  });
});
