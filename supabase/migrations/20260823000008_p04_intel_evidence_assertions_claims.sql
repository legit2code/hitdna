-- Migration: 20260823000008_p04_intel_evidence_assertions_claims.sql
-- Purpose: Create External Intelligence, Evidence, Assertions, Claims, Support Links, and Contradictions
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21

-- 1. External Intelligence References Table (CVE, CWE, GHSA, MITRE ATT&CK)
CREATE TABLE IF NOT EXISTS intel.external_intelligence_refs (
  intel_ref_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_name text NOT NULL,
  external_id text NOT NULL,
  title text NOT NULL,
  url text NULL,
  severity text NULL,
  cvss_score numeric(3,1) NULL,
  epss_score numeric(5,4) NULL,
  published_date date NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_external_intel_source_id UNIQUE (source_name, external_id)
);

CREATE INDEX IF NOT EXISTS idx_external_intel_external_id ON intel.external_intelligence_refs(external_id);

-- 2. Evidence Table (Normalized Evidence Artifacts)
CREATE TABLE IF NOT EXISTS intel.evidence (
  evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  evidence_type text NOT NULL CHECK (evidence_type IN ('STATIC_CODE', 'AST_MATCH', 'DYNAMIC_CALL', 'METADATA_MANIFEST', 'EXTERNAL_INTEL', 'HEURISTIC')),
  source_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  source_observation_id uuid NULL REFERENCES source.source_observations(source_observation_id) ON DELETE SET NULL,
  artifact_id uuid NULL REFERENCES source.artifacts(artifact_id) ON DELETE SET NULL,
  static_finding_id uuid NULL REFERENCES analysis.static_findings(finding_id) ON DELETE SET NULL,
  runtime_event_id uuid NULL REFERENCES analysis.runtime_events(runtime_event_id) ON DELETE SET NULL,
  external_intel_ref_id uuid NULL REFERENCES intel.external_intelligence_refs(intel_ref_id) ON DELETE SET NULL,
  description text NOT NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  weight numeric(5,4) NOT NULL DEFAULT 1.0000,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_run ON intel.evidence(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scope ON intel.evidence(scope_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON intel.evidence(static_finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_span ON intel.evidence(source_span_id);
CREATE INDEX IF NOT EXISTS idx_evidence_observation ON intel.evidence(source_observation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON intel.evidence(artifact_id);

-- 3. Assertions Table (Atomic Analytical Observations with Confidence and Uncertainty)
CREATE TABLE IF NOT EXISTS intel.assertions (
  assertion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  assertion_key text NOT NULL,
  concept_id uuid NULL REFERENCES ontology.ontology_concepts(concept_id) ON DELETE SET NULL,
  predicate text NOT NULL,
  subject_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  object_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  assertion_value text NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  uncertainty_score numeric(5,4) NOT NULL DEFAULT 0.0000 CHECK (uncertainty_score >= 0 AND uncertainty_score <= 1),
  uncertainty_factors jsonb NULL,
  calibration_version text NULL,
  engine_key text NOT NULL,
  rule_id text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assertions_run ON intel.assertions(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_assertions_scope ON intel.assertions(scope_id);
CREATE INDEX IF NOT EXISTS idx_assertions_key ON intel.assertions(assertion_key);
CREATE INDEX IF NOT EXISTS idx_assertions_concept ON intel.assertions(concept_id);
CREATE INDEX IF NOT EXISTS idx_assertions_subject ON intel.assertions(subject_ref_id);

-- 4. Assertion Evidence Links Table
CREATE TABLE IF NOT EXISTS intel.assertion_evidence_links (
  link_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assertion_id uuid NOT NULL REFERENCES intel.assertions(assertion_id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES intel.evidence(evidence_id) ON DELETE CASCADE,
  relationship_type text NOT NULL DEFAULT 'SUPPORTS' CHECK (relationship_type IN ('SUPPORTS', 'REFUTES', 'CONTEXTUALIZES')),
  relevance_weight numeric(5,4) NOT NULL DEFAULT 1.0000,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_assertion_evidence UNIQUE (assertion_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_assertion_evidence_assertion ON intel.assertion_evidence_links(assertion_id);
CREATE INDEX IF NOT EXISTS idx_assertion_evidence_evidence ON intel.assertion_evidence_links(evidence_id);

-- 5. Claims Table (High-Level Posture & Safety Claims)
CREATE TABLE IF NOT EXISTS intel.claims (
  claim_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  claim_type text NOT NULL CHECK (claim_type IN ('SECURITY_POSTURE', 'CAPABILITY', 'COMPLIANCE', 'BEHAVIORAL_SAFETY', 'DATA_INTEGRITY', 'SUPPLY_CHAIN')),
  claim_text text NOT NULL,
  state text NOT NULL DEFAULT 'SUPPORTED' CHECK (state IN ('SUPPORTED', 'REFUTED', 'CONTESTED', 'UNVERIFIED')),
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  uncertainty_score numeric(5,4) NOT NULL DEFAULT 0.0000 CHECK (uncertainty_score >= 0 AND uncertainty_score <= 1),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_claims_run ON intel.claims(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_claims_scope ON intel.claims(scope_id);
CREATE INDEX IF NOT EXISTS idx_claims_type ON intel.claims(claim_type);
CREATE INDEX IF NOT EXISTS idx_claims_state ON intel.claims(state);

-- 6. Claim Evidence Links Table
CREATE TABLE IF NOT EXISTS intel.claim_evidence_links (
  link_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id uuid NOT NULL REFERENCES intel.claims(claim_id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES intel.evidence(evidence_id) ON DELETE CASCADE,
  support_type text NOT NULL DEFAULT 'DIRECT_SUPPORT' CHECK (support_type IN ('DIRECT_SUPPORT', 'INDIRECT_SUPPORT', 'CONTRADICTORY', 'MITIGATING')),
  weight numeric(5,4) NOT NULL DEFAULT 1.0000,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_claim_evidence UNIQUE (claim_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_claim_evidence_claim ON intel.claim_evidence_links(claim_id);
CREATE INDEX IF NOT EXISTS idx_claim_evidence_evidence ON intel.claim_evidence_links(evidence_id);

-- 7. Claim Support Links Table (Claim derived from Assertions)
CREATE TABLE IF NOT EXISTS intel.claim_support_links (
  link_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id uuid NOT NULL REFERENCES intel.claims(claim_id) ON DELETE CASCADE,
  assertion_id uuid NOT NULL REFERENCES intel.assertions(assertion_id) ON DELETE CASCADE,
  link_type text NOT NULL DEFAULT 'SUPPORTS' CHECK (link_type IN ('SUPPORTS', 'CONTRADICTS', 'DERIVED_FROM')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_claim_assertion UNIQUE (claim_id, assertion_id)
);

CREATE INDEX IF NOT EXISTS idx_claim_support_claim ON intel.claim_support_links(claim_id);
CREATE INDEX IF NOT EXISTS idx_claim_support_assertion ON intel.claim_support_links(assertion_id);

-- 8. Contradictions Table (Contradictions between Claims or Assertions)
CREATE TABLE IF NOT EXISTS intel.contradictions (
  contradiction_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  claim_a_id uuid NULL REFERENCES intel.claims(claim_id) ON DELETE CASCADE,
  claim_b_id uuid NULL REFERENCES intel.claims(claim_id) ON DELETE CASCADE,
  assertion_a_id uuid NULL REFERENCES intel.assertions(assertion_id) ON DELETE CASCADE,
  assertion_b_id uuid NULL REFERENCES intel.assertions(assertion_id) ON DELETE CASCADE,
  conflict_reason text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  resolution_status text NOT NULL DEFAULT 'UNRESOLVED' CHECK (resolution_status IN ('UNRESOLVED', 'RESOLVED_A', 'RESOLVED_B', 'ACCEPTED_AMBIGUITY')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_contradictions_run ON intel.contradictions(analysis_run_id);

-- 9. Trigger Function and Triggers for Derived Inherited Scope (Architecture V2.0.1 Document 21)
-- Automatically resolves and enforces child.scope_id = parent.scope_id from analysis.analysis_runs at insert time
CREATE OR REPLACE FUNCTION intel.trg_fn_populate_scope_from_analysis_run()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.scope_id IS NULL AND NEW.analysis_run_id IS NOT NULL THEN
    SELECT scope_id INTO NEW.scope_id
    FROM analysis.analysis_runs
    WHERE analysis_run_id = NEW.analysis_run_id;
  END IF;
  
  IF NEW.scope_id IS NULL THEN
    RAISE EXCEPTION 'Cannot resolve scope_id for % from analysis_run_id %', TG_TABLE_NAME, NEW.analysis_run_id;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_evidence_populate_scope
  BEFORE INSERT ON intel.evidence
  FOR EACH ROW
  EXECUTE FUNCTION intel.trg_fn_populate_scope_from_analysis_run();

CREATE TRIGGER trg_assertions_populate_scope
  BEFORE INSERT ON intel.assertions
  FOR EACH ROW
  EXECUTE FUNCTION intel.trg_fn_populate_scope_from_analysis_run();

CREATE TRIGGER trg_claims_populate_scope
  BEFORE INSERT ON intel.claims
  FOR EACH ROW
  EXECUTE FUNCTION intel.trg_fn_populate_scope_from_analysis_run();

