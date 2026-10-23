-- Reference Seed Data for Platform Baseline (P03)
-- Strictly reference metadata only; zero fake runtime or mock application records

-- 1. Security Classifications
INSERT INTO security.security_classifications (security_classification_id, code, rank, description)
VALUES
  ('00000000-0000-0000-0000-000000000010', 'PUBLIC_METADATA', 0, 'Publicly readable catalog, publisher and registry metadata'),
  ('00000000-0000-0000-0000-000000000011', 'INTERNAL', 1, 'Internal platform evaluation results, workflow state and scoring configurations'),
  ('00000000-0000-0000-0000-000000000012', 'SENSITIVE', 2, 'Sensitive source code spans, static findings, query history and recommendations'),
  ('00000000-0000-0000-0000-000000000013', 'VAULT_RESTRICTED', 3, 'Vault-restricted credentials, raw sandbox traces, taint flows and exploit details')
ON CONFLICT (code) DO UPDATE SET
  rank = EXCLUDED.rank,
  description = EXCLUDED.description;

-- 2. Single Authoritative PLATFORM Access Scope
INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
VALUES
  ('00000000-0000-0000-0000-000000000001', 'PLATFORM', NULL)
ON CONFLICT DO NOTHING;

-- 3. Standard Platform Roles
INSERT INTO security.roles (role_id, role_key, description, status)
VALUES
  ('00000000-0000-0000-0000-000000000020', 'admin', 'Full administrative authority across platform and tenant scopes', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000021', 'reviewer', 'Review, verification, validation comparison and package approval authority', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000022', 'analyst', 'Analytical query execution, static findings review and evidence exploration', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000023', 'vault_reader', 'Access to vault-restricted taint paths, traces and confidential disclosures', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000024', 'system_service', 'Automated backend pipeline and worker daemon execution identity', 'ACTIVE')
ON CONFLICT (role_key) DO UPDATE SET
  description = EXCLUDED.description,
  status = EXCLUDED.status;

-- 4. Baseline CAIM Ontology Version 2.0.1
INSERT INTO ontology.ontology_versions (ontology_version_id, version_label, status, released_at)
VALUES
  ('00000000-0000-0000-0001-000000000001', '2.0.1', 'ACTIVE', now())
ON CONFLICT (version_label) DO UPDATE SET
  status = EXCLUDED.status;

-- 5. Foundational CAIM Ontology Concepts
INSERT INTO ontology.ontology_concepts (concept_id, ontology_version_id, namespace, canonical_name, concept_type, status)
VALUES
  ('00000000-0000-0000-0001-000000000100', '00000000-0000-0000-0001-000000000001', 'caim', 'agent', 'ENTITY', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000101', '00000000-0000-0000-0001-000000000001', 'caim', 'tool', 'ENTITY', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000102', '00000000-0000-0000-0001-000000000001', 'caim', 'permission', 'CAPABILITY', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000103', '00000000-0000-0000-0001-000000000001', 'caim', 'endpoint', 'SURFACE', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000104', '00000000-0000-0000-0001-000000000001', 'caim', 'protocol', 'SPECIFICATION', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000105', '00000000-0000-0000-0001-000000000001', 'caim', 'artifact', 'ASSET', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000106', '00000000-0000-0000-0001-000000000001', 'caim', 'evidence', 'PROOF', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000107', '00000000-0000-0000-0001-000000000001', 'caim', 'claim', 'INTEL', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000108', '00000000-0000-0000-0001-000000000001', 'caim', 'vulnerability', 'SECURITY', 'ACTIVE'),
  ('00000000-0000-0000-0001-000000000109', '00000000-0000-0000-0001-000000000001', 'caim', 'risk', 'GOVERNANCE', 'ACTIVE')
ON CONFLICT (ontology_version_id, namespace, canonical_name) DO UPDATE SET
  status = EXCLUDED.status;

-- 6. Foundational Ontology Relationship Types
INSERT INTO ontology.ontology_relationship_types (relationship_type_id, ontology_version_id, canonical_name, transitive, is_symmetric)
VALUES
  ('00000000-0000-0000-0001-000000000200', '00000000-0000-0000-0001-000000000001', 'USES_TOOL', false, false),
  ('00000000-0000-0000-0001-000000000201', '00000000-0000-0000-0001-000000000001', 'REQUIRES_PERMISSION', false, false),
  ('00000000-0000-0000-0001-000000000202', '00000000-0000-0000-0001-000000000001', 'EXPOSES_ENDPOINT', false, false),
  ('00000000-0000-0000-0001-000000000203', '00000000-0000-0000-0001-000000000001', 'IMPLEMENTS_PROTOCOL', false, false),
  ('00000000-0000-0000-0001-000000000204', '00000000-0000-0000-0001-000000000001', 'DEPENDS_ON', true, false)
ON CONFLICT (ontology_version_id, canonical_name) DO NOTHING;

-- 7. Platform Version Registry Active Baselines
INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash, activated_at)
VALUES
  ('00000000-0000-0000-0002-000000000001', 'ONTOLOGY', 'caim-standard', '2.0.1', 'ACTIVE', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', now()),
  ('00000000-0000-0000-0002-000000000002', 'PIPELINE', 'analysis-pipeline', '2.0.1', 'ACTIVE', 'sha256:7b249b6b8b0e8b233a0890a59752b041cf98fec8618e4745d064cfcbbfca0c2f', now()),
  ('00000000-0000-0000-0002-000000000003', 'RULESET', 'static-finding-rules', '2.0.1', 'ACTIVE', 'sha256:8897c9b83b38ca152345d3762888147d3d2ebaaecfeec8e54737dd3475d6919e', now())
ON CONFLICT (artifact_type, artifact_key, version) DO UPDATE SET
  status = EXCLUDED.status,
  activated_at = EXCLUDED.activated_at;

-- 8. Authoritative Admin Bootstrap Notice:
-- Static password seeding in seed.sql has been removed for security hardening.
-- Initial administrators are provisioned via secure first-run enrollment or deploy-time secret.

-- 9. Baseline Score Models and Policy Versions
INSERT INTO intel.score_models (score_model_id, model_key, version, formula_type, status)
VALUES
  ('00000000-0000-0000-0003-000000000001', 'caim-standard-risk-v2', '2.0.1', 'WEIGHTED_MULTI_DIMENSIONAL', 'ACTIVE')
ON CONFLICT (model_key, version) DO NOTHING;

INSERT INTO intel.policy_versions (policy_version_id, policy_key, version, name, status)
VALUES
  ('00000000-0000-0000-0003-000000000002', 'pol-enterprise-prod-v2', '2.0.1', 'Enterprise Production Admission Policy', 'ACTIVE')
ON CONFLICT (policy_key, version) DO NOTHING;


