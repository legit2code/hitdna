# Table Tenancy Classification Architecture

**Document:** 22  
**Version:** 2.0.1  
**Status:** LOCKED — Authoritative R06 Complete Table Tenancy & RLS Governance  
**Total Tables Mapped:** 130

## 1. Governance & Classification Model

In accordance with Document 13, Document 18, Document 21, and the Master Constitution, every table in the platform catalog belongs to one of five authoritative tenancy classes:

| Class | Definition | Access & Isolation Rule |
|---|---|---|
| `GLOBAL_REFERENCE` | Immutable public reference corpus, taxonomies, scoring models. | Readable across tenants via authenticated/app; no tenant isolation required. |
| `PLATFORM_SHARED` | Root scope-bearing entities (PLATFORM or ORGANIZATION scope). | Governed by `security.is_scope_accessible(scope_id)`. RLS enabled and forced. |
| `TENANT_OWNED` | Strictly private to a specific tenant organization. | Governed by `security.current_tenant_id()`. Zero rows returned to other tenants or unauthenticated contexts. RLS enabled and forced. |
| `DERIVED_FROM_PARENT` | Inherits tenant or scope boundary from parent FK entity. | Governed by parent relation scope or tenant check. RLS enabled and forced. |
| `SYSTEM_ONLY` | Internal worker pipelines, security ledgers, audit trails. | Governed by `security.is_system_bypass()` (caim_system role only). `caim_app` has no direct access. RLS enabled and forced. |

## 2. Classification Summary Matrix

| Classification | Table Count | Percentage |
|---|---:|---:|
| `PLATFORM_SHARED` | 14 | 10.8% |
| `DERIVED_FROM_PARENT` | 52 | 40.0% |
| `GLOBAL_REFERENCE` | 25 | 19.2% |
| `TENANT_OWNED` | 12 | 9.2% |
| `SYSTEM_ONLY` | 27 | 20.8% |
| **Total Catalog** | **130** | **100.0%** |

## 3. Authoritative Physical Table Catalog

| Schema.Table | Classification | Tenant Column | Scope Column | Parent FK Path | Description |
|---|---|---|---|---|---|
| `analysis.analysis_runs` | `PLATFORM_SHARED` | - | `scope_id` | - | Root scope bearing analysis runs |
| `analysis.analysis_stage_runs` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (analysis_stage_runs) |
| `analysis.callgraph_edges` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (callgraph_edges) |
| `analysis.callgraph_nodes` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (callgraph_nodes) |
| `analysis.runtime_events` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (runtime_events) |
| `analysis.sbom_components` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (sbom_components) |
| `analysis.sbom_dependencies` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (sbom_dependencies) |
| `analysis.static_findings` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (static_findings) |
| `analysis.taint_flows` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived analysis data from analysis_runs (taint_flows) |
| `core.agent_versions` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.canonical_agents` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.canonical_relationships` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.distributions` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.entity_refs` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.external_aliases` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.organization_relationships` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.organizations` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `core.publishers` | `GLOBAL_REFERENCE` | - | - | - | Canonical public agent registry and ecosystem metadata |
| `intel.assertion_evidence_links` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (assertion_evidence_links) |
| `intel.assertions` | `PLATFORM_SHARED` | - | `scope_id` | - | Intelligence facts, assertions and claims with scope |
| `intel.claim_evidence_links` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (claim_evidence_links) |
| `intel.claim_support_links` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (claim_support_links) |
| `intel.claims` | `PLATFORM_SHARED` | - | `scope_id` | - | Intelligence facts, assertions and claims with scope |
| `intel.contradictions` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (contradictions) |
| `intel.evidence` | `PLATFORM_SHARED` | - | `scope_id` | - | Intelligence facts, assertions and claims with scope |
| `intel.external_intelligence_refs` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (external_intelligence_refs) |
| `intel.lineage_edges` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (lineage_edges) |
| `intel.policy_decision_reasons` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (policy_decision_reasons) |
| `intel.policy_decisions` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (policy_decisions) |
| `intel.policy_overrides` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (policy_overrides) |
| `intel.policy_rules` | `GLOBAL_REFERENCE` | - | - | - | Platform scoring models and governance policies |
| `intel.policy_versions` | `GLOBAL_REFERENCE` | - | - | - | Platform scoring models and governance policies |
| `intel.recommendation_evidence` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (recommendation_evidence) |
| `intel.recommendations` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (recommendations) |
| `intel.risk_evidence` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (risk_evidence) |
| `intel.risks` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (risks) |
| `intel.score_dimension_values` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (score_dimension_values) |
| `intel.score_dimensions` | `GLOBAL_REFERENCE` | - | - | - | Platform scoring models and governance policies |
| `intel.score_models` | `GLOBAL_REFERENCE` | - | - | - | Platform scoring models and governance policies |
| `intel.score_results` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (score_results) |
| `intel.use_case_evaluations` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (use_case_evaluations) |
| `intel.use_case_evidence` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (use_case_evidence) |
| `intel.use_cases` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived intelligence items (use_cases) |
| `knowledge.answer_claims` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (answer_claims) |
| `knowledge.answers` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (answers) |
| `knowledge.citations` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (citations) |
| `knowledge.context_packages` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (context_packages) |
| `knowledge.embeddings` | `DERIVED_FROM_PARENT` | - | `scope_id` | `knowledge.knowledge_objects` | Derived projection/embedding from knowledge_objects (embeddings) |
| `knowledge.grounding_results` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (grounding_results) |
| `knowledge.index_states` | `DERIVED_FROM_PARENT` | - | `scope_id` | `knowledge.knowledge_objects` | Derived projection/embedding from knowledge_objects (index_states) |
| `knowledge.knowledge_chunks` | `DERIVED_FROM_PARENT` | - | `scope_id` | `knowledge.knowledge_objects` | Derived projection/embedding from knowledge_objects (knowledge_chunks) |
| `knowledge.knowledge_objects` | `PLATFORM_SHARED` | - | `scope_id` | - | Root knowledge objects projected from analysis runs |
| `knowledge.knowledge_projections` | `DERIVED_FROM_PARENT` | - | `scope_id` | `knowledge.knowledge_objects` | Derived projection/embedding from knowledge_objects (knowledge_projections) |
| `knowledge.queries` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant interactive RAG query session and queries |
| `knowledge.query_plans` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (query_plans) |
| `knowledge.query_sessions` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant interactive RAG query session and queries |
| `knowledge.retrieval_results` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (retrieval_results) |
| `knowledge.retrieval_runs` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `knowledge.queries` | Derived RAG execution artifact from queries (retrieval_runs) |
| `knowledge.vector_embeddings` | `DERIVED_FROM_PARENT` | - | `scope_id` | `knowledge.knowledge_objects` | Derived projection/embedding from knowledge_objects (vector_embeddings) |
| `lifecycle.approvals` | `SYSTEM_ONLY` | - | - | - | Lifecycle version comparison and approval tracking |
| `lifecycle.attestations` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived agent release packages, attestations and shipments |
| `lifecycle.diff_items` | `SYSTEM_ONLY` | - | - | - | Lifecycle version comparison and approval tracking |
| `lifecycle.impact_assessments` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `lifecycle.modification_workspaces` | Derived modification changes and impact assessments |
| `lifecycle.impact_items` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `lifecycle.modification_workspaces` | Derived modification changes and impact assessments |
| `lifecycle.modification_changes` | `DERIVED_FROM_PARENT` | `tenant_id` | - | `lifecycle.modification_workspaces` | Derived modification changes and impact assessments |
| `lifecycle.modification_workspaces` | `TENANT_OWNED` | `tenant_id` | - | - | Private tenant agent modification workspaces |
| `lifecycle.package_contents` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived agent release packages, attestations and shipments |
| `lifecycle.packages` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived agent release packages, attestations and shipments |
| `lifecycle.shipments` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived agent release packages, attestations and shipments |
| `lifecycle.signatures` | `DERIVED_FROM_PARENT` | - | `scope_id` | `analysis.analysis_runs` | Derived agent release packages, attestations and shipments |
| `lifecycle.validation_results` | `DERIVED_FROM_PARENT` | - | `scope_id` | `lifecycle.validation_runs` | Derived validation results |
| `lifecycle.validation_runs` | `PLATFORM_SHARED` | - | `scope_id` | - | Root scope bearing validation runs |
| `lifecycle.version_diffs` | `SYSTEM_ONLY` | - | - | - | Lifecycle version comparison and approval tracking |
| `ontology.ontology_change_log` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_concept_aliases` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_concepts` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_deprecations` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_inference_rules` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_mapping_rules` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_relationship_types` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_relationships` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ontology.ontology_versions` | `GLOBAL_REFERENCE` | - | - | - | Canonical CAIM ontology concept and relationship taxonomy |
| `ops.audit_events` | `SYSTEM_ONLY` | - | - | - | Immutable operational audit and resource metering ledger |
| `ops.compatibility_rules` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.cost_usage_events` | `SYSTEM_ONLY` | - | - | - | Immutable operational audit and resource metering ledger |
| `ops.dead_letter_jobs` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.evaluation_cases` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.evaluation_datasets` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.evaluation_results` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.evaluation_runs` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.golden_corpus_items` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.job_attempts` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.jobs` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.lifecycle_state_transitions` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.outbox_deliveries` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.outbox_events` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `ops.telemetry_records` | `SYSTEM_ONLY` | - | - | - | Immutable operational audit and resource metering ledger |
| `ops.version_registry` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.workflow_definitions` | `PLATFORM_SHARED` | - | `scope_id` | - | Shared ops versioning, golden corpus and evaluation baselines |
| `ops.workflow_runs` | `SYSTEM_ONLY` | - | - | - | Operational worker queue, execution state and event dispatch |
| `security.access_grants` | `TENANT_OWNED` | `tenant_id` | - | - | Granular capability access grants |
| `security.access_scopes` | `PLATFORM_SHARED` | `tenant_id` | `scope_id` | - | Access scope registry (PLATFORM or ORGANIZATION) |
| `security.composer_generation_log` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant activity and rate limiting |
| `security.platform_audit_log` | `SYSTEM_ONLY` | - | - | - | Platform security and administrative system ledger |
| `security.principals` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant directory, membership and credentials |
| `security.rate_limit_buckets` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant activity and rate limiting |
| `security.refresh_tokens` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant directory, membership and credentials |
| `security.restricted_capability_grants` | `TENANT_OWNED` | `tenant_id` | - | - | Granular capability access grants |
| `security.revoked_tokens` | `SYSTEM_ONLY` | - | - | - | Platform security and administrative system ledger |
| `security.roles` | `GLOBAL_REFERENCE` | - | - | - | Global platform security roles and classification levels |
| `security.security_classifications` | `GLOBAL_REFERENCE` | - | - | - | Global platform security roles and classification levels |
| `security.service_accounts` | `SYSTEM_ONLY` | - | - | - | Platform security and administrative system ledger |
| `security.system_tx_audit` | `SYSTEM_ONLY` | - | - | - | Platform security and administrative system ledger |
| `security.table_tenant_classifications` | `SYSTEM_ONLY` | - | - | - | Platform security and administrative system ledger |
| `security.tenant_memberships` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant directory, membership and credentials |
| `security.tenants` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant directory, membership and credentials |
| `security.user_roles` | `TENANT_OWNED` | `tenant_id` | - | - | Tenant directory, membership and credentials |
| `source.acquisition_runs` | `DERIVED_FROM_PARENT` | - | `scope_id` | `source.source_observations` | Derived artifact acquisition and source analysis spans |
| `source.artifact_files` | `DERIVED_FROM_PARENT` | - | `scope_id` | `source.source_observations` | Derived artifact acquisition and source analysis spans |
| `source.artifacts` | `DERIVED_FROM_PARENT` | - | `scope_id` | `source.source_observations` | Derived artifact acquisition and source analysis spans |
| `source.discovery_candidates` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_edge_types` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_edges` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_queries` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_relationships` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_roots` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.discovery_runs` | `SYSTEM_ONLY` | - | - | - | System discovery pipeline runs and candidate graph |
| `source.source_adapters` | `GLOBAL_REFERENCE` | - | - | - | External source adapter registry |
| `source.source_observations` | `PLATFORM_SHARED` | - | `scope_id` | - | Root scope bearing observation records |
| `source.source_spans` | `DERIVED_FROM_PARENT` | - | `scope_id` | `source.source_observations` | Derived artifact acquisition and source analysis spans |
