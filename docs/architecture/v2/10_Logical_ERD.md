# Logical ERD

**Document:** 10  
**Status:** Complete logical relationship baseline  
**Notation:** Logical entities/cardinalities; not PostgreSQL table DDL.

## 1. Master Intelligence Spine

```mermaid
erDiagram
    CANONICAL_AGENT ||--o{ AGENT_VERSION : has
    AGENT_VERSION ||--o{ ARTIFACT : contains
    ARTIFACT ||--o{ ARTIFACT_FILE : contains
    ARTIFACT_FILE ||--o{ SOURCE_SPAN : locates
    ARTIFACT ||--o{ NORMALIZED_SOURCE_FACT : yields
    AGENT_VERSION ||--o{ ANALYSIS_RUN : analyzed_by
    ANALYSIS_RUN ||--o{ ANALYSIS_STAGE_RUN : executes
    ANALYSIS_RUN ||--o{ STATIC_FINDING : produces
    ANALYSIS_RUN ||--o{ RUNTIME_EVENT : observes
    ANALYSIS_RUN ||--o{ EVIDENCE_ITEM : collects
    EVIDENCE_ITEM ||--o{ ASSERTION_EVIDENCE : supports
    ASSERTION ||--o{ ASSERTION_EVIDENCE : has
    ASSERTION ||--o{ CLAIM_ASSERTION : supports
    CLAIM ||--o{ CLAIM_ASSERTION : built_from
    ANALYSIS_RUN ||--o{ RISK : assesses
    RISK ||--o{ RISK_CLAIM : supported_by
    CLAIM ||--o{ RISK_CLAIM : supports
    ANALYSIS_RUN ||--o{ SCORE : scores
    ANALYSIS_RUN ||--o{ POLICY_DECISION : governs
```

## 2. Discovery / Identity ERD

```mermaid
erDiagram
    SOURCE_ADAPTER ||--o{ SOURCE_OBSERVATION : produces
    DISCOVERY_RUN ||--o{ DISCOVERY_QUERY : contains
    DISCOVERY_QUERY ||--o{ DISCOVERY_CANDIDATE : finds
    DISCOVERY_CANDIDATE ||--o{ DISCOVERY_RELATIONSHIP : expands
    DISCOVERY_CANDIDATE ||--o{ SOURCE_OBSERVATION : observed_as
    SOURCE_OBSERVATION ||--o{ ACQUISITION_RUN : acquisition
    SOURCE_OBSERVATION ||--o{ ARTIFACT : snapshot
    CANONICAL_AGENT ||--o{ AGENT_VERSION : versions
    AGENT_VERSION ||--o{ DISTRIBUTION : distributed_as
    AGENT_VERSION ||--o{ ARTIFACT : artifacts
    PUBLISHER ||--o{ DISTRIBUTION : publishes
```

## 3. Canonical Composition ERD

```mermaid
erDiagram
    AGENT_VERSION ||--o{ RUNTIME_ENVIRONMENT : requires
    AGENT_VERSION ||--o{ ENTRYPOINT : exposes
    AGENT_VERSION ||--o{ PROTOCOL_INSTANCE : implements
    PROTOCOL_INSTANCE ||--o{ PROTOCOL_CAPABILITY : advertises
    AGENT_VERSION ||--o{ TOOL : tools
    TOOL ||--o{ TOOL_BINDING : binds
    AGENT_VERSION ||--o{ CAPABILITY_INSTANCE : capabilities
    AGENT_VERSION ||--o{ PERMISSION : permissions
    AGENT_VERSION ||--o{ DATA_ACCESS_REQUIREMENT : accesses
    AGENT_VERSION ||--o{ ENDPOINT : endpoints
    AGENT_VERSION ||--o{ MODEL_REFERENCE : models
    AGENT_VERSION ||--o{ DATASET_REFERENCE : datasets
    AGENT_VERSION ||--o{ PROMPT_ASSET : prompts
    AGENT_VERSION ||--o{ CONFIGURATION_OBJECT : configurations
    CONFIGURATION_OBJECT ||--o{ CONFIGURATION_ENTRY : entries
    AGENT_VERSION ||--o{ CREDENTIAL_REFERENCE : credentials
    COMPONENT ||--o{ DEPENDENCY_RELATIONSHIP : dependency_node
```

## 4. Ontology ERD

```mermaid
erDiagram
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_CONCEPT : contains
    ONTOLOGY_CONCEPT ||--o{ ONTOLOGY_CONCEPT_ALIAS : aliases
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_RELATIONSHIP_TYPE : predicates
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_RELATIONSHIP : relations
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_MAPPING_RULE : mappings
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_INFERENCE_RULE : inference
    ONTOLOGY_VERSION ||--o{ ONTOLOGY_DEPRECATION : deprecations
```

## 5. Static / Dynamic Analysis ERD

```mermaid
erDiagram
    AGENT_VERSION ||--o{ ANALYSIS_RUN : analyzed_by
    ANALYSIS_RUN ||--o{ ANALYSIS_STAGE_RUN : stages
    ANALYSIS_RUN ||--o{ CODE_SYMBOL : symbols
    CODE_SYMBOL ||--o{ CALL_GRAPH_EDGE : caller
    ANALYSIS_RUN ||--o{ CONTROL_FLOW_GRAPH : cfgs
    CONTROL_FLOW_GRAPH ||--o{ CONTROL_FLOW_NODE : nodes
    CONTROL_FLOW_GRAPH ||--o{ CONTROL_FLOW_EDGE : edges
    ANALYSIS_RUN ||--o{ STATIC_FINDING : findings
    ANALYSIS_RUN ||--o{ TAINT_PATH : taint
    TAINT_PATH ||--o{ TAINT_PATH_STEP : steps
    ANALYSIS_RUN ||--o{ SBOM : sboms
    SBOM ||--o{ SBOM_COMPONENT : components
    VULNERABILITY_ADVISORY ||--o{ VULNERABILITY_MATCH : matched
    ANALYSIS_RUN ||--o{ VULNERABILITY_MATCH : vulnerability_matches
    ANALYSIS_RUN ||--o{ REACHABILITY_RESULT : reachability
    SCENARIO_PACK ||--o{ SCENARIO : scenarios
    ANALYSIS_RUN ||--o{ SANDBOX_RUN : sandbox
    SANDBOX_RUN ||--o{ SCENARIO_RUN : scenario_runs
    SCENARIO ||--o{ SCENARIO_RUN : executes
    SANDBOX_RUN ||--o{ SANDBOX_TRACE : traces
    SANDBOX_RUN ||--o{ RUNTIME_EVENT : events
    ANALYSIS_RUN ||--o{ BEHAVIOR_SEQUENCE : behaviors
    BEHAVIOR_SEQUENCE ||--o{ BEHAVIOR_SEQUENCE_EVENT : members
    RUNTIME_EVENT ||--o{ BEHAVIOR_SEQUENCE_EVENT : participates
```

## 6. Evidence / Decision ERD

```mermaid
erDiagram
    ANALYSIS_RUN ||--o{ EVIDENCE_ITEM : evidence
    EVIDENCE_ITEM ||--o{ EVIDENCE_LINK : links
    ANALYSIS_RUN ||--o{ ASSERTION : assertions
    ASSERTION ||--o{ ASSERTION_EVIDENCE : evidence_links
    EVIDENCE_ITEM ||--o{ ASSERTION_EVIDENCE : supports
    ANALYSIS_RUN ||--o{ CLAIM : claims
    CLAIM ||--o{ CLAIM_ASSERTION : assertion_links
    ASSERTION ||--o{ CLAIM_ASSERTION : supports
    CONTRADICTION ||--o{ CONTRADICTION_MEMBER : members
    ANALYSIS_RUN ||--o{ RISK : risks
    RISK ||--o{ RISK_CLAIM : claim_links
    CLAIM ||--o{ RISK_CLAIM : supports
    SCORE_MODEL ||--o{ SCORE_MODEL_DIMENSION : dimensions
    ANALYSIS_RUN ||--o{ SCORE : score_results
    SCORE_MODEL ||--o{ SCORE : calculates
    SCORE ||--o{ SCORE_DIMENSION_RESULT : dimension_results
    POLICY_SET ||--o{ POLICY_RULE : rules
    ANALYSIS_RUN ||--o{ POLICY_DECISION : policy
    POLICY_SET ||--o{ POLICY_DECISION : evaluates
    POLICY_DECISION ||--o{ POLICY_DECISION_REASON : reasons
    ANALYSIS_RUN ||--o{ RECOMMENDATION : recommendations
    RECOMMENDATION ||--o{ RECOMMENDATION_SUPPORT : support
    ANALYSIS_RUN ||--o{ USE_CASE : use_cases
    USE_CASE ||--o{ USE_CASE_SUPPORT : support
```

## 7. Knowledge / RAG ERD

```mermaid
erDiagram
    ENTITY_REF ||--o{ KNOWLEDGE_OBJECT : projects
    KNOWLEDGE_OBJECT ||--o{ KNOWLEDGE_PROJECTION : projections
    KNOWLEDGE_PROJECTION ||--o{ KNOWLEDGE_CHUNK : chunks
    KNOWLEDGE_CHUNK ||--o{ EMBEDDING : embeddings
    KNOWLEDGE_OBJECT ||--o{ INDEX_STATE : indexes
    QUERY_SESSION ||--o{ QUERY : queries
    QUERY ||--o{ QUERY_PLAN : plans
    QUERY_PLAN ||--o{ RETRIEVAL_RUN : retrievals
    RETRIEVAL_RUN ||--o{ RETRIEVAL_RESULT : results
    QUERY ||--o{ CONTEXT_PACKAGE : context
    QUERY ||--o{ ANSWER : answers
    ANSWER ||--o{ ANSWER_CLAIM : claims
    ANSWER ||--o{ CITATION : citations
    ANSWER ||--o{ GROUNDING_RESULT : grounding
```

## 8. Lifecycle / Control ERD

```mermaid
erDiagram
    VERSION_DIFF ||--o{ DIFF_ITEM : items
    AGENT_VERSION ||--o{ MODIFICATION_WORKSPACE : workspaces
    MODIFICATION_WORKSPACE ||--o{ MODIFICATION_CHANGE : changes
    MODIFICATION_WORKSPACE ||--o{ IMPACT_ASSESSMENT : impact
    IMPACT_ASSESSMENT ||--o{ IMPACT_ITEM : items
    AGENT_VERSION ||--o{ VALIDATION_RUN : baseline_or_modified_version
    ANALYSIS_RUN ||--o{ VALIDATION_RUN : baseline_analysis
    ANALYSIS_RUN ||--o{ VALIDATION_RUN : modified_analysis
    ANALYSIS_RUN ||--o{ VALIDATION_RUN : validation_execution
    VALIDATION_RUN ||--o{ VALIDATION_RESULT : results
    AGENT_VERSION ||--o{ PACKAGE : packages
    PACKAGE ||--o{ PACKAGE_CONTENT : contents
    PACKAGE ||--o{ ATTESTATION : attestations
    PACKAGE ||--o{ SHIPMENT : shipments
    WORKFLOW_DEFINITION ||--o{ WORKFLOW_RUN : runs
    WORKFLOW_RUN ||--o{ JOB : jobs
    JOB ||--o{ JOB_ATTEMPT : attempts
    ROLE ||--o{ USER_ROLE : assignments
    EVALUATION_DATASET ||--o{ EVALUATION_CASE : cases
    EVALUATION_DATASET ||--o{ EVALUATION_RUN : runs
    EVALUATION_RUN ||--o{ EVALUATION_RESULT : results
```

## 9. Universal Lineage Model

`entity_refs` provides a stable cross-domain address for durable objects that need generic links.

```mermaid
flowchart LR
    S[Source Span / Runtime Event] --> N[Normalized Source Fact]
    N --> C[Canonical Entity]
    C --> F[Finding / Behavior]
    F --> E[Evidence]
    E --> A[Assertion]
    A --> CL[Claim]
    CL --> R[Risk]
    R --> SC[Score]
    R --> P[Policy Decision]

    ST[Analysis Stage Run] -. produced .-> F
    ST -. produced .-> E
    ST -. produced .-> A
    ST -. produced .-> CL
```

Every arrow that represents derivation can be persisted as a `lineage_edges` record.

## 10. Cardinality Rules

- `CanonicalAgent 1:N AgentVersion`.
- `AgentVersion 1:N AnalysisRun`.
- `AnalysisRun 1:N AnalysisStageRun`.
- `AnalysisRun` has `UNIQUE(analysis_run_id, agent_version_id)` and `UNIQUE(analysis_run_id, scope_id)` in the physical model.
- `ValidationRun` references exact baseline, modified and validation AnalysisRuns; baseline/modified run-version pairs are database-enforced composite FKs.
- Analysis-derived records reference exactly one AnalysisRun unless explicitly external/global.
- Evidence may support many assertions; an assertion may have many evidence items.
- Claims may combine many assertions; assertions may contribute to many claims.
- Risks may be supported by many claims; claims may support multiple risks.
- A score is model-version-specific and analysis-run-specific.
- Policy decisions are policy-set-version-specific and analysis-run-specific.
- RAG knowledge objects are derivative projections of authoritative entity references.
- Embeddings are derivative, versioned and rebuildable.
## 11. Tenant / Scope ERD — V2.0.1

```mermaid
erDiagram
    TENANT ||--o{ TENANT_MEMBERSHIP : memberships
    TENANT ||--|| ACCESS_SCOPE : organization_scope
    ACCESS_SCOPE ||--o{ ANALYSIS_RUN : scopes
    ANALYSIS_RUN ||--o{ ANALYSIS_STAGE_RUN : inherits_scope
    ANALYSIS_RUN ||--o{ EVIDENCE_ITEM : inherits_scope
    ANALYSIS_RUN ||--o{ ASSERTION : inherits_scope
    ANALYSIS_RUN ||--o{ CLAIM : inherits_scope
    ANALYSIS_RUN ||--o{ RISK : inherits_scope
    ANALYSIS_RUN ||--o{ SCORE : inherits_scope
```

`DERIVED_INHERITED_SCOPE` is not a database scope type. It means the child `scope_id` is forced to the authoritative parent/resolved input scope. PLATFORM vs ORGANIZATION is stored in `security.access_scopes`. See Documents 21/21A.
