import type {
  CanonicalAgent,
  AgentVersion,
  Tenant,
  AccessScope,
  TenantMembership,
  SourceObservation,
  Artifact,
  Distribution,
  ExternalAlias,
  SourceSpan,
  AnalysisRun,
  AnalysisStageRun,
  OntologyVersion,
  OntologyConcept,
  VersionRegistryEntry,
  StaticFinding,
  CallGraphNode,
  CallGraphEdge,
  TaintFlow,
  SbomComponent,
  SbomDependency,
  RuntimeEvent,
  ExternalIntelligenceRef,
  Evidence,
  Assertion,
  AssertionEvidenceLink,
  Claim,
  ClaimEvidenceLink,
  ClaimSupportLink,
  Contradiction,
  Risk,
  ScoreModel,
  ScoreDimension,
  ScoreResult,
  ScoreDimensionValue,
  PolicyVersion,
  PolicyRule,
  PolicyDecision,
  PolicyDecisionReason,
  Recommendation,
  UseCase,
  UseCaseEvaluation,
  LineageEdge,
  BackwardLineageNode,
  KnowledgeObject,
  KnowledgeProjection,
  KnowledgeChunk,
  Embedding,
  IndexState,
  QuerySession,
  Query,
  QueryPlan,
  RetrievalRun,
  RetrievalResult,
  ContextPackage,
  Answer,
  AnswerClaim,
  Citation,
  GroundingResult,
  VersionDiff,
  DiffItem,
  ModificationWorkspace,
  ModificationChange,
  Approval,
  ImpactAssessment,
  ImpactItem,
  ValidationRun,
  ValidationResult,
  Package,
  PackageContent,
  Attestation,
  Signature,
  Shipment,
  WorkflowDefinition,
  WorkflowRun,
  Job,
  JobAttempt,
  DeadLetterJob,
  LifecycleStateTransition,
  OutboxEvent,
  OutboxDelivery,
  AuditEvent,
  EvaluationDataset,
  EvaluationCase,
  EvaluationRun,
  EvaluationResult,
  GoldenCorpusItem,
  CostUsageEvent,
  Role,
  UserRole,
  AccessGrant,
  SecurityClassification,
  TelemetryRecord,
  CreateStaticFindingInput,
  CreateRuntimeEventInput,
  CreateEvidenceInput,
  CreateClaimInput,
  CreateAnswerClaimInput,
  CreateTelemetryRecordInput,
} from './types.js';
import {
  AnalysisPersistenceCoordinator,
  type PersistAnalysisBundleInput,
  type PersistAnalysisResult,
} from './analysis-persistence.js';

export interface ICanonicalAgentRepository {
  createAgent(agent: Omit<CanonicalAgent, 'created_at' | 'updated_at'>): Promise<CanonicalAgent>;
  getAgentById(agentId: string): Promise<CanonicalAgent | null>;
  findAgentByName(canonicalName: string): Promise<CanonicalAgent | null>;
  createAgentVersion(version: Omit<AgentVersion, 'created_at' | 'observed_at'>): Promise<AgentVersion>;
  getAgentVersions(agentId: string): Promise<AgentVersion[]>;
}

export interface ISecurityTenantRepository {
  createTenant(tenant: Omit<Tenant, 'created_at' | 'updated_at'>): Promise<Tenant>;
  getTenantById(tenantId: string): Promise<Tenant | null>;
  createAccessScope(scope: Omit<AccessScope, 'created_at'>): Promise<AccessScope>;
  getPlatformScope(): Promise<AccessScope | null>;
  getTenantScope(tenantId: string): Promise<AccessScope | null>;
  createMembership(membership: Omit<TenantMembership, 'joined_at'>): Promise<TenantMembership>;
  createRole(role: Omit<Role, 'created_at'>): Promise<Role>;
  getRoleByKey(roleKey: string): Promise<Role | null>;
  getAllRoles(): Promise<Role[]>;
  assignUserRole(userRole: Omit<UserRole, 'granted_at' | 'revoked_at'>): Promise<UserRole>;
  getUserRoles(principalId: string): Promise<UserRole[]>;
  revokeUserRole(principalId: string, roleId: string): Promise<boolean>;
  createAccessGrant(grant: Omit<AccessGrant, 'granted_at' | 'revoked_at'>): Promise<AccessGrant>;
  getAccessGrantsForPrincipal(principalId: string): Promise<AccessGrant[]>;
  getClassifications(): Promise<SecurityClassification[]>;
}

export interface ISourceObservationRepository {
  createObservation(obs: Omit<SourceObservation, 'created_at' | 'observed_at'>): Promise<SourceObservation>;
  createArtifact(artifact: Omit<Artifact, 'created_at'>): Promise<Artifact>;
  createDistribution(distribution: Omit<Distribution, 'created_at'>): Promise<Distribution>;
  createExternalAlias(alias: Omit<ExternalAlias, 'created_at' | 'observed_at'>): Promise<ExternalAlias>;
  createSourceSpan(span: Omit<SourceSpan, 'created_at'>): Promise<SourceSpan>;
}

export interface IAnalysisRunRepository {
  createAnalysisRun(run: Omit<AnalysisRun, 'created_at' | 'started_at'>): Promise<AnalysisRun>;
  getAnalysisRunById(analysisRunId: string): Promise<AnalysisRun | null>;
  getAnalysisRunsByAgentVersion(agentVersionId: string): Promise<AnalysisRun[]>;
  updateAnalysisRunStatus(analysisRunId: string, status: string, completedAt?: string): Promise<AnalysisRun>;
  createStageRun(stage: Omit<AnalysisStageRun, 'created_at' | 'started_at'>): Promise<AnalysisStageRun>;
  getStageRuns(analysisRunId: string): Promise<AnalysisStageRun[]>;
  
  // Findings & Graph
  createStaticFinding(finding: CreateStaticFindingInput): Promise<StaticFinding>;
  getStaticFindings(analysisRunId: string): Promise<StaticFinding[]>;
  createCallGraphNode(node: Omit<CallGraphNode, 'created_at'>): Promise<CallGraphNode>;
  createCallGraphEdge(edge: Omit<CallGraphEdge, 'created_at'>): Promise<CallGraphEdge>;
  getCallGraph(analysisRunId: string): Promise<{ nodes: CallGraphNode[]; edges: CallGraphEdge[] }>;
  createTaintFlow(flow: Omit<TaintFlow, 'created_at'>): Promise<TaintFlow>;
  getTaintFlows(analysisRunId: string): Promise<TaintFlow[]>;
  createSbomComponent(component: Omit<SbomComponent, 'created_at'>): Promise<SbomComponent>;
  createSbomDependency(dep: Omit<SbomDependency, 'created_at'>): Promise<SbomDependency>;
  getSbom(analysisRunId: string): Promise<{ components: SbomComponent[]; dependencies: SbomDependency[] }>;
  createRuntimeEvent(event: CreateRuntimeEventInput): Promise<RuntimeEvent>;
  getRuntimeEvents(analysisRunId: string): Promise<RuntimeEvent[]>;
  persistAnalysisBundle(bundle: PersistAnalysisBundleInput): Promise<PersistAnalysisResult>;
}

export interface IIntelRepository {
  createExternalIntelRef(ref: Omit<ExternalIntelligenceRef, 'created_at'>): Promise<ExternalIntelligenceRef>;
  getExternalIntelRef(sourceName: string, externalId: string): Promise<ExternalIntelligenceRef | null>;
  
  createEvidence(evidence: CreateEvidenceInput): Promise<Evidence>;
  getEvidenceById(evidenceId: string): Promise<Evidence | null>;
  getEvidenceForRun(analysisRunId: string): Promise<Evidence[]>;
  
  createAssertion(assertion: Omit<Assertion, 'created_at'>): Promise<Assertion>;
  getAssertionById(assertionId: string): Promise<Assertion | null>;
  getAssertionsForRun(analysisRunId: string): Promise<Assertion[]>;
  linkAssertionEvidence(link: Omit<AssertionEvidenceLink, 'created_at'>): Promise<AssertionEvidenceLink>;
  getEvidenceForAssertion(assertionId: string): Promise<Evidence[]>;
  
  createClaim(claim: CreateClaimInput): Promise<Claim>;
  getClaimById(claimId: string): Promise<Claim | null>;
  getClaimsForRun(analysisRunId: string): Promise<Claim[]>;
  linkClaimEvidence(link: Omit<ClaimEvidenceLink, 'created_at'>): Promise<ClaimEvidenceLink>;
  linkClaimAssertion(link: Omit<ClaimSupportLink, 'created_at'>): Promise<ClaimSupportLink>;
  
  createContradiction(contradiction: Omit<Contradiction, 'created_at'>): Promise<Contradiction>;
  getContradictionsForRun(analysisRunId: string): Promise<Contradiction[]>;
}

export interface IScoringAndPolicyRepository {
  createRisk(risk: Omit<Risk, 'created_at'>): Promise<Risk>;
  getRisksForRun(analysisRunId: string): Promise<Risk[]>;
  
  createScoreModel(model: Omit<ScoreModel, 'created_at'>): Promise<ScoreModel>;
  createScoreDimension(dimension: Omit<ScoreDimension, 'created_at'>): Promise<ScoreDimension>;
  createScoreResult(result: Omit<ScoreResult, 'created_at'>): Promise<ScoreResult>;
  createScoreDimensionValue(value: Omit<ScoreDimensionValue, 'created_at'>): Promise<ScoreDimensionValue>;
  getScoreResult(analysisRunId: string, scoreModelId: string): Promise<ScoreResult | null>;
  
  createPolicyVersion(policy: Omit<PolicyVersion, 'created_at'>): Promise<PolicyVersion>;
  createPolicyRule(rule: Omit<PolicyRule, 'created_at'>): Promise<PolicyRule>;
  createPolicyDecision(decision: Omit<PolicyDecision, 'created_at'>): Promise<PolicyDecision>;
  createPolicyDecisionReason(reason: Omit<PolicyDecisionReason, 'created_at'>): Promise<PolicyDecisionReason>;
  getPolicyDecision(analysisRunId: string, policyVersionId: string): Promise<PolicyDecision | null>;
  
  createRecommendation(rec: Omit<Recommendation, 'created_at'>): Promise<Recommendation>;
  getRecommendationsForRun(analysisRunId: string): Promise<Recommendation[]>;
  
  createUseCase(useCase: Omit<UseCase, 'created_at'>): Promise<UseCase>;
  createUseCaseEvaluation(evaluation: Omit<UseCaseEvaluation, 'created_at'>): Promise<UseCaseEvaluation>;
  getUseCaseEvaluationsForRun(analysisRunId: string): Promise<UseCaseEvaluation[]>;
}

export interface ILineageRepository {
  createLineageEdge(edge: Omit<LineageEdge, 'created_at'>): Promise<LineageEdge>;
  getLineageEdgesForRun(analysisRunId: string): Promise<LineageEdge[]>;
  resolveBackwardLineage(claimId: string): Promise<BackwardLineageNode | null>;
}

export interface IOntologyRepository {
  getOntologyVersion(versionLabel: string): Promise<OntologyVersion | null>;
  listConcepts(versionId: string): Promise<OntologyConcept[]>;
  createConcept(concept: Omit<OntologyConcept, 'created_at'>): Promise<OntologyConcept>;
}

export interface IVersionRegistryRepository {
  getActiveVersion(artifactType: string, artifactKey: string): Promise<VersionRegistryEntry | null>;
  registerVersion(entry: Omit<VersionRegistryEntry, 'created_at'>): Promise<VersionRegistryEntry>;
}

export interface IKnowledgeRepository {
  createKnowledgeObject(obj: Omit<KnowledgeObject, 'created_at' | 'updated_at'>): Promise<KnowledgeObject>;
  getKnowledgeObject(id: string): Promise<KnowledgeObject | null>;
  getKnowledgeObjectsForRun(analysisRunId: string): Promise<KnowledgeObject[]>;
  createKnowledgeProjection(proj: Omit<KnowledgeProjection, 'created_at'>): Promise<KnowledgeProjection>;
  createKnowledgeChunk(chunk: Omit<KnowledgeChunk, 'created_at'>): Promise<KnowledgeChunk>;
  createEmbedding(emb: Omit<Embedding, 'created_at'>): Promise<Embedding>;
  createIndexState(state: Omit<IndexState, 'last_indexed_at'>): Promise<IndexState>;
  createQuerySession(session: Omit<QuerySession, 'created_at' | 'started_at'>): Promise<QuerySession>;
  createQuery(query: Omit<Query, 'created_at' | 'received_at'>): Promise<Query>;
  createQueryPlan(plan: Omit<QueryPlan, 'created_at'>): Promise<QueryPlan>;
  createRetrievalRun(run: Omit<RetrievalRun, 'created_at' | 'started_at'>): Promise<RetrievalRun>;
  createRetrievalResult(res: RetrievalResult): Promise<RetrievalResult>;
  createContextPackage(pkg: Omit<ContextPackage, 'created_at'>): Promise<ContextPackage>;
  createAnswer(ans: Omit<Answer, 'created_at'>): Promise<Answer>;
  createAnswerClaim(claim: CreateAnswerClaimInput): Promise<AnswerClaim>;
  createCitation(citation: Citation): Promise<Citation>;
  createGroundingResult(res: Omit<GroundingResult, 'created_at'>): Promise<GroundingResult>;
  purgeDerivativeKnowledge(entityRefId: string): Promise<{ deletedObjects: number }>;
}

export interface ILifecycleRepository {
  createVersionDiff(diff: Omit<VersionDiff, 'created_at'>): Promise<VersionDiff>;
  createDiffItem(item: Omit<DiffItem, 'created_at'>): Promise<DiffItem>;
  createModificationWorkspace(ws: Omit<ModificationWorkspace, 'created_at'>): Promise<ModificationWorkspace>;
  createModificationChange(change: Omit<ModificationChange, 'created_at'>): Promise<ModificationChange>;
  createApproval(approval: Omit<Approval, 'decided_at'>): Promise<Approval>;
  createImpactAssessment(ia: Omit<ImpactAssessment, 'created_at'>): Promise<ImpactAssessment>;
  createImpactItem(item: ImpactItem): Promise<ImpactItem>;
  createValidationRun(run: Omit<ValidationRun, 'created_at' | 'started_at'>): Promise<ValidationRun>;
  getValidationRun(id: string): Promise<ValidationRun | null>;
  createValidationResult(res: Omit<ValidationResult, 'created_at'>): Promise<ValidationResult>;
  createPackage(pkg: Omit<Package, 'created_at'>): Promise<Package>;
  createPackageContent(content: PackageContent): Promise<PackageContent>;
  createAttestation(att: Omit<Attestation, 'created_at'>): Promise<Attestation>;
  createSignature(sig: Omit<Signature, 'signed_at'>): Promise<Signature>;
  createShipment(shipment: Omit<Shipment, 'created_at'>): Promise<Shipment>;
}

export interface IOperationsRepository {
  createWorkflowDefinition(def: Omit<WorkflowDefinition, 'created_at'>): Promise<WorkflowDefinition>;
  createWorkflowRun(run: Omit<WorkflowRun, 'created_at' | 'started_at'>): Promise<WorkflowRun>;
  createJob(job: Omit<Job, 'created_at'>): Promise<Job>;
  createJobAttempt(att: Omit<JobAttempt, 'created_at'>): Promise<JobAttempt>;
  createDeadLetterJob(dlj: Omit<DeadLetterJob, 'dead_lettered_at'>): Promise<DeadLetterJob>;
  recordStateTransition(tr: Omit<LifecycleStateTransition, 'occurred_at'>): Promise<LifecycleStateTransition>;
  createOutboxEvent(event: Omit<OutboxEvent, 'occurred_at'>): Promise<OutboxEvent>;
  createOutboxDelivery(delivery: OutboxDelivery): Promise<OutboxDelivery>;
  createAuditEvent(event: Omit<AuditEvent, 'occurred_at'>): Promise<AuditEvent>;
  getAuditEvents(targetEntityRefId?: string): Promise<AuditEvent[]>;
  createEvaluationDataset(ds: Omit<EvaluationDataset, 'created_at'>): Promise<EvaluationDataset>;
  createEvaluationCase(ec: Omit<EvaluationCase, 'created_at'>): Promise<EvaluationCase>;
  createEvaluationRun(run: Omit<EvaluationRun, 'created_at' | 'started_at'>): Promise<EvaluationRun>;
  createEvaluationResult(res: Omit<EvaluationResult, 'created_at'>): Promise<EvaluationResult>;
  createGoldenCorpusItem(item: Omit<GoldenCorpusItem, 'created_at'>): Promise<GoldenCorpusItem>;
  recordCostUsageEvent(event: Omit<CostUsageEvent, 'occurred_at'>): Promise<CostUsageEvent>;
  createTelemetryRecord(record: CreateTelemetryRecordInput): Promise<TelemetryRecord>;
  getTelemetryRecords(sourceId?: string): Promise<TelemetryRecord[]>;
}

/**
 * In-memory adapter backed by pg-mem instance for fast, faithful unit & migration testing
 */
export class PgMemDbRepositories implements 
  ICanonicalAgentRepository, 
  ISecurityTenantRepository, 
  ISourceObservationRepository, 
  IAnalysisRunRepository, 
  IIntelRepository,
  IScoringAndPolicyRepository,
  ILineageRepository,
  IOntologyRepository, 
  IVersionRegistryRepository,
  IKnowledgeRepository,
  ILifecycleRepository,
  IOperationsRepository
{
  private readonly client: any;

  constructor(db: any) {
    if (db && typeof db.query === 'function') {
      this.client = db;
    } else if (db && db.adapters && typeof db.adapters.createPg === 'function') {
      const pgAdapter = db.adapters.createPg();
      this.client = pgAdapter.Pool ? new pgAdapter.Pool() : pgAdapter;
    } else {
      this.client = db;
    }
  }

  // --- Canonical Agent Repository ---
  async createAgent(agent: Omit<CanonicalAgent, 'created_at' | 'updated_at'>): Promise<CanonicalAgent> {
    const res = await this.client.query(`
      INSERT INTO core.canonical_agents (agent_id, canonical_name, agent_type_concept_id, status, identity_confidence)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [agent.agent_id, agent.canonical_name, agent.agent_type_concept_id || null, agent.status || 'ACTIVE', agent.identity_confidence ?? 1.0]);
    return res.rows[0] as CanonicalAgent;
  }

  async getAgentById(agentId: string): Promise<CanonicalAgent | null> {
    const res = await this.client.query(`
      SELECT * FROM core.canonical_agents WHERE agent_id = $1;
    `, [agentId]);
    return res.rows.length ? (res.rows[0] as CanonicalAgent) : null;
  }

  async findAgentByName(canonicalName: string): Promise<CanonicalAgent | null> {
    const res = await this.client.query(`
      SELECT * FROM core.canonical_agents WHERE lower(canonical_name) = lower($1) AND status = 'ACTIVE';
    `, [canonicalName]);
    return res.rows.length ? (res.rows[0] as CanonicalAgent) : null;
  }

  async createAgentVersion(version: Omit<AgentVersion, 'created_at' | 'observed_at'>): Promise<AgentVersion> {
    const res = await this.client.query(`
      INSERT INTO core.agent_versions (agent_version_id, agent_id, version_label, source_commit, content_fingerprint, release_date, supersedes_version_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      version.agent_version_id,
      version.agent_id,
      version.version_label || null,
      version.source_commit || null,
      version.content_fingerprint,
      version.release_date || null,
      version.supersedes_version_id || null,
    ]);
    return res.rows[0] as AgentVersion;
  }

  async getAgentVersions(agentId: string): Promise<AgentVersion[]> {
    const res = await this.client.query(`
      SELECT * FROM core.agent_versions WHERE agent_id = $1 ORDER BY observed_at DESC;
    `, [agentId]);
    return res.rows as AgentVersion[];
  }

  // --- Security & Tenant Repository ---
  async createTenant(tenant: Omit<Tenant, 'created_at' | 'updated_at'>): Promise<Tenant> {
    const res = await this.client.query(`
      INSERT INTO security.tenants (tenant_id, tenant_key, display_name, status)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [tenant.tenant_id, tenant.tenant_key, tenant.display_name, tenant.status || 'ACTIVE']);
    return res.rows[0] as Tenant;
  }

  async getTenantById(tenantId: string): Promise<Tenant | null> {
    const res = await this.client.query(`
      SELECT * FROM security.tenants WHERE tenant_id = $1;
    `, [tenantId]);
    return res.rows.length ? (res.rows[0] as Tenant) : null;
  }

  async createAccessScope(scope: Omit<AccessScope, 'created_at'>): Promise<AccessScope> {
    const res = await this.client.query(`
      INSERT INTO security.access_scopes (scope_id, scope_type, tenant_id)
      VALUES ($1, $2, $3)
      RETURNING *;
    `, [scope.scope_id, scope.scope_type, scope.tenant_id || null]);
    return res.rows[0] as AccessScope;
  }

  async getPlatformScope(): Promise<AccessScope | null> {
    const res = await this.client.query(`
      SELECT * FROM security.access_scopes WHERE scope_type = 'PLATFORM';
    `);
    return res.rows.length ? (res.rows[0] as AccessScope) : null;
  }

  async getTenantScope(tenantId: string): Promise<AccessScope | null> {
    const res = await this.client.query(`
      SELECT * FROM security.access_scopes WHERE scope_type = 'ORGANIZATION' AND tenant_id = $1;
    `, [tenantId]);
    return res.rows.length ? (res.rows[0] as AccessScope) : null;
  }

  async createMembership(membership: Omit<TenantMembership, 'joined_at'>): Promise<TenantMembership> {
    const res = await this.client.query(`
      INSERT INTO security.tenant_memberships (tenant_membership_id, tenant_id, principal_id, role_id, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [membership.tenant_membership_id, membership.tenant_id, membership.principal_id, membership.role_id, membership.status || 'ACTIVE']);
    return res.rows[0] as TenantMembership;
  }

  async createRole(role: Omit<Role, 'created_at'>): Promise<Role> {
    const res = await this.client.query(`
      INSERT INTO security.roles (role_id, role_key, description, status)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [role.role_id, role.role_key, role.description, role.status || 'ACTIVE']);
    return res.rows[0] as Role;
  }

  async getRoleByKey(roleKey: string): Promise<Role | null> {
    const res = await this.client.query(`
      SELECT * FROM security.roles WHERE role_key = $1;
    `, [roleKey]);
    return res.rows.length ? (res.rows[0] as Role) : null;
  }

  async getAllRoles(): Promise<Role[]> {
    const res = await this.client.query(`
      SELECT * FROM security.roles ORDER BY role_key ASC;
    `);
    return res.rows as Role[];
  }

  async assignUserRole(userRole: Omit<UserRole, 'granted_at' | 'revoked_at'>): Promise<UserRole> {
    const res = await this.client.query(`
      INSERT INTO security.user_roles (user_role_id, principal_id, role_id, granted_by)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [userRole.user_role_id, userRole.principal_id, userRole.role_id, userRole.granted_by]);
    return res.rows[0] as UserRole;
  }

  async getUserRoles(principalId: string): Promise<UserRole[]> {
    const res = await this.client.query(`
      SELECT * FROM security.user_roles WHERE principal_id = $1 AND revoked_at IS NULL;
    `, [principalId]);
    return res.rows as UserRole[];
  }

  async revokeUserRole(principalId: string, roleId: string): Promise<boolean> {
    const res = await this.client.query(`
      UPDATE security.user_roles SET revoked_at = now() WHERE principal_id = $1 AND role_id = $2;
    `, [principalId, roleId]);
    return res.rowCount > 0;
  }

  async createAccessGrant(grant: Omit<AccessGrant, 'granted_at' | 'revoked_at'>): Promise<AccessGrant> {
    const res = await this.client.query(`
      INSERT INTO security.access_grants (access_grant_id, principal_id, grant_type, target_scope, granted_by, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [grant.access_grant_id, grant.principal_id, grant.grant_type, grant.target_scope || null, grant.granted_by, grant.expires_at || null]);
    return res.rows[0] as AccessGrant;
  }

  async getAccessGrantsForPrincipal(principalId: string): Promise<AccessGrant[]> {
    const res = await this.client.query(`
      SELECT * FROM security.access_grants WHERE principal_id = $1 AND revoked_at IS NULL;
    `, [principalId]);
    return res.rows as AccessGrant[];
  }

  async getClassifications(): Promise<SecurityClassification[]> {
    const res = await this.client.query(`
      SELECT * FROM security.security_classifications ORDER BY rank ASC;
    `);
    return res.rows as SecurityClassification[];
  }

  // --- Source Observation Repository ---
  async createObservation(obs: Omit<SourceObservation, 'created_at' | 'observed_at'>): Promise<SourceObservation> {
    const res = await this.client.query(`
      INSERT INTO source.source_observations (source_observation_id, candidate_id, source_adapter_id, source_locator, raw_metadata_locator, content_hash, scope_id, security_classification_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      obs.source_observation_id,
      obs.candidate_id || null,
      obs.source_adapter_id,
      obs.source_locator,
      obs.raw_metadata_locator || null,
      obs.content_hash || null,
      obs.scope_id,
      obs.security_classification_id,
    ]);
    return res.rows[0] as SourceObservation;
  }

  async createArtifact(artifact: Omit<Artifact, 'created_at'>): Promise<Artifact> {
    const res = await this.client.query(`
      INSERT INTO source.artifacts (artifact_id, agent_version_id, distribution_id, source_observation_id, artifact_type_concept_id, content_hash, storage_locator, size_bytes, security_classification_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      artifact.artifact_id,
      artifact.agent_version_id || null,
      artifact.distribution_id || null,
      artifact.source_observation_id,
      artifact.artifact_type_concept_id || null,
      artifact.content_hash,
      artifact.storage_locator,
      artifact.size_bytes || null,
      artifact.security_classification_id,
    ]);
    return res.rows[0] as Artifact;
  }

  async createDistribution(dist: Omit<Distribution, 'created_at'>): Promise<Distribution> {
    const res = await this.client.query(`
      INSERT INTO core.distributions (distribution_id, agent_version_id, distribution_type_concept_id, ecosystem, locator, version, publisher_id, source_observation_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      dist.distribution_id,
      dist.agent_version_id,
      dist.distribution_type_concept_id || null,
      dist.ecosystem || null,
      dist.locator,
      dist.version || null,
      dist.publisher_id || null,
      dist.source_observation_id,
    ]);
    return res.rows[0] as Distribution;
  }

  async createExternalAlias(alias: Omit<ExternalAlias, 'created_at' | 'observed_at'>): Promise<ExternalAlias> {
    const res = await this.client.query(`
      INSERT INTO core.external_aliases (external_alias_id, entity_ref_id, source_adapter_id, alias_type, alias_value, confidence)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      alias.external_alias_id,
      alias.entity_ref_id,
      alias.source_adapter_id || null,
      alias.alias_type,
      alias.alias_value,
      alias.confidence ?? 1.0,
    ]);
    return res.rows[0] as ExternalAlias;
  }

  async createSourceSpan(span: Omit<SourceSpan, 'created_at'>): Promise<SourceSpan> {
    const res = await this.client.query(`
      INSERT INTO source.source_spans (source_span_id, artifact_file_id, start_line, start_col, end_line, end_col, byte_offset_start, byte_offset_end, symbol_hint)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      span.source_span_id,
      span.artifact_file_id,
      span.start_line,
      span.start_col,
      span.end_line,
      span.end_col,
      span.byte_offset_start || null,
      span.byte_offset_end || null,
      span.symbol_hint || null,
    ]);
    return res.rows[0] as SourceSpan;
  }

  // --- Analysis Run Repository ---
  async createAnalysisRun(run: Omit<AnalysisRun, 'created_at' | 'started_at'>): Promise<AnalysisRun> {
    const res = await this.client.query(`
      INSERT INTO analysis.analysis_runs (analysis_run_id, agent_version_id, scope_id, pipeline_version, caim_version, ontology_version, trigger_type, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      run.analysis_run_id,
      run.agent_version_id,
      run.scope_id,
      run.pipeline_version,
      run.caim_version,
      run.ontology_version,
      run.trigger_type,
      run.status || 'PENDING',
    ]);
    return res.rows[0] as AnalysisRun;
  }

  async getAnalysisRunById(analysisRunId: string): Promise<AnalysisRun | null> {
    const res = await this.client.query(`
      SELECT * FROM analysis.analysis_runs WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows.length ? (res.rows[0] as AnalysisRun) : null;
  }

  async getAnalysisRunsByAgentVersion(agentVersionId: string): Promise<AnalysisRun[]> {
    const res = await this.client.query(`
      SELECT * FROM analysis.analysis_runs WHERE agent_version_id = $1 ORDER BY started_at DESC;
    `, [agentVersionId]);
    return res.rows as AnalysisRun[];
  }

  async updateAnalysisRunStatus(analysisRunId: string, status: string, completedAt?: string): Promise<AnalysisRun> {
    if (status === 'COMPLETED') {
      await AnalysisPersistenceCoordinator.assertMandatoryDurableRecordsExist(this.client, analysisRunId);
    }
    const res = await this.client.query(`
      UPDATE analysis.analysis_runs 
      SET status = $2, completed_at = $3
      WHERE analysis_run_id = $1
      RETURNING *;
    `, [analysisRunId, status, completedAt || null]);
    return res.rows[0] as AnalysisRun;
  }

  async persistAnalysisBundle(bundle: PersistAnalysisBundleInput): Promise<PersistAnalysisResult> {
    return AnalysisPersistenceCoordinator.persistAnalysisTransactionally(this.client, bundle);
  }

  async createStageRun(stage: Omit<AnalysisStageRun, 'created_at' | 'started_at'>): Promise<AnalysisStageRun> {
    const res = await this.client.query(`
      INSERT INTO analysis.analysis_stage_runs (stage_run_id, analysis_run_id, engine_key, engine_version, ruleset_version, model_version, input_snapshot_hash, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      stage.stage_run_id,
      stage.analysis_run_id,
      stage.engine_key,
      stage.engine_version,
      stage.ruleset_version || null,
      stage.model_version || null,
      stage.input_snapshot_hash || null,
      stage.status || 'PENDING',
    ]);
    return res.rows[0] as AnalysisStageRun;
  }

  async getStageRuns(analysisRunId: string): Promise<AnalysisStageRun[]> {
    const res = await this.client.query(`
      SELECT * FROM analysis.analysis_stage_runs WHERE analysis_run_id = $1 ORDER BY started_at ASC;
    `, [analysisRunId]);
    return res.rows as AnalysisStageRun[];
  }

  async createStaticFinding(finding: CreateStaticFindingInput): Promise<StaticFinding> {
    const truthState = (finding as any).truthState ?? (finding as any).truth_state ?? null;
    const sourceId = (finding as any).sourceId ?? (finding as any).source_id ?? finding.rule_id ?? finding.analysis_run_id;
    const evidenceId = (finding as any).evidenceId ?? (finding as any).evidence_id ?? null;
    const analyzerVersion = (finding as any).analyzerVersion ?? (finding as any).analyzer_version ?? '2.0.1';
    const observedAt = (finding as any).observedAt ?? (finding as any).observed_at ?? new Date().toISOString();
    const limitations = (finding as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO analysis.static_findings (
        finding_id, analysis_run_id, stage_run_id, entity_ref_id, source_span_id, rule_id, finding_type, severity, confidence, message, location_hint, raw_payload,
        truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *;
    `, [
      finding.finding_id,
      finding.analysis_run_id,
      finding.stage_run_id || null,
      finding.entity_ref_id || null,
      finding.source_span_id || null,
      finding.rule_id,
      finding.finding_type,
      finding.severity,
      finding.confidence ?? 1.0,
      finding.message,
      finding.location_hint || null,
      finding.raw_payload ? JSON.stringify(finding.raw_payload) : null,
      truthState,
      sourceId,
      evidenceId,
      analyzerVersion,
      observedAt,
      limitations,
    ]);
    return res.rows[0] as StaticFinding;
  }

  async getStaticFindings(analysisRunId: string): Promise<StaticFinding[]> {
    const res = await this.client.query(`
      SELECT * FROM analysis.static_findings WHERE analysis_run_id = $1 ORDER BY created_at ASC;
    `, [analysisRunId]);
    return res.rows as StaticFinding[];
  }

  async createCallGraphNode(node: Omit<CallGraphNode, 'created_at'>): Promise<CallGraphNode> {
    const res = await this.client.query(`
      INSERT INTO analysis.callgraph_nodes (node_id, analysis_run_id, stage_run_id, source_span_id, symbol_name, node_type, qualified_name, properties)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      node.node_id,
      node.analysis_run_id,
      node.stage_run_id || null,
      node.source_span_id || null,
      node.symbol_name,
      node.node_type,
      node.qualified_name,
      node.properties ? JSON.stringify(node.properties) : null,
    ]);
    return res.rows[0] as CallGraphNode;
  }

  async createCallGraphEdge(edge: Omit<CallGraphEdge, 'created_at'>): Promise<CallGraphEdge> {
    const res = await this.client.query(`
      INSERT INTO analysis.callgraph_edges (edge_id, analysis_run_id, caller_node_id, callee_node_id, call_type, call_site_span_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      edge.edge_id,
      edge.analysis_run_id,
      edge.caller_node_id,
      edge.callee_node_id,
      edge.call_type || 'DIRECT',
      edge.call_site_span_id || null,
    ]);
    return res.rows[0] as CallGraphEdge;
  }

  async getCallGraph(analysisRunId: string): Promise<{ nodes: CallGraphNode[]; edges: CallGraphEdge[] }> {
    const nodeRes = await this.client.query(`
      SELECT * FROM analysis.callgraph_nodes WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    const edgeRes = await this.client.query(`
      SELECT * FROM analysis.callgraph_edges WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return { nodes: nodeRes.rows as CallGraphNode[], edges: edgeRes.rows as CallGraphEdge[] };
  }

  async createTaintFlow(flow: Omit<TaintFlow, 'created_at'>): Promise<TaintFlow> {
    const res = await this.client.query(`
      INSERT INTO analysis.taint_flows (taint_flow_id, analysis_run_id, stage_run_id, source_span_id, sink_span_id, source_type, sink_type, sanitizer_type, confidence, path_summary)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *;
    `, [
      flow.taint_flow_id,
      flow.analysis_run_id,
      flow.stage_run_id || null,
      flow.source_span_id || null,
      flow.sink_span_id || null,
      flow.source_type,
      flow.sink_type,
      flow.sanitizer_type || null,
      flow.confidence ?? 1.0,
      flow.path_summary,
    ]);
    return res.rows[0] as TaintFlow;
  }

  async getTaintFlows(analysisRunId: string): Promise<TaintFlow[]> {
    const res = await this.client.query(`
      SELECT * FROM analysis.taint_flows WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as TaintFlow[];
  }

  async createSbomComponent(component: Omit<SbomComponent, 'created_at'>): Promise<SbomComponent> {
    const res = await this.client.query(`
      INSERT INTO analysis.sbom_components (sbom_component_id, analysis_run_id, stage_run_id, purl, name, version, ecosystem, license_expression)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      component.sbom_component_id,
      component.analysis_run_id,
      component.stage_run_id || null,
      component.purl || null,
      component.name,
      component.version,
      component.ecosystem,
      component.license_expression || null,
    ]);
    return res.rows[0] as SbomComponent;
  }

  async createSbomDependency(dep: Omit<SbomDependency, 'created_at'>): Promise<SbomDependency> {
    const res = await this.client.query(`
      INSERT INTO analysis.sbom_dependencies (sbom_dependency_id, analysis_run_id, parent_component_id, child_component_id, dependency_scope)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      dep.sbom_dependency_id,
      dep.analysis_run_id,
      dep.parent_component_id,
      dep.child_component_id,
      dep.dependency_scope || 'RUNTIME',
    ]);
    return res.rows[0] as SbomDependency;
  }

  async getSbom(analysisRunId: string): Promise<{ components: SbomComponent[]; dependencies: SbomDependency[] }> {
    const compRes = await this.client.query(`
      SELECT * FROM analysis.sbom_components WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    const depRes = await this.client.query(`
      SELECT * FROM analysis.sbom_dependencies WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return { components: compRes.rows as SbomComponent[], dependencies: depRes.rows as SbomDependency[] };
  }

  async createRuntimeEvent(event: CreateRuntimeEventInput): Promise<RuntimeEvent> {
    const truthState = (event as any).truthState ?? (event as any).truth_state ?? null;
    const sourceId = (event as any).sourceId ?? (event as any).source_id ?? event.source_locator ?? event.analysis_run_id;
    const evidenceId = (event as any).evidenceId ?? (event as any).evidence_id ?? null;
    const analyzerVersion = (event as any).analyzerVersion ?? (event as any).analyzer_version ?? '2.0.1';
    const observedAt = (event as any).observedAt ?? (event as any).observed_at ?? event.event_timestamp ?? new Date().toISOString();
    const confidence = (event as any).confidence ?? 1.0;
    const limitations = (event as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO analysis.runtime_events (
        runtime_event_id, analysis_run_id, stage_run_id, entity_ref_id, event_type, event_timestamp, duration_ms, source_locator, payload, status,
        truth_state, source_id, evidence_id, analyzer_version, observed_at, confidence, limitations
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
      RETURNING *;
    `, [
      event.runtime_event_id,
      event.analysis_run_id,
      event.stage_run_id || null,
      event.entity_ref_id || null,
      event.event_type,
      event.event_timestamp || new Date().toISOString(),
      event.duration_ms || null,
      event.source_locator || null,
      event.payload ? JSON.stringify(event.payload) : null,
      event.status || 'RECORDED',
      truthState,
      sourceId,
      evidenceId,
      analyzerVersion,
      observedAt,
      confidence,
      limitations,
    ]);
    return res.rows[0] as RuntimeEvent;
  }

  async getRuntimeEvents(analysisRunId: string): Promise<RuntimeEvent[]> {
    const res = await this.client.query(`
      SELECT * FROM analysis.runtime_events WHERE analysis_run_id = $1 ORDER BY event_timestamp ASC;
    `, [analysisRunId]);
    return res.rows as RuntimeEvent[];
  }

  // --- Intel Repository ---
  async createExternalIntelRef(ref: Omit<ExternalIntelligenceRef, 'created_at'>): Promise<ExternalIntelligenceRef> {
    const res = await this.client.query(`
      INSERT INTO intel.external_intelligence_refs (intel_ref_id, source_name, external_id, title, url, severity, cvss_score, epss_score, published_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      ref.intel_ref_id,
      ref.source_name,
      ref.external_id,
      ref.title,
      ref.url || null,
      ref.severity || null,
      ref.cvss_score || null,
      ref.epss_score || null,
      ref.published_date || null,
    ]);
    return res.rows[0] as ExternalIntelligenceRef;
  }

  async getExternalIntelRef(sourceName: string, externalId: string): Promise<ExternalIntelligenceRef | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.external_intelligence_refs WHERE source_name = $1 AND external_id = $2;
    `, [sourceName, externalId]);
    return res.rows.length ? (res.rows[0] as ExternalIntelligenceRef) : null;
  }

  async createEvidence(evidence: CreateEvidenceInput): Promise<Evidence> {
    const truthState = (evidence as any).truthState ?? (evidence as any).truth_state ?? null;
    const sourceId = (evidence as any).sourceId ?? (evidence as any).source_id ?? evidence.source_observation_id ?? evidence.source_span_id ?? evidence.analysis_run_id;
    const analyzerVersion = (evidence as any).analyzerVersion ?? (evidence as any).analyzer_version ?? '2.0.1';
    const observedAt = (evidence as any).observedAt ?? (evidence as any).observed_at ?? new Date().toISOString();
    const limitations = (evidence as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO intel.evidence (
        evidence_id, analysis_run_id, stage_run_id, entity_ref_id, evidence_type, source_span_id, source_observation_id, artifact_id, static_finding_id, runtime_event_id, external_intel_ref_id, description, confidence, weight, scope_id,
        truth_state, source_id, analyzer_version, observed_at, limitations
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, COALESCE($15, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)), $16, $17, $18, $19, $20)
      RETURNING *;
    `, [
      evidence.evidence_id,
      evidence.analysis_run_id,
      evidence.stage_run_id || null,
      evidence.entity_ref_id || null,
      evidence.evidence_type,
      evidence.source_span_id || null,
      evidence.source_observation_id || null,
      evidence.artifact_id || null,
      evidence.static_finding_id || null,
      evidence.runtime_event_id || null,
      evidence.external_intel_ref_id || null,
      evidence.description,
      evidence.confidence ?? 1.0,
      evidence.weight ?? 1.0,
      evidence.scope_id || null,
      truthState,
      sourceId,
      analyzerVersion,
      observedAt,
      limitations,
    ]);
    return res.rows[0] as Evidence;
  }

  async getEvidenceById(evidenceId: string): Promise<Evidence | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.evidence WHERE evidence_id = $1;
    `, [evidenceId]);
    return res.rows.length ? (res.rows[0] as Evidence) : null;
  }

  async getEvidenceForRun(analysisRunId: string): Promise<Evidence[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.evidence WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as Evidence[];
  }

  async createAssertion(assertion: Omit<Assertion, 'created_at'>): Promise<Assertion> {
    const res = await this.client.query(`
      INSERT INTO intel.assertions (assertion_id, analysis_run_id, stage_run_id, entity_ref_id, assertion_key, concept_id, predicate, subject_ref_id, object_ref_id, assertion_value, confidence, uncertainty_score, uncertainty_factors, calibration_version, engine_key, rule_id, scope_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, COALESCE($17, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)))
      RETURNING *;
    `, [
      assertion.assertion_id,
      assertion.analysis_run_id,
      assertion.stage_run_id || null,
      assertion.entity_ref_id || null,
      assertion.assertion_key,
      assertion.concept_id || null,
      assertion.predicate,
      assertion.subject_ref_id,
      assertion.object_ref_id || null,
      assertion.assertion_value || null,
      assertion.confidence ?? 1.0,
      assertion.uncertainty_score ?? 0.0,
      assertion.uncertainty_factors ? JSON.stringify(assertion.uncertainty_factors) : null,
      assertion.calibration_version || null,
      assertion.engine_key,
      assertion.rule_id || null,
      assertion.scope_id || null,
    ]);
    return res.rows[0] as Assertion;
  }

  async getAssertionById(assertionId: string): Promise<Assertion | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.assertions WHERE assertion_id = $1;
    `, [assertionId]);
    return res.rows.length ? (res.rows[0] as Assertion) : null;
  }

  async getAssertionsForRun(analysisRunId: string): Promise<Assertion[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.assertions WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as Assertion[];
  }

  async linkAssertionEvidence(link: Omit<AssertionEvidenceLink, 'created_at'>): Promise<AssertionEvidenceLink> {
    const res = await this.client.query(`
      INSERT INTO intel.assertion_evidence_links (link_id, assertion_id, evidence_id, relationship_type, relevance_weight)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      link.link_id,
      link.assertion_id,
      link.evidence_id,
      link.relationship_type || 'SUPPORTS',
      link.relevance_weight ?? 1.0,
    ]);
    return res.rows[0] as AssertionEvidenceLink;
  }

  async getEvidenceForAssertion(assertionId: string): Promise<Evidence[]> {
    const res = await this.client.query(`
      SELECT e.* FROM intel.evidence e
      INNER JOIN intel.assertion_evidence_links l ON e.evidence_id = l.evidence_id
      WHERE l.assertion_id = $1;
    `, [assertionId]);
    return res.rows as Evidence[];
  }

  async createClaim(claim: CreateClaimInput): Promise<Claim> {
    const truthState = (claim as any).truthState ?? (claim as any).truth_state ?? null;
    const sourceId = (claim as any).sourceId ?? (claim as any).source_id ?? claim.analysis_run_id;
    const evidenceId = (claim as any).evidenceId ?? (claim as any).evidence_id ?? null;
    const analyzerVersion = (claim as any).analyzerVersion ?? (claim as any).analyzer_version ?? '2.0.1';
    const observedAt = (claim as any).observedAt ?? (claim as any).observed_at ?? new Date().toISOString();
    const limitations = (claim as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO intel.claims (
        claim_id, analysis_run_id, entity_ref_id, claim_type, claim_text, state, confidence, uncertainty_score, scope_id,
        truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, (SELECT scope_id FROM analysis.analysis_runs WHERE analysis_run_id = $2)), $10, $11, $12, $13, $14, $15)
      RETURNING *;
    `, [
      claim.claim_id,
      claim.analysis_run_id,
      claim.entity_ref_id || null,
      claim.claim_type,
      claim.claim_text,
      claim.state || 'SUPPORTED',
      claim.confidence ?? 1.0,
      claim.uncertainty_score ?? 0.0,
      claim.scope_id || null,
      truthState,
      sourceId,
      evidenceId,
      analyzerVersion,
      observedAt,
      limitations,
    ]);
    return res.rows[0] as Claim;
  }

  async getClaimById(claimId: string): Promise<Claim | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.claims WHERE claim_id = $1;
    `, [claimId]);
    return res.rows.length ? (res.rows[0] as Claim) : null;
  }

  async getClaimsForRun(analysisRunId: string): Promise<Claim[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.claims WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as Claim[];
  }

  async linkClaimEvidence(link: Omit<ClaimEvidenceLink, 'created_at'>): Promise<ClaimEvidenceLink> {
    const res = await this.client.query(`
      INSERT INTO intel.claim_evidence_links (link_id, claim_id, evidence_id, support_type, weight)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      link.link_id,
      link.claim_id,
      link.evidence_id,
      link.support_type || 'DIRECT_SUPPORT',
      link.weight ?? 1.0,
    ]);
    return res.rows[0] as ClaimEvidenceLink;
  }

  async linkClaimAssertion(link: Omit<ClaimSupportLink, 'created_at'>): Promise<ClaimSupportLink> {
    const res = await this.client.query(`
      INSERT INTO intel.claim_support_links (link_id, claim_id, assertion_id, link_type)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [
      link.link_id,
      link.claim_id,
      link.assertion_id,
      link.link_type || 'SUPPORTS',
    ]);
    return res.rows[0] as ClaimSupportLink;
  }

  async createContradiction(contradiction: Omit<Contradiction, 'created_at'>): Promise<Contradiction> {
    const res = await this.client.query(`
      INSERT INTO intel.contradictions (contradiction_id, analysis_run_id, claim_a_id, claim_b_id, assertion_a_id, assertion_b_id, conflict_reason, severity, resolution_status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      contradiction.contradiction_id,
      contradiction.analysis_run_id,
      contradiction.claim_a_id || null,
      contradiction.claim_b_id || null,
      contradiction.assertion_a_id || null,
      contradiction.assertion_b_id || null,
      contradiction.conflict_reason,
      contradiction.severity,
      contradiction.resolution_status || 'UNRESOLVED',
    ]);
    return res.rows[0] as Contradiction;
  }

  async getContradictionsForRun(analysisRunId: string): Promise<Contradiction[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.contradictions WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as Contradiction[];
  }

  // --- Scoring and Policy Repository ---
  async createRisk(risk: Omit<Risk, 'created_at'>): Promise<Risk> {
    const res = await this.client.query(`
      INSERT INTO intel.risks (risk_id, analysis_run_id, entity_ref_id, claim_id, risk_type, title, description, severity, likelihood, impact, risk_score, remediation_guidance)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `, [
      risk.risk_id,
      risk.analysis_run_id,
      risk.entity_ref_id || null,
      risk.claim_id || null,
      risk.risk_type,
      risk.title,
      risk.description,
      risk.severity,
      risk.likelihood ?? 1.0,
      risk.impact ?? 1.0,
      risk.risk_score ?? 0.0,
      risk.remediation_guidance || null,
    ]);
    return res.rows[0] as Risk;
  }

  async getRisksForRun(analysisRunId: string): Promise<Risk[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.risks WHERE analysis_run_id = $1 ORDER BY severity DESC;
    `, [analysisRunId]);
    return res.rows as Risk[];
  }

  async createScoreModel(model: Omit<ScoreModel, 'created_at'>): Promise<ScoreModel> {
    const res = await this.client.query(`
      INSERT INTO intel.score_models (score_model_id, model_key, version, formula_type, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      model.score_model_id,
      model.model_key,
      model.version,
      model.formula_type,
      model.status || 'ACTIVE',
    ]);
    return res.rows[0] as ScoreModel;
  }

  async createScoreDimension(dim: Omit<ScoreDimension, 'created_at'>): Promise<ScoreDimension> {
    const res = await this.client.query(`
      INSERT INTO intel.score_dimensions (dimension_id, score_model_id, dimension_key, display_name, weight)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      dim.dimension_id,
      dim.score_model_id,
      dim.dimension_key,
      dim.display_name,
      dim.weight ?? 1.0,
    ]);
    return res.rows[0] as ScoreDimension;
  }

  async createScoreResult(result: Omit<ScoreResult, 'created_at'>): Promise<ScoreResult> {
    const res = await this.client.query(`
      INSERT INTO intel.score_results (score_result_id, analysis_run_id, score_model_id, overall_score, grade, calibration_version)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      result.score_result_id,
      result.analysis_run_id,
      result.score_model_id,
      result.overall_score,
      result.grade || null,
      result.calibration_version,
    ]);
    return res.rows[0] as ScoreResult;
  }

  async createScoreDimensionValue(val: Omit<ScoreDimensionValue, 'created_at'>): Promise<ScoreDimensionValue> {
    const res = await this.client.query(`
      INSERT INTO intel.score_dimension_values (score_dimension_value_id, score_result_id, dimension_id, raw_value, weighted_value)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      val.score_dimension_value_id,
      val.score_result_id,
      val.dimension_id,
      val.raw_value,
      val.weighted_value,
    ]);
    return res.rows[0] as ScoreDimensionValue;
  }

  async getScoreResult(analysisRunId: string, scoreModelId: string): Promise<ScoreResult | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.score_results WHERE analysis_run_id = $1 AND score_model_id = $2;
    `, [analysisRunId, scoreModelId]);
    return res.rows.length ? (res.rows[0] as ScoreResult) : null;
  }

  async createPolicyVersion(policy: Omit<PolicyVersion, 'created_at'>): Promise<PolicyVersion> {
    const res = await this.client.query(`
      INSERT INTO intel.policy_versions (policy_version_id, policy_key, version, name, description, status)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      policy.policy_version_id,
      policy.policy_key,
      policy.version,
      policy.name,
      policy.description || null,
      policy.status || 'ACTIVE',
    ]);
    return res.rows[0] as PolicyVersion;
  }

  async createPolicyRule(rule: Omit<PolicyRule, 'created_at'>): Promise<PolicyRule> {
    const res = await this.client.query(`
      INSERT INTO intel.policy_rules (rule_id, policy_version_id, rule_key, rule_name, severity, condition_expression)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      rule.rule_id,
      rule.policy_version_id,
      rule.rule_key,
      rule.rule_name,
      rule.severity,
      rule.condition_expression,
    ]);
    return res.rows[0] as PolicyRule;
  }

  async createPolicyDecision(decision: Omit<PolicyDecision, 'created_at'>): Promise<PolicyDecision> {
    const res = await this.client.query(`
      INSERT INTO intel.policy_decisions (decision_id, analysis_run_id, policy_version_id, decision, evaluation_summary)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      decision.decision_id,
      decision.analysis_run_id,
      decision.policy_version_id,
      decision.decision,
      decision.evaluation_summary,
    ]);
    return res.rows[0] as PolicyDecision;
  }

  async createPolicyDecisionReason(reason: Omit<PolicyDecisionReason, 'created_at'>): Promise<PolicyDecisionReason> {
    const res = await this.client.query(`
      INSERT INTO intel.policy_decision_reasons (reason_id, decision_id, rule_id, risk_id, reason_text, is_blocking)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      reason.reason_id,
      reason.decision_id,
      reason.rule_id || null,
      reason.risk_id || null,
      reason.reason_text,
      reason.is_blocking ?? false,
    ]);
    return res.rows[0] as PolicyDecisionReason;
  }

  async getPolicyDecision(analysisRunId: string, policyVersionId: string): Promise<PolicyDecision | null> {
    const res = await this.client.query(`
      SELECT * FROM intel.policy_decisions WHERE analysis_run_id = $1 AND policy_version_id = $2;
    `, [analysisRunId, policyVersionId]);
    return res.rows.length ? (res.rows[0] as PolicyDecision) : null;
  }

  async createRecommendation(rec: Omit<Recommendation, 'created_at'>): Promise<Recommendation> {
    const res = await this.client.query(`
      INSERT INTO intel.recommendations (recommendation_id, analysis_run_id, entity_ref_id, risk_id, recommendation_type, title, action_steps, priority, effort_estimate)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      rec.recommendation_id,
      rec.analysis_run_id,
      rec.entity_ref_id || null,
      rec.risk_id || null,
      rec.recommendation_type,
      rec.title,
      rec.action_steps,
      rec.priority,
      rec.effort_estimate || null,
    ]);
    return res.rows[0] as Recommendation;
  }

  async getRecommendationsForRun(analysisRunId: string): Promise<Recommendation[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.recommendations WHERE analysis_run_id = $1 ORDER BY priority ASC;
    `, [analysisRunId]);
    return res.rows as Recommendation[];
  }

  async createUseCase(useCase: Omit<UseCase, 'created_at'>): Promise<UseCase> {
    const res = await this.client.query(`
      INSERT INTO intel.use_cases (use_case_id, use_case_key, title, description, category)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      useCase.use_case_id,
      useCase.use_case_key,
      useCase.title,
      useCase.description,
      useCase.category,
    ]);
    return res.rows[0] as UseCase;
  }

  async createUseCaseEvaluation(evaluation: Omit<UseCaseEvaluation, 'created_at'>): Promise<UseCaseEvaluation> {
    const res = await this.client.query(`
      INSERT INTO intel.use_case_evaluations (evaluation_id, analysis_run_id, use_case_id, suitability, suitability_score, justification)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      evaluation.evaluation_id,
      evaluation.analysis_run_id,
      evaluation.use_case_id,
      evaluation.suitability,
      evaluation.suitability_score ?? 1.0,
      evaluation.justification,
    ]);
    return res.rows[0] as UseCaseEvaluation;
  }

  async getUseCaseEvaluationsForRun(analysisRunId: string): Promise<UseCaseEvaluation[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.use_case_evaluations WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as UseCaseEvaluation[];
  }

  // --- Lineage Repository ---
  async createLineageEdge(edge: Omit<LineageEdge, 'created_at'>): Promise<LineageEdge> {
    const res = await this.client.query(`
      INSERT INTO intel.lineage_edges (lineage_edge_id, from_entity_ref_id, to_entity_ref_id, lineage_type, analysis_run_id, stage_run_id, transformation_version, confidence)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      edge.lineage_edge_id,
      edge.from_entity_ref_id,
      edge.to_entity_ref_id,
      edge.lineage_type,
      edge.analysis_run_id || null,
      edge.stage_run_id || null,
      edge.transformation_version || null,
      edge.confidence ?? 1.0,
    ]);
    return res.rows[0] as LineageEdge;
  }

  async getLineageEdgesForRun(analysisRunId: string): Promise<LineageEdge[]> {
    const res = await this.client.query(`
      SELECT * FROM intel.lineage_edges WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as LineageEdge[];
  }

  /**
   * Resolves complete backward lineage graph for a Claim:
   * Claim -> Assertions -> Evidence -> Static Findings / Spans / Observations / Artifacts
   */
  async resolveBackwardLineage(claimId: string): Promise<BackwardLineageNode | null> {
    const claimRes = await this.client.query(`
      SELECT * FROM intel.claims WHERE claim_id = $1;
    `, [claimId]);
    if (!claimRes.rows.length) return null;
    const claim = claimRes.rows[0] as Claim;

    // 1. Fetch Assertions linked to this Claim
    const assertionLinksRes = await this.client.query(`
      SELECT a.*, l.link_type 
      FROM intel.assertions a
      INNER JOIN intel.claim_support_links l ON a.assertion_id = l.assertion_id
      WHERE l.claim_id = $1;
    `, [claimId]);

    const assertions: BackwardLineageNode['assertions'] = [];

    for (const row of assertionLinksRes.rows) {
      const assertion: Assertion = {
        assertion_id: row.assertion_id,
        analysis_run_id: row.analysis_run_id,
        stage_run_id: row.stage_run_id,
        entity_ref_id: row.entity_ref_id,
        assertion_key: row.assertion_key,
        concept_id: row.concept_id,
        predicate: row.predicate,
        subject_ref_id: row.subject_ref_id,
        object_ref_id: row.object_ref_id,
        assertion_value: row.assertion_value,
        confidence: parseFloat(row.confidence),
        uncertainty_score: parseFloat(row.uncertainty_score),
        uncertainty_factors: row.uncertainty_factors,
        calibration_version: row.calibration_version,
        engine_key: row.engine_key,
        rule_id: row.rule_id,
        created_at: row.created_at,
      };

      // Fetch evidence linked to this assertion
      const evRes = await this.client.query(`
        SELECT e.*, l.relationship_type 
        FROM intel.evidence e
        INNER JOIN intel.assertion_evidence_links l ON e.evidence_id = l.evidence_id
        WHERE l.assertion_id = $1;
      `, [assertion.assertion_id]);

      const evList = [];
      for (const evRow of evRes.rows) {
        const evidence: Evidence = {
          evidence_id: evRow.evidence_id,
          analysis_run_id: evRow.analysis_run_id,
          stage_run_id: evRow.stage_run_id,
          entity_ref_id: evRow.entity_ref_id,
          evidence_type: evRow.evidence_type,
          source_span_id: evRow.source_span_id,
          source_observation_id: evRow.source_observation_id,
          artifact_id: evRow.artifact_id,
          static_finding_id: evRow.static_finding_id,
          runtime_event_id: evRow.runtime_event_id,
          external_intel_ref_id: evRow.external_intel_ref_id,
          description: evRow.description,
          confidence: parseFloat(evRow.confidence),
          weight: parseFloat(evRow.weight),
          created_at: evRow.created_at,
        };

        let finding: StaticFinding | null = null;
        if (evidence.static_finding_id) {
          const fRes = await this.client.query(`SELECT * FROM analysis.static_findings WHERE finding_id = $1`, [evidence.static_finding_id]);
          if (fRes.rows.length) finding = fRes.rows[0] as StaticFinding;
        }

        let sourceSpan: SourceSpan | null = null;
        if (evidence.source_span_id) {
          const sRes = await this.client.query(`SELECT * FROM source.source_spans WHERE source_span_id = $1`, [evidence.source_span_id]);
          if (sRes.rows.length) sourceSpan = sRes.rows[0] as SourceSpan;
        }

        let observation: SourceObservation | null = null;
        if (evidence.source_observation_id) {
          const oRes = await this.client.query(`SELECT * FROM source.source_observations WHERE source_observation_id = $1`, [evidence.source_observation_id]);
          if (oRes.rows.length) observation = oRes.rows[0] as SourceObservation;
        }

        let artifact: Artifact | null = null;
        if (evidence.artifact_id) {
          const aRes = await this.client.query(`SELECT * FROM source.artifacts WHERE artifact_id = $1`, [evidence.artifact_id]);
          if (aRes.rows.length) artifact = aRes.rows[0] as Artifact;
        }

        evList.push({
          evidence,
          relationship_type: evRow.relationship_type,
          finding,
          sourceSpan,
          observation,
          artifact,
        });
      }

      assertions.push({
        assertion,
        link_type: row.link_type,
        evidence: evList,
      });
    }

    // 2. Fetch Direct Evidence linked to this Claim
    const directEvRes = await this.client.query(`
      SELECT e.*, l.support_type 
      FROM intel.evidence e
      INNER JOIN intel.claim_evidence_links l ON e.evidence_id = l.evidence_id
      WHERE l.claim_id = $1;
    `, [claimId]);

    const directEvidence = [];
    for (const evRow of directEvRes.rows) {
      const evidence: Evidence = {
        evidence_id: evRow.evidence_id,
        analysis_run_id: evRow.analysis_run_id,
        stage_run_id: evRow.stage_run_id,
        entity_ref_id: evRow.entity_ref_id,
        evidence_type: evRow.evidence_type,
        source_span_id: evRow.source_span_id,
        source_observation_id: evRow.source_observation_id,
        artifact_id: evRow.artifact_id,
        static_finding_id: evRow.static_finding_id,
        runtime_event_id: evRow.runtime_event_id,
        external_intel_ref_id: evRow.external_intel_ref_id,
        description: evRow.description,
        confidence: parseFloat(evRow.confidence),
        weight: parseFloat(evRow.weight),
        created_at: evRow.created_at,
      };

      let finding: StaticFinding | null = null;
      if (evidence.static_finding_id) {
        const fRes = await this.client.query(`SELECT * FROM analysis.static_findings WHERE finding_id = $1`, [evidence.static_finding_id]);
        if (fRes.rows.length) finding = fRes.rows[0] as StaticFinding;
      }

      let sourceSpan: SourceSpan | null = null;
      if (evidence.source_span_id) {
        const sRes = await this.client.query(`SELECT * FROM source.source_spans WHERE source_span_id = $1`, [evidence.source_span_id]);
        if (sRes.rows.length) sourceSpan = sRes.rows[0] as SourceSpan;
      }

      let observation: SourceObservation | null = null;
      if (evidence.source_observation_id) {
        const oRes = await this.client.query(`SELECT * FROM source.source_observations WHERE source_observation_id = $1`, [evidence.source_observation_id]);
        if (oRes.rows.length) observation = oRes.rows[0] as SourceObservation;
      }

      let artifact: Artifact | null = null;
      if (evidence.artifact_id) {
        const aRes = await this.client.query(`SELECT * FROM source.artifacts WHERE artifact_id = $1`, [evidence.artifact_id]);
        if (aRes.rows.length) artifact = aRes.rows[0] as Artifact;
      }

      directEvidence.push({
        evidence,
        support_type: evRow.support_type,
        finding,
        sourceSpan,
        observation,
        artifact,
      });
    }

    return {
      claim,
      assertions,
      directEvidence,
    };
  }

  // --- Ontology Repository ---
  async getOntologyVersion(versionLabel: string): Promise<OntologyVersion | null> {
    const res = await this.client.query(`
      SELECT * FROM ontology.ontology_versions WHERE version_label = $1;
    `, [versionLabel]);
    return res.rows.length ? (res.rows[0] as OntologyVersion) : null;
  }

  async listConcepts(versionId: string): Promise<OntologyConcept[]> {
    const res = await this.client.query(`
      SELECT * FROM ontology.ontology_concepts WHERE ontology_version_id = $1;
    `, [versionId]);
    return res.rows as OntologyConcept[];
  }

  async createConcept(concept: Omit<OntologyConcept, 'created_at'>): Promise<OntologyConcept> {
    const res = await this.client.query(`
      INSERT INTO ontology.ontology_concepts (concept_id, ontology_version_id, namespace, canonical_name, concept_type, parent_concept_id, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      concept.concept_id,
      concept.ontology_version_id,
      concept.namespace,
      concept.canonical_name,
      concept.concept_type,
      concept.parent_concept_id || null,
      concept.status || 'ACTIVE',
    ]);
    return res.rows[0] as OntologyConcept;
  }

  // --- Version Registry Repository ---
  async getActiveVersion(artifactType: string, artifactKey: string): Promise<VersionRegistryEntry | null> {
    const res = await this.client.query(`
      SELECT * FROM ops.version_registry WHERE artifact_type = $1 AND artifact_key = $2 AND status = 'ACTIVE';
    `, [artifactType, artifactKey]);
    return res.rows.length ? (res.rows[0] as VersionRegistryEntry) : null;
  }

  async registerVersion(entry: Omit<VersionRegistryEntry, 'created_at'>): Promise<VersionRegistryEntry> {
    const res = await this.client.query(`
      INSERT INTO ops.version_registry (version_registry_id, artifact_type, artifact_key, version, status, content_hash, activated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      entry.version_registry_id,
      entry.artifact_type,
      entry.artifact_key,
      entry.version,
      entry.status || 'ACTIVE',
      entry.content_hash,
      entry.activated_at || null,
    ]);
    return res.rows[0] as VersionRegistryEntry;
  }

  // --- Knowledge Repository Implementations ---
  async createKnowledgeObject(obj: Omit<KnowledgeObject, 'created_at' | 'updated_at'>): Promise<KnowledgeObject> {
    const res = await this.client.query(`
      INSERT INTO knowledge.knowledge_objects (knowledge_object_id, entity_ref_id, object_type, agent_id, agent_version_id, analysis_run_id, security_classification_id, projection_version)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      obj.knowledge_object_id,
      obj.entity_ref_id,
      obj.object_type,
      obj.agent_id || null,
      obj.agent_version_id || null,
      obj.analysis_run_id || null,
      obj.security_classification_id,
      obj.projection_version,
    ]);
    return res.rows[0] as KnowledgeObject;
  }

  async getKnowledgeObject(id: string): Promise<KnowledgeObject | null> {
    const res = await this.client.query(`
      SELECT * FROM knowledge.knowledge_objects WHERE knowledge_object_id = $1;
    `, [id]);
    return res.rows.length ? (res.rows[0] as KnowledgeObject) : null;
  }

  async getKnowledgeObjectsForRun(analysisRunId: string): Promise<KnowledgeObject[]> {
    const res = await this.client.query(`
      SELECT * FROM knowledge.knowledge_objects WHERE analysis_run_id = $1;
    `, [analysisRunId]);
    return res.rows as KnowledgeObject[];
  }

  async createKnowledgeProjection(proj: Omit<KnowledgeProjection, 'created_at'>): Promise<KnowledgeProjection> {
    const res = await this.client.query(`
      INSERT INTO knowledge.knowledge_projections (knowledge_projection_id, knowledge_object_id, projection_type, projection_version, payload, stale, indexed_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      proj.knowledge_projection_id,
      proj.knowledge_object_id,
      proj.projection_type,
      proj.projection_version,
      JSON.stringify(proj.payload || {}),
      proj.stale || false,
      proj.indexed_at || null,
    ]);
    return res.rows[0] as KnowledgeProjection;
  }

  async createKnowledgeChunk(chunk: Omit<KnowledgeChunk, 'created_at'>): Promise<KnowledgeChunk> {
    const res = await this.client.query(`
      INSERT INTO knowledge.knowledge_chunks (knowledge_chunk_id, knowledge_projection_id, sequence, content_hash, text_or_locator, token_count, security_classification_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      chunk.knowledge_chunk_id,
      chunk.knowledge_projection_id,
      chunk.sequence,
      chunk.content_hash,
      chunk.text_or_locator,
      chunk.token_count || null,
      chunk.security_classification_id,
    ]);
    return res.rows[0] as KnowledgeChunk;
  }

  async createEmbedding(emb: Omit<Embedding, 'created_at'>): Promise<Embedding> {
    const res = await this.client.query(`
      INSERT INTO knowledge.embeddings (embedding_id, knowledge_chunk_id, knowledge_object_id, embedding_model_version, dimensions, vector)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      emb.embedding_id,
      emb.knowledge_chunk_id || null,
      emb.knowledge_object_id || null,
      emb.embedding_model_version,
      emb.dimensions,
      emb.vector || null,
    ]);
    return res.rows[0] as Embedding;
  }

  async createIndexState(state: Omit<IndexState, 'last_indexed_at'>): Promise<IndexState> {
    const res = await this.client.query(`
      INSERT INTO knowledge.index_states (index_state_id, knowledge_object_id, index_type, index_version, source_version_hash, stale)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      state.index_state_id,
      state.knowledge_object_id,
      state.index_type,
      state.index_version,
      state.source_version_hash,
      state.stale || false,
    ]);
    return res.rows[0] as IndexState;
  }

  async createQuerySession(session: Omit<QuerySession, 'created_at' | 'started_at'>): Promise<QuerySession> {
    const res = await this.client.query(`
      INSERT INTO knowledge.query_sessions (query_session_id, principal_id, access_context_hash)
      VALUES ($1, $2, $3)
      RETURNING *;
    `, [
      session.query_session_id,
      session.principal_id,
      session.access_context_hash,
    ]);
    return res.rows[0] as QuerySession;
  }

  async createQuery(query: Omit<Query, 'created_at' | 'received_at'>): Promise<Query> {
    const res = await this.client.query(`
      INSERT INTO knowledge.queries (query_id, query_session_id, principal_id, query_text_or_hash, intent_type, security_classification_id)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      query.query_id,
      query.query_session_id || null,
      query.principal_id,
      query.query_text_or_hash,
      query.intent_type || null,
      query.security_classification_id,
    ]);
    return res.rows[0] as Query;
  }

  async createQueryPlan(plan: Omit<QueryPlan, 'created_at'>): Promise<QueryPlan> {
    const res = await this.client.query(`
      INSERT INTO knowledge.query_plans (query_plan_id, query_id, planner_version, plan_payload, cost_budget)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      plan.query_plan_id,
      plan.query_id,
      plan.planner_version,
      JSON.stringify(plan.plan_payload || {}),
      plan.cost_budget || null,
    ]);
    return res.rows[0] as QueryPlan;
  }

  async createRetrievalRun(run: Omit<RetrievalRun, 'created_at' | 'started_at'>): Promise<RetrievalRun> {
    const res = await this.client.query(`
      INSERT INTO knowledge.retrieval_runs (retrieval_run_id, query_plan_id, retrieval_type, index_version, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      run.retrieval_run_id,
      run.query_plan_id,
      run.retrieval_type,
      run.index_version || null,
      run.status || 'PENDING',
    ]);
    return res.rows[0] as RetrievalRun;
  }

  async createRetrievalResult(result: RetrievalResult): Promise<RetrievalResult> {
    const res = await this.client.query(`
      INSERT INTO knowledge.retrieval_results (retrieval_result_id, retrieval_run_id, knowledge_object_id, rank, score, retrieval_method, authorized)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      result.retrieval_result_id,
      result.retrieval_run_id,
      result.knowledge_object_id,
      result.rank,
      result.score || null,
      result.retrieval_method,
      result.authorized ?? true,
    ]);
    return res.rows[0] as RetrievalResult;
  }

  async createContextPackage(pkg: Omit<ContextPackage, 'created_at'>): Promise<ContextPackage> {
    const res = await this.client.query(`
      INSERT INTO knowledge.context_packages (context_package_id, query_id, assembler_version, content_hash, token_count, storage_locator)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      pkg.context_package_id,
      pkg.query_id,
      pkg.assembler_version,
      pkg.content_hash,
      pkg.token_count || 0,
      pkg.storage_locator || null,
    ]);
    return res.rows[0] as ContextPackage;
  }

  async createAnswer(ans: Omit<Answer, 'created_at'>): Promise<Answer> {
    const res = await this.client.query(`
      INSERT INTO knowledge.answers (answer_id, query_id, context_package_id, model_version, prompt_version, answer_text_or_locator, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      ans.answer_id,
      ans.query_id,
      ans.context_package_id || null,
      ans.model_version,
      ans.prompt_version,
      ans.answer_text_or_locator,
      ans.status || 'COMPLETED',
    ]);
    return res.rows[0] as Answer;
  }

  async createAnswerClaim(claim: CreateAnswerClaimInput): Promise<AnswerClaim> {
    const truthState = (claim as any).truthState ?? (claim as any).truth_state ?? null;
    const sourceId = (claim as any).sourceId ?? (claim as any).source_id ?? claim.answer_id;
    const evidenceId = (claim as any).evidenceId ?? (claim as any).evidence_id ?? null;
    const analyzerVersion = (claim as any).analyzerVersion ?? (claim as any).analyzer_version ?? '2.0.1';
    const observedAt = (claim as any).observedAt ?? (claim as any).observed_at ?? new Date().toISOString();
    const limitations = (claim as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO knowledge.answer_claims (
        answer_claim_id, answer_id, sequence, claim_text, grounding_state, confidence,
        truth_state, source_id, evidence_id, analyzer_version, observed_at, limitations
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `, [
      claim.answer_claim_id,
      claim.answer_id,
      claim.sequence,
      claim.claim_text,
      claim.grounding_state || 'UNGROUNDED',
      claim.confidence ?? 1.0,
      truthState,
      sourceId,
      evidenceId,
      analyzerVersion,
      observedAt,
      limitations,
    ]);
    return res.rows[0] as AnswerClaim;
  }

  async createCitation(citation: Citation): Promise<Citation> {
    const res = await this.client.query(`
      INSERT INTO knowledge.citations (citation_id, answer_id, answer_claim_id, target_entity_ref_id, citation_type, locator_payload, sequence)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      citation.citation_id,
      citation.answer_id,
      citation.answer_claim_id || null,
      citation.target_entity_ref_id,
      citation.citation_type,
      JSON.stringify(citation.locator_payload || {}),
      citation.sequence,
    ]);
    return res.rows[0] as Citation;
  }

  async createGroundingResult(resObj: Omit<GroundingResult, 'created_at'>): Promise<GroundingResult> {
    const res = await this.client.query(`
      INSERT INTO knowledge.grounding_results (grounding_result_id, answer_id, grounding_ruleset_version, supported_claims, unsupported_claims, contradiction_count, verdict)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      resObj.grounding_result_id,
      resObj.answer_id,
      resObj.grounding_ruleset_version,
      resObj.supported_claims || 0,
      resObj.unsupported_claims || 0,
      resObj.contradiction_count || 0,
      resObj.verdict,
    ]);
    return res.rows[0] as GroundingResult;
  }

  async purgeDerivativeKnowledge(entityRefId: string): Promise<{ deletedObjects: number }> {
    const res = await this.client.query(`
      DELETE FROM knowledge.knowledge_objects WHERE entity_ref_id = $1 RETURNING knowledge_object_id;
    `, [entityRefId]);
    return { deletedObjects: res.rowCount || res.rows.length };
  }

  // --- Lifecycle Repository Implementations ---
  async createVersionDiff(diff: Omit<VersionDiff, 'created_at'>): Promise<VersionDiff> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.version_diffs (version_diff_id, left_entity_ref_id, right_entity_ref_id, diff_type, engine_version)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      diff.version_diff_id,
      diff.left_entity_ref_id,
      diff.right_entity_ref_id,
      diff.diff_type,
      diff.engine_version,
    ]);
    return res.rows[0] as VersionDiff;
  }

  async createDiffItem(item: Omit<DiffItem, 'created_at'>): Promise<DiffItem> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.diff_items (diff_item_id, version_diff_id, change_type, subject_entity_ref_id, before_payload, after_payload, significance)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      item.diff_item_id,
      item.version_diff_id,
      item.change_type,
      item.subject_entity_ref_id || null,
      item.before_payload ? JSON.stringify(item.before_payload) : null,
      item.after_payload ? JSON.stringify(item.after_payload) : null,
      item.significance || 'MINOR',
    ]);
    return res.rows[0] as DiffItem;
  }

  async createModificationWorkspace(ws: Omit<ModificationWorkspace, 'created_at'>): Promise<ModificationWorkspace> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.modification_workspaces (modification_workspace_id, base_agent_version_id, created_by, status)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [
      ws.modification_workspace_id,
      ws.base_agent_version_id,
      ws.created_by,
      ws.status || 'OPEN',
    ]);
    return res.rows[0] as ModificationWorkspace;
  }

  async createModificationChange(change: Omit<ModificationChange, 'created_at'>): Promise<ModificationChange> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.modification_changes (modification_change_id, modification_workspace_id, artifact_file_id, source_span_id, change_type, patch_locator, author_type)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      change.modification_change_id,
      change.modification_workspace_id,
      change.artifact_file_id || null,
      change.source_span_id || null,
      change.change_type,
      change.patch_locator,
      change.author_type || 'HUMAN',
    ]);
    return res.rows[0] as ModificationChange;
  }

  async createApproval(approval: Omit<Approval, 'decided_at'>): Promise<Approval> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.approvals (approval_id, approval_type, target_entity_ref_id, approver_id, decision, rationale)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      approval.approval_id,
      approval.approval_type,
      approval.target_entity_ref_id,
      approval.approver_id,
      approval.decision,
      approval.rationale || null,
    ]);
    return res.rows[0] as Approval;
  }

  async createImpactAssessment(ia: Omit<ImpactAssessment, 'created_at'>): Promise<ImpactAssessment> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.impact_assessments (impact_assessment_id, modification_workspace_id, engine_version, scope_state)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `, [
      ia.impact_assessment_id,
      ia.modification_workspace_id,
      ia.engine_version,
      ia.scope_state || 'CALCULATED',
    ]);
    return res.rows[0] as ImpactAssessment;
  }

  async createImpactItem(item: ImpactItem): Promise<ImpactItem> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.impact_items (impact_item_id, impact_assessment_id, target_entity_ref_id, impact_type, severity, required_action)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      item.impact_item_id,
      item.impact_assessment_id,
      item.target_entity_ref_id,
      item.impact_type,
      item.severity,
      item.required_action,
    ]);
    return res.rows[0] as ImpactItem;
  }

  async createValidationRun(run: Omit<ValidationRun, 'created_at' | 'started_at'>): Promise<ValidationRun> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.validation_runs (
        validation_run_id,
        validation_type,
        baseline_agent_version_id,
        modified_agent_version_id,
        baseline_analysis_run_id,
        modified_analysis_run_id,
        validation_analysis_run_id,
        scenario_pack_id,
        validation_plan_version,
        policy_ruleset_version,
        scope_id,
        status
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `, [
      run.validation_run_id,
      run.validation_type,
      run.baseline_agent_version_id,
      run.modified_agent_version_id,
      run.baseline_analysis_run_id,
      run.modified_analysis_run_id,
      run.validation_analysis_run_id,
      run.scenario_pack_id || null,
      run.validation_plan_version,
      run.policy_ruleset_version || null,
      run.scope_id,
      run.status || 'PENDING',
    ]);
    return res.rows[0] as ValidationRun;
  }

  async getValidationRun(id: string): Promise<ValidationRun | null> {
    const res = await this.client.query(`
      SELECT * FROM lifecycle.validation_runs WHERE validation_run_id = $1;
    `, [id]);
    return res.rows.length ? (res.rows[0] as ValidationRun) : null;
  }

  async createValidationResult(result: Omit<ValidationResult, 'created_at'>): Promise<ValidationResult> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.validation_results (validation_result_id, validation_run_id, result_type, target_entity_ref_id, status, before_value, after_value, evidence_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      result.validation_result_id,
      result.validation_run_id,
      result.result_type,
      result.target_entity_ref_id || null,
      result.status,
      result.before_value ? JSON.stringify(result.before_value) : null,
      result.after_value ? JSON.stringify(result.after_value) : null,
      result.evidence_id || null,
    ]);
    return res.rows[0] as ValidationResult;
  }

  async createPackage(pkg: Omit<Package, 'created_at'>): Promise<Package> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.packages (package_id, agent_version_id, analysis_run_id, manifest_hash, storage_locator, status)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      pkg.package_id,
      pkg.agent_version_id,
      pkg.analysis_run_id,
      pkg.manifest_hash,
      pkg.storage_locator,
      pkg.status || 'GENERATED',
    ]);
    return res.rows[0] as Package;
  }

  async createPackageContent(content: PackageContent): Promise<PackageContent> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.package_contents (package_content_id, package_id, entity_ref_id, content_type, storage_locator, content_hash, sequence)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      content.package_content_id,
      content.package_id,
      content.entity_ref_id || null,
      content.content_type,
      content.storage_locator || null,
      content.content_hash,
      content.sequence || 1,
    ]);
    return res.rows[0] as PackageContent;
  }

  async createAttestation(att: Omit<Attestation, 'created_at'>): Promise<Attestation> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.attestations (attestation_id, package_id, attestation_type, schema_version, payload_hash, storage_locator)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      att.attestation_id,
      att.package_id,
      att.attestation_type,
      att.schema_version,
      att.payload_hash,
      att.storage_locator,
    ]);
    return res.rows[0] as Attestation;
  }

  async createSignature(sig: Omit<Signature, 'signed_at'>): Promise<Signature> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.signatures (signature_id, target_entity_ref_id, signature_scheme, key_version, signature_locator)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      sig.signature_id,
      sig.target_entity_ref_id,
      sig.signature_scheme,
      sig.key_version,
      sig.signature_locator,
    ]);
    return res.rows[0] as Signature;
  }

  async createShipment(shipment: Omit<Shipment, 'created_at'>): Promise<Shipment> {
    const res = await this.client.query(`
      INSERT INTO lifecycle.shipments (shipment_id, package_id, target_type, target_locator, status, shipped_at, receipt_locator)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      shipment.shipment_id,
      shipment.package_id,
      shipment.target_type,
      shipment.target_locator,
      shipment.status || 'PENDING',
      shipment.shipped_at || null,
      shipment.receipt_locator || null,
    ]);
    return res.rows[0] as Shipment;
  }

  // --- Operations Repository Implementations ---
  async createWorkflowDefinition(def: Omit<WorkflowDefinition, 'created_at'>): Promise<WorkflowDefinition> {
    const res = await this.client.query(`
      INSERT INTO ops.workflow_definitions (workflow_definition_id, workflow_key, version, status, definition_payload)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      def.workflow_definition_id,
      def.workflow_key,
      def.version,
      def.status || 'ACTIVE',
      JSON.stringify(def.definition_payload || {}),
    ]);
    return res.rows[0] as WorkflowDefinition;
  }

  async createWorkflowRun(run: Omit<WorkflowRun, 'created_at' | 'started_at'>): Promise<WorkflowRun> {
    const res = await this.client.query(`
      INSERT INTO ops.workflow_runs (workflow_run_id, workflow_definition_id, agent_id, agent_version_id, analysis_run_id, status, correlation_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      run.workflow_run_id,
      run.workflow_definition_id,
      run.agent_id || null,
      run.agent_version_id || null,
      run.analysis_run_id || null,
      run.status || 'PENDING',
      run.correlation_id,
    ]);
    return res.rows[0] as WorkflowRun;
  }

  async createJob(job: Omit<Job, 'created_at'>): Promise<Job> {
    const res = await this.client.query(`
      INSERT INTO ops.jobs (job_id, workflow_run_id, stage_run_id, queue_key, idempotency_key, priority, status, next_attempt_at, payload)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `, [
      job.job_id,
      job.workflow_run_id || null,
      job.stage_run_id || null,
      job.queue_key,
      job.idempotency_key,
      job.priority ?? 10,
      job.status || 'QUEUED',
      job.next_attempt_at || new Date().toISOString(),
      JSON.stringify(job.payload || {}),
    ]);
    return res.rows[0] as Job;
  }

  async createJobAttempt(att: Omit<JobAttempt, 'created_at'>): Promise<JobAttempt> {
    const res = await this.client.query(`
      INSERT INTO ops.job_attempts (job_attempt_id, job_id, attempt_no, worker_id, leased_at, lease_expires_at, completed_at, failure_class, failure_code, error_message)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *;
    `, [
      att.job_attempt_id,
      att.job_id,
      att.attempt_no,
      att.worker_id || null,
      att.leased_at || null,
      att.lease_expires_at || null,
      att.completed_at || null,
      att.failure_class || null,
      att.failure_code || null,
      att.error_message || null,
    ]);
    return res.rows[0] as JobAttempt;
  }

  async createDeadLetterJob(dlj: Omit<DeadLetterJob, 'dead_lettered_at'>): Promise<DeadLetterJob> {
    const res = await this.client.query(`
      INSERT INTO ops.dead_letter_jobs (dead_letter_job_id, job_id, final_failure_code, payload_snapshot_locator, resolution_state)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      dlj.dead_letter_job_id,
      dlj.job_id,
      dlj.final_failure_code,
      dlj.payload_snapshot_locator || null,
      dlj.resolution_state || 'UNRESOLVED',
    ]);
    return res.rows[0] as DeadLetterJob;
  }

  async recordStateTransition(tr: Omit<LifecycleStateTransition, 'occurred_at'>): Promise<LifecycleStateTransition> {
    const res = await this.client.query(`
      INSERT INTO ops.lifecycle_state_transitions (state_transition_id, entity_ref_id, from_state, to_state, transition_reason, actor_ref)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      tr.state_transition_id,
      tr.entity_ref_id,
      tr.from_state || null,
      tr.to_state,
      tr.transition_reason,
      tr.actor_ref || null,
    ]);
    return res.rows[0] as LifecycleStateTransition;
  }

  async createOutboxEvent(event: Omit<OutboxEvent, 'occurred_at'>): Promise<OutboxEvent> {
    const res = await this.client.query(`
      INSERT INTO ops.outbox_events (event_id, event_type, aggregate_entity_ref_id, payload, schema_version, correlation_id, causation_id, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `, [
      event.event_id,
      event.event_type,
      event.aggregate_entity_ref_id || null,
      JSON.stringify(event.payload || {}),
      event.schema_version || '1.0.0',
      event.correlation_id,
      event.causation_id || null,
      event.status || 'PENDING',
    ]);
    return res.rows[0] as OutboxEvent;
  }

  async createOutboxDelivery(delivery: OutboxDelivery): Promise<OutboxDelivery> {
    const res = await this.client.query(`
      INSERT INTO ops.outbox_deliveries (delivery_id, event_id, target_subscriber, status, attempt_count, delivered_at, last_error)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      delivery.delivery_id,
      delivery.event_id,
      delivery.target_subscriber,
      delivery.status || 'PENDING',
      delivery.attempt_count || 0,
      delivery.delivered_at || null,
      delivery.last_error || null,
    ]);
    return res.rows[0] as OutboxDelivery;
  }

  async createAuditEvent(event: Omit<AuditEvent, 'occurred_at'>): Promise<AuditEvent> {
    const res = await this.client.query(`
      INSERT INTO ops.audit_events (audit_event_id, principal_or_service_id, action, target_entity_ref_id, outcome, correlation_id, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      event.audit_event_id,
      event.principal_or_service_id,
      event.action,
      event.target_entity_ref_id || null,
      event.outcome,
      event.correlation_id,
      JSON.stringify(event.metadata || {}),
    ]);
    return res.rows[0] as AuditEvent;
  }

  async getAuditEvents(targetEntityRefId?: string): Promise<AuditEvent[]> {
    if (targetEntityRefId) {
      const res = await this.client.query(`
        SELECT * FROM ops.audit_events WHERE target_entity_ref_id = $1 ORDER BY occurred_at DESC;
      `, [targetEntityRefId]);
      return res.rows as AuditEvent[];
    }
    const res = await this.client.query(`
      SELECT * FROM ops.audit_events ORDER BY occurred_at DESC;
    `);
    return res.rows as AuditEvent[];
  }

  async createEvaluationDataset(ds: Omit<EvaluationDataset, 'created_at'>): Promise<EvaluationDataset> {
    const res = await this.client.query(`
      INSERT INTO ops.evaluation_datasets (evaluation_dataset_id, name, version, scope, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      ds.evaluation_dataset_id,
      ds.name,
      ds.version,
      ds.scope || 'SYSTEM',
      ds.status || 'ACTIVE',
    ]);
    return res.rows[0] as EvaluationDataset;
  }

  async createEvaluationCase(ec: Omit<EvaluationCase, 'created_at'>): Promise<EvaluationCase> {
    const res = await this.client.query(`
      INSERT INTO ops.evaluation_cases (evaluation_case_id, evaluation_dataset_id, input_entity_ref_id, expected_payload, tags)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `, [
      ec.evaluation_case_id,
      ec.evaluation_dataset_id,
      ec.input_entity_ref_id || null,
      JSON.stringify(ec.expected_payload || {}),
      JSON.stringify(ec.tags || []),
    ]);
    return res.rows[0] as EvaluationCase;
  }

  async createEvaluationRun(run: Omit<EvaluationRun, 'created_at' | 'started_at'>): Promise<EvaluationRun> {
    const res = await this.client.query(`
      INSERT INTO ops.evaluation_runs (evaluation_run_id, evaluation_dataset_id, engine_key, engine_version, ruleset_version, status)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      run.evaluation_run_id,
      run.evaluation_dataset_id,
      run.engine_key,
      run.engine_version,
      run.ruleset_version || null,
      run.status || 'PENDING',
    ]);
    return res.rows[0] as EvaluationRun;
  }

  async createEvaluationResult(result: Omit<EvaluationResult, 'created_at'>): Promise<EvaluationResult> {
    const res = await this.client.query(`
      INSERT INTO ops.evaluation_results (evaluation_result_id, evaluation_run_id, evaluation_case_id, metric_key, metric_value, pass, details)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *;
    `, [
      result.evaluation_result_id,
      result.evaluation_run_id,
      result.evaluation_case_id || null,
      result.metric_key,
      result.metric_value,
      result.pass,
      result.details ? JSON.stringify(result.details) : null,
    ]);
    return res.rows[0] as EvaluationResult;
  }

  async createGoldenCorpusItem(item: Omit<GoldenCorpusItem, 'created_at'>): Promise<GoldenCorpusItem> {
    const res = await this.client.query(`
      INSERT INTO ops.golden_corpus_items (golden_corpus_item_id, entity_ref_id, fixture_locator, corpus_version, truth_status, tags)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *;
    `, [
      item.golden_corpus_item_id,
      item.entity_ref_id || null,
      item.fixture_locator,
      item.corpus_version,
      item.truth_status || 'VERIFIED',
      JSON.stringify(item.tags || []),
    ]);
    return res.rows[0] as GoldenCorpusItem;
  }

  async recordCostUsageEvent(event: Omit<CostUsageEvent, 'occurred_at'>): Promise<CostUsageEvent> {
    const res = await this.client.query(`
      INSERT INTO ops.cost_usage_events (cost_usage_event_id, usage_type, quantity, unit, provider, unit_cost_snapshot, agent_id, analysis_run_id, job_id, query_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *;
    `, [
      event.cost_usage_event_id,
      event.usage_type,
      event.quantity,
      event.unit,
      event.provider,
      event.unit_cost_snapshot || null,
      event.agent_id || null,
      event.analysis_run_id || null,
      event.job_id || null,
      event.query_id || null,
    ]);
    return res.rows[0] as CostUsageEvent;
  }

  async createTelemetryRecord(record: CreateTelemetryRecordInput): Promise<TelemetryRecord> {
    const truthState = (record as any).truthState ?? (record as any).truth_state ?? null;
    const sourceId = (record as any).sourceId ?? (record as any).source_id;
    const evidenceId = (record as any).evidenceId ?? (record as any).evidence_id ?? null;
    const analyzerVersion = (record as any).analyzerVersion ?? (record as any).analyzer_version ?? '2.0.1';
    const observedAt = (record as any).observedAt ?? (record as any).observed_at ?? new Date().toISOString();
    const confidence = (record as any).confidence ?? 1.0;
    const limitations = (record as any).limitations ?? null;

    const res = await this.client.query(`
      INSERT INTO ops.telemetry_records (
        telemetry_id, truth_state, source_id, evidence_id, analyzer_version, observed_at, confidence, limitations, metric_name, payload
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *;
    `, [
      record.telemetry_id,
      truthState,
      sourceId,
      evidenceId,
      analyzerVersion,
      observedAt,
      confidence,
      limitations,
      record.metric_name || null,
      record.payload ? JSON.stringify(record.payload) : '{}',
    ]);
    return res.rows[0] as TelemetryRecord;
  }

  async getTelemetryRecords(sourceId?: string): Promise<TelemetryRecord[]> {
    if (sourceId) {
      const res = await this.client.query(`
        SELECT * FROM ops.telemetry_records WHERE source_id = $1 ORDER BY observed_at DESC;
      `, [sourceId]);
      return res.rows as TelemetryRecord[];
    }
    const res = await this.client.query(`
      SELECT * FROM ops.telemetry_records ORDER BY observed_at DESC;
    `);
    return res.rows as TelemetryRecord[];
  }
}

export { PgMemDbRepositories as Repository };


