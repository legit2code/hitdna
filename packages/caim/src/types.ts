/**
 * Common Artifact Intelligence Model (CAIM) — V2.0.1
 * Pure Semantic & Structural Entities (Source-Independent)
 * 
 * Invariants:
 * - AgentVersion != AnalysisRun
 * - Permission != Capability != BehaviorObserved
 * - Pure contracts without analyzer business logic or runtime services
 */

export const CAIM_SPEC_VERSION = '2.0.1' as const;

export type DeclarationState = 'DECLARED_EXPLICIT' | 'INFERRED_STATIC' | 'OBSERVED_RUNTIME' | 'SYNTHESIZED';
export type ComponentType = 'LIBRARY' | 'FRAMEWORK' | 'PLUGIN' | 'RUNTIME' | 'SERVICE' | 'MODEL_ADAPTER';
export type ToolType = 'FUNCTION' | 'HTTP_API' | 'CLI_COMMAND' | 'MCP_TOOL' | 'CUSTOM_PLUGIN';
export type InterfaceType = 'JSON_SCHEMA' | 'OPENAPI' | 'GRAPHQL' | 'POSIX_EXEC';
export type BindingType = 'DIRECT_DISPATCH' | 'RPC_PROXY' | 'SANDBOX_ISOLATED' | 'HOST_EXEC';
export type DependencyType = 'DIRECT' | 'TRANSITIVE' | 'DEV' | 'PEER' | 'OPTIONAL' | 'DYNAMIC';
export type RuntimeType = 'NODEJS' | 'PYTHON' | 'BASH' | 'DOCKER' | 'WASM' | 'NATIVE_BINARY';
export type ExecutionMode = 'SANDBOXED' | 'CONTAINERIZED' | 'HOST_PROCESS' | 'SERVERLESS';
export type EndpointType = 'INGRESS' | 'EGRESS' | 'WEBHOOK' | 'SOCKET';
export type EndpointDirection = 'INBOUND' | 'OUTBOUND' | 'BIDIRECTIONAL';
export type ModelUsageRole = 'PLANNER' | 'CODER' | 'EMBEDDER' | 'EVALUATOR' | 'AGENT_CORE';
export type DatasetUsageRole = 'FEW_SHOT_PROMPTS' | 'RAG_GROUNDING' | 'FINE_TUNING' | 'BENCHMARK';
export type PromptRole = 'SYSTEM' | 'USER' | 'TOOL' | 'METAPROMPT';
export type ConfigValueType = 'STRING' | 'NUMBER' | 'BOOLEAN' | 'JSON' | 'SECRET_REF';
export type CredentialType = 'API_KEY' | 'OAUTH2_TOKEN' | 'MTLS_CERT' | 'SSH_KEY' | 'SESSION_COOKIE';
export type DataResourceType = 'FILESYSTEM' | 'DATABASE' | 'MEMORY' | 'EXTERNAL_API' | 'SECRETS_VAULT';
export type DataAccessMode = 'READ' | 'WRITE' | 'DELETE' | 'EXECUTE';
export type SecurityClassification = 'PUBLIC_METADATA' | 'INTERNAL' | 'SENSITIVE' | 'VAULT_RESTRICTED';

/**
 * 1. Canonical Agent Definition
 */
export interface CaimAgent {
  readonly _entity_kind: 'CANONICAL_AGENT';
  agent_id: string;
  canonical_name: string;
  description?: string;
  agent_type_concept_id?: string;
  status: 'ACTIVE' | 'DEPRECATED' | 'SUSPENDED' | 'MERGED';
  identity_confidence: number;
}

/**
 * 2. Immutable Agent Version
 * INVARIANT: AgentVersion represents static content identity, NEVER an analysis execution.
 */
export interface CaimAgentVersion {
  readonly _entity_kind: 'AGENT_VERSION';
  agent_version_id: string;
  agent_id: string;
  version_label?: string;
  source_commit?: string;
  content_fingerprint: string;
  release_date?: string;
  supersedes_version_id?: string;
}

/**
 * 3. Software & Logical Components
 */
export interface CaimComponent {
  readonly _entity_kind: 'COMPONENT';
  component_id: string;
  canonical_name: string;
  component_type: ComponentType;
  ecosystem?: string;
  version?: string;
  purl?: string;
  cpe?: string;
  hash?: string;
}

export interface CaimDependencyRelationship {
  readonly _entity_kind: 'DEPENDENCY_RELATIONSHIP';
  relationship_id: string;
  agent_version_id: string;
  from_component_id?: string;
  to_component_id: string;
  dependency_type: DependencyType;
  scope: string;
  resolved_version?: string;
  is_direct: boolean;
}

/**
 * 4. Tools & Protocol Bindings
 */
export interface CaimTool {
  readonly _entity_kind: 'TOOL';
  tool_id: string;
  agent_version_id: string;
  canonical_name: string;
  tool_type: ToolType;
  interface_type: InterfaceType;
  description?: string;
  protocol_instance_id?: string;
  parameters_schema?: Record<string, unknown>;
  returns_schema?: Record<string, unknown>;
  confidence: number;
}

export interface CaimToolBinding {
  readonly _entity_kind: 'TOOL_BINDING';
  binding_id: string;
  tool_id: string;
  target_entity_ref_id: string;
  binding_type: BindingType;
  confidence: number;
}

export interface CaimProtocolInstance {
  readonly _entity_kind: 'PROTOCOL_INSTANCE';
  protocol_instance_id: string;
  agent_version_id: string;
  protocol_name: string;
  protocol_version?: string;
  role: 'SERVER' | 'CLIENT' | 'PEER' | 'BIDIRECTIONAL';
  endpoint_id?: string;
  confidence: number;
}

export interface CaimProtocolCapability {
  readonly _entity_kind: 'PROTOCOL_CAPABILITY';
  protocol_capability_id: string;
  protocol_instance_id: string;
  capability_name: string;
  schema_payload?: Record<string, unknown>;
  confidence: number;
}

/**
 * 5. Capability vs Permission vs Observed Behavior (Strict Invariant Separation)
 */

/**
 * Capability: Functional capability/feature that the agent can perform.
 */
export interface CaimCapabilityInstance {
  readonly _entity_kind: 'CAPABILITY';
  capability_id: string;
  agent_version_id: string;
  capability_concept_id: string;
  canonical_key: string;
  declaration_state: DeclarationState;
  source_type: 'MANIFEST' | 'CODE_AST' | 'RUNTIME_TRACE' | 'HEURISTIC';
  confidence: number;
}

/**
 * Permission: Security/access authorization requested, granted, or declared.
 */
export interface CaimPermission {
  readonly _entity_kind: 'PERMISSION';
  permission_id: string;
  agent_version_id: string;
  permission_concept_id: string;
  scope?: string;
  target?: string;
  declared_state: 'REQUESTED' | 'GRANTED' | 'REQUIRED' | 'ASSUMED';
  confidence: number;
}

/**
 * Behavior Observed: Empirical dynamic event or sequence captured during execution.
 */
export interface CaimBehaviorObserved {
  readonly _entity_kind: 'BEHAVIOR_OBSERVED';
  behavior_observation_id: string;
  behavior_concept_id: string;
  runtime_event_id: string;
  occurred_at: string;
  observed_action: string;
  target_resource: string;
  execution_context?: Record<string, unknown>;
  confidence: number;
}

/**
 * 6. Runtime, Entrypoints & Endpoints
 */
export interface CaimEntrypoint {
  readonly _entity_kind: 'ENTRYPOINT';
  entrypoint_id: string;
  agent_version_id: string;
  entrypoint_type: 'CLI' | 'HTTP_HANDLER' | 'EVENT_SUBSCRIBER' | 'SCHEDULED_TASK' | 'LIBRARY_EXPORT';
  symbol_or_path: string;
  trigger_type?: string;
  confidence: number;
}

export interface CaimRuntimeEnvironment {
  readonly _entity_kind: 'RUNTIME_ENVIRONMENT';
  runtime_id: string;
  agent_version_id: string;
  runtime_type: RuntimeType;
  runtime_name: string;
  runtime_version?: string;
  os?: 'LINUX' | 'DARWIN' | 'WINDOWS' | 'ANY';
  architecture?: 'X86_64' | 'AARCH64' | 'WASM32' | 'ANY';
  execution_mode: ExecutionMode;
}

export interface CaimEndpoint {
  readonly _entity_kind: 'ENDPOINT';
  endpoint_id: string;
  agent_version_id: string;
  endpoint_type: EndpointType;
  direction: EndpointDirection;
  scheme?: string;
  host?: string;
  port?: number;
  path?: string;
  auth_scheme?: string;
  security_classification: SecurityClassification;
}

/**
 * 7. Model References, Datasets & Prompt Assets
 */
export interface CaimModelReference {
  readonly _entity_kind: 'MODEL_REFERENCE';
  model_reference_id: string;
  agent_version_id: string;
  provider: string;
  model_name: string;
  model_version?: string;
  usage_role: ModelUsageRole;
  confidence: number;
}

export interface CaimDatasetReference {
  readonly _entity_kind: 'DATASET_REFERENCE';
  dataset_reference_id: string;
  agent_version_id: string;
  dataset_name: string;
  locator?: string;
  usage_role?: DatasetUsageRole;
  confidence: number;
}

export interface CaimPromptAsset {
  readonly _entity_kind: 'PROMPT_ASSET';
  prompt_asset_id: string;
  agent_version_id: string;
  role?: PromptRole;
  purpose?: string;
  template_hash: string;
  security_classification: SecurityClassification;
}

/**
 * 8. Configurations, Credentials & Data Access Requirements
 */
export interface CaimConfigEntry {
  key_path: string;
  value_type: ConfigValueType;
  normalized_value?: string;
  secret_reference_id?: string;
  security_classification: SecurityClassification;
}

export interface CaimConfiguration {
  readonly _entity_kind: 'CONFIGURATION';
  configuration_id: string;
  agent_version_id: string;
  configuration_type: 'ENV_VARS' | 'CONFIG_FILE' | 'DYNAMIC_DISCOVERY' | 'REMOTE_STORE';
  environment?: string;
  entries: CaimConfigEntry[];
}

export interface CaimCredentialReference {
  readonly _entity_kind: 'CREDENTIAL_REFERENCE';
  credential_reference_id: string;
  agent_version_id: string;
  credential_type: CredentialType;
  reference_name?: string;
  usage_context?: string;
  confidence: number;
}

export interface CaimDataAccessRequirement {
  readonly _entity_kind: 'DATA_ACCESS_REQUIREMENT';
  requirement_id: string;
  agent_version_id: string;
  resource_type: DataResourceType;
  resource_locator?: string;
  access_modes: DataAccessMode[];
  confidence: number;
}

/**
 * 9. Distribution
 */
export interface CaimDistribution {
  readonly _entity_kind: 'DISTRIBUTION';
  distribution_id: string;
  agent_version_id: string;
  ecosystem: string;
  locator: string;
  version?: string;
  publisher?: string;
}

/**
 * 10. Complete CAIM Manifest (Source-Independent Unified Artifact Model)
 */
export interface CaimManifest {
  readonly caim_version: typeof CAIM_SPEC_VERSION;
  agent: CaimAgent;
  version: CaimAgentVersion;
  distributions: CaimDistribution[];
  components: CaimComponent[];
  dependencies: CaimDependencyRelationship[];
  tools: CaimTool[];
  tool_bindings: CaimToolBinding[];
  protocols: CaimProtocolInstance[];
  protocol_capabilities: CaimProtocolCapability[];
  capabilities: CaimCapabilityInstance[];
  permissions: CaimPermission[];
  entrypoints: CaimEntrypoint[];
  runtimes: CaimRuntimeEnvironment[];
  endpoints: CaimEndpoint[];
  models: CaimModelReference[];
  datasets: CaimDatasetReference[];
  prompts: CaimPromptAsset[];
  configurations: CaimConfiguration[];
  credentials: CaimCredentialReference[];
  data_access_requirements: CaimDataAccessRequirement[];
}
