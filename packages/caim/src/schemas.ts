import { z } from 'zod';
import { CAIM_SPEC_VERSION } from './types.ts';

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const uuidSchema = z.string().regex(uuidRegex, 'Invalid UUID');

export const CaimAgentSchema = z.object({
  _entity_kind: z.literal('CANONICAL_AGENT').default('CANONICAL_AGENT'),
  agent_id: uuidSchema,
  canonical_name: z.string().min(1),
  description: z.string().optional(),
  agent_type_concept_id: z.string().optional(),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'SUSPENDED', 'MERGED']).default('ACTIVE'),
  identity_confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimAgentVersionSchema = z.object({
  _entity_kind: z.literal('AGENT_VERSION').default('AGENT_VERSION'),
  agent_version_id: uuidSchema,
  agent_id: uuidSchema,
  version_label: z.string().optional(),
  source_commit: z.string().optional(),
  content_fingerprint: z.string().min(1),
  release_date: z.string().datetime().optional(),
  supersedes_version_id: uuidSchema.optional(),
});

export const CaimComponentSchema = z.object({
  _entity_kind: z.literal('COMPONENT').default('COMPONENT'),
  component_id: uuidSchema,
  canonical_name: z.string().min(1),
  component_type: z.enum(['LIBRARY', 'FRAMEWORK', 'PLUGIN', 'RUNTIME', 'SERVICE', 'MODEL_ADAPTER']),
  ecosystem: z.string().optional(),
  version: z.string().optional(),
  purl: z.string().optional(),
  cpe: z.string().optional(),
  hash: z.string().optional(),
});

export const CaimDependencyRelationshipSchema = z.object({
  _entity_kind: z.literal('DEPENDENCY_RELATIONSHIP').default('DEPENDENCY_RELATIONSHIP'),
  relationship_id: uuidSchema,
  agent_version_id: uuidSchema,
  from_component_id: uuidSchema.optional(),
  to_component_id: uuidSchema,
  dependency_type: z.enum(['DIRECT', 'TRANSITIVE', 'DEV', 'PEER', 'OPTIONAL', 'DYNAMIC']),
  scope: z.string().default('production'),
  resolved_version: z.string().optional(),
  is_direct: z.boolean().default(true),
});

export const CaimToolSchema = z.object({
  _entity_kind: z.literal('TOOL').default('TOOL'),
  tool_id: uuidSchema,
  agent_version_id: uuidSchema,
  canonical_name: z.string().min(1),
  tool_type: z.enum(['FUNCTION', 'HTTP_API', 'CLI_COMMAND', 'MCP_TOOL', 'CUSTOM_PLUGIN']),
  interface_type: z.enum(['JSON_SCHEMA', 'OPENAPI', 'GRAPHQL', 'POSIX_EXEC']),
  description: z.string().optional(),
  protocol_instance_id: uuidSchema.optional(),
  parameters_schema: z.record(z.string(), z.unknown()).optional(),
  returns_schema: z.record(z.string(), z.unknown()).optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimToolBindingSchema = z.object({
  _entity_kind: z.literal('TOOL_BINDING').default('TOOL_BINDING'),
  binding_id: uuidSchema,
  tool_id: uuidSchema,
  target_entity_ref_id: uuidSchema,
  binding_type: z.enum(['DIRECT_DISPATCH', 'RPC_PROXY', 'SANDBOX_ISOLATED', 'HOST_EXEC']),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimProtocolInstanceSchema = z.object({
  _entity_kind: z.literal('PROTOCOL_INSTANCE').default('PROTOCOL_INSTANCE'),
  protocol_instance_id: uuidSchema,
  agent_version_id: uuidSchema,
  protocol_name: z.string().min(1),
  protocol_version: z.string().optional(),
  role: z.enum(['SERVER', 'CLIENT', 'PEER', 'BIDIRECTIONAL']),
  endpoint_id: uuidSchema.optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimProtocolCapabilitySchema = z.object({
  _entity_kind: z.literal('PROTOCOL_CAPABILITY').default('PROTOCOL_CAPABILITY'),
  protocol_capability_id: uuidSchema,
  protocol_instance_id: uuidSchema,
  capability_name: z.string().min(1),
  schema_payload: z.record(z.string(), z.unknown()).optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimCapabilityInstanceSchema = z.object({
  _entity_kind: z.literal('CAPABILITY').default('CAPABILITY'),
  capability_id: uuidSchema,
  agent_version_id: uuidSchema,
  capability_concept_id: z.string().min(1),
  canonical_key: z.string().min(1),
  declaration_state: z.enum(['DECLARED_EXPLICIT', 'INFERRED_STATIC', 'OBSERVED_RUNTIME', 'SYNTHESIZED']),
  source_type: z.enum(['MANIFEST', 'CODE_AST', 'RUNTIME_TRACE', 'HEURISTIC']),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimPermissionSchema = z.object({
  _entity_kind: z.literal('PERMISSION').default('PERMISSION'),
  permission_id: uuidSchema,
  agent_version_id: uuidSchema,
  permission_concept_id: z.string().min(1),
  scope: z.string().optional(),
  target: z.string().optional(),
  declared_state: z.enum(['REQUESTED', 'GRANTED', 'REQUIRED', 'ASSUMED']),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimBehaviorObservedSchema = z.object({
  _entity_kind: z.literal('BEHAVIOR_OBSERVED').default('BEHAVIOR_OBSERVED'),
  behavior_observation_id: uuidSchema,
  behavior_concept_id: z.string().min(1),
  runtime_event_id: uuidSchema,
  occurred_at: z.string().datetime(),
  observed_action: z.string().min(1),
  target_resource: z.string().min(1),
  execution_context: z.record(z.string(), z.unknown()).optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimEntrypointSchema = z.object({
  _entity_kind: z.literal('ENTRYPOINT').default('ENTRYPOINT'),
  entrypoint_id: uuidSchema,
  agent_version_id: uuidSchema,
  entrypoint_type: z.enum(['CLI', 'HTTP_HANDLER', 'EVENT_SUBSCRIBER', 'SCHEDULED_TASK', 'LIBRARY_EXPORT']),
  symbol_or_path: z.string().min(1),
  trigger_type: z.string().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimRuntimeEnvironmentSchema = z.object({
  _entity_kind: z.literal('RUNTIME_ENVIRONMENT').default('RUNTIME_ENVIRONMENT'),
  runtime_id: uuidSchema,
  agent_version_id: uuidSchema,
  runtime_type: z.enum(['NODEJS', 'PYTHON', 'BASH', 'DOCKER', 'WASM', 'NATIVE_BINARY']),
  runtime_name: z.string().min(1),
  runtime_version: z.string().optional(),
  os: z.enum(['LINUX', 'DARWIN', 'WINDOWS', 'ANY']).optional(),
  architecture: z.enum(['X86_64', 'AARCH64', 'WASM32', 'ANY']).optional(),
  execution_mode: z.enum(['SANDBOXED', 'CONTAINERIZED', 'HOST_PROCESS', 'SERVERLESS']),
});

export const CaimEndpointSchema = z.object({
  _entity_kind: z.literal('ENDPOINT').default('ENDPOINT'),
  endpoint_id: uuidSchema,
  agent_version_id: uuidSchema,
  endpoint_type: z.enum(['INGRESS', 'EGRESS', 'WEBHOOK', 'SOCKET']),
  direction: z.enum(['INBOUND', 'OUTBOUND', 'BIDIRECTIONAL']),
  scheme: z.string().optional(),
  host: z.string().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  path: z.string().optional(),
  auth_scheme: z.string().optional(),
  security_classification: z.enum(['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED']),
});

export const CaimModelReferenceSchema = z.object({
  _entity_kind: z.literal('MODEL_REFERENCE').default('MODEL_REFERENCE'),
  model_reference_id: uuidSchema,
  agent_version_id: uuidSchema,
  provider: z.string().min(1),
  model_name: z.string().min(1),
  model_version: z.string().optional(),
  usage_role: z.enum(['PLANNER', 'CODER', 'EMBEDDER', 'EVALUATOR', 'AGENT_CORE']),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimDatasetReferenceSchema = z.object({
  _entity_kind: z.literal('DATASET_REFERENCE').default('DATASET_REFERENCE'),
  dataset_reference_id: uuidSchema,
  agent_version_id: uuidSchema,
  dataset_name: z.string().min(1),
  locator: z.string().optional(),
  usage_role: z.enum(['FEW_SHOT_PROMPTS', 'RAG_GROUNDING', 'FINE_TUNING', 'BENCHMARK']).optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimPromptAssetSchema = z.object({
  _entity_kind: z.literal('PROMPT_ASSET').default('PROMPT_ASSET'),
  prompt_asset_id: uuidSchema,
  agent_version_id: uuidSchema,
  role: z.enum(['SYSTEM', 'USER', 'TOOL', 'METAPROMPT']).optional(),
  purpose: z.string().optional(),
  template_hash: z.string().min(1),
  security_classification: z.enum(['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED']),
});

export const CaimConfigEntrySchema = z.object({
  key_path: z.string().min(1),
  value_type: z.enum(['STRING', 'NUMBER', 'BOOLEAN', 'JSON', 'SECRET_REF']),
  normalized_value: z.string().optional(),
  secret_reference_id: uuidSchema.optional(),
  security_classification: z.enum(['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED']),
});

export const CaimConfigurationSchema = z.object({
  _entity_kind: z.literal('CONFIGURATION').default('CONFIGURATION'),
  configuration_id: uuidSchema,
  agent_version_id: uuidSchema,
  configuration_type: z.enum(['ENV_VARS', 'CONFIG_FILE', 'DYNAMIC_DISCOVERY', 'REMOTE_STORE']),
  environment: z.string().optional(),
  entries: z.array(CaimConfigEntrySchema),
});

export const CaimCredentialReferenceSchema = z.object({
  _entity_kind: z.literal('CREDENTIAL_REFERENCE').default('CREDENTIAL_REFERENCE'),
  credential_reference_id: uuidSchema,
  agent_version_id: uuidSchema,
  credential_type: z.enum(['API_KEY', 'OAUTH2_TOKEN', 'MTLS_CERT', 'SSH_KEY', 'SESSION_COOKIE']),
  reference_name: z.string().optional(),
  usage_context: z.string().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimDataAccessRequirementSchema = z.object({
  _entity_kind: z.literal('DATA_ACCESS_REQUIREMENT').default('DATA_ACCESS_REQUIREMENT'),
  requirement_id: uuidSchema,
  agent_version_id: uuidSchema,
  resource_type: z.enum(['FILESYSTEM', 'DATABASE', 'MEMORY', 'EXTERNAL_API', 'SECRETS_VAULT']),
  resource_locator: z.string().optional(),
  access_modes: z.array(z.enum(['READ', 'WRITE', 'DELETE', 'EXECUTE'])).min(1),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const CaimDistributionSchema = z.object({
  _entity_kind: z.literal('DISTRIBUTION').default('DISTRIBUTION'),
  distribution_id: uuidSchema,
  agent_version_id: uuidSchema,
  ecosystem: z.string().min(1),
  locator: z.string().min(1),
  version: z.string().optional(),
  publisher: z.string().optional(),
});

export const CaimManifestSchema = z.object({
  caim_version: z.literal(CAIM_SPEC_VERSION),
  agent: CaimAgentSchema,
  version: CaimAgentVersionSchema,
  distributions: z.array(CaimDistributionSchema).default([]),
  components: z.array(CaimComponentSchema).default([]),
  dependencies: z.array(CaimDependencyRelationshipSchema).default([]),
  tools: z.array(CaimToolSchema).default([]),
  tool_bindings: z.array(CaimToolBindingSchema).default([]),
  protocols: z.array(CaimProtocolInstanceSchema).default([]),
  protocol_capabilities: z.array(CaimProtocolCapabilitySchema).default([]),
  capabilities: z.array(CaimCapabilityInstanceSchema).default([]),
  permissions: z.array(CaimPermissionSchema).default([]),
  entrypoints: z.array(CaimEntrypointSchema).default([]),
  runtimes: z.array(CaimRuntimeEnvironmentSchema).default([]),
  endpoints: z.array(CaimEndpointSchema).default([]),
  models: z.array(CaimModelReferenceSchema).default([]),
  datasets: z.array(CaimDatasetReferenceSchema).default([]),
  prompts: z.array(CaimPromptAssetSchema).default([]),
  configurations: z.array(CaimConfigurationSchema).default([]),
  credentials: z.array(CaimCredentialReferenceSchema).default([]),
  data_access_requirements: z.array(CaimDataAccessRequirementSchema).default([]),
});
