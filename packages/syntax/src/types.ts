import { z } from 'zod';
import { 
  type ProvenanceRecord, 
  ProvenanceRecordSchema, 
  type SourceSpanLocator, 
  SourceSpanLocatorSchema 
} from '../../contracts/src/index.ts';

export { ProvenanceRecordSchema, SourceSpanLocatorSchema };
export type { ProvenanceRecord, SourceSpanLocator };

// 1. File Type & Encoding Types
export const FileFormatCategoryEnum = z.enum([
  'SOURCE_CODE',
  'STRUCTURED_DATA',
  'CONTAINER_INFRA',
  'SPECIFICATION_SCHEMA',
  'DOCUMENTATION',
  'BINARY_COMPILED',
  'UNKNOWN_UNSUPPORTED',
]);
export type FileFormatCategory = z.infer<typeof FileFormatCategoryEnum>;

export const DetectedEncodingEnum = z.enum([
  'utf-8',
  'utf-16le',
  'utf-16be',
  'ascii',
  'iso-8859-1',
  'binary',
]);
export type DetectedEncoding = z.infer<typeof DetectedEncodingEnum>;

export const FileTypeInfoSchema = z.object({
  format_category: FileFormatCategoryEnum,
  language: z.string(),
  mime_type: z.string(),
  encoding: DetectedEncodingEnum,
  extension: z.string(),
  is_binary: z.boolean(),
  magic_signature: z.string().optional(),
  byte_size: z.number().int().min(0),
});
export type FileTypeInfo = z.infer<typeof FileTypeInfoSchema>;

// 2. Source Span Schema
export const SourceSpanSchema = z.object({
  file_path: z.string(),
  start_line: z.number().int().min(1),
  start_col: z.number().int().min(1),
  end_line: z.number().int().min(1),
  end_col: z.number().int().min(1),
  byte_offset_start: z.number().int().min(0),
  byte_offset_end: z.number().int().min(0),
  text_slice: z.string().optional(),
  symbol_hint: z.string().optional(),
});
export type SourceSpan = z.infer<typeof SourceSpanSchema>;

// 3. Symbol Extraction Types
export const SymbolKindEnum = z.enum([
  'FUNCTION',
  'ASYNC_FUNCTION',
  'GENERATOR_FUNCTION',
  'CLASS',
  'INTERFACE',
  'METHOD',
  'CONSTRUCTOR',
  'PROPERTY',
  'VARIABLE',
  'CONSTANT',
  'ENUM',
  'ENUM_MEMBER',
  'TYPE_ALIAS',
  'STRUCT',
  'TRAIT',
  'MODULE',
  'NAMESPACE',
  'DECORATOR',
  'MACRO',
]);
export type SymbolKind = z.infer<typeof SymbolKindEnum>;

export const SymbolVisibilityEnum = z.enum([
  'PUBLIC',
  'PRIVATE',
  'PROTECTED',
  'INTERNAL',
  'PACKAGE',
]);
export type SymbolVisibility = z.infer<typeof SymbolVisibilityEnum>;

export const SymbolParameterSchema = z.object({
  name: z.string(),
  type: z.string().optional(),
  default_value: z.string().optional(),
  is_rest: z.boolean().default(false),
});
export type SymbolParameter = z.infer<typeof SymbolParameterSchema>;

export const SymbolFactSchema = z.object({
  name: z.string(),
  kind: SymbolKindEnum,
  visibility: SymbolVisibilityEnum.default('PUBLIC'),
  span: SourceSpanSchema,
  docstring: z.string().optional(),
  parameters: z.array(SymbolParameterSchema).default([]),
  return_type: z.string().optional(),
  parent_symbol: z.string().optional(),
  modifiers: z.array(z.string()).default([]),
  decorators: z.array(z.string()).default([]),
});
export type SymbolFact = z.infer<typeof SymbolFactSchema>;

// 4. Imports & Exports Types
export const ImportKindEnum = z.enum([
  'STATIC',
  'DYNAMIC',
  'REQUIRE',
  'CONDITIONAL',
]);
export type ImportKind = z.infer<typeof ImportKindEnum>;

export const ImportedSymbolSchema = z.object({
  name: z.string(),
  alias: z.string().optional(),
  is_type_only: z.boolean().default(false),
  is_default: z.boolean().default(false),
  is_namespace: z.boolean().default(false),
});
export type ImportedSymbol = z.infer<typeof ImportedSymbolSchema>;

export const ImportFactSchema = z.object({
  module_specifier: z.string(),
  import_kind: ImportKindEnum.default('STATIC'),
  imported_symbols: z.array(ImportedSymbolSchema).default([]),
  raw_statement: z.string().optional(),
  span: SourceSpanSchema,
});
export type ImportFact = z.infer<typeof ImportFactSchema>;

export const ExportFactSchema = z.object({
  exported_symbol: z.string(),
  alias: z.string().optional(),
  is_default: z.boolean().default(false),
  is_reexport: z.boolean().default(false),
  source_module: z.string().optional(),
  raw_statement: z.string().optional(),
  span: SourceSpanSchema,
});
export type ExportFact = z.infer<typeof ExportFactSchema>;

// 5. Call Site / Invocation Types
export const CallSiteFactSchema = z.object({
  callee_name: z.string(),
  receiver: z.string().optional(),
  argument_count: z.number().int().default(0),
  arguments_summary: z.array(z.string()).default([]),
  is_await: z.boolean().default(false),
  span: SourceSpanSchema,
});
export type CallSiteFact = z.infer<typeof CallSiteFactSchema>;

// 6. Protocol Intelligence Types
export const ProtocolKindEnum = z.enum([
  'MCP',
  'A2A',
  'OPENAPI',
  'ASYNCAPI',
  'JSON_RPC',
  'GRPC_PROTOBUF',
  'GRAPHQL',
  'WEBSOCKET',
  'REST_HTTP',
]);
export type ProtocolKind = z.infer<typeof ProtocolKindEnum>;

export const McpToolSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  parameters_schema: z.record(z.string(), z.any()).optional(),
  span: SourceSpanSchema.optional(),
});
export type McpTool = z.infer<typeof McpToolSchema>;

export const McpPromptSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  arguments: z.array(z.object({ name: z.string(), required: z.boolean().default(false) })).default([]),
  span: SourceSpanSchema.optional(),
});
export type McpPrompt = z.infer<typeof McpPromptSchema>;

export const McpResourceSchema = z.object({
  uri: z.string(),
  name: z.string().optional(),
  mime_type: z.string().optional(),
  span: SourceSpanSchema.optional(),
});
export type McpResource = z.infer<typeof McpResourceSchema>;

export const McpDetailsSchema = z.object({
  role: z.enum(['SERVER', 'CLIENT', 'DUAL']),
  tools: z.array(McpToolSchema).default([]),
  prompts: z.array(McpPromptSchema).default([]),
  resources: z.array(McpResourceSchema).default([]),
  transports: z.array(z.enum(['stdio', 'sse', 'streamable_http', 'custom'])).default([]),
});
export type McpDetails = z.infer<typeof McpDetailsSchema>;

export const A2aDetailsSchema = z.object({
  agent_id: z.string().optional(),
  protocol_version: z.string().optional(),
  handshake_methods: z.array(z.string()).default([]),
  task_delegation_interfaces: z.array(z.string()).default([]),
  signing_methods: z.array(z.string()).default([]),
  agent_cards: z.array(z.object({
    name: z.string(),
    capabilities: z.array(z.string()).default([]),
    endpoint: z.string().optional(),
  })).default([]),
});
export type A2aDetails = z.infer<typeof A2aDetailsSchema>;

export const OpenApiEndpointSchema = z.object({
  path: z.string(),
  method: z.string(),
  operation_id: z.string().optional(),
  summary: z.string().optional(),
  description: z.string().optional(),
  parameters: z.array(z.string()).default([]),
  security_requirements: z.array(z.string()).default([]),
  span: SourceSpanSchema.optional(),
});
export type OpenApiEndpoint = z.infer<typeof OpenApiEndpointSchema>;

export const GrpcServiceSchema = z.object({
  name: z.string(),
  methods: z.array(z.object({
    name: z.string(),
    input_type: z.string(),
    output_type: z.string(),
    client_streaming: z.boolean().default(false),
    server_streaming: z.boolean().default(false),
  })).default([]),
});
export type GrpcService = z.infer<typeof GrpcServiceSchema>;

export const ProtocolFactSchema = z.object({
  protocol_kind: ProtocolKindEnum,
  version: z.string().optional(),
  title: z.string().optional(),
  endpoints: z.array(OpenApiEndpointSchema).default([]),
  mcp_details: McpDetailsSchema.optional(),
  a2a_details: A2aDetailsSchema.optional(),
  grpc_services: z.array(GrpcServiceSchema).default([]),
  jsonrpc_methods: z.array(z.string()).default([]),
  graphql_types: z.array(z.string()).default([]),
  span: SourceSpanSchema,
  confidence: z.number().min(0).max(1).default(1.0),
  detection_evidence: z.array(z.string()).default([]),
});
export type ProtocolFact = z.infer<typeof ProtocolFactSchema>;

// 7. Framework Fingerprinting Types
export const FrameworkCategoryEnum = z.enum([
  'AGENT_FRAMEWORK',
  'LLM_ORCHESTRATOR',
  'MULTI_AGENT',
  'BACKEND_WEB',
  'RPC_SERVICE',
  'CLI_TOOL',
  'DATABASE_ORM',
]);
export type FrameworkCategory = z.infer<typeof FrameworkCategoryEnum>;

export const FrameworkEvidenceSchema = z.object({
  type: z.enum(['IMPORT', 'MANIFEST_DEPENDENCY', 'DECORATOR', 'API_USAGE', 'CONFIG_FILE']),
  description: z.string(),
  span: SourceSpanSchema.optional(),
});
export type FrameworkEvidence = z.infer<typeof FrameworkEvidenceSchema>;

export const FrameworkFingerprintSchema = z.object({
  framework_name: z.string(),
  framework_category: FrameworkCategoryEnum,
  detected_version: z.string().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  evidence: z.array(FrameworkEvidenceSchema).default([]),
});
export type FrameworkFingerprint = z.infer<typeof FrameworkFingerprintSchema>;

// 8. Configuration Extraction Types
export const EnvVarRefSchema = z.object({
  name: z.string(),
  required: z.boolean().default(false),
  default_value: z.string().optional(),
  reference_kind: z.enum(['PROCESS_ENV', 'OS_ENV', 'DOCKERFILE_ENV', 'DOTENV', 'CONFIG_SCHEMA']),
  span: SourceSpanSchema,
});
export type EnvVarRef = z.infer<typeof EnvVarRefSchema>;

export const ToolDeclarationSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  parameters: z.record(z.string(), z.any()).optional(),
  declaration_kind: z.enum(['DECORATOR', 'FUNCTION_CALL', 'CLASS_METHOD', 'MANIFEST_SCHEMA']),
  span: SourceSpanSchema,
});
export type ToolDeclaration = z.infer<typeof ToolDeclarationSchema>;

export const ModelReferenceSchema = z.object({
  model_id: z.string(),
  provider: z.string().optional(),
  temperature: z.number().optional(),
  max_tokens: z.number().optional(),
  span: SourceSpanSchema,
});
export type ModelReference = z.infer<typeof ModelReferenceSchema>;

export const PermissionCapabilityEnum = z.enum([
  'FILESYSTEM',
  'NETWORK',
  'SUBPROCESS_EXEC',
  'DATABASE',
  'BROWSER_AUTOMATION',
  'AUDIO_MEDIA',
  'GEOLOCATION',
  'ENVIRONMENT_ACCESS',
]);
export type PermissionCapability = z.infer<typeof PermissionCapabilityEnum>;

export const PermissionRefSchema = z.object({
  capability: PermissionCapabilityEnum,
  description: z.string(),
  span: SourceSpanSchema,
});
export type PermissionRef = z.infer<typeof PermissionRefSchema>;

export const DeploymentComputeSchema = z.object({
  base_image: z.string().optional(),
  ports: z.array(z.number().int()).default([]),
  entrypoint: z.array(z.string()).default([]),
  cmd: z.array(z.string()).default([]),
  workdir: z.string().optional(),
  healthcheck: z.string().optional(),
  span: SourceSpanSchema.optional(),
});
export type DeploymentCompute = z.infer<typeof DeploymentComputeSchema>;

export const SecretReferenceSchema = z.object({
  secret_name: z.string(),
  category: z.enum(['API_KEY', 'BEARER_TOKEN', 'PASSWORD', 'PRIVATE_KEY', 'VAULT_SECRET']),
  detection_kind: z.enum(['ENV_PATTERN', 'VAULT_CLIENT', 'CONFIG_KEY', 'HIGH_ENTROPY_LITERAL']),
  is_masked: z.boolean().default(true),
  span: SourceSpanSchema,
});
export type SecretReference = z.infer<typeof SecretReferenceSchema>;

export const ConfigurationFactSchema = z.object({
  env_vars: z.array(EnvVarRefSchema).default([]),
  tools: z.array(ToolDeclarationSchema).default([]),
  models: z.array(ModelReferenceSchema).default([]),
  permissions: z.array(PermissionRefSchema).default([]),
  deployment: DeploymentComputeSchema.optional(),
  secrets: z.array(SecretReferenceSchema).default([]),
});
export type ConfigurationFact = z.infer<typeof ConfigurationFactSchema>;

// 9. Parsed File Facts Schema
export const ParserStatusEnum = z.enum([
  'SUCCESS',
  'PARTIAL_SUCCESS',
  'UNSUPPORTED_LANGUAGE',
  'PARSE_ERROR',
  'BINARY_PRESERVED',
]);
export type ParserStatus = z.infer<typeof ParserStatusEnum>;

export const ParsedSourceFactsSchema = z.object({
  file_path: z.string(),
  file_type: FileTypeInfoSchema,
  parser_id: z.string(),
  parser_version: z.string(),
  status: ParserStatusEnum,
  confidence: z.number().min(0).max(1).default(1.0),
  partial_coverage_reason: z.string().optional(),
  error_details: z.object({
    message: z.string(),
    line: z.number().int().optional(),
    col: z.number().int().optional(),
    offset: z.number().int().optional(),
  }).optional(),
  symbols: z.array(SymbolFactSchema).default([]),
  imports: z.array(ImportFactSchema).default([]),
  exports: z.array(ExportFactSchema).default([]),
  call_sites: z.array(CallSiteFactSchema).default([]),
  protocols: z.array(ProtocolFactSchema).default([]),
  frameworks: z.array(FrameworkFingerprintSchema).default([]),
  configuration: ConfigurationFactSchema,
  raw_content_preview: z.string().optional(),
  provenance: ProvenanceRecordSchema,
});
export type ParsedSourceFacts = z.infer<typeof ParsedSourceFactsSchema>;

// 10. Aggregated Artifact Result Schema
export const ArtifactParseResultSchema = z.object({
  artifact_id: z.string(),
  total_files: z.number().int().default(0),
  parsed_files: z.number().int().default(0),
  partial_files: z.number().int().default(0),
  unsupported_files: z.number().int().default(0),
  failed_files: z.number().int().default(0),
  byte_coverage_ratio: z.number().min(0).max(1).default(1.0),
  total_symbols: z.number().int().default(0),
  total_protocols: z.number().int().default(0),
  total_frameworks: z.number().int().default(0),
  total_env_vars: z.number().int().default(0),
  total_tools: z.number().int().default(0),
  total_models: z.number().int().default(0),
  file_facts: z.array(ParsedSourceFactsSchema).default([]),
  aggregate_frameworks: z.array(FrameworkFingerprintSchema).default([]),
  aggregate_protocols: z.array(ProtocolFactSchema).default([]),
  aggregate_env_vars: z.array(z.object({
    name: z.string(),
    occurrences: z.number().int(),
    required: z.boolean(),
  })).default([]),
  aggregate_models: z.array(z.object({
    model_id: z.string(),
    provider: z.string().optional(),
    count: z.number().int(),
  })).default([]),
  aggregate_tools: z.array(z.object({
    name: z.string(),
    description: z.string().optional(),
  })).default([]),
  unsupported_artifacts: z.array(z.object({
    file_path: z.string(),
    reason: z.string(),
  })).default([]),
  provenance: ProvenanceRecordSchema,
});
export type ArtifactParseResult = z.infer<typeof ArtifactParseResultSchema>;
