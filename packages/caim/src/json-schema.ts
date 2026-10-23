import { CAIM_SPEC_VERSION } from './types.ts';

/**
 * Standard JSON Schemas for CAIM models for worker/API interoperability.
 */
export function getCaimManifestJsonSchema(): Record<string, unknown> {
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: 'CaimManifest',
    description: `Common Artifact Intelligence Model Manifest (v${CAIM_SPEC_VERSION})`,
    type: 'object',
    required: ['caim_version', 'agent', 'version'],
    properties: {
      caim_version: { type: 'string', enum: [CAIM_SPEC_VERSION] },
      agent: {
        type: 'object',
        required: ['agent_id', 'canonical_name', 'status', 'identity_confidence'],
        properties: {
          _entity_kind: { type: 'string', enum: ['CANONICAL_AGENT'] },
          agent_id: { type: 'string', format: 'uuid' },
          canonical_name: { type: 'string' },
          description: { type: 'string' },
          agent_type_concept_id: { type: 'string' },
          status: { type: 'string', enum: ['ACTIVE', 'DEPRECATED', 'SUSPENDED', 'MERGED'] },
          identity_confidence: { type: 'number', minimum: 0, maximum: 1 },
        },
      },
      version: {
        type: 'object',
        required: ['agent_version_id', 'agent_id', 'content_fingerprint'],
        properties: {
          _entity_kind: { type: 'string', enum: ['AGENT_VERSION'] },
          agent_version_id: { type: 'string', format: 'uuid' },
          agent_id: { type: 'string', format: 'uuid' },
          version_label: { type: 'string' },
          source_commit: { type: 'string' },
          content_fingerprint: { type: 'string' },
          release_date: { type: 'string', format: 'date-time' },
          supersedes_version_id: { type: 'string', format: 'uuid' },
        },
      },
      distributions: { type: 'array' },
      components: { type: 'array' },
      dependencies: { type: 'array' },
      tools: { type: 'array' },
      tool_bindings: { type: 'array' },
      protocols: { type: 'array' },
      protocol_capabilities: { type: 'array' },
      capabilities: { type: 'array' },
      permissions: { type: 'array' },
      entrypoints: { type: 'array' },
      runtimes: { type: 'array' },
      endpoints: { type: 'array' },
      models: { type: 'array' },
      datasets: { type: 'array' },
      prompts: { type: 'array' },
      configurations: { type: 'array' },
      credentials: { type: 'array' },
      data_access_requirements: { type: 'array' },
    },
  };
}
