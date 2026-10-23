import { INTELLIGENCE_ENVELOPE_VERSION } from './envelope.ts';

export function getIntelligenceEnvelopeJsonSchema(): Record<string, unknown> {
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: 'IntelligenceEnvelope',
    description: `Durable shared intelligence envelope (v${INTELLIGENCE_ENVELOPE_VERSION})`,
    type: 'object',
    required: [
      'envelope_version',
      'envelope_id',
      'pipeline_version',
      'caim_version',
      'ontology_version',
      'analysis_run_id',
      'agent_version_id',
      'scope_id',
      'security_classification',
      'producer',
      'created_at',
      'payload',
      'provenance',
    ],
    properties: {
      envelope_version: { type: 'string', enum: [INTELLIGENCE_ENVELOPE_VERSION] },
      envelope_id: { type: 'string', format: 'uuid' },
      pipeline_version: { type: 'string' },
      caim_version: { type: 'string' },
      ontology_version: { type: 'string' },
      analysis_run_id: { type: 'string', format: 'uuid' },
      stage_run_id: { type: 'string', format: 'uuid' },
      agent_version_id: { type: 'string', format: 'uuid' },
      scope_id: { type: 'string', format: 'uuid' },
      security_classification: {
        type: 'string',
        enum: ['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED'],
      },
      producer: {
        type: 'object',
        required: ['engine_key', 'engine_version'],
        properties: {
          engine_key: { type: 'string' },
          engine_version: { type: 'string' },
          ruleset_version: { type: 'string' },
          model_version: { type: 'string' },
        },
      },
      created_at: { type: 'string', format: 'date-time' },
      payload: { type: 'object' },
      provenance: {
        type: 'object',
        required: ['provenance_id', 'derived_at', 'engine_signature'],
        properties: {
          provenance_id: { type: 'string', format: 'uuid' },
          source_spans: { type: 'array' },
          input_hashes: { type: 'array', items: { type: 'string' } },
          rule_id: { type: 'string' },
          ruleset_version: { type: 'string' },
          calibration_version: { type: 'string' },
          transformation_type: { type: 'string' },
          confidence: { type: 'number', minimum: 0, maximum: 1 },
          derived_at: { type: 'string', format: 'date-time' },
          engine_signature: { type: 'string' },
        },
      },
    },
  };
}
