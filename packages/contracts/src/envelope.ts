import { z } from 'zod';
import { ProvenanceRecord, ProvenanceRecordSchema } from './provenance.ts';
import { SecurityClassification, SecurityClassificationEnum } from './enums.ts';

export const INTELLIGENCE_ENVELOPE_VERSION = '2.0.1' as const;

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const uuidSchema = z.string().regex(uuidRegex, 'Invalid UUID');

export interface IntelligenceProducer {
  engine_key: string;
  engine_version: string;
  ruleset_version?: string;
  model_version?: string;
}

export const IntelligenceProducerSchema = z.object({
  engine_key: z.string().min(1),
  engine_version: z.string().min(1),
  ruleset_version: z.string().optional(),
  model_version: z.string().optional(),
});

export interface IntelligenceEnvelope<T = unknown> {
  readonly envelope_version: typeof INTELLIGENCE_ENVELOPE_VERSION;
  envelope_id: string;
  pipeline_version: string;
  caim_version: string;
  ontology_version: string;
  analysis_run_id: string;
  stage_run_id?: string;
  agent_version_id: string;
  scope_id: string;
  security_classification: SecurityClassification;
  producer: IntelligenceProducer;
  created_at: string;
  payload: T;
  provenance: ProvenanceRecord;
}

export function createIntelligenceEnvelopeSchema<T extends z.ZodTypeAny>(payloadSchema: T) {
  return z.object({
    envelope_version: z.literal(INTELLIGENCE_ENVELOPE_VERSION),
    envelope_id: uuidSchema,
    pipeline_version: z.string().min(1),
    caim_version: z.string().min(1),
    ontology_version: z.string().min(1),
    analysis_run_id: uuidSchema,
    stage_run_id: uuidSchema.optional(),
    agent_version_id: uuidSchema,
    scope_id: uuidSchema,
    security_classification: SecurityClassificationEnum,
    producer: IntelligenceProducerSchema,
    created_at: z.string().datetime(),
    payload: payloadSchema,
    provenance: ProvenanceRecordSchema,
  });
}

export function wrapInIntelligenceEnvelope<T>(params: {
  envelope_id?: string;
  pipeline_version: string;
  caim_version?: string;
  ontology_version?: string;
  analysis_run_id: string;
  stage_run_id?: string;
  agent_version_id: string;
  scope_id: string;
  security_classification: SecurityClassification;
  producer: IntelligenceProducer;
  payload: T;
  provenance: ProvenanceRecord;
}): IntelligenceEnvelope<T> {
  return {
    envelope_version: INTELLIGENCE_ENVELOPE_VERSION,
    envelope_id: params.envelope_id || crypto.randomUUID(),
    pipeline_version: params.pipeline_version,
    caim_version: params.caim_version || '2.0.1',
    ontology_version: params.ontology_version || '2.0.1',
    analysis_run_id: params.analysis_run_id,
    stage_run_id: params.stage_run_id,
    agent_version_id: params.agent_version_id,
    scope_id: params.scope_id,
    security_classification: params.security_classification,
    producer: params.producer,
    created_at: new Date().toISOString(),
    payload: params.payload,
    provenance: params.provenance,
  };
}
