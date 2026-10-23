import { z } from 'zod';

export const EVENT_SCHEMA_VERSION = '2.0.1' as const;

export interface EventProducer {
  service_name: string;
  version: string;
  host?: string;
}

export const EventProducerSchema = z.object({
  service_name: z.string().min(1),
  version: z.string().min(1),
  host: z.string().optional(),
});

export interface EventEnvelope<T = unknown> {
  event_id: string;
  event_type: string;
  schema_version: string;
  aggregate_id: string;
  aggregate_type: string;
  occurred_at: string;
  correlation_id: string;
  causation_id?: string | null;
  producer: EventProducer;
  payload: T;
}

export function createEventEnvelope<T>(params: {
  event_id?: string;
  event_type: string;
  schema_version?: string;
  aggregate_id: string;
  aggregate_type: string;
  correlation_id: string;
  causation_id?: string | null;
  producer: EventProducer;
  payload: T;
  occurred_at?: string;
}): EventEnvelope<T> {
  return {
    event_id: params.event_id || `evt-${crypto.randomUUID()}`,
    event_type: params.event_type,
    schema_version: params.schema_version || EVENT_SCHEMA_VERSION,
    aggregate_id: params.aggregate_id,
    aggregate_type: params.aggregate_type,
    occurred_at: params.occurred_at || new Date().toISOString(),
    correlation_id: params.correlation_id,
    causation_id: params.causation_id || null,
    producer: params.producer,
    payload: params.payload,
  };
}

export function createEventEnvelopeSchema<T extends z.ZodTypeAny>(payloadSchema: T) {
  return z.object({
    event_id: z.string().min(1),
    event_type: z.string().min(1),
    schema_version: z.string().min(1),
    aggregate_id: z.string().min(1),
    aggregate_type: z.string().min(1),
    occurred_at: z.string().datetime(),
    correlation_id: z.string().min(1),
    causation_id: z.string().nullable().optional(),
    producer: EventProducerSchema,
    payload: payloadSchema,
  });
}
