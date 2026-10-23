import { z } from 'zod';

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const uuidSchema = z.string().regex(uuidRegex, 'Invalid UUID');

export const SourceSpanLocatorSchema = z.object({
  artifact_file_id: uuidSchema.optional(),
  file_path: z.string().min(1),
  start_line: z.number().int().min(1),
  start_col: z.number().int().min(1),
  end_line: z.number().int().min(1),
  end_col: z.number().int().min(1),
  byte_offset_start: z.number().int().optional(),
  byte_offset_end: z.number().int().optional(),
  symbol_hint: z.string().optional(),
});
export type SourceSpanLocator = z.infer<typeof SourceSpanLocatorSchema>;

export const ProvenanceRecordSchema = z.object({
  provenance_id: uuidSchema,
  source_spans: z.array(SourceSpanLocatorSchema).default([]),
  input_hashes: z.array(z.string()).default([]),
  rule_id: z.string().optional(),
  ruleset_version: z.string().optional(),
  calibration_version: z.string().optional(),
  transformation_type: z.enum(['DIRECT_EXTRACTION', 'SYNTAX_TRANSFORMATION', 'CALIBRATED_INFERENCE', 'EXTERNAL_ENRICHMENT', 'HEURISTIC_ESTIMATE']),
  confidence: z.number().min(0).max(1).default(1.0),
  derived_at: z.string().datetime(),
  engine_signature: z.string().min(1),
});
export type ProvenanceRecord = z.infer<typeof ProvenanceRecordSchema>;
