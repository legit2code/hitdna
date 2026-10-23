import { 
  OntologyMappingRule, 
  OntologyInferenceRule, 
  InferenceProvenance 
} from './types.ts';
import { 
  OntologyMappingRuleSchema, 
  OntologyInferenceRuleSchema, 
  InferenceProvenanceSchema 
} from './schemas.ts';

export function createMappingRule(params: Omit<OntologyMappingRule, 'rule_id'> & { rule_id?: string }): OntologyMappingRule {
  const rule: OntologyMappingRule = {
    rule_id: params.rule_id || `rule_map_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    ...params,
  };
  return OntologyMappingRuleSchema.parse(rule) as OntologyMappingRule;
}

export function createInferenceRule(params: Omit<OntologyInferenceRule, 'inference_rule_id'> & { inference_rule_id?: string }): OntologyInferenceRule {
  const rule: OntologyInferenceRule = {
    inference_rule_id: params.inference_rule_id || `rule_inf_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    ...params,
  };
  return OntologyInferenceRuleSchema.parse(rule) as OntologyInferenceRule;
}

export function recordInferenceProvenance(params: {
  provenance_id?: string;
  inference_rule_id: string;
  engine_key: string;
  engine_version: string;
  input_entity_ref_ids: string[];
  derived_concept_id: string;
  confidence: number;
  inferred_at?: string;
}): InferenceProvenance {
  const prov: InferenceProvenance = {
    provenance_id: params.provenance_id || crypto.randomUUID(),
    inference_rule_id: params.inference_rule_id,
    engine_key: params.engine_key,
    engine_version: params.engine_version,
    input_entity_ref_ids: params.input_entity_ref_ids,
    derived_concept_id: params.derived_concept_id,
    confidence: params.confidence,
    inferred_at: params.inferred_at || new Date().toISOString(),
  };
  return InferenceProvenanceSchema.parse(prov) as InferenceProvenance;
}
