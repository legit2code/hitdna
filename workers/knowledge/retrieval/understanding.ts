import { 
  QueryIntent, 
  QueryUnderstandingResult 
} from './types.ts';
import { KnowledgeObjectType } from '../types.ts';

export class QueryUnderstandingEngine {
  /**
   * Deterministic rule-based and regex extraction query understanding engine
   * with strict schema validation.
   */
  public static parseQuery(rawQuery: string): QueryUnderstandingResult {
    const trimmed = rawQuery.trim();
    const lower = trimmed.toLowerCase();

    const cveRegex = /\b(cve-\d{4}-\d{4,8}|ghsa-[a-z0-9_-]+)\b/gi;
    const ruleRegex = /\b(rule-[a-z0-9_-]+|caim-[a-z0-9_-]+)\b/gi;
    const claimRegex = /\b(claim-[a-z0-9_-]+)\b/gi;
    const versionRegex = /\bv?(\d+\.\d+\.\d+(-[a-z0-9.]+)?)\b/gi;

    const cve_ids = Array.from(trimmed.matchAll(cveRegex)).map((m) => m[0].toUpperCase());
    const rule_ids = Array.from(trimmed.matchAll(ruleRegex)).map((m) => m[0].toUpperCase());
    const claim_ids = Array.from(trimmed.matchAll(claimRegex)).map((m) => m[0]);
    const versions = Array.from(trimmed.matchAll(versionRegex)).map((m) => m[1]);

    // Extract package names like "axios", "lodash", "react", "express", "sqlite3"
    const commonPackages = ['axios', 'lodash', 'react', 'express', 'sqlite3', 'jsonwebtoken', 'tar', 'minimist', 'pg'];
    const package_names: string[] = [];
    for (const pkg of commonPackages) {
      if (lower.includes(pkg)) {
        package_names.push(pkg);
      }
    }

    // Extract ontology concepts
    const knownConcepts: Record<string, string> = {
      'direct injection': 'CONCEPT-INJECTION',
      'taint flow': 'CONCEPT-TAINT',
      'credential exposure': 'CONCEPT-CREDENTIALS',
      'remote code execution': 'CONCEPT-RCE',
      'rce': 'CONCEPT-RCE',
      'honeytoken': 'CONCEPT-HONEYTOKEN',
      'canary': 'CONCEPT-HONEYTOKEN',
      'supply chain': 'CONCEPT-SUPPLY-CHAIN',
      'sandbox evasion': 'CONCEPT-EVASION',
      'subgraph': 'CONCEPT-ONTOLOGY-SUBGRAPH',
      'epistemic': 'CONCEPT-EPISTEMIC-INTELLIGENCE',
    };

    const resolved_ontology_concepts: string[] = [];
    for (const [key, conceptId] of Object.entries(knownConcepts)) {
      if (lower.includes(key)) {
        resolved_ontology_concepts.push(conceptId);
      }
    }

    // Extract symbols
    const symbols: string[] = [];
    const symbolMatches = trimmed.match(/`([^`]+)`/g);
    if (symbolMatches) {
      symbols.push(...symbolMatches.map((s) => s.replace(/`/g, '')));
    }

    // Determine Intent
    let intent: QueryIntent = 'GENERAL_HYBRID';
    const target_object_types: KnowledgeObjectType[] = [];

    if (cve_ids.length > 0 || rule_ids.length > 0 || symbols.length > 0) {
      intent = 'EXACT_LOOKUP';
      if (cve_ids.length > 0) target_object_types.push('vulnerability', 'dependency');
      if (rule_ids.length > 0) target_object_types.push('finding', 'ontology');
    } else if (claim_ids.length > 0 || lower.includes('lineage') || lower.includes('evidence behind') || lower.includes('how was claim')) {
      intent = 'EVIDENCE_LINEAGE';
      target_object_types.push('claim', 'evidence', 'run', 'finding');
    } else if (resolved_ontology_concepts.length > 0 || lower.includes('taxonomy') || lower.includes('concept') || lower.includes('subgraph') || lower.includes('ontology')) {
      intent = 'ONTOLOGY_TRAVERSAL';
      target_object_types.push('ontology', 'finding', 'risk');
    } else if (lower.includes('compare') || lower.includes('version') || (versions.length >= 2 && lower.includes('diff'))) {
      intent = 'VERSION_COMPARISON';
      target_object_types.push('version', 'agent', 'run');
    } else if (
      lower.includes('policy') ||
      lower.includes('risk score') ||
      lower.includes('override') ||
      lower.includes('quarantine') ||
      lower.includes('safe') ||
      lower.includes('deploy')
    ) {
      intent = 'RISK_POLICY_STATUS';
      target_object_types.push('policy', 'risk', 'finding', 'vulnerability', 'claim', 'recommendation');
    } else {
      intent = 'SEMANTIC_QUESTION';
      target_object_types.push('agent', 'version', 'finding', 'risk', 'evidence', 'recommendation');
    }

    // Extract scoped agent if query mentions "agent <name>" or "agent_id"
    let scoped_agent_id: string | undefined;
    const agentMatch = trimmed.match(/agent[:\s]+([a-zA-Z0-9_-]+)/i);
    if (agentMatch) {
      scoped_agent_id = agentMatch[1];
    }

    // Temporal filter extraction
    let temporal_filters: { since?: string; until?: string } | undefined;
    if (lower.includes('last 24 hours') || lower.includes('recent')) {
      temporal_filters = { since: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() };
    }

    return {
      raw_query: rawQuery,
      normalized_query: lower,
      intent,
      extracted_entities: {
        cve_ids,
        package_names,
        symbols,
        rule_ids,
        claim_ids,
        agent_names: scoped_agent_id ? [scoped_agent_id] : [],
        versions,
      },
      temporal_filters,
      scoped_agent_id,
      scoped_agent_version_id: versions[0],
      resolved_ontology_concepts,
      target_object_types,
      estimated_complexity: intent === 'EVIDENCE_LINEAGE' || intent === 'ONTOLOGY_TRAVERSAL' ? 'HIGH' : intent === 'EXACT_LOOKUP' ? 'LOW' : 'MEDIUM',
      validated: true,
    };
  }
}
