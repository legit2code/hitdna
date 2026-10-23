import { RetrievedDocument } from '../retrieval/types.ts';
import { SerializedFact } from './types.ts';
import { SecurityClassificationCode, SecurityClassificationRank, CLASSIFICATION_CODE_TO_RANK } from '@caim/auth/types.ts';
import crypto from 'crypto';

export class StructuredFactSerializer {
  /**
   * Converts a raw retrieved document into a strongly-typed, sanitized, and verifiable SerializedFact.
   */
  public static serialize(doc: RetrievedDocument): SerializedFact {
    const rawContent = doc.full_content || '';
    
    // Hash content to provide integrity checksum
    const checksum = crypto.createHash('sha256').update(`${doc.object_type}:${doc.entity_ref_id}:${rawContent}`).digest('hex').substring(0, 16);

    const classification = (doc.security_classification || 'INTERNAL') as SecurityClassificationCode;
    const rank = CLASSIFICATION_CODE_TO_RANK[classification] ?? SecurityClassificationRank.INTERNAL;

    const formatted = this.formatFactContent(doc, checksum);
    const token_estimate = Math.ceil(formatted.length / 4);
    const structured_attributes = StructuredFactSerializer.extractStructuredAttributes(doc);

    return {
      fact_id: `fact-${doc.object_type}-${doc.entity_ref_id}`,
      entity_ref_id: doc.entity_ref_id,
      entity_type: doc.object_type,
      security_classification: classification,
      security_rank: rank,
      agent_id: doc.agent_id,
      agent_version_id: doc.agent_version_id,
      analysis_run_id: doc.analysis_run_id,
      token_estimate,
      formatted_content: formatted,
      source_retriever: doc.retriever_source || 'VECTOR_SEMANTIC',
      checksum,
      vault_restricted: Boolean(doc.vault_restricted),
      title: doc.title,
      raw_content: doc.full_content,
      payload: doc.payload,
      structured_attributes,
    };
  }

  private static extractStructuredAttributes(doc: RetrievedDocument): SerializedFact['structured_attributes'] {
    const payload = doc.payload || {};
    const exact = doc.exact_keywords || {};
    const content = doc.full_content || '';

    // 1. Severity
    let severity: string | null = payload.severity || exact.severity || null;
    if (!severity) {
      const match = content.match(/\bSeverity:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\b/i);
      if (match) severity = match[1].toUpperCase();
    }

    // 2. CVSS Score
    let cvss_score: number | null = null;
    if (payload.cvss_score !== undefined && payload.cvss_score !== null) {
      cvss_score = Number(payload.cvss_score);
    } else if (exact.cvss_score !== undefined && exact.cvss_score !== null) {
      cvss_score = Number(exact.cvss_score);
    } else {
      const match = content.match(/\bCVSS(?:\s*v3)?:\s*([0-9]+(?:\.[0-9]+)?)/i);
      if (match) cvss_score = parseFloat(match[1]);
    }

    // 3. Sinks
    const sinks: string[] = [];
    if (Array.isArray(payload.reachable_sinks)) {
      sinks.push(...payload.reachable_sinks);
    } else if (payload.sink) {
      sinks.push(payload.sink);
    }
    const sinkMatches = content.match(/Reachable Sinks:\s*([^\n]+)/i);
    if (sinkMatches && sinkMatches[1] !== 'None') {
      const parsedSinks = sinkMatches[1].split(',').map((s) => s.trim()).filter(Boolean);
      for (const ps of parsedSinks) {
        if (!sinks.includes(ps)) sinks.push(ps);
      }
    }

    // 4. File path and line
    const file_path = payload.file_path || exact.file_path || null;
    const line_number = payload.line_number || exact.line_number || null;

    // 5. Rule ID
    const rule_id = payload.rule_id || exact.rule_id || null;

    // 6. Outcome
    let outcome: string | null = payload.outcome || exact.outcome || null;
    if (!outcome) {
      const match = content.match(/\bOutcome:\s*([A-Z_]+)\b/);
      if (match) outcome = match[1];
    }

    // 7. Package Name
    const package_name = payload.package_name || exact.package_name || null;

    // 8. Observation
    let observation: string | null = payload.observation || null;
    if (!observation) {
      const match = content.match(/Observation:\s*([^\n]+)/i);
      if (match) observation = match[1].trim();
    }

    // 9. Statement
    let statement: string | null = payload.statement || payload.claim_text || null;
    if (!statement) {
      const match = content.match(/Statement:\s*([^\n]+)/i);
      if (match) statement = match[1].trim();
    }

    // 10. Claim state
    const claim_state = payload.claim_state || exact.claim_state || null;

    // 11. Category
    const category = payload.category || exact.category || null;

    // 12. Fixed version
    const fixed_version = payload.fixed_version || exact.fixed_version || null;

    return {
      severity,
      cvss_score,
      sinks,
      file_path,
      line_number: line_number ? Number(line_number) : null,
      rule_id,
      outcome,
      package_name,
      observation,
      statement,
      claim_state,
      category,
      fixed_version,
    };
  }

  private static formatFactContent(doc: RetrievedDocument, checksum: string): string {
    const lines: string[] = [];
    lines.push(`<knowledge_fact type="${doc.object_type}" id="${doc.entity_ref_id}" checksum="${checksum}" class="${doc.security_classification}">`);

    if (doc.agent_id) lines.push(`  <scope agent_id="${doc.agent_id}" ${doc.agent_version_id ? `version_id="${doc.agent_version_id}"` : ''} ${doc.analysis_run_id ? `run_id="${doc.analysis_run_id}"` : ''} />`);

    if (doc.exact_keywords && Object.keys(doc.exact_keywords).length > 0) {
      const keys = Object.entries(doc.exact_keywords)
        .filter(([_, v]) => Boolean(v))
        .map(([k, v]) => `${k}="${Array.isArray(v) ? v.join(',') : v}"`)
        .join(' ');
      if (keys) {
        lines.push(`  <exact_identifiers ${keys} />`);
      }
    }

    if (doc.lineage_trail) {
      lines.push(`  <lineage_trail claim_id="${doc.lineage_trail.claim_id || ''}" evidence_id="${doc.lineage_trail.evidence_id || ''}" confidence="${doc.lineage_trail.confidence || 1.0}" />`);
    }

    lines.push(`  <content>`);
    // Indent content lines
    const contentLines = doc.full_content.split('\n');
    for (const cl of contentLines) {
      lines.push(`    ${cl.trimEnd()}`);
    }
    lines.push(`  </content>`);
    lines.push(`</knowledge_fact>`);

    return lines.join('\n');
  }
}
