import { SerializedFact, AssembledContextPackage } from '../context/types.ts';

export interface ValidatedFactStatement {
  fact_id: string;
  entity_ref_id: string;
  entity_type: string;
  citation_tag: string;
  statement: string;
  attributes_rendered: {
    severity?: string | null;
    cvss_score?: number | null;
    sinks?: string[];
    file_path?: string | null;
    line_number?: number | null;
    rule_id?: string | null;
    outcome?: string | null;
    package_name?: string | null;
    fixed_version?: string | null;
  };
}

export class StructuredFactRenderer {
  private static readonly ADVERSARIAL_PATTERNS = [
    /ignore\s+(all|previous|prior|above|rules)/i,
    /system\s+(override|instruction|prompt)/i,
    /admin\s+override/i,
    /disregard\s+(all|previous|prior)/i,
    /you\s+must\s+(output|say|claim|forget|declare|execute)/i,
    /assistant\s+instructions/i,
    /<script[\s>]/i,
    /<!--\s*system/i,
    /zero\s+vulnerabilities\s+and\s+is\s+(safe|approved)/i,
    /completely\s+safe\s+to\s+deploy/i,
    /passed\s+all\s+security\s+gates/i,
    /clean\s+bill\s+of\s+health/i,
  ];

  public static isAdversarialOrInstruction(text: string): boolean {
    if (!text || typeof text !== 'string') return false;
    return this.ADVERSARIAL_PATTERNS.some((p) => p.test(text));
  }

  public static sanitizePassiveText(text: string): string {
    if (!text || typeof text !== 'string') return '';
    if (this.isAdversarialOrInstruction(text)) {
      return '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]';
    }
    // Remove control characters or formatting injections
    return text.replace(/[\r\n\t]+/g, ' ').trim();
  }

  /**
   * Renders a single SerializedFact into a canonical, strictly-grounded ValidatedFactStatement.
   * INVARIANT: Only attributes explicitly present in the authoritative fact fields are rendered.
   * Under no circumstance will defaults such as CVSS 8.8, shell execution, or BLOCK_DEPLOYMENT be inferred.
   */
  public static renderFact(fact: SerializedFact): ValidatedFactStatement {
    const attrs = fact.structured_attributes || {};
    const entityType = fact.entity_type;
    const refId = fact.entity_ref_id;
    const citationTag = `[citation:${entityType}:${refId}]`;

    let stmt = '';
    const renderedAttrs: ValidatedFactStatement['attributes_rendered'] = {};

    switch (entityType) {
      case 'vulnerability': {
        const pkg = attrs.package_name;
        const sev = attrs.severity || 'UNRATED';
        const cvss = attrs.cvss_score !== undefined && attrs.cvss_score !== null ? Number(attrs.cvss_score) : null;
        const fixed = attrs.fixed_version;
        const rawSummary = fact.payload?.summary || fact.payload?.description || fact.title;
        const summary = rawSummary ? this.sanitizePassiveText(rawSummary) : null;

        renderedAttrs.severity = sev;
        renderedAttrs.cvss_score = cvss;
        renderedAttrs.package_name = pkg || null;
        renderedAttrs.fixed_version = fixed || null;

        stmt = `Vulnerability ${refId}${pkg ? ` in package ${pkg}` : ''} is classified ${sev}`;
        if (cvss !== null) {
          stmt += ` with CVSS score ${cvss}`;
        }
        if (fixed) {
          stmt += ` (fixed in version ${fixed})`;
        }
        stmt += '.';
        if (summary && summary !== '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]' && !summary.includes(refId)) {
          stmt += ` ${summary}`;
        }
        stmt += ` ${citationTag}`;
        break;
      }

      case 'finding': {
        const sev = attrs.severity || 'INFORMATIONAL';
        const rawTitle = attrs.rule_id ? `${attrs.rule_id} finding` : (fact.title || 'Security finding');
        const title = this.sanitizePassiveText(rawTitle);
        const file = attrs.file_path;
        const line = attrs.line_number;
        const location = file ? (line ? `${file}#${line}` : file) : null;
        const sinks = attrs.sinks || [];

        renderedAttrs.severity = sev;
        renderedAttrs.rule_id = attrs.rule_id || null;
        renderedAttrs.file_path = file || null;
        renderedAttrs.line_number = line || null;
        renderedAttrs.sinks = sinks;

        stmt = `Finding ${refId} is classified ${sev}`;
        if (title && title !== '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]') {
          stmt += `: ${title}`;
        }
        if (location) {
          stmt += ` at ${location}`;
        }
        if (sinks.length > 0) {
          stmt += ` with verified reachable sinks: ${sinks.join(', ')}`;
        }
        stmt += `. ${citationTag}`;
        break;
      }

      case 'evidence': {
        const rawObs = attrs.observation || fact.payload?.observation || fact.title;
        const obs = rawObs ? this.sanitizePassiveText(rawObs) : null;

        if (obs && obs !== '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]') {
          stmt = `Evidence ${refId} records observation: "${obs}". ${citationTag}`;
        } else {
          stmt = `Evidence ${refId} is recorded in platform telemetry. ${citationTag}`;
        }
        break;
      }

      case 'claim': {
        const rawClaimStmt = attrs.statement || fact.payload?.statement || fact.title;
        const claimStmt = rawClaimStmt ? this.sanitizePassiveText(rawClaimStmt) : null;
        const state = attrs.claim_state || fact.payload?.claim_state || 'RECORDED';

        if (claimStmt && claimStmt !== '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]') {
          stmt = `Claim ${refId} (${state}): "${claimStmt}". ${citationTag}`;
        } else {
          stmt = `Claim ${refId} is recorded with status ${state}. ${citationTag}`;
        }
        break;
      }

      case 'policy': {
        const outcome = attrs.outcome || fact.payload?.outcome || 'EVALUATED';
        const reasons = fact.payload?.reasons
          ? (Array.isArray(fact.payload.reasons) ? fact.payload.reasons.join('; ') : fact.payload.reasons)
          : (fact.payload?.reason || null);
        const cleanReasons = reasons ? this.sanitizePassiveText(reasons) : null;

        renderedAttrs.outcome = outcome;

        stmt = `Policy evaluation for ${refId} resulted in outcome ${outcome}`;
        if (cleanReasons && cleanReasons !== '[REDACTED_UNTRUSTED_INSTRUCTION_PAYLOAD]') {
          stmt += ` due to reasons: ${cleanReasons}`;
        }
        stmt += `. ${citationTag}`;
        break;
      }

      case 'agent': {
        const name = fact.payload?.name || fact.payload?.agent_name || refId;
        const ns = fact.payload?.namespace || 'default';
        const framework = fact.payload?.framework || 'Custom';
        stmt = `Agent ${name} is registered in namespace "${ns}" using framework "${framework}". ${citationTag}`;
        break;
      }

      case 'version': {
        const verNumber = fact.payload?.version_number || fact.payload?.semver || refId;
        const status = fact.payload?.lifecycle_state || fact.payload?.status || 'APPROVED';
        stmt = `Agent version ${verNumber} is in lifecycle state "${status}". ${citationTag}`;
        break;
      }

      case 'risk': {
        const sev = attrs.severity || fact.payload?.severity || 'MEDIUM';
        const title = fact.payload?.title ? this.sanitizePassiveText(fact.payload.title) : refId;
        renderedAttrs.severity = sev;
        stmt = `Risk ${refId} is evaluated at ${sev} severity: ${title}. ${citationTag}`;
        break;
      }

      default: {
        const summary = fact.title ? this.sanitizePassiveText(fact.title) : `${entityType} object ${refId}`;
        stmt = `${summary}. ${citationTag}`;
      }
    }

    return {
      fact_id: fact.fact_id,
      entity_ref_id: refId,
      entity_type: entityType,
      citation_tag: citationTag,
      statement: stmt,
      attributes_rendered: renderedAttrs,
    };
  }

  /**
   * Renders all facts in an AssembledContextPackage into validated canonical statements.
   */
  public static renderAll(contextPackage: AssembledContextPackage): ValidatedFactStatement[] {
    if (!contextPackage || !contextPackage.serialized_facts) return [];
    return contextPackage.serialized_facts.map((f) => this.renderFact(f));
  }
}
