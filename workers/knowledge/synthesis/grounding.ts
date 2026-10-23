import { DraftClaim, GroundingVerdict, EvidenceConflict } from './types.ts';
import { AssembledContextPackage, SerializedFact } from '../context/types.ts';

const DOMAIN_STOP_WORDS = new Set([
  'vulnerability', 'vulnerabilities', 'security', 'finding', 'findings',
  'evidence', 'claim', 'claims', 'agent', 'version', 'system', 'platform',
  'analysis', 'recorded', 'identified', 'verified', 'inquiry', 'knowledge',
  'corpus', 'posture', 'issue', 'issues', 'information', 'details', 'rule',
  'check', 'checks', 'status', 'report', 'code', 'file', 'line', 'package',
  'dependency', 'risk', 'runs', 'with', 'from', 'this', 'that', 'have',
  'been', 'were', 'also', 'such', 'into', 'which', 'here', 'the', 'and',
  'for', 'about', 'how', 'does', 'tell', 'show', 'are', 'exist', 'is',
  'has', 'had', 'classified', 'evaluation', 'active', 'due', 'records',
  'observation', 'records'
]);

export class GroundingValidator {
  /**
   * Evaluates draft claims against the verified facts and evidence bundles in the context package.
   */
  public static validateGrounding(
    claims: DraftClaim[],
    contextPackage: AssembledContextPackage
  ): {
    validatedClaims: DraftClaim[];
    groundedClaims: DraftClaim[];
    unsupportedClaims: DraftClaim[];
    contradictedClaims: DraftClaim[];
    verdict: GroundingVerdict;
    averageGroundingScore: number;
    contradictionReason?: string;
    evidenceConflicts: EvidenceConflict[];
  } {
    if (!contextPackage || contextPackage.serialized_facts.length === 0) {
      // Empty context -> All substantive claims are unsupported
      const ungrounded = claims.map((c) => ({
        ...c,
        grounding_score: 0,
        supported: !c.is_substantive, // non-substantive filler can pass
      }));
      return {
        validatedClaims: ungrounded,
        groundedClaims: ungrounded.filter((c) => c.supported),
        unsupportedClaims: ungrounded.filter((c) => !c.supported && c.is_substantive),
        contradictedClaims: [],
        verdict: 'NO_EVIDENCE',
        averageGroundingScore: 0,
        contradictionReason: undefined,
        evidenceConflicts: [],
      };
    }

    const validated: DraftClaim[] = [];
    const grounded: DraftClaim[] = [];
    const unsupported: DraftClaim[] = [];
    const contradicted: DraftClaim[] = [];

    let totalScore = 0;

    for (const claim of claims) {
      if (!claim.is_substantive) {
        const passClaim: DraftClaim = {
          ...claim,
          grounding_score: 1.0,
          supported: true,
        };
        validated.push(passClaim);
        grounded.push(passClaim);
        totalScore += 1.0;
        continue;
      }

      // Check contradiction first
      const contradiction = ContradictionDetector.checkContradiction(claim, contextPackage);
      if (contradiction.isContradicted) {
        const contClaim: DraftClaim = {
          ...claim,
          grounding_score: 0,
          supported: false,
          contradicted: true,
          contradiction_reason: contradiction.reason,
        };
        validated.push(contClaim);
        contradicted.push(contClaim);
        continue;
      }

      // Find supporting facts and evidence
      const matchResult = this.matchClaimToContext(claim, contextPackage);
      const isSupported = matchResult.score >= 0.35 && (matchResult.supportingFacts.length > 0 || matchResult.supportingEvidence.length > 0);

      const evalClaim: DraftClaim = {
        ...claim,
        grounding_score: matchResult.score,
        supported: isSupported,
        contradicted: false,
        supporting_evidence_ids: matchResult.supportingEvidence,
        supporting_fact_ids: matchResult.supportingFacts,
      };

      validated.push(evalClaim);
      totalScore += matchResult.score;

      if (isSupported) {
        grounded.push(evalClaim);
      } else {
        unsupported.push(evalClaim);
      }
    }

    const avgScore = claims.length > 0 ? totalScore / claims.length : 0;

    const contextConflicts = ContradictionDetector.detectContextConflicts(contextPackage);
    let contradictionReason: string | undefined = undefined;
    if (contradicted.length > 0) {
      contradictionReason = (contradicted[0] as any).contradiction_reason;
    } else if (contextConflicts.length > 0) {
      contradictionReason = contextConflicts.map((c) => c.description).join(' ');
    }

    // Determine overall verdict
    let verdict: GroundingVerdict;
    if (contradicted.length > 0 || contextConflicts.length > 0) {
      verdict = 'CONTRADICTED';
    } else if (unsupported.length === 0 && grounded.length > 0) {
      verdict = 'FULLY_GROUNDED';
    } else if (grounded.length > 0 && unsupported.length > 0) {
      verdict = 'PARTIALLY_GROUNDED';
    } else if (grounded.length === 0 && unsupported.length > 0) {
      verdict = 'UNSUPPORTED';
    } else {
      verdict = 'NO_EVIDENCE';
    }

    return {
      validatedClaims: validated,
      groundedClaims: grounded,
      unsupportedClaims: unsupported,
      contradictedClaims: contradicted,
      verdict,
      averageGroundingScore: avgScore,
      contradictionReason,
      evidenceConflicts: contextConflicts,
    };
  }

  private static matchClaimToContext(
    claim: DraftClaim,
    contextPackage: AssembledContextPackage
  ): {
    score: number;
    supportingFacts: string[];
    supportingEvidence: string[];
  } {
    const claimLower = claim.statement.toLowerCase();
    const claimUpper = claim.statement.toUpperCase();

    // 1. Structured attributes extraction from claim
    // CVSS assertion
    const cvssMatch = claimLower.match(/\bcvss(?:\s*v?3(?:\.[0-9])?)?(?:\s+score)?\s*(?:is|of|:)?\s*([0-9]+(?:\.[0-9]+)?)/i);
    const claimedCvss = cvssMatch ? parseFloat(cvssMatch[1]) : null;

    // Severity assertion
    const sevMatch = claimUpper.match(/\b(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b/);
    const claimedSev = sevMatch ? sevMatch[1] : null;

    // Shell execution assertion
    const shellTerms = ['child_process.exec', 'execsync', 'child_process.spawn', 'child_process', 'shell execution', 'shell_executor', 'reaches exec', 'into exec', 'invokes exec', 'executes command', 'command execution'];
    const claimedShell = shellTerms.some((t) => claimLower.includes(t));

    // Remote code execution assertion
    const claimedRce = /\b(remote code execution|rce)\b/i.test(claimLower);

    // Policy outcome assertion
    const policyMatch = claimUpper.match(/\b(BLOCK_DEPLOYMENT|REQUIRE_REVIEW|ALLOW)\b/);
    const claimedPolicy = policyMatch ? policyMatch[1] : null;

    // Citations in claim
    const citedEntityIds = (claim.citation_tags || []).map((tag) => {
      const match = tag.match(/\[(?:citation:)?(?:[a-z_]+):([^\]]+)\]/i);
      return match ? match[1].toLowerCase().trim() : '';
    }).filter(Boolean);

    // If citation tags exist, ensure they exist in contextPackage
    if (citedEntityIds.length > 0) {
      const allKnownIds = new Set<string>();
      for (const f of contextPackage.serialized_facts) {
        allKnownIds.add(f.entity_ref_id.toLowerCase());
        if (f.fact_id) allKnownIds.add(f.fact_id.toLowerCase());
        if (f.structured_attributes?.rule_id) allKnownIds.add(f.structured_attributes.rule_id.toLowerCase());
      }
      for (const b of contextPackage.bundles) {
        if (b.claim_id) allKnownIds.add(b.claim_id.toLowerCase());
        for (const e of b.evidence_items) {
          allKnownIds.add(e.evidence_id.toLowerCase());
        }
      }
      const hasAnyValidCitation = citedEntityIds.some((id) => allKnownIds.has(id));
      if (!hasAnyValidCitation) {
        return { score: 0, supportingFacts: [], supportingEvidence: [] };
      }
    }

    const claimWords = claimLower
      .replace(/[^\w\s-]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length > 2 && !DOMAIN_STOP_WORDS.has(w));

    let bestScore = 0;
    const supportingFacts: string[] = [];
    const supportingEvidence: string[] = [];

    // 1. Match against serialized facts
    for (const fact of contextPackage.serialized_facts) {
      const factLower = (
        fact.formatted_content + ' ' +
        (fact.raw_content || '') + ' ' +
        (fact.title || '') + ' ' +
        JSON.stringify(fact.structured_attributes || {}) + ' ' +
        JSON.stringify(fact.payload || {})
      ).toLowerCase();
      const factAttrs = fact.structured_attributes || {};

      // If citation IDs exist, require match to this fact
      if (citedEntityIds.length > 0) {
        const isCited = citedEntityIds.some(
          (cid) =>
            fact.entity_ref_id.toLowerCase() === cid ||
            (factAttrs.rule_id && factAttrs.rule_id.toLowerCase() === cid) ||
            fact.fact_id.toLowerCase().includes(cid)
        );
        if (!isCited) {
          continue;
        }
      }

      // Check for explicit entity references in statement
      const entityInStatement = claimLower.match(/\b(cve-[0-9]{4}-[0-9]+|agent-[a-z0-9_-]+|rule-[a-z0-9_-]+|find-[a-z0-9_-]+|finding-[a-z0-9_-]+|claim-[a-z0-9_-]+|evidence-[a-z0-9_-]+|ev-[a-z0-9_-]+|ver-[a-z0-9_-]+|policy-[a-z0-9_-]+)\b/i);
      if (entityInStatement) {
        const targetId = entityInStatement[1].toLowerCase();
        const matchesEntity =
          fact.entity_ref_id.toLowerCase() === targetId ||
          (fact.agent_id && fact.agent_id.toLowerCase() === targetId) ||
          (factAttrs.rule_id && factAttrs.rule_id.toLowerCase() === targetId) ||
          fact.fact_id.toLowerCase().includes(targetId);
        if (!matchesEntity) {
          continue;
        }
      }

      // STRUCTURED ATTRIBUTES VALIDATION
      // CVSS Check
      if (claimedCvss !== null) {
        if (factAttrs.cvss_score === null || factAttrs.cvss_score === undefined) {
          // Fact has no CVSS score!
          continue;
        }
        if (Math.abs(factAttrs.cvss_score - claimedCvss) > 0.1) {
          // CVSS score does not match!
          continue;
        }
      }

      // Severity Check: only enforce when fact has a severity, or fact is a vulnerability/finding/risk
      if (claimedSev !== null) {
        const factSev = (factAttrs.severity || fact.payload?.severity || '').toUpperCase();
        if (factSev && factSev !== claimedSev) {
          continue;
        }
        if (!factSev && (fact.entity_type === 'vulnerability' || fact.entity_type === 'finding' || fact.entity_type === 'risk')) {
          continue;
        }
      }

      // Shell Execution Check
      if (claimedShell) {
        const factHasShell =
          shellTerms.some((t) => factLower.includes(t)) ||
          (factAttrs.sinks || []).some((s) => shellTerms.some((st) => s.toLowerCase().includes(st)));
        if (!factHasShell) {
          continue;
        }
      }

      // RCE Check
      if (claimedRce) {
        const factHasRce = /\b(remote code execution|rce)\b/i.test(factLower);
        if (!factHasRce) {
          continue;
        }
      }

      // Policy Check
      if (claimedPolicy) {
        const factOutcome = (factAttrs.outcome || fact.payload?.outcome || '').toUpperCase();
        if (!factOutcome || factOutcome !== claimedPolicy) {
          continue;
        }
      }

      // Substantive word matches
      let matchCount = 0;
      for (const word of claimWords) {
        if (factLower.includes(word)) {
          matchCount++;
        }
      }

      const matchRatio = claimWords.length > 0 ? matchCount / claimWords.length : 1.0;
      const hasDirectIdMatch =
        claimLower.includes(fact.entity_ref_id.toLowerCase()) ||
        (claim.citation_tags || []).some((tag) => tag.toLowerCase().includes(fact.entity_ref_id.toLowerCase()));

      // Security action / payload / execution terms that cannot be assumed without explicit presence
      const sensitiveTerms = [
        'injection', 'rce', 'execution', 'exec', 'spawn', 'sink', 'payload',
        'ransomware', 'teleportation', 'exfiltrat', 'bypass', 'backdoor',
        'trojan', 'miner', 'exploit', 'unauthorized', 'privilege', 'escalat'
      ];
      const hasSensitiveTermInClaim = sensitiveTerms.some((t) => claimLower.includes(t));
      const hasSensitiveTermInFact = sensitiveTerms.some((t) => factLower.includes(t));
      if (hasSensitiveTermInClaim && !hasSensitiveTermInFact) {
        continue;
      }

      // Do NOT consider a claim grounded simply because it contains an entity ID or citation
      // if it introduces unsupported substantive assertions
      if (claimWords.length > 0 && matchRatio < 0.35) {
        continue;
      }

      if (matchRatio >= 0.5 || (claimWords.length === 0 && hasDirectIdMatch && (claimedSev || claimedCvss || claimedPolicy || fact.entity_type === 'agent' || fact.entity_type === 'version'))) {
        const finalFactScore = Math.min(1.0, Math.max(matchRatio, 0.4) + (hasDirectIdMatch ? 0.35 : 0));
        supportingFacts.push(fact.fact_id);
        if (finalFactScore > bestScore) {
          bestScore = finalFactScore;
        }
      }
    }

    // 2. Match against evidence bundles
    for (const bundle of contextPackage.bundles) {
      for (const ev of bundle.evidence_items) {
        const evLower = ev.observation.toLowerCase();

        if (claimedShell) {
          const evHasShell = shellTerms.some((t) => evLower.includes(t));
          if (!evHasShell) continue;
        }

        if (claimedRce) {
          const evHasRce = /\b(remote code execution|rce)\b/i.test(evLower);
          if (!evHasRce) continue;
        }

        if (claimedCvss !== null) {
          const cvssInEv = evLower.match(/\bcvss(?:\s*v?3(?:\.[0-9])?)?(?:\s+score)?\s*(?:is|of|:)?\s*([0-9]+(?:\.[0-9]+)?)/i);
          if (!cvssInEv || Math.abs(parseFloat(cvssInEv[1]) - claimedCvss) > 0.1) continue;
        }

        if (claimedSev !== null) {
          if (!evLower.includes(claimedSev.toLowerCase())) continue;
        }

        if (claimedPolicy !== null) {
          if (!evLower.includes(claimedPolicy.toLowerCase())) continue;
        }

        const sensitiveTerms = [
          'injection', 'rce', 'execution', 'exec', 'spawn', 'sink', 'payload',
          'ransomware', 'teleportation', 'exfiltrat', 'bypass', 'backdoor',
          'trojan', 'miner', 'exploit', 'unauthorized', 'privilege', 'escalat'
        ];
        const hasSensitiveTermInClaim = sensitiveTerms.some((t) => claimLower.includes(t));
        if (hasSensitiveTermInClaim && !sensitiveTerms.some((t) => evLower.includes(t))) {
          continue;
        }

        let evMatches = 0;
        for (const word of claimWords) {
          if (evLower.includes(word)) {
            evMatches++;
          }
        }
        const evRatio = claimWords.length > 0 ? evMatches / claimWords.length : 0;
        const hasDirectEvId =
          claimLower.includes(ev.evidence_id.toLowerCase()) ||
          (claim.citation_tags || []).some((tag) => tag.toLowerCase().includes(ev.evidence_id.toLowerCase()));

        if (evRatio >= 0.3 || hasDirectEvId) {
          supportingEvidence.push(ev.evidence_id);
          bestScore = Math.max(bestScore, evRatio + (hasDirectEvId ? 0.4 : 0.1));
        }
      }
    }

    return {
      score: bestScore,
      supportingFacts,
      supportingEvidence,
    };
  }
}

export class ContradictionDetector {
  /**
   * Detects all direct factual conflicts within the retrieved context package.
   * INVARIANT: Never silently choose the more severe result when evidence conflicts.
   */
  public static detectContextConflicts(contextPackage: AssembledContextPackage): EvidenceConflict[] {
    const conflicts: EvidenceConflict[] = [];
    if (!contextPackage || !contextPackage.serialized_facts) return conflicts;

    // 1. Check for conflicting severities across facts for the same entity
    const severityMap = new Map<string, { severity: string; factId: string }[]>();
    for (const f of contextPackage.serialized_facts) {
      const entityKey = f.entity_ref_id.toLowerCase();
      const sev = (f.structured_attributes?.severity || f.payload?.severity || '').toUpperCase();
      if (sev && sev !== 'UNKNOWN') {
        const list = severityMap.get(entityKey) || [];
        list.push({ severity: sev, factId: f.fact_id });
        severityMap.set(entityKey, list);
      }
    }

    for (const [entityKey, records] of severityMap.entries()) {
      const distinct = Array.from(new Set(records.map((r) => r.severity)));
      if (distinct.length > 1) {
        conflicts.push({
          entity_ref_id: entityKey,
          conflict_type: 'SEVERITY',
          conflicting_values: distinct,
          description: `Conflicting severity evaluations found in retrieved context for entity ${entityKey}: ${distinct.join(' vs ')}.`,
        });
      }
    }

    // 2. Check for conflicting policy outcomes
    const policyMap = new Map<string, { outcome: string; factId: string }[]>();
    for (const f of contextPackage.serialized_facts) {
      if (f.entity_type === 'policy') {
        const outcome = (f.structured_attributes?.outcome || (f.formatted_content.includes('BLOCK_DEPLOYMENT') ? 'BLOCK_DEPLOYMENT' : 'ALLOW')).toUpperCase();
        const key = f.entity_ref_id;
        const list = policyMap.get(key) || [];
        list.push({ outcome, factId: f.fact_id });
        policyMap.set(key, list);
      }
    }

    for (const [policyKey, records] of policyMap.entries()) {
      const distinct = Array.from(new Set(records.map((r) => r.outcome)));
      if (distinct.length > 1) {
        conflicts.push({
          entity_ref_id: policyKey,
          conflict_type: 'POLICY',
          conflicting_values: distinct,
          description: `Conflicting policy evaluations found in context for ${policyKey}: ${distinct.join(' vs ')}.`,
        });
      }
    }

    // 3. Check for conflicting CVSS scores
    const cvssMap = new Map<string, number[]>();
    for (const f of contextPackage.serialized_facts) {
      const cvss = f.structured_attributes?.cvss_score;
      if (cvss !== null && cvss !== undefined) {
        const key = f.entity_ref_id.toLowerCase();
        const list = cvssMap.get(key) || [];
        list.push(cvss);
        cvssMap.set(key, list);
      }
    }

    for (const [key, scores] of cvssMap.entries()) {
      const distinct = Array.from(new Set(scores));
      if (distinct.length > 1 && Math.abs(distinct[0] - distinct[1]) > 0.1) {
        conflicts.push({
          entity_ref_id: key,
          conflict_type: 'CVSS',
          conflicting_values: distinct.map(String),
          description: `Conflicting CVSS scores found in retrieved context for entity ${key}: ${distinct.join(' vs ')}.`,
        });
      }
    }

    return conflicts;
  }

  /**
   * Detects direct factual or semantic contradictions against known authoritative findings.
   */
  public static checkContradiction(
    claim: DraftClaim,
    contextPackage: AssembledContextPackage
  ): { isContradicted: boolean; reason?: string } {
    const claimLower = (claim.statement + ' ' + (claim.citation_tags || []).join(' ')).toLowerCase();
    const claimUpper = claim.statement.toUpperCase();

    // 1. Check for critical finding or vulnerability inversion (claiming safe when severe risks exist)
    const hasCriticalSecurityIssue =
      contextPackage.serialized_facts.some(
        (f) =>
          (f.structured_attributes?.severity === 'CRITICAL' || f.structured_attributes?.severity === 'HIGH') ||
          f.formatted_content.toUpperCase().includes('CRITICAL') ||
          f.formatted_content.toUpperCase().includes('HIGH') ||
          f.formatted_content.includes('BLOCK_DEPLOYMENT') ||
          f.formatted_content.includes('RCE')
      ) ||
      contextPackage.bundles.some((b) => b.evidence_items.some((e) => /critical|high|rce|block_deployment/i.test(e.observation)));

    if (hasCriticalSecurityIssue) {
      const claimAssertsNoIssues =
        claimLower.includes('no vulnerabilities') ||
        claimLower.includes('completely safe') ||
        claimLower.includes('zero risk') ||
        claimLower.includes('no security issues') ||
        claimLower.includes('no security issues found') ||
        claimLower.includes('safe to deploy without changes') ||
        claimLower.includes('safe to deploy') ||
        claimLower.includes('passed all security gates') ||
        claimLower.includes('clean bill of health');

      if (claimAssertsNoIssues) {
        return {
          isContradicted: true,
          reason: 'Claim asserts absence of vulnerabilities or complete safety, directly contradicting verified security findings and risks in context.',
        };
      }
    }

    // 2. Check for policy outcome inversion
    const blockPolicyFact = contextPackage.serialized_facts.find(
      (f) =>
        f.entity_type === 'policy' &&
        (f.structured_attributes?.outcome === 'BLOCK_DEPLOYMENT' || f.formatted_content.includes('BLOCK_DEPLOYMENT'))
    );

    if (blockPolicyFact) {
      const claimAssertsApproved =
        claimLower.includes('policy approved') ||
        claimLower.includes('deployment is allowed') ||
        claimLower.includes('passed all policy gates') ||
        claimLower.includes('outcome is allow');

      if (claimAssertsApproved) {
        return {
          isContradicted: true,
          reason: 'Claim asserts policy approval, directly contradicting the active BLOCK_DEPLOYMENT policy evaluation.',
        };
      }
    }

    // 3. Dynamic severity and CVSS contradiction check
    for (const f of contextPackage.serialized_facts) {
      const entityId = f.entity_ref_id.toLowerCase();
      const mentionsEntity =
        claimLower.includes(entityId) ||
        (claim.citation_tags || []).some((t) => t.toLowerCase().includes(entityId));
      if (!mentionsEntity) continue;

      const factSev = f.structured_attributes?.severity?.toUpperCase();
      if (factSev === 'LOW' || factSev === 'INFORMATIONAL') {
        if (claimUpper.includes('CRITICAL') || claimUpper.includes('HIGH SEVERITY')) {
          return {
            isContradicted: true,
            reason: `Claim asserts CRITICAL/HIGH severity for ${f.entity_ref_id}, directly contradicting recorded ${factSev} severity.`,
          };
        }
      } else if (factSev === 'HIGH' || factSev === 'CRITICAL') {
        if (claimLower.includes('low severity') || claimLower.includes('minor issue') || claimLower.includes('negligible risk')) {
          return {
            isContradicted: true,
            reason: `Claim asserts low severity for ${f.entity_ref_id}, directly contradicting recorded ${factSev} severity.`,
          };
        }
      }

      // CVSS score conflict check
      const factCvss = f.structured_attributes?.cvss_score;
      if (factCvss !== null && factCvss !== undefined) {
        const claimCvssMatch = claimLower.match(/\bcvss(?:\s*v?3(?:\.[0-9])?)?(?:\s+score)?\s*(?:is|of|:)?\s*([0-9]+(?:\.[0-9]+)?)/i);
        if (claimCvssMatch) {
          const claimedCvss = parseFloat(claimCvssMatch[1]);
          if (Math.abs(claimedCvss - factCvss) > 1.0) {
            return {
              isContradicted: true,
              reason: `Claim asserts CVSS ${claimedCvss} contradicting recorded CVSS ${factCvss} for ${f.entity_ref_id}.`,
            };
          }
        }
      }
    }

    // 4. Check for context-level conflicts (severity, policy, CVSS)
    const contextConflicts = this.detectContextConflicts(contextPackage);
    for (const conflict of contextConflicts) {
      const mentionsConflictEntity =
        claimLower.includes(conflict.entity_ref_id.toLowerCase()) ||
        (claim.citation_tags || []).some((t) => t.toLowerCase().includes(conflict.entity_ref_id.toLowerCase()));
      if (mentionsConflictEntity) {
        return {
          isContradicted: true,
          reason: conflict.description,
        };
      }
    }

    return { isContradicted: false };
  }
}
