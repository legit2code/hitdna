import { SerializedFact, EvidenceClaimBundle, VersionGroupedContext } from './types.ts';

export class RedundancyRemovalEngine {
  /**
   * Identifies and removes redundant facts with overlapping or identical entity IDs / content.
   */
  public static deduplicate(facts: SerializedFact[]): {
    uniqueFacts: SerializedFact[];
    prunedCount: number;
  } {
    const seenEntities = new Set<string>();
    const seenChecksums = new Set<string>();
    const uniqueFacts: SerializedFact[] = [];
    let prunedCount = 0;

    for (const fact of facts) {
      const entityKey = `${fact.entity_type}:${fact.entity_ref_id}`;
      if (seenEntities.has(entityKey) || seenChecksums.has(fact.checksum)) {
        prunedCount++;
        continue;
      }
      seenEntities.add(entityKey);
      seenChecksums.add(fact.checksum);
      uniqueFacts.push(fact);
    }

    return { uniqueFacts, prunedCount };
  }
}

export class TemporalVersionGroupingEngine {
  /**
   * Groups serialized facts and evidence bundles chronologically by Agent, Version, and Analysis Run.
   */
  public static groupContext(
    facts: SerializedFact[],
    bundles: EvidenceClaimBundle[]
  ): VersionGroupedContext[] {
    const groupsMap = new Map<string, VersionGroupedContext>();

    // 1. Initialize groups from facts with agent_id and agent_version_id
    for (const fact of facts) {
      const agentId = fact.agent_id || 'global_scope';
      const versionId = fact.agent_version_id || 'unversioned';
      const key = `${agentId}::${versionId}`;

      if (!groupsMap.has(key)) {
        groupsMap.set(key, {
          agent_id: agentId,
          agent_version_id: versionId,
          runs: [],
          unassigned_facts: [],
        });
      }

      const group = groupsMap.get(key)!;
      if (fact.analysis_run_id) {
        let run = group.runs.find((r) => r.run_id === fact.analysis_run_id);
        if (!run) {
          run = {
            run_id: fact.analysis_run_id,
            timestamp: fact.timestamp || new Date().toISOString(),
            facts: [],
            bundles: [],
          };
          group.runs.push(run);
        }
        run.facts.push(fact);
      } else {
        group.unassigned_facts.push(fact);
      }
    }

    // 2. Assign bundles to version groups
    for (const bundle of bundles) {
      const agentId = bundle.agent_id || 'global_scope';
      const versionId = bundle.agent_version_id || 'unversioned';
      const key = `${agentId}::${versionId}`;

      const group = groupsMap.get(key);
      if (group) {
        // Attach to first run or create a default run
        if (group.runs.length > 0) {
          group.runs[0].bundles.push(bundle);
        }
      }
    }

    return Array.from(groupsMap.values());
  }
}
