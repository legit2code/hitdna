import { RetrievedDocument } from '../retrieval/types.ts';
import { AssembledContextPackage, ContextBudgetConfig } from './types.ts';
import { StructuredFactSerializer } from './serializer.ts';
import { EvidenceClaimBundleBuilder } from './bundler.ts';
import { RedundancyRemovalEngine, TemporalVersionGroupingEngine } from './grouping.ts';
import { ContextBudgetManager } from './budget.ts';
import { PromptIsolationGuard } from './isolation.ts';
import crypto from 'crypto';

export interface ContextAssemblyOptions {
  budgetConfig?: Partial<ContextBudgetConfig>;
  caller_security_rank?: number;
  caller_has_vault?: boolean;
  target_agent_id?: string;
  target_version_id?: string;
}

export class ContextAssembler {
  private budgetManager: ContextBudgetManager;

  constructor(budgetConfig?: Partial<ContextBudgetConfig>) {
    this.budgetManager = new ContextBudgetManager(budgetConfig);
  }

  /**
   * Assembles a verified, deduplicated, isolated context package from retrieved documents.
   */
  public assembleContextPackage(
    query: string,
    documents: RetrievedDocument[],
    options?: ContextAssemblyOptions
  ): AssembledContextPackage {
    const rawFacts = documents.map((doc) => StructuredFactSerializer.serialize(doc));

    // 1. Redundancy Removal
    const { uniqueFacts, prunedCount } = RedundancyRemovalEngine.deduplicate(rawFacts);

    // 2. Budget Allocation
    const { allocatedFacts, totalTokens, budgetUtilization } = this.budgetManager.allocateFactsUnderBudget(uniqueFacts);

    // 3. Build Evidence Bundles
    const bundles = EvidenceClaimBundleBuilder.buildBundles(documents);

    // 4. Temporal & Version Grouping
    const versionGroups = TemporalVersionGroupingEngine.groupContext(allocatedFacts, bundles);

    // 5. Prompt Isolation
    const isolatedPromptContext = PromptIsolationGuard.buildIsolatedPromptContext(
      query,
      versionGroups,
      allocatedFacts,
      bundles
    );

    // Compute package hash for audit tracking
    const packageHash = crypto
      .createHash('sha256')
      .update(`${query}:${totalTokens}:${allocatedFacts.map((f) => f.checksum).join(',')}`)
      .digest('hex');

    const packageId = `pkg-${packageHash.substring(0, 16)}`;

    return {
      package_id: packageId,
      package_hash: packageHash,
      assembled_at: new Date().toISOString(),
      query,
      target_agent_id: options?.target_agent_id,
      target_version_id: options?.target_version_id,
      caller_security_rank: options?.caller_security_rank ?? 0,
      caller_has_vault: options?.caller_has_vault ?? false,
      total_tokens_estimated: totalTokens,
      budget_utilization_ratio: budgetUtilization,
      facts_count: allocatedFacts.length,
      bundles_count: bundles.length,
      redundant_facts_pruned: prunedCount,
      version_groups: versionGroups,
      isolated_prompt_context: isolatedPromptContext,
      serialized_facts: allocatedFacts,
      bundles,
    };
  }
}
