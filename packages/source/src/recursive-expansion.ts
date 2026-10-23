import crypto from 'crypto';
import {
  ExpansionBudget,
  RecursiveExpansionReport,
  ExpansionTreeNode,
  DiscoveryCandidate,
} from './types.ts';
import { SourceAdapterRegistry } from './registry.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export class RecursiveExpansionEngine {
  private registry: SourceAdapterRegistry;

  constructor(registry: SourceAdapterRegistry) {
    this.registry = registry;
  }

  /**
   * Recursively expands discovered candidate relationships subject to depth and budget bounds.
   */
  async expand(
    rootLocators: string[],
    budget: Partial<ExpansionBudget> = {}
  ): Promise<RecursiveExpansionReport> {
    const fullBudget: ExpansionBudget = {
      max_depth: budget.max_depth ?? 2,
      max_total_candidates: budget.max_total_candidates ?? 50,
      max_calls_per_source: budget.max_calls_per_source ?? 20,
      max_time_ms: budget.max_time_ms ?? 5000,
      stop_on_rate_limit_remaining: budget.stop_on_rate_limit_remaining ?? 5,
    };

    const startTime = Date.now();
    const visited = new Set<string>();
    const callsPerSource: Record<string, number> = {};
    let totalDiscovered = 0;
    let depthReached = 0;
    let budgetExhausted = false;
    let exhaustionReason: RecursiveExpansionReport['budget_exhaustion_reason'];

    const trees: ExpansionTreeNode[] = [];

    for (const rootLocator of rootLocators) {
      if (budgetExhausted) break;
      const rootNode = await this.expandNode(
        rootLocator,
        0,
        undefined,
        undefined,
        fullBudget,
        visited,
        callsPerSource,
        startTime,
        (reason) => {
          budgetExhausted = true;
          exhaustionReason = reason;
        },
        (depth) => {
          if (depth > depthReached) depthReached = depth;
        },
        () => {
          totalDiscovered++;
        }
      );
      if (rootNode) {
        trees.push(rootNode);
      }
    }

    const duration = Date.now() - startTime;
    const expansionId = `exp-${crypto.randomUUID().substring(0, 8)}`;

    const inputHash = crypto.createHash('sha256')
      .update(rootLocators.join(',') + ':' + JSON.stringify(fullBudget))
      .digest('hex');

    const provenance: ProvenanceRecord = ProvenanceRecordSchema.parse({
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [inputHash],
      rule_id: 'RECURSIVE_RELATIONSHIP_EXPANSION_V1',
      ruleset_version: '1.0.0',
      transformation_type: 'CALIBRATED_INFERENCE',
      confidence: 0.9,
      derived_at: new Date().toISOString(),
      engine_signature: 'caim:recursive-expansion:engine:v1.0.0',
    });

    return {
      expansion_id: expansionId,
      root_locators: rootLocators,
      depth_reached: depthReached,
      total_nodes_visited: visited.size,
      total_candidates_discovered: totalDiscovered,
      tree: trees,
      budget_exhausted: budgetExhausted,
      budget_exhaustion_reason: exhaustionReason,
      duration_ms: duration,
      provenance,
    };
  }

  private async expandNode(
    locator: string,
    depth: number,
    discoveredFrom: string | undefined,
    relationshipType: string | undefined,
    budget: ExpansionBudget,
    visited: Set<string>,
    callsPerSource: Record<string, number>,
    startTime: number,
    onExhaust: (reason: NonNullable<RecursiveExpansionReport['budget_exhaustion_reason']>) => void,
    onDepth: (depth: number) => void,
    onDiscovered: () => void
  ): Promise<ExpansionTreeNode | null> {
    onDepth(depth);

    // Guard 1: Timeout
    if (Date.now() - startTime >= budget.max_time_ms) {
      onExhaust('TIMEOUT');
      return null;
    }

    // Guard 2: Max candidates
    if (visited.size >= budget.max_total_candidates) {
      onExhaust('MAX_CANDIDATES');
      return null;
    }

    // Cycle detection
    if (visited.has(locator)) {
      return null;
    }
    visited.add(locator);
    onDiscovered();

    // Adapter resolution
    const adapter = this.registry.resolveForLocator(locator);
    const sourceType = adapter ? adapter.sourceType : 'unknown';

    const node: ExpansionTreeNode = {
      locator,
      depth,
      source_type: sourceType,
      discovered_from: discoveredFrom,
      relationship_type: relationshipType,
      children: [],
    };

    // Guard 3: Max depth
    if (depth >= budget.max_depth) {
      return node;
    }

    if (!adapter) {
      return node;
    }

    // Guard 4: Rate limit remaining
    const rateLimit = adapter.get_rate_limit_state();
    if (rateLimit.remaining <= budget.stop_on_rate_limit_remaining && !rateLimit.is_exhausted) {
      onExhaust('RATE_LIMIT_GUARD');
      return node;
    }

    // Guard 5: Max calls per source
    callsPerSource[sourceType] = (callsPerSource[sourceType] || 0) + 1;
    if (callsPerSource[sourceType] > budget.max_calls_per_source) {
      onExhaust('MAX_CALLS_PER_SOURCE');
      return node;
    }

    // Fetch relationships
    try {
      const relsResult = await adapter.enumerate_relationships(locator);
      for (const rel of relsResult.relationships) {
        if (visited.has(rel.target_locator)) continue;

        // Recurse to child
        const childNode = await this.expandNode(
          rel.target_locator,
          depth + 1,
          locator,
          rel.relationship_type,
          budget,
          visited,
          callsPerSource,
          startTime,
          onExhaust,
          onDepth,
          onDiscovered
        );

        if (childNode) {
          node.children.push(childNode);
        }
      }
    } catch {
      // Gracefully continue recursion on single-node errors
    }

    return node;
  }
}
