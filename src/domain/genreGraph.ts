/**
 * Domain Engine: Genre Graph & Taxonomy Traversal
 * Engine: RI-06 (Genre, Subgenre, Scene & Hybrid Taxonomy)
 * Architecture Version: 5.0.0 | Phase: P03
 */

import {
  GenreNode,
  GenreEdge,
  GenreBlendDefinition,
  GenreNodeType,
  GenreEdgeType,
} from '../contracts/genreGraph.ts';

export interface LineageResult {
  rootFamilies: GenreNode[];
  primaryPath: GenreNode[];
  fusedInfluences: GenreNode[];
}

export interface TaxonomyValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  cycles: string[][];
  isolatedNodes: string[];
}

export interface BlendValidationResult {
  isResearched: boolean;
  allowsEmpiricalClaims: boolean;
  valid: boolean;
  errors: string[];
}

export class GenreGraph {
  private nodes: Map<string, GenreNode> = new Map();
  private nodesBySlug: Map<string, GenreNode> = new Map();
  private edges: Map<string, GenreEdge> = new Map();
  private outgoingEdges: Map<string, GenreEdge[]> = new Map();
  private incomingEdges: Map<string, GenreEdge[]> = new Map();

  constructor(initialNodes: GenreNode[] = [], initialEdges: GenreEdge[] = []) {
    for (const node of initialNodes) {
      this.addNode(node);
    }
    for (const edge of initialEdges) {
      this.addEdge(edge);
    }
  }

  public addNode(node: GenreNode): void {
    this.nodes.set(node.genreId, node);
    this.nodesBySlug.set(node.slug.toLowerCase(), node);
    if (!this.outgoingEdges.has(node.genreId)) {
      this.outgoingEdges.set(node.genreId, []);
    }
    if (!this.incomingEdges.has(node.genreId)) {
      this.incomingEdges.set(node.genreId, []);
    }
  }

  public addEdge(edge: GenreEdge): void {
    this.edges.set(edge.edgeId, edge);

    const outList = this.outgoingEdges.get(edge.sourceGenreId) || [];
    outList.push(edge);
    this.outgoingEdges.set(edge.sourceGenreId, outList);

    const inList = this.incomingEdges.get(edge.targetGenreId) || [];
    inList.push(edge);
    this.incomingEdges.set(edge.targetGenreId, inList);
  }

  public getNode(genreId: string): GenreNode | undefined {
    return this.nodes.get(genreId);
  }

  public getNodeBySlug(slug: string): GenreNode | undefined {
    return this.nodesBySlug.get(slug.toLowerCase());
  }

  public getAllNodes(): GenreNode[] {
    return Array.from(this.nodes.values());
  }

  public getAllEdges(): GenreEdge[] {
    return Array.from(this.edges.values());
  }

  public getNodesByType(nodeType: GenreNodeType): GenreNode[] {
    return this.getAllNodes().filter(n => n.nodeType === nodeType);
  }

  public getOutgoingEdges(genreId: string): GenreEdge[] {
    return this.outgoingEdges.get(genreId) || [];
  }

  public getIncomingEdges(genreId: string): GenreEdge[] {
    return this.incomingEdges.get(genreId) || [];
  }

  /**
   * Retrieves all ancestor nodes following hierarchical edges (IS_A, DERIVED_FROM, REGIONAL_VARIANT, ERA_VARIANT).
   */
  public getAncestors(genreId: string, visited: Set<string> = new Set()): GenreNode[] {
    if (visited.has(genreId)) return [];
    visited.add(genreId);

    const ancestors: GenreNode[] = [];
    const outgoing = this.getOutgoingEdges(genreId);

    for (const edge of outgoing) {
      if (['IS_A', 'DERIVED_FROM', 'REGIONAL_VARIANT', 'ERA_VARIANT'].includes(edge.edgeType)) {
        const target = this.getNode(edge.targetGenreId);
        if (target) {
          ancestors.push(target);
          const deeper = this.getAncestors(target.genreId, visited);
          for (const d of deeper) {
            if (!ancestors.some(a => a.genreId === d.genreId)) {
              ancestors.push(d);
            }
          }
        }
      }
    }

    return ancestors;
  }

  /**
   * Retrieves all descendant subgenres or variants.
   */
  public getDescendants(genreId: string, visited: Set<string> = new Set()): GenreNode[] {
    if (visited.has(genreId)) return [];
    visited.add(genreId);

    const descendants: GenreNode[] = [];
    const incoming = this.getIncomingEdges(genreId);

    for (const edge of incoming) {
      if (['IS_A', 'DERIVED_FROM', 'REGIONAL_VARIANT', 'ERA_VARIANT'].includes(edge.edgeType)) {
        const source = this.getNode(edge.sourceGenreId);
        if (source) {
          descendants.push(source);
          const deeper = this.getDescendants(source.genreId, visited);
          for (const d of deeper) {
            if (!descendants.some(a => a.genreId === d.genreId)) {
              descendants.push(d);
            }
          }
        }
      }
    }

    return descendants;
  }

  /**
   * Resolves complete lineage including root family parents and primary path.
   */
  public getLineage(genreId: string): LineageResult {
    const node = this.getNode(genreId);
    if (!node) {
      return { rootFamilies: [], primaryPath: [], fusedInfluences: [] };
    }

    const ancestors = this.getAncestors(genreId);
    const rootFamilies = ancestors.filter(a => a.nodeType === 'ROOT_FAMILY');
    if (node.nodeType === 'ROOT_FAMILY' && !rootFamilies.some(r => r.genreId === node.genreId)) {
      rootFamilies.push(node);
    }

    // Direct fused / influenced connections
    const fusedInfluences = this.getFusedInfluences(genreId);

    return {
      rootFamilies,
      primaryPath: [node, ...ancestors],
      fusedInfluences,
    };
  }

  /**
   * Identifies fused partner genres (e.g. for hybrids like Country Rap -> Country, Hip-Hop).
   */
  public getFusedInfluences(genreId: string): GenreNode[] {
    const outgoing = this.getOutgoingEdges(genreId);
    const fusedNodes: GenreNode[] = [];

    for (const edge of outgoing) {
      if (['FUSED_WITH', 'INFLUENCED_BY'].includes(edge.edgeType)) {
        const target = this.getNode(edge.targetGenreId);
        if (target && !fusedNodes.some(n => n.genreId === target.genreId)) {
          fusedNodes.push(target);
        }
      }
    }

    return fusedNodes;
  }

  /**
   * Calculates shortest path graph distance between two genre nodes using BFS.
   * Treats graph as undirected for distance computation.
   */
  public calculateDistance(sourceId: string, targetId: string): number | null {
    if (sourceId === targetId) return 0;
    if (!this.nodes.has(sourceId) || !this.nodes.has(targetId)) return null;

    const queue: Array<{ id: string; dist: number }> = [{ id: sourceId, dist: 0 }];
    const visited = new Set<string>([sourceId]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.id === targetId) return current.dist;

      // Check all neighbors (both outgoing and incoming)
      const outgoing = this.getOutgoingEdges(current.id).map(e => e.targetGenreId);
      const incoming = this.getIncomingEdges(current.id).map(e => e.sourceGenreId);
      const neighbors = [...outgoing, ...incoming];

      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push({ id: neighbor, dist: current.dist + 1 });
        }
      }
    }

    return null; // Disconnected
  }

  /**
   * Validates taxonomy integrity: checks for cycles in hierarchical edges and isolated nodes.
   */
  public validateTaxonomy(): TaxonomyValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const cycles: string[][] = [];
    const isolatedNodes: string[] = [];

    // Cycle detection for hierarchical edges using DFS
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const path: string[] = [];

    const isCyclic = (nodeId: string): boolean => {
      visited.add(nodeId);
      recStack.add(nodeId);
      path.push(nodeId);

      const edges = this.getOutgoingEdges(nodeId).filter(e =>
        ['IS_A', 'DERIVED_FROM', 'REGIONAL_VARIANT'].includes(e.edgeType)
      );

      for (const edge of edges) {
        if (!visited.has(edge.targetGenreId)) {
          if (isCyclic(edge.targetGenreId)) return true;
        } else if (recStack.has(edge.targetGenreId)) {
          cycles.push([...path, edge.targetGenreId]);
          return true;
        }
      }

      recStack.delete(nodeId);
      path.pop();
      return false;
    };

    for (const nodeId of this.nodes.keys()) {
      if (!visited.has(nodeId)) {
        if (isCyclic(nodeId)) {
          errors.push(`Cycle detected in hierarchical taxonomy edges involving node "${nodeId}"`);
        }
      }
    }

    // Check isolated non-root nodes
    for (const node of this.nodes.values()) {
      if (node.nodeType !== 'ROOT_FAMILY') {
        const outCount = this.getOutgoingEdges(node.genreId).length;
        const inCount = this.getIncomingEdges(node.genreId).length;
        if (outCount === 0 && inCount === 0) {
          isolatedNodes.push(node.genreId);
          warnings.push(`Node "${node.name}" (${node.genreId}) has no incoming or outgoing edges`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      cycles,
      isolatedNodes,
    };
  }

  /**
   * Distinguishes RESEARCHED_HYBRID from CREATIVE_BLEND.
   * Enforces that CREATIVE_BLEND cannot claim empirical prevalence without measured evidence.
   */
  public distinguishBlend(blend: GenreBlendDefinition): BlendValidationResult {
    const errors: string[] = [];

    if (!this.nodes.has(blend.primaryGenreId)) {
      errors.push(`Primary genre ID "${blend.primaryGenreId}" does not exist in taxonomy`);
    }

    for (const secId of blend.secondaryGenreIds) {
      if (!this.nodes.has(secId)) {
        errors.push(`Secondary genre ID "${secId}" does not exist in taxonomy`);
      }
    }

    // Weight validation: if weights are present, they must be between 0 and 1
    if (blend.weights !== null) {
      let sum = 0;
      for (const [gid, w] of Object.entries(blend.weights)) {
        if (typeof w !== 'number' || w < 0 || w > 1) {
          errors.push(`Weight for genre "${gid}" must be between 0.0 and 1.0 (got ${w})`);
        }
        sum += w;
      }
      // Floating point tolerance for sum = 1.0
      if (Math.abs(sum - 1.0) > 0.01) {
        errors.push(`Blend component weights must sum to 1.0 (got ${sum.toFixed(3)})`);
      }
    }

    // Constitution Law: Researched Hybrid vs Creative Blend
    if (blend.blendType === 'CREATIVE_BLEND') {
      if (blend.empiricalSupport.hasEmpiricalPrevalence) {
        errors.push('A CREATIVE_BLEND cannot claim empirical prevalence (hasEmpiricalPrevalence must be false)');
      }
      if (blend.empiricalSupport.qualifyingCohortId !== null) {
        errors.push('A CREATIVE_BLEND cannot attach a qualifying research cohort ID without being promoted to RESEARCHED_HYBRID');
      }
    } else if (blend.blendType === 'RESEARCHED_HYBRID') {
      if (!blend.empiricalSupport.hasEmpiricalPrevalence && !blend.evidence) {
        errors.push('A RESEARCHED_HYBRID requires verifiable evidence or qualifying cohort empirical support');
      }
    }

    const isResearched = blend.blendType === 'RESEARCHED_HYBRID';
    const allowsEmpiricalClaims = isResearched && blend.empiricalSupport.hasEmpiricalPrevalence;

    return {
      isResearched,
      allowsEmpiricalClaims,
      valid: errors.length === 0,
      errors,
    };
  }
}
