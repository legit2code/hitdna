/**
 * Call Graph Builder & Reachability Resolver
 * P15 — Static Analysis & Control Flow
 */

import { CallGraph, CallGraphNode, CallGraphEdge, CallGraphTraceNode } from './types.ts';
import { ArtifactParseResult, CallSiteFact } from '@caim/syntax/types.ts';
import { SymbolImportGraph } from './types.ts';

export class StaticCallGraphBuilder {
  /**
   * Constructs the call graph and resolves caller-callee relationships across files
   */
  public static build(
    artifactParse: ArtifactParseResult,
    symbolGraph: SymbolImportGraph,
    entrypointFiles: string[]
  ): CallGraph {
    const nodes: Record<string, CallGraphNode> = {};
    const edges: CallGraphEdge[] = [];
    const entrypointsSet = new Set(entrypointFiles);

    // 1. Create nodes for all declared functions/methods across files
    for (const fileFact of artifactParse.file_facts) {
      const isFileEntrypoint = entrypointsSet.has(fileFact.file_path);

      // Top-level module pseudo-function
      const moduleNodeId = `${fileFact.file_path}:<top-level>`;
      nodes[moduleNodeId] = {
        node_id: moduleNodeId,
        file_path: fileFact.file_path,
        function_name: '<top-level>',
        is_entrypoint: isFileEntrypoint,
        is_exported: true,
        parameter_names: [],
        call_count: 0,
      };

      for (const sym of fileFact.symbols) {
        if (sym.kind === 'FUNCTION' || sym.kind === 'ASYNC_FUNCTION' || sym.kind === 'METHOD' || sym.kind === 'CLASS') {
          const nodeId = `${fileFact.file_path}:${sym.name}`;
          const isEntry = isFileEntrypoint && (
            sym.name === 'main' || 
            sym.name === 'handler' || 
            sym.name === 'run' || 
            sym.visibility === 'PUBLIC'
          );

          nodes[nodeId] = {
            node_id: nodeId,
            file_path: fileFact.file_path,
            function_name: sym.name,
            is_entrypoint: isEntry,
            is_exported: sym.visibility === 'PUBLIC',
            span: sym.span,
            parameter_names: (sym.parameters || []).map(p => p.name),
            call_count: 0,
          };
        }
      }
    }

    // 2. Connect CallSites to Nodes and establish CallGraphEdges
    for (const fileFact of artifactParse.file_facts) {
      for (const call of fileFact.call_sites) {
        // Look up which function encloses this call site by span
        const callerName = this.findEnclosingFunctionName(call, fileFact.symbols) || '<top-level>';
        const callerNodeId = `${fileFact.file_path}:${callerName}`;

        // Ensure caller node exists
        if (!nodes[callerNodeId]) {
          nodes[callerNodeId] = {
            node_id: callerNodeId,
            file_path: fileFact.file_path,
            function_name: callerName,
            is_entrypoint: false,
            is_exported: false,
            parameter_names: [],
            call_count: 0,
          };
        }
        nodes[callerNodeId].call_count++;

        // Determine target callee node
        const resolvedCallee = this.resolveCallee(call, fileFact.file_path, symbolGraph, nodes);
        const calleeNodeId = resolvedCallee.node_id;

        // If callee node is not registered yet (e.g. external / SDK / synthetic), create it
        if (!nodes[calleeNodeId]) {
          nodes[calleeNodeId] = {
            node_id: calleeNodeId,
            file_path: resolvedCallee.file_path,
            function_name: resolvedCallee.function_name,
            is_entrypoint: false,
            is_exported: true,
            parameter_names: [],
            call_count: 0,
          };
        }

        const isInterprocedural = callerNodeId !== calleeNodeId;
        const isCrossFile = fileFact.file_path !== resolvedCallee.file_path;

        let callType: 'DIRECT' | 'METHOD' | 'DYNAMIC' | 'CONSTRUCTOR' = 'DIRECT';
        if (call.callee_name.startsWith('new ') || call.callee_name === 'constructor') {
          callType = 'CONSTRUCTOR';
        } else if (call.receiver) {
          callType = call.receiver.includes('[') ? 'DYNAMIC' : 'METHOD';
        }

        edges.push({
          edge_id: `edge_${crypto.randomUUID().slice(0, 8)}`,
          caller_node_id: callerNodeId,
          callee_node_id: calleeNodeId,
          callee_name: call.callee_name,
          call_site_span: call.span,
          is_interprocedural: isInterprocedural,
          is_cross_file: isCrossFile,
          call_type: callType,
        });
      }
    }

    // 3. Compute Transitive Reachability Map
    const reachabilityMap: Record<string, string[]> = {};
    const adjacency: Record<string, Set<string>> = {};

    for (const edge of edges) {
      if (!adjacency[edge.caller_node_id]) {
        adjacency[edge.caller_node_id] = new Set();
      }
      adjacency[edge.caller_node_id].add(edge.callee_node_id);
    }

    for (const nodeId of Object.keys(nodes)) {
      reachabilityMap[nodeId] = this.computeReachableNodes(nodeId, adjacency);
    }

    const entrypointNodeIds = Object.values(nodes)
      .filter(n => n.is_entrypoint)
      .map(n => n.node_id);

    return {
      nodes,
      edges,
      entrypoints: entrypointNodeIds,
      reachability_map: reachabilityMap,
    };
  }

  private static findEnclosingFunctionName(
    call: CallSiteFact,
    symbols: Array<{ name: string; kind: string; span: { start_line: number; end_line: number } }>
  ): string | undefined {
    const callLine = call.span.start_line;
    // Tightest enclosing AST scope
    const enclosing = symbols
      .filter(s => (s.kind.includes('FUNCTION') || s.kind === 'METHOD' || s.kind === 'CLASS' || s.kind === 'CONSTRUCTOR') &&
                   s.span.start_line <= callLine &&
                   s.span.end_line >= callLine)
      .sort((a, b) => (a.span.end_line - a.span.start_line) - (b.span.end_line - b.span.start_line));

    if (enclosing.length > 0) {
      return enclosing[0].name;
    }

    const candidates = symbols
      .filter(s => (s.kind.includes('FUNCTION') || s.kind === 'METHOD' || s.kind === 'CLASS' || s.kind === 'CONSTRUCTOR') && s.span.start_line <= callLine)
      .sort((a, b) => b.span.start_line - a.span.start_line);

    return candidates.length > 0 ? candidates[0].name : undefined;
  }

  /**
   * Resolves a CallSiteFact to its target node ID across local and imported symbols
   */
  private static resolveCallee(
    call: CallSiteFact,
    currentFilePath: string,
    symbolGraph: SymbolImportGraph,
    nodes: Record<string, CallGraphNode>
  ): { node_id: string; file_path: string; function_name: string } {
    const rawCallee = call.callee_name;
    const receiver = call.receiver;

    // 1. Check local file functions first if no receiver
    if (!receiver) {
      const localNodeId = `${currentFilePath}:${rawCallee}`;
      if (nodes[localNodeId]) {
        return { node_id: localNodeId, file_path: currentFilePath, function_name: rawCallee };
      }

      // 2. Check imported functions via symbol graph
      const mod = symbolGraph.modules[currentFilePath];
      if (mod) {
        for (const imp of mod.imports) {
          if (imp.imported_symbols.includes(rawCallee) && imp.resolved_path) {
            const targetNodeId = `${imp.resolved_path}:${rawCallee}`;
            return { node_id: targetNodeId, file_path: imp.resolved_path, function_name: rawCallee };
          }
        }
      }
    } else {
      // 3. Receiver-based call (e.g. `service.execCmd` or `axios.get`)
      const mod = symbolGraph.modules[currentFilePath];
      if (mod) {
        for (const imp of mod.imports) {
          if (imp.imported_symbols.includes(receiver) && imp.resolved_path) {
            const targetNodeId = `${imp.resolved_path}:${rawCallee}`;
            return { node_id: targetNodeId, file_path: imp.resolved_path, function_name: `${receiver}.${rawCallee}` };
          }
        }
      }
    }

    // 4. Default external or unlocated call
    const fullCallee = receiver ? `${receiver}.${rawCallee}` : rawCallee;
    return {
      node_id: `external:${fullCallee}`,
      file_path: 'external',
      function_name: fullCallee,
    };
  }

  /**
   * Computes all reachable node IDs using Breadth-First Search (BFS)
   */
  private static computeReachableNodes(
    startNodeId: string,
    adjacency: Record<string, Set<string>>
  ): string[] {
    const visited = new Set<string>();
    const queue = [startNodeId];

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const neighbors = adjacency[curr];
      if (neighbors) {
        for (const next of neighbors) {
          if (!visited.has(next)) {
            visited.add(next);
            queue.push(next);
          }
        }
      }
    }

    return Array.from(visited);
  }

  /**
   * Finds the shortest call path from any entrypoint to a target sink function
   */
  public static traceInterproceduralPath(
    targetNodeId: string,
    callGraph: CallGraph
  ): CallGraphTraceNode[] | undefined {
    // Reverse adjacency search
    const reverseAdjacency: Record<string, Array<{ caller_node_id: string; edge: CallGraphEdge }>> = {};

    for (const edge of callGraph.edges) {
      if (!reverseAdjacency[edge.callee_node_id]) {
        reverseAdjacency[edge.callee_node_id] = [];
      }
      reverseAdjacency[edge.callee_node_id].push({
        caller_node_id: edge.caller_node_id,
        edge,
      });
    }

    // BFS backwards from target to any entrypoint
    const queue: Array<{ curr: string; path: CallGraphEdge[] }> = [{ curr: targetNodeId, path: [] }];
    const visited = new Set<string>([targetNodeId]);

    while (queue.length > 0) {
      const { curr, path } = queue.shift()!;
      const node = callGraph.nodes[curr];

      if (path.length > 0 && node && (node.is_entrypoint || node.function_name === 'main' || node.function_name === 'handler' || node.function_name === '<top-level>')) {
        // Construct trace from entrypoint to sink
        const trace: CallGraphTraceNode[] = [];
        let step = 1;

        // Entrypoint step
        trace.push({
          function_name: node.function_name,
          file_path: node.file_path,
          span: node.span,
          call_site: path.length > 0 ? path[path.length - 1]?.callee_name : undefined,
          step_number: step++,
        });

        // Intermediary steps
        for (let i = path.length - 1; i >= 0; i--) {
          const e = path[i];
          const calleeNode = callGraph.nodes[e.callee_node_id];
          trace.push({
            function_name: calleeNode ? calleeNode.function_name : e.callee_name,
            file_path: calleeNode ? calleeNode.file_path : 'unknown',
            span: e.call_site_span,
            call_site: e.callee_name,
            step_number: step++,
          });
        }

        return trace;
      }

      const parents = reverseAdjacency[curr] || [];
      for (const parent of parents) {
        if (!visited.has(parent.caller_node_id)) {
          visited.add(parent.caller_node_id);
          queue.push({
            curr: parent.caller_node_id,
            path: [...path, parent.edge],
          });
        }
      }
    }

    return undefined;
  }
}
