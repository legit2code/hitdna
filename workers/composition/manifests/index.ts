/**
 * Unified Manifest & Lockfile Parsing Registry
 */

import { PackageEcosystem, DependencyGraph, PackageIdentifier, DependencyEdge } from '../types.ts';
import { NpmManifestParser } from './npm.ts';
import { PypiManifestParser } from './pypi.ts';
import { GolangManifestParser, CargoManifestParser } from './golang.ts';
import { PurlHelper } from '../purl/index.ts';

export class ManifestParserRegistry {
  /**
   * Discovers and parses all manifests from a map of file paths to content
   */
  public static parseAll(files: Map<string, string>): DependencyGraph {
    let primaryEcosystem: PackageEcosystem = 'npm';
    let rootName = 'unnamed-artifact';
    let rootVersion = '1.0.0';

    const directMap: Map<string, PackageIdentifier> = new Map();
    const transitiveMap: Map<string, PackageIdentifier> = new Map();
    const allEdges: DependencyEdge[] = [];

    // 1. Check for npm package.json
    let packageJson = files.get('package.json');
    if (!packageJson) {
      // Check subdirectories
      for (const [path, content] of files.entries()) {
        if (path.endsWith('package.json')) {
          packageJson = content;
          break;
        }
      }
    }

    if (packageJson) {
      primaryEcosystem = 'npm';
      let lockfile: string | undefined;
      let lockfileName: string | undefined;

      for (const [path, content] of files.entries()) {
        if (path.endsWith('package-lock.json') || path.endsWith('yarn.lock') || path.endsWith('pnpm-lock.yaml')) {
          lockfile = content;
          lockfileName = path;
          break;
        }
      }

      const res = NpmManifestParser.parse(packageJson, lockfile, lockfileName);
      rootName = res.rootName;
      rootVersion = res.rootVersion;

      for (const d of res.directDependencies) directMap.set(d.purl, d);
      for (const t of res.transitiveDependencies) transitiveMap.set(t.purl, t);
      allEdges.push(...res.edges);
    }

    // 2. Check for Python requirements.txt or pyproject.toml
    for (const [path, content] of files.entries()) {
      if (path.endsWith('requirements.txt')) {
        primaryEcosystem = 'pypi';
        const res = PypiManifestParser.parseRequirementsTxt(content);
        if (rootName === 'unnamed-artifact') rootName = res.rootName;
        for (const d of res.directDependencies) directMap.set(d.purl, d);
        allEdges.push(...res.edges);
      } else if (path.endsWith('pyproject.toml')) {
        primaryEcosystem = 'pypi';
        const res = PypiManifestParser.parsePyprojectToml(content);
        if (rootName === 'unnamed-artifact') rootName = res.rootName;
        for (const d of res.directDependencies) directMap.set(d.purl, d);
        allEdges.push(...res.edges);
      }
    }

    // 3. Check for Go go.mod
    for (const [path, content] of files.entries()) {
      if (path.endsWith('go.mod')) {
        primaryEcosystem = 'golang';
        const goSum = files.get('go.sum');
        const res = GolangManifestParser.parse(content, goSum);
        rootName = res.rootName;
        for (const d of res.directDependencies) directMap.set(d.purl, d);
        for (const t of res.transitiveDependencies) transitiveMap.set(t.purl, t);
        allEdges.push(...res.edges);
      }
    }

    // 4. Check for Rust Cargo.toml
    for (const [path, content] of files.entries()) {
      if (path.endsWith('Cargo.toml')) {
        primaryEcosystem = 'cargo';
        const cargoLock = files.get('Cargo.lock');
        const res = CargoManifestParser.parse(content, cargoLock);
        rootName = res.rootName;
        rootVersion = res.rootVersion;
        for (const d of res.directDependencies) directMap.set(d.purl, d);
        for (const t of res.transitiveDependencies) transitiveMap.set(t.purl, t);
        allEdges.push(...res.edges);
      }
    }

    // Ensure transitive map does not duplicate direct dependencies
    for (const directPurl of directMap.keys()) {
      transitiveMap.delete(directPurl);
    }

    const directList = Array.from(directMap.values());
    const transitiveList = Array.from(transitiveMap.values());
    const allComponents = [...directList, ...transitiveList];

    // Build Adjacency List
    const adjacency_list: Record<string, string[]> = {};
    for (const edge of allEdges) {
      if (!adjacency_list[edge.from_purl]) {
        adjacency_list[edge.from_purl] = [];
      }
      if (!adjacency_list[edge.from_purl].includes(edge.to_purl)) {
        adjacency_list[edge.from_purl].push(edge.to_purl);
      }
    }

    // Circular Dependency Detection (DFS)
    const circular_dependencies: string[][] = [];
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const currentPath: string[] = [];

    const detectCycles = (node: string) => {
      visited.add(node);
      recStack.add(node);
      currentPath.push(node);

      const neighbors = adjacency_list[node] || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          detectCycles(neighbor);
        } else if (recStack.has(neighbor)) {
          const cycleStart = currentPath.indexOf(neighbor);
          if (cycleStart !== -1) {
            circular_dependencies.push([...currentPath.slice(cycleStart), neighbor]);
          }
        }
      }

      currentPath.pop();
      recStack.delete(node);
    };

    const rootPurl = PurlHelper.generate(primaryEcosystem, rootName, rootVersion);
    detectCycles(rootPurl);

    return {
      root_name: rootName,
      root_version: rootVersion,
      ecosystem: primaryEcosystem,
      direct_dependencies: directList,
      transitive_dependencies: transitiveList,
      all_components: allComponents,
      edges: allEdges,
      adjacency_list,
      circular_dependencies,
      total_direct_count: directList.length,
      total_transitive_count: transitiveList.length,
    };
  }
}
