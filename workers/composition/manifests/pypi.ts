/**
 * PyPI / Python Manifest Parsers (requirements.txt, pyproject.toml, Pipfile, poetry.lock)
 */

import { PackageIdentifier, DependencyEdge, DependencyScope } from '../types.ts';
import { PurlHelper } from '../purl/index.ts';

export interface ParsedPypiResult {
  rootName: string;
  rootVersion: string;
  directDependencies: PackageIdentifier[];
  transitiveDependencies: PackageIdentifier[];
  edges: DependencyEdge[];
}

export class PypiManifestParser {
  /**
   * Parses Python requirements.txt or pyproject.toml
   */
  public static parseRequirementsTxt(
    content: string,
    rootName = 'python-project',
    rootVersion = '0.1.0'
  ): ParsedPypiResult {
    const rootPurl = PurlHelper.generate('pypi', rootName, rootVersion);
    const directDependencies: PackageIdentifier[] = [];
    const edges: DependencyEdge[] = [];

    const lines = content.split('\n');
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('-r') || line.startsWith('-i') || line.startsWith('--')) {
        continue;
      }

      // Regex matching package specs: requests==2.31.0, numpy>=1.20, torch~=2.0.1, pandas
      const match = line.match(/^([a-zA-Z0-9_\-\.]+)(?:\s*([~>=<!=]+)\s*([a-zA-Z0-9_\-\.\*]+))?/);
      if (match) {
        const name = match[1].toLowerCase();
        const op = match[2] || '==';
        const version = match[3] || '0.0.0';
        const purl = PurlHelper.generate('pypi', name, version);

        directDependencies.push({
          ecosystem: 'pypi',
          name,
          version,
          purl,
          scope: 'RUNTIME',
          is_direct: true,
          depth: 1,
          resolved_version: version,
        });

        edges.push({
          from_purl: rootPurl,
          to_purl: purl,
          requirement_spec: `${op}${version}`,
          scope: 'RUNTIME',
        });
      }
    }

    return {
      rootName,
      rootVersion,
      directDependencies,
      transitiveDependencies: [],
      edges,
    };
  }

  /**
   * Parses pyproject.toml dependencies section
   */
  public static parsePyprojectToml(
    content: string,
    rootName = 'python-project',
    rootVersion = '0.1.0'
  ): ParsedPypiResult {
    const rootPurl = PurlHelper.generate('pypi', rootName, rootVersion);
    const directDependencies: PackageIdentifier[] = [];
    const edges: DependencyEdge[] = [];

    // Extract dependencies under [project.dependencies] or [tool.poetry.dependencies]
    const inDepsBlockRegex = /(?:\[project\.dependencies\]|dependencies\s*=\s*\[)([\s\S]*?)(?:\]|\[|$)/g;
    let match: RegExpExecArray | null;

    while ((match = inDepsBlockRegex.exec(content)) !== null) {
      const block = match[1];
      const depLines = block.split('\n');
      for (const dLine of depLines) {
        const line = dLine.replace(/['",]/g, '').trim();
        if (!line || line.startsWith('#')) continue;

        const specMatch = line.match(/^([a-zA-Z0-9_\-\.]+)(?:\s*([~>=<!=^]+)\s*([a-zA-Z0-9_\-\.\*]+))?/);
        if (specMatch) {
          const name = specMatch[1].toLowerCase();
          const version = specMatch[3] || '0.0.0';
          const purl = PurlHelper.generate('pypi', name, version);

          directDependencies.push({
            ecosystem: 'pypi',
            name,
            version,
            purl,
            scope: 'RUNTIME',
            is_direct: true,
            depth: 1,
            resolved_version: version,
          });

          edges.push({
            from_purl: rootPurl,
            to_purl: purl,
            requirement_spec: line,
            scope: 'RUNTIME',
          });
        }
      }
    }

    return {
      rootName,
      rootVersion,
      directDependencies,
      transitiveDependencies: [],
      edges,
    };
  }
}
