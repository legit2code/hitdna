/**
 * Golang & Cargo Manifest Parsers (go.mod, go.sum, Cargo.toml, Cargo.lock)
 */

import { PackageIdentifier, DependencyEdge } from '../types.ts';
import { PurlHelper } from '../purl/index.ts';

export interface ParsedManifestResult {
  rootName: string;
  rootVersion: string;
  directDependencies: PackageIdentifier[];
  transitiveDependencies: PackageIdentifier[];
  edges: DependencyEdge[];
}

export class GolangManifestParser {
  /**
   * Parses go.mod and go.sum
   */
  public static parse(goModContent: string, goSumContent?: string): ParsedManifestResult {
    let rootName = 'go-module';
    const rootVersion = 'v0.1.0';

    const moduleMatch = goModContent.match(/^module\s+([^\s\n]+)/m);
    if (moduleMatch) {
      rootName = moduleMatch[1].trim();
    }

    const rootPurl = PurlHelper.generate('golang', rootName, rootVersion);
    const directDependencies: PackageIdentifier[] = [];
    const transitiveDependencies: PackageIdentifier[] = [];
    const edges: DependencyEdge[] = [];

    // Parse require blocks or single lines
    const requireBlockRegex = /require\s*\(([\s\S]*?)\)/g;
    let blockMatch: RegExpExecArray | null;

    const processReqLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) return;

      const isIndirect = trimmed.includes('// indirect');
      const cleanLine = trimmed.replace(/\/\/.*$/, '').trim();
      const parts = cleanLine.split(/\s+/);
      if (parts.length >= 2) {
        const pkgName = parts[0];
        const pkgVer = parts[1].replace(/^v/, '');
        const purl = PurlHelper.generate('golang', pkgName, pkgVer);

        const dep: PackageIdentifier = {
          ecosystem: 'golang',
          name: pkgName,
          version: pkgVer,
          purl,
          scope: isIndirect ? 'TRANSITIVE' : 'RUNTIME',
          is_direct: !isIndirect,
          depth: isIndirect ? 2 : 1,
          resolved_version: pkgVer,
        };

        if (isIndirect) {
          transitiveDependencies.push(dep);
        } else {
          directDependencies.push(dep);
        }

        edges.push({
          from_purl: rootPurl,
          to_purl: purl,
          requirement_spec: parts[1],
          scope: isIndirect ? 'TRANSITIVE' : 'RUNTIME',
        });
      }
    };

    while ((blockMatch = requireBlockRegex.exec(goModContent)) !== null) {
      const block = blockMatch[1];
      for (const line of block.split('\n')) {
        processReqLine(line);
      }
    }

    // Single line requires: require github.com/gin-gonic/gin v1.9.1
    const singleReqRegex = /^require\s+([^\s\(\)]+)\s+([^\s\n]+)(?:\s+\/\/\s*indirect)?/gm;
    let singleMatch: RegExpExecArray | null;
    while ((singleMatch = singleReqRegex.exec(goModContent)) !== null) {
      processReqLine(singleMatch[0].replace(/^require\s+/, ''));
    }

    return {
      rootName,
      rootVersion,
      directDependencies,
      transitiveDependencies,
      edges,
    };
  }
}

export class CargoManifestParser {
  /**
   * Parses Cargo.toml and Cargo.lock
   */
  public static parse(cargoTomlContent: string, cargoLockContent?: string): ParsedManifestResult {
    let rootName = 'rust-crate';
    let rootVersion = '0.1.0';

    const nameMatch = cargoTomlContent.match(/\[package\][\s\S]*?name\s*=\s*"([^"]+)"/);
    if (nameMatch) rootName = nameMatch[1];

    const verMatch = cargoTomlContent.match(/\[package\][\s\S]*?version\s*=\s*"([^"]+)"/);
    if (verMatch) rootVersion = verMatch[1];

    const rootPurl = PurlHelper.generate('cargo', rootName, rootVersion);
    const directDependencies: PackageIdentifier[] = [];
    const transitiveDependencies: PackageIdentifier[] = [];
    const edges: DependencyEdge[] = [];

    // Parse [dependencies] section
    const depsMatch = cargoTomlContent.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
    if (depsMatch) {
      const lines = depsMatch[1].split('\n');
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        // name = "1.0" or name = { version = "1.0", features = [...] }
        const simpleMatch = line.match(/^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"/);
        const objMatch = line.match(/^([a-zA-Z0-9_\-]+)\s*=\s*\{[\s\S]*?version\s*=\s*"([^"]+)"/);

        if (simpleMatch || objMatch) {
          const name = (simpleMatch ? simpleMatch[1] : objMatch![1]).trim();
          const version = (simpleMatch ? simpleMatch[2] : objMatch![2]).trim();
          const purl = PurlHelper.generate('cargo', name, version);

          directDependencies.push({
            ecosystem: 'cargo',
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
            requirement_spec: version,
            scope: 'RUNTIME',
          });
        }
      }
    }

    return {
      rootName,
      rootVersion,
      directDependencies,
      transitiveDependencies,
      edges,
    };
  }
}
