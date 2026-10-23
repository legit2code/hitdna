/**
 * NPM Manifest & Lockfile Parsers (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml)
 */

import { PackageIdentifier, DependencyEdge, DependencyScope } from '../types.ts';
import { PurlHelper } from '../purl/index.ts';

export interface ParsedNpmResult {
  rootName: string;
  rootVersion: string;
  directDependencies: PackageIdentifier[];
  transitiveDependencies: PackageIdentifier[];
  edges: DependencyEdge[];
}

export class NpmManifestParser {
  /**
   * Parses package.json and optional package-lock.json / yarn.lock
   */
  public static parse(
    packageJsonContent: string,
    lockfileContent?: string,
    lockfileName?: string
  ): ParsedNpmResult {
    let pkg: any = {};
    try {
      pkg = JSON.parse(packageJsonContent);
    } catch {
      // Fallback to empty
    }

    const rootName = pkg.name || 'unnamed-project';
    const rootVersion = pkg.version || '0.0.0';
    const rootPurl = PurlHelper.generate('npm', rootName, rootVersion);

    const directDependencies: PackageIdentifier[] = [];
    const transitiveMap: Map<string, PackageIdentifier> = new Map();
    const edges: DependencyEdge[] = [];

    // Helper to add dependencies by section
    const addDirectSection = (deps: Record<string, string> | undefined, scope: DependencyScope) => {
      if (!deps || typeof deps !== 'object') return;
      for (const [name, versionSpec] of Object.entries(deps)) {
        if (typeof versionSpec !== 'string') continue;
        const cleanVersion = versionSpec.replace(/^[~^>=<v\s]+/, '').trim() || '0.0.0';
        const purl = PurlHelper.generate('npm', name, cleanVersion);
        
        const dep: PackageIdentifier = {
          ecosystem: 'npm',
          name,
          version: cleanVersion,
          purl,
          scope,
          is_direct: true,
          depth: 1,
          resolved_version: cleanVersion,
        };
        directDependencies.push(dep);

        edges.push({
          from_purl: rootPurl,
          to_purl: purl,
          requirement_spec: versionSpec,
          scope,
        });
      }
    };

    addDirectSection(pkg.dependencies, 'RUNTIME');
    addDirectSection(pkg.devDependencies, 'DEV');
    addDirectSection(pkg.peerDependencies, 'PEER');
    addDirectSection(pkg.optionalDependencies, 'OPTIONAL');

    // Parse package-lock.json v1/v2/v3
    if (lockfileContent && (!lockfileName || lockfileName.includes('package-lock.json'))) {
      try {
        const lock = JSON.parse(lockfileContent);
        // Lockfile v2/v3 packages object
        if (lock.packages && typeof lock.packages === 'object') {
          for (const [pkgPath, pkgInfo] of Object.entries<any>(lock.packages)) {
            if (!pkgPath || pkgPath === '') continue; // Skip root
            const cleanName = pkgPath.replace(/^node_modules\//, '');
            if (!cleanName || cleanName.includes('node_modules/')) {
              // Nested or sub-dependency
              const nameParts = cleanName.split('node_modules/');
              const finalName = nameParts[nameParts.length - 1];
              const version = pkgInfo.version || '0.0.0';
              const purl = PurlHelper.generate('npm', finalName, version);
              
              if (!directDependencies.some(d => d.name === finalName)) {
                transitiveMap.set(purl, {
                  ecosystem: 'npm',
                  name: finalName,
                  version,
                  purl,
                  scope: 'TRANSITIVE',
                  is_direct: false,
                  depth: 2,
                  resolved_version: version,
                  license: pkgInfo.license,
                  checksum_sha256: pkgInfo.integrity,
                });
              }
            } else {
              // Direct or top-level lock entry
              const version = pkgInfo.version || '0.0.0';
              const purl = PurlHelper.generate('npm', cleanName, version);
              const directMatch = directDependencies.find(d => d.name === cleanName);
              if (directMatch) {
                directMatch.resolved_version = version;
                directMatch.license = pkgInfo.license;
                directMatch.checksum_sha256 = pkgInfo.integrity;
              } else {
                transitiveMap.set(purl, {
                  ecosystem: 'npm',
                  name: cleanName,
                  version,
                  purl,
                  scope: 'TRANSITIVE',
                  is_direct: false,
                  depth: 2,
                  resolved_version: version,
                  license: pkgInfo.license,
                });
              }
            }

            // Dependencies of this package
            if (pkgInfo.dependencies && typeof pkgInfo.dependencies === 'object') {
              const fromPurl = PurlHelper.generate('npm', cleanName.split('node_modules/').pop() || cleanName, pkgInfo.version);
              for (const [childName, childVer] of Object.entries<string>(pkgInfo.dependencies)) {
                const cleanChildVer = (childVer || '').replace(/^[~^>=<v\s]+/, '').trim() || '0.0.0';
                const toPurl = PurlHelper.generate('npm', childName, cleanChildVer);
                edges.push({
                  from_purl: fromPurl,
                  to_purl: toPurl,
                  requirement_spec: childVer,
                  scope: 'TRANSITIVE',
                });
              }
            }
          }
        } else if (lock.dependencies && typeof lock.dependencies === 'object') {
          // Lockfile v1 dependencies object
          for (const [name, depInfo] of Object.entries<any>(lock.dependencies)) {
            const version = depInfo.version || '0.0.0';
            const purl = PurlHelper.generate('npm', name, version);
            const directMatch = directDependencies.find(d => d.name === name);
            if (directMatch) {
              directMatch.resolved_version = version;
            } else {
              transitiveMap.set(purl, {
                ecosystem: 'npm',
                name,
                version,
                purl,
                scope: 'TRANSITIVE',
                is_direct: false,
                depth: 2,
                resolved_version: version,
              });
            }
          }
        }
      } catch {
        // Lockfile parse error fallback
      }
    } else if (lockfileContent && lockfileName?.includes('yarn.lock')) {
      // Yarn.lock simplistic regex parser
      const yarnBlocks = lockfileContent.split(/\n(?=[^\s#])/);
      for (const block of yarnBlocks) {
        const headerMatch = block.match(/^"?([^@\n]+(?:@[^@\n]+)?)@/);
        const versionMatch = block.match(/version "([^"]+)"/);
        if (headerMatch && versionMatch) {
          const name = headerMatch[1].replace(/^"/, '');
          const version = versionMatch[1];
          const purl = PurlHelper.generate('npm', name, version);
          if (!directDependencies.some(d => d.name === name)) {
            transitiveMap.set(purl, {
              ecosystem: 'npm',
              name,
              version,
              purl,
              scope: 'TRANSITIVE',
              is_direct: false,
              depth: 2,
              resolved_version: version,
            });
          }
        }
      }
    }

    return {
      rootName,
      rootVersion,
      directDependencies,
      transitiveDependencies: Array.from(transitiveMap.values()),
      edges,
    };
  }
}
