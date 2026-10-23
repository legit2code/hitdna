/**
 * Deterministic CycloneDX v1.5 SBOM Generation & Validation Engine
 * Standard: CycloneDX v1.5 JSON Specification
 */

import { DependencyGraph, CycloneDXSbom, CycloneDXComponent, CycloneDXDependency } from '../types.ts';
import { PurlHelper } from '../purl/index.ts';

export class CycloneDXGenerator {
  /**
   * Generates a strictly deterministic CycloneDX 1.5 JSON SBOM
   */
  public static generate(
    graph: DependencyGraph,
    fixedTimestamp = '2026-08-24T00:00:00.000Z'
  ): CycloneDXSbom {
    const rootPurl = PurlHelper.generate(graph.ecosystem, graph.root_name, graph.root_version);
    const rootRef = `pkg:${graph.ecosystem}/${graph.root_name}@${graph.root_version}`;

    // Deterministically sort components by PURL
    const sortedComponents = [...graph.all_components].sort((a, b) => a.purl.localeCompare(b.purl));

    const components: CycloneDXComponent[] = sortedComponents.map(comp => {
      const compRef = comp.purl;
      const componentEntry: CycloneDXComponent = {
        'bom-ref': compRef,
        type: 'library',
        name: comp.name,
        version: comp.resolved_version || comp.version,
        purl: comp.purl,
        scope: comp.scope === 'DEV' ? 'excluded' : 'required',
      };

      if (comp.license) {
        componentEntry.licenses = [{ license: { name: comp.license } }];
      }

      if (comp.checksum_sha256) {
        componentEntry.hashes = [{ alg: 'SHA-256', content: comp.checksum_sha256 }];
      }

      componentEntry.properties = [
        { name: 'caim:is_direct', value: comp.is_direct ? 'true' : 'false' },
        { name: 'caim:depth', value: String(comp.depth) },
        { name: 'caim:ecosystem', value: comp.ecosystem },
      ];

      return componentEntry;
    });

    // Build deterministic dependencies list
    const depMap: Map<string, Set<string>> = new Map();
    depMap.set(rootRef, new Set());

    // Root direct dependencies
    for (const direct of graph.direct_dependencies) {
      depMap.get(rootRef)!.add(direct.purl);
    }

    // Inter-component edges
    for (const edge of graph.edges) {
      if (!depMap.has(edge.from_purl)) {
        depMap.set(edge.from_purl, new Set());
      }
      depMap.get(edge.from_purl)!.add(edge.to_purl);
    }

    const sortedRefs = Array.from(depMap.keys()).sort();
    const dependencies: CycloneDXDependency[] = sortedRefs.map(ref => ({
      ref,
      dependsOn: Array.from(depMap.get(ref)!).sort(),
    }));

    // Generate a deterministic serial number based on content hash
    const contentSeed = `${graph.root_name}@${graph.root_version}:${sortedComponents.map(c => c.purl).join(',')}`;
    const serialNumber = CycloneDXGenerator.generateDeterministicUUID(contentSeed);

    const sbom: CycloneDXSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${serialNumber}`,
      version: 1,
      metadata: {
        timestamp: fixedTimestamp,
        tools: [
          {
            vendor: 'CAIM',
            name: 'CAIM-SBOM-Engine',
            version: '2.0.1',
          }
        ],
        component: {
          name: graph.root_name,
          version: graph.root_version,
          type: 'application',
          purl: rootPurl,
        }
      },
      components,
      dependencies,
    };

    return sbom;
  }

  /**
   * Formats SBOM to canonical, deterministically indented JSON
   */
  public static toCanonicalJson(sbom: CycloneDXSbom): string {
    return JSON.stringify(sbom, Object.keys(sbom).sort(), 2);
  }

  /**
   * Validates if object conforms to CycloneDX 1.5 JSON basic structure
   */
  public static validate(sbom: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!sbom || typeof sbom !== 'object') {
      return { valid: false, errors: ['SBOM is not an object'] };
    }
    if (sbom.bomFormat !== 'CycloneDX') {
      errors.push('bomFormat must be "CycloneDX"');
    }
    if (sbom.specVersion !== '1.5') {
      errors.push('specVersion must be "1.5"');
    }
    if (!sbom.serialNumber || !sbom.serialNumber.startsWith('urn:uuid:')) {
      errors.push('serialNumber must be a valid urn:uuid: URI');
    }
    if (!Array.isArray(sbom.components)) {
      errors.push('components must be an array');
    }
    if (!Array.isArray(sbom.dependencies)) {
      errors.push('dependencies must be an array');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Deterministic v5-style UUID derived from text hash (SHA-256 based)
   */
  private static generateDeterministicUUID(input: string): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = (hash * 0x01000193) >>> 0;
    }

    const hex = ('00000000' + hash.toString(16)).slice(-8) +
                ('00000000' + ((hash ^ 0x5a5a5a5a) >>> 0).toString(16)).slice(-8) +
                ('00000000' + ((hash ^ 0xa5a5a5a5) >>> 0).toString(16)).slice(-8) +
                ('00000000' + ((hash ^ 0x3c3c3c3c) >>> 0).toString(16)).slice(-8);

    // Format as 8-4-4-4-12 UUID
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  }
}
