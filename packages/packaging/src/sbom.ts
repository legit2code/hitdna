import { sha256 } from './hashing.ts';

/**
 * CycloneDX SBOM Generator (Specification 1.5)
 * Builds deterministic Software Bill of Materials for Agent Releases.
 */

export interface SbomComponent {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'application' | 'model' | 'tool';
  purl?: string;
  licenses?: string[];
  description?: string;
  sha256?: string;
  vulnerabilities?: Array<{
    id: string;
    severity: string;
    description: string;
  }>;
}

export interface CycloneDxMetadata {
  componentName: string;
  version: string;
  author?: string;
  licenses?: string[];
  timestamp?: string;
}

export class CycloneDxGenerator {
  /**
   * Generates a valid CycloneDX v1.5 JSON SBOM.
   */
  static generateSbom(
    metadata: CycloneDxMetadata,
    components: SbomComponent[]
  ): Record<string, any> {
    // Sort components deterministically by name and version
    const sortedComponents = [...components].sort((a, b) => {
      const nameCmp = a.name.localeCompare(b.name);
      if (nameCmp !== 0) return nameCmp;
      return a.version.localeCompare(b.version);
    });

    const serialNumberUuid = `urn:uuid:caim-sbom-${sha256(`${metadata.componentName}@${metadata.version}`).slice(0, 32)}`;

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: serialNumberUuid,
      version: 1,
      metadata: {
        timestamp: metadata.timestamp || '2026-08-26T00:00:00Z',
        tools: [
          {
            vendor: 'CAIM Platform',
            name: 'CycloneDX SBOM Generator',
            version: '2.0.1',
          },
        ],
        component: {
          type: 'application',
          name: metadata.componentName,
          version: metadata.version,
          author: metadata.author || 'CAIM Engineering',
          licenses: (metadata.licenses || ['Apache-2.0']).map((lic) => ({
            license: { id: lic },
          })),
        },
      },
      components: sortedComponents.map((comp) => {
        const item: Record<string, any> = {
          type: comp.type,
          name: comp.name,
          version: comp.version,
          purl: comp.purl || `pkg:generic/${comp.name}@${comp.version}`,
        };

        if (comp.description) {
          item.description = comp.description;
        }

        if (comp.licenses && comp.licenses.length > 0) {
          item.licenses = comp.licenses.map((lic) => ({
            license: { id: lic },
          }));
        }

        if (comp.sha256) {
          item.hashes = [
            {
              alg: 'SHA-256',
              content: comp.sha256,
            },
          ];
        }

        return item;
      }),
      vulnerabilities: sortedComponents.flatMap((comp) => {
        if (!comp.vulnerabilities || comp.vulnerabilities.length === 0) {
          return [];
        }
        return comp.vulnerabilities.map((vuln) => ({
          id: vuln.id,
          source: { name: 'NVD' },
          ratings: [
            {
              severity: vuln.severity.toLowerCase(),
              method: 'CVSSv3',
            },
          ],
          description: vuln.description,
          affects: [
            {
              ref: comp.purl || `pkg:generic/${comp.name}@${comp.version}`,
            },
          ],
        }));
      }),
    };
  }
}
