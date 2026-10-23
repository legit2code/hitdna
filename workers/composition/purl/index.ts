/**
 * Package URL (PURL) Specification Normalizer
 * Standard: https://github.com/package-url/purl-spec
 */

import { PackageEcosystem } from '../types.ts';

export interface ParsedPurl {
  scheme: 'pkg';
  type: PackageEcosystem;
  namespace?: string;
  name: string;
  version?: string;
  qualifiers?: Record<string, string>;
  subpath?: string;
}

export class PurlHelper {
  /**
   * Generates a canonical PURL string
   */
  public static generate(
    ecosystem: PackageEcosystem,
    name: string,
    version?: string,
    namespace?: string,
    qualifiers?: Record<string, string>,
    subpath?: string
  ): string {
    const normType = PurlHelper.normalizeEcosystem(ecosystem);
    let purlName = name.trim();
    let normNamespace = namespace?.trim();

    // In npm, scoped packages like @foo/bar have namespace 'foo' and name 'bar'
    if (normType === 'npm' && purlName.startsWith('@') && purlName.includes('/')) {
      const parts = purlName.split('/');
      normNamespace = parts[0].replace(/^@/, '');
      purlName = parts.slice(1).join('/');
    } else if (normType === 'golang' && purlName.includes('/')) {
      const parts = purlName.split('/');
      normNamespace = parts.slice(0, -1).join('/');
      purlName = parts[parts.length - 1];
    }

    let url = `pkg:${normType}`;
    if (normNamespace) {
      url += `/${encodeURIComponent(normNamespace)}`;
    }
    url += `/${encodeURIComponent(purlName)}`;

    if (version) {
      // Strip leading 'v' if golang or standard semver
      const cleanVer = version.trim();
      url += `@${encodeURIComponent(cleanVer)}`;
    }

    if (qualifiers && Object.keys(qualifiers).length > 0) {
      const sortedKeys = Object.keys(qualifiers).sort();
      const qStr = sortedKeys.map(k => `${encodeURIComponent(k)}=${encodeURIComponent(qualifiers[k])}`).join('&');
      url += `?${qStr}`;
    }

    if (subpath) {
      url += `#${subpath.replace(/^\//, '')}`;
    }

    return url;
  }

  /**
   * Parses a PURL string into structured parts
   */
  public static parse(purlStr: string): ParsedPurl | null {
    if (!purlStr || !purlStr.startsWith('pkg:')) return null;

    try {
      const remainder = purlStr.slice(4);
      const [typePart, ...restParts] = remainder.split('/');
      if (!typePart) return null;

      const ecosystem = PurlHelper.normalizeEcosystem(typePart);
      const fullPath = restParts.join('/');

      let pathWithoutSubpath = fullPath;
      let subpath: string | undefined;
      if (pathWithoutSubpath.includes('#')) {
        const hashIdx = pathWithoutSubpath.indexOf('#');
        subpath = decodeURIComponent(pathWithoutSubpath.slice(hashIdx + 1));
        pathWithoutSubpath = pathWithoutSubpath.slice(0, hashIdx);
      }

      let pathWithoutQualifiers = pathWithoutSubpath;
      let qualifiers: Record<string, string> | undefined;
      if (pathWithoutQualifiers.includes('?')) {
        const qIdx = pathWithoutQualifiers.indexOf('?');
        const qStr = pathWithoutQualifiers.slice(qIdx + 1);
        pathWithoutQualifiers = pathWithoutQualifiers.slice(0, qIdx);

        qualifiers = {};
        for (const pair of qStr.split('&')) {
          const [k, v] = pair.split('=');
          if (k) qualifiers[decodeURIComponent(k)] = decodeURIComponent(v || '');
        }
      }

      let version: string | undefined;
      let nameNamespacePart = pathWithoutQualifiers;
      if (nameNamespacePart.includes('@')) {
        const atIdx = nameNamespacePart.lastIndexOf('@');
        version = decodeURIComponent(nameNamespacePart.slice(atIdx + 1));
        nameNamespacePart = nameNamespacePart.slice(0, atIdx);
      }

      const segments = nameNamespacePart.split('/').filter(Boolean);
      if (segments.length === 0) return null;

      let namespace: string | undefined;
      let name: string;

      if (segments.length === 1) {
        name = decodeURIComponent(segments[0]);
      } else {
        namespace = decodeURIComponent(segments.slice(0, -1).join('/'));
        name = decodeURIComponent(segments[segments.length - 1]);
      }

      return {
        scheme: 'pkg',
        type: ecosystem,
        namespace,
        name,
        version,
        qualifiers,
        subpath,
      };
    } catch {
      return null;
    }
  }

  /**
   * Normalize ecosystem identifier to canonical PURL type
   */
  public static normalizeEcosystem(eco: string): PackageEcosystem {
    const low = eco.toLowerCase().trim();
    if (low === 'npm' || low === 'javascript' || low === 'node' || low === 'typescript') return 'npm';
    if (low === 'pypi' || low === 'python' || low === 'pip') return 'pypi';
    if (low === 'golang' || low === 'go') return 'golang';
    if (low === 'cargo' || low === 'rust' || low === 'crates.io') return 'cargo';
    if (low === 'maven' || low === 'java') return 'maven';
    if (low === 'nuget' || low === 'csharp' || low === 'dotnet') return 'nuget';
    return 'generic';
  }
}
