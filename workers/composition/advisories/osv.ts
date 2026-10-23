/**
 * OSV (Open Source Vulnerabilities) API Adapter
 * Standard: https://osv.dev/api
 */

import { VulnerabilityAdvisory, PackageEcosystem } from '../types.ts';
import { CANONICAL_ADVISORY_FIXTURES } from './catalog.ts';

export class OSVAdapter {
  private static readonly OSV_BASE_URL = 'https://api.osv.dev/v1/query';

  /**
   * Queries OSV for a package by name and ecosystem, or returns cached/offline matching advisories
   */
  public static async queryPackage(
    ecosystem: PackageEcosystem,
    packageName: string,
    version?: string
  ): Promise<VulnerabilityAdvisory[]> {
    const lowName = packageName.toLowerCase();

    // 1. Check local canonical catalog
    const localMatches = CANONICAL_ADVISORY_FIXTURES.filter(adv => 
      adv.package_name.toLowerCase() === lowName && 
      (adv.ecosystem === ecosystem || adv.ecosystem === 'generic')
    );

    if (localMatches.length > 0) {
      if (version) {
        return localMatches.filter(adv => 
          !adv.affected_version_ranges || 
          adv.affected_version_ranges.length === 0 || 
          OSVAdapter.isVersionVulnerable(version, adv.affected_version_ranges)
        );
      }
      return localMatches;
    }

    // 2. In live environments, attempt network fetch with graceful offline fallback
    try {
      if (typeof fetch !== 'undefined') {
        const payload: any = {
          package: {
            name: packageName,
            ecosystem: OSVAdapter.mapEcosystemToOsv(ecosystem),
          }
        };
        if (version) {
          payload.version = version;
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1500);

        const res = await fetch(OSVAdapter.OSV_BASE_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        }).catch(() => null);

        clearTimeout(timeoutId);

        if (res && res.ok) {
          const data = await res.json();
          if (data.vulns && Array.isArray(data.vulns)) {
            return data.vulns.map((v: any) => OSVAdapter.normalizeOsvRecord(v, ecosystem, packageName));
          }
        }
      }
    } catch {
      // Network failure / offline mode gracefully handled
    }

    return [];
  }

  private static mapEcosystemToOsv(eco: PackageEcosystem): string {
    switch (eco) {
      case 'npm': return 'npm';
      case 'pypi': return 'PyPI';
      case 'golang': return 'Go';
      case 'cargo': return 'crates.io';
      case 'maven': return 'Maven';
      case 'nuget': return 'NuGet';
      default: return 'npm';
    }
  }

  private static normalizeOsvRecord(raw: any, eco: PackageEcosystem, pkgName: string): VulnerabilityAdvisory {
    const id = raw.id || 'OSV-UNKNOWN';
    const aliases = raw.aliases || [];
    const summary = raw.summary || raw.details?.slice(0, 120) || 'Security vulnerability in ' + pkgName;
    const severity = raw.database_specific?.severity || 'HIGH';

    const fixedVersions: string[] = [];
    const affectedRanges: string[] = [];

    if (raw.affected && Array.isArray(raw.affected)) {
      for (const aff of raw.affected) {
        if (aff.ranges && Array.isArray(aff.ranges)) {
          for (const r of aff.ranges) {
            if (r.events && Array.isArray(r.events)) {
              for (const ev of r.events) {
                if (ev.fixed) fixedVersions.push(ev.fixed);
                if (ev.introduced) affectedRanges.push(`>=${ev.introduced}`);
              }
            }
          }
        }
      }
    }

    return {
      vuln_id: id,
      aliases,
      title: summary,
      summary,
      details: raw.details,
      ecosystem: eco,
      package_name: pkgName,
      affected_version_ranges: affectedRanges,
      fixed_versions: fixedVersions,
      severity: severity.toUpperCase() as any,
      cwe_ids: [],
      references: (raw.references || []).map((r: any) => r.url).filter(Boolean),
    };
  }

  public static isVersionVulnerable(version: string, affectedRanges: string[]): boolean {
    if (!affectedRanges || affectedRanges.length === 0) return true;
    const cleanVer = version.replace(/^[v^~>=<]+/, '').trim();
    if (!cleanVer) return true;

    for (const range of affectedRanges) {
      const match = range.match(/^([<>=!~]+)\s*(.+)$/);
      if (match) {
        const op = match[1];
        const target = match[2];
        const cmp = OSVAdapter.compareSemver(cleanVer, target);
        if (op === '<' && cmp >= 0) return false;
        if (op === '<=' && cmp > 0) return false;
        if (op === '>' && cmp <= 0) return false;
        if (op === '>=' && cmp < 0) return false;
      }
    }
    return true;
  }

  public static compareSemver(v1: string, v2: string): number {
    const p1 = v1.split(/[\.-]/).map(n => parseInt(n, 10) || 0);
    const p2 = v2.split(/[\.-]/).map(n => parseInt(n, 10) || 0);
    const len = Math.max(p1.length, p2.length);

    for (let i = 0; i < len; i++) {
      const a = p1[i] || 0;
      const b = p2[i] || 0;
      if (a > b) return 1;
      if (a < b) return -1;
    }
    return 0;
  }
}
