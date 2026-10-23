/**
 * NVD (National Vulnerability Database) 2.0 API Adapter
 * Standard: https://nvd.nist.gov/developers/vulnerabilities
 * Supports: Keyless Degraded Mode (stricter rate limit, caching, fallback) & API-Key Production Mode
 */

import { VulnerabilityAdvisory, PackageEcosystem } from '../types.ts';
import { CANONICAL_ADVISORY_FIXTURES } from './catalog.ts';

export interface NVDAdapterConfig {
  apiKey?: string;
  cacheTtlMs?: number;
}

export class NVDAdapter {
  private static readonly NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private static readonly cache: Map<string, { data: VulnerabilityAdvisory[]; cachedAt: number }> = new Map();
  private static lastRequestTime = 0;

  /**
   * Queries NVD by CVE ID or keyword
   */
  public static async queryCve(
    cveId: string,
    config: NVDAdapterConfig = {}
  ): Promise<VulnerabilityAdvisory | null> {
    // 1. Check local catalog first
    const localMatch = CANONICAL_ADVISORY_FIXTURES.find(adv => 
      adv.vuln_id === cveId || adv.aliases.includes(cveId)
    );
    if (localMatch) return localMatch;

    // 2. Check in-memory cache
    const cacheKey = `cve:${cveId}`;
    const cached = NVDAdapter.cache.get(cacheKey);
    const ttl = config.cacheTtlMs || 3600000;
    if (cached && Date.now() - cached.cachedAt < ttl) {
      return cached.data[0] || null;
    }

    // 3. Keyless degraded mode rate limiter (5000ms delay if keyless, 600ms if with API key)
    const minDelay = config.apiKey ? 600 : 5000;
    const now = Date.now();
    const elapsed = now - NVDAdapter.lastRequestTime;
    if (elapsed < minDelay) {
      // Degraded mode: return local or empty to prevent blocking/rate limit throttling
      return null;
    }

    try {
      if (typeof fetch !== 'undefined') {
        const headers: Record<string, string> = {};
        if (config.apiKey) {
          headers['apiKey'] = config.apiKey;
        }

        NVDAdapter.lastRequestTime = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const url = `${NVDAdapter.NVD_BASE_URL}?cveId=${encodeURIComponent(cveId)}`;
        const res = await fetch(url, { headers, signal: controller.signal }).catch(() => null);
        clearTimeout(timeoutId);

        if (res && res.ok) {
          const data = await res.json();
          if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            const cveItem = data.vulnerabilities[0].cve;
            const norm = NVDAdapter.normalizeNvdCve(cveItem);
            NVDAdapter.cache.set(cacheKey, { data: [norm], cachedAt: Date.now() });
            return norm;
          }
        }
      }
    } catch {
      // Graceful degraded mode handling
    }

    return null;
  }

  private static normalizeNvdCve(cve: any): VulnerabilityAdvisory {
    const vulnId = cve.id || 'CVE-UNKNOWN';
    const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'NVD Security Advisory';
    
    // Extract CVSS v3.1
    let cvssScore: number | undefined;
    let cvssVector: string | undefined;
    let severity = 'MEDIUM';

    if (cve.metrics?.cvssMetricV31 && cve.metrics.cvssMetricV31.length > 0) {
      const cvssData = cve.metrics.cvssMetricV31[0].cvssData;
      cvssScore = cvssData?.baseScore;
      cvssVector = cvssData?.vectorString;
      severity = cvssData?.baseSeverity || 'MEDIUM';
    }

    // Extract CWEs
    const cweIds: string[] = [];
    if (cve.weaknesses) {
      for (const w of cve.weaknesses) {
        for (const desc of w.description || []) {
          if (desc.value && desc.value.startsWith('CWE-')) {
            cweIds.push(desc.value);
          }
        }
      }
    }

    const references = (cve.references || []).map((r: any) => r.url).filter(Boolean);

    return {
      vuln_id: vulnId,
      aliases: [],
      title: description.slice(0, 100),
      summary: description.slice(0, 200),
      details: description,
      ecosystem: 'generic',
      package_name: 'generic',
      affected_version_ranges: [],
      fixed_versions: [],
      cvss_v3_score: cvssScore,
      cvss_v3_vector: cvssVector,
      severity: severity.toUpperCase() as any,
      cwe_ids: cweIds,
      references,
      published_at: cve.published,
    };
  }
}
