import crypto from 'crypto';
import {
  WebSearchProvider,
  WebSearchOptions,
  WebSearchResult,
  WebSearchItem,
  RateLimitState,
  AdapterHealth,
  HttpFetcher,
} from './types.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';
import { normalizeSourceHttpError, SourceAuthenticationError } from './errors.ts';
import { getDefaultFetchGateway } from './fetch-gateway/index.ts';

export interface BraveSearchProviderOptions {
  apiKey?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class BraveSearchProvider implements WebSearchProvider {
  readonly providerName = 'BraveSearch';
  readonly providerVersion = '1.0.0';

  private readonly apiKey?: string;
  private readonly baseUrl: string;
  private readonly fetcher: HttpFetcher;
  private rateLimit: RateLimitState;

  constructor(options: BraveSearchProviderOptions = {}) {
    this.apiKey = options.apiKey || (typeof process !== 'undefined' ? process.env.BRAVE_API_KEY : undefined);
    this.baseUrl = options.baseUrl || 'https://api.search.brave.com/res/v1/web/search';
    this.fetcher = options.fetcher || getDefaultFetchGateway().createFetcher();
    this.rateLimit = {
      limit: this.apiKey ? 1000 : 50,
      remaining: this.apiKey ? 1000 : 50,
      reset_at: new Date(Date.now() + 3600000).toISOString(),
      window_seconds: 3600,
      is_exhausted: false,
    };
  }

  private async defaultFetch(url: string, options: any = {}): Promise<any> {
    return getDefaultFetchGateway().request(url, {
      method: options.method,
      headers: options.headers,
      body: options.body,
      sourceType: 'brave_search',
    });
  }

  get_rate_limit_state(): RateLimitState {
    return { ...this.rateLimit };
  }

  async search(query: string, options: WebSearchOptions = {}): Promise<WebSearchResult> {
    if (process.env.NODE_ENV === 'production' && !this.apiKey) {
      throw new SourceAuthenticationError('BRAVE_API_KEY environment variable is not configured in production mode', {
        sourceType: 'brave_search',
        authStatus: 'MISSING_CREDENTIALS',
      });
    }

    if (!this.apiKey && !this.fetcher) {
      throw new SourceAuthenticationError('BRAVE_API_KEY environment variable is not configured', {
        sourceType: 'brave_search',
        authStatus: 'MISSING_CREDENTIALS',
      });
    }

    const count = options.count ?? 10;
    const offset = options.offset ?? 0;
    const url = new URL(this.baseUrl);
    url.searchParams.set('q', query);
    url.searchParams.set('count', String(Math.min(count, 20)));
    url.searchParams.set('offset', String(offset));
    if (options.freshness) url.searchParams.set('freshness', options.freshness);
    if (options.safesearch) url.searchParams.set('safesearch', options.safesearch);
    if (options.search_lang) url.searchParams.set('search_lang', options.search_lang);

    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-discovery-engine/1.0.0',
    };
    if (this.apiKey) {
      headers['X-Subscription-Token'] = this.apiKey;
    }

    const res = await this.fetcher(url.toString(), {
      method: 'GET',
      headers,
    });

    if (res.status >= 400) {
      throw normalizeSourceHttpError('brave_search', res.status, res.statusText, res.data, query);
    }

    // Update rate limits from response headers if present
    if (res.headers['x-ratelimit-remaining']) {
      const remaining = parseInt(res.headers['x-ratelimit-remaining'], 10);
      this.rateLimit.remaining = isNaN(remaining) ? this.rateLimit.remaining : remaining;
      this.rateLimit.is_exhausted = this.rateLimit.remaining <= 0;
    }

    const rawResults = res.data?.web?.results || res.data?.results || [];
    const items: WebSearchItem[] = rawResults.map((raw: any) => {
      let hostname = '';
      try {
        hostname = new URL(raw.url).hostname;
      } catch {
        hostname = 'unknown';
      }

      return {
        title: raw.title || 'Untitled',
        url: raw.url,
        description: raw.description || raw.snippet || '',
        source_hostname: hostname,
        published_at: raw.page_age || raw.age || undefined,
        language: raw.language || 'en',
        raw_metadata: raw,
        confidence: 0.85,
        discovered_at: new Date().toISOString(),
      };
    });

    const inputHash = crypto.createHash('sha256').update(`${query}:${JSON.stringify(options)}`).digest('hex');

    return {
      query,
      provider: this.providerName,
      items,
      total_results: res.data?.web?.total ?? items.length,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('WEB_SEARCH', [inputHash]),
    };
  }

  async health_check(): Promise<AdapterHealth> {
    const start = Date.now();
    try {
      if (!this.apiKey) {
        return {
          status: 'DEGRADED',
          auth_status: 'MISSING_CREDENTIALS',
          message: 'Brave Search operational in degraded/mock mode (BRAVE_API_KEY missing)',
          rate_limit: this.get_rate_limit_state(),
          checked_at: new Date().toISOString(),
        };
      }

      // Lightweight test query
      await this.search('caim agent verification', { count: 1 });
      return {
        status: 'HEALTHY',
        auth_status: 'AUTHENTICATED',
        message: 'Brave Search API connected and operational',
        latency_ms: Date.now() - start,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'INVALID_CREDENTIALS',
        message: `Brave Search health check failed: ${err.message}`,
        latency_ms: Date.now() - start,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }

  generate_provenance(action: string, inputHashes?: string[], ruleId?: string): ProvenanceRecord {
    const record: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: inputHashes || [crypto.createHash('sha256').update(action).digest('hex')],
      rule_id: ruleId || `WEB_SEARCH_${action.toUpperCase()}`,
      ruleset_version: '1.0.0',
      transformation_type: 'DIRECT_EXTRACTION',
      confidence: 0.9,
      derived_at: new Date().toISOString(),
      engine_signature: `caim:web-search:${this.providerName.toLowerCase()}:v${this.providerVersion}`,
    };
    return ProvenanceRecordSchema.parse(record);
  }
}
