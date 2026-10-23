import crypto from 'crypto';
import { 
  SourceAdapter, 
  DiscoveryCriteria, 
  DiscoveryResult, 
  CursorState, 
  SourceMetadataResult, 
  ResolvedArtifactLocatorsResult, 
  DiscoveryRelationshipsResult, 
  ChangeTokenResult, 
  RateLimitState, 
  SourcePolicy, 
  AdapterHealth, 
  DiscoveryCandidate,
  HttpFetcher,
  HttpResponse
} from './types.ts';
import { 
  SourceAdapterError, 
  SourceRateLimitExhaustedError, 
  SourceNetworkError,
  normalizeSourceHttpError 
} from './errors.ts';
import { FetchGateway, getDefaultFetchGateway, FetchGatewayError } from './fetch-gateway/index.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export abstract class BaseSourceAdapter implements SourceAdapter {
  abstract readonly sourceType: string;
  abstract readonly sourceName: string;
  abstract readonly adapterVersion: string;

  protected readonly gateway: FetchGateway;
  protected readonly fetcher: HttpFetcher;
  protected rateLimitState: RateLimitState;

  constructor(options: {
    fetcher?: HttpFetcher;
    initialRateLimit?: Partial<RateLimitState>;
    gateway?: FetchGateway;
  } = {}) {
    this.gateway = options.gateway || getDefaultFetchGateway();
    this.fetcher = options.fetcher || this.defaultFetchTransport.bind(this);
    this.rateLimitState = {
      limit: options.initialRateLimit?.limit ?? 60,
      remaining: options.initialRateLimit?.remaining ?? 60,
      reset_at: options.initialRateLimit?.reset_at ?? new Date(Date.now() + 3600 * 1000).toISOString(),
      window_seconds: options.initialRateLimit?.window_seconds ?? 3600,
      is_exhausted: options.initialRateLimit?.is_exhausted ?? false,
    };
  }

  abstract discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult>;
  abstract fetch_metadata(locator: string): Promise<SourceMetadataResult>;
  abstract resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult>;
  abstract enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult>;
  abstract get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult>;
  abstract get_source_policy(): SourcePolicy;
  abstract health_check(): Promise<AdapterHealth>;

  get_rate_limit_state(): RateLimitState {
    return { ...this.rateLimitState };
  }

  generate_provenance(action: string, inputHashes: string[] = [], ruleId?: string): ProvenanceRecord {
    const derivedAt = new Date().toISOString();
    const record: ProvenanceRecord = {
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: inputHashes,
      rule_id: ruleId || `SOURCE_ADAPTER_${this.sourceType.toUpperCase()}_${action.toUpperCase()}`,
      ruleset_version: this.adapterVersion,
      transformation_type: 'DIRECT_EXTRACTION',
      confidence: 1.0,
      derived_at: derivedAt,
      engine_signature: `caim:source-adapter:${this.sourceType}:v${this.adapterVersion}`,
    };
    return ProvenanceRecordSchema.parse(record);
  }

  /**
   * Computes deterministic SHA-256 hash of any JavaScript payload / object.
   */
  protected hashPayload(payload: unknown): string {
    const serialized = typeof payload === 'string' 
      ? payload 
      : JSON.stringify(payload, Object.keys(payload as any || {}).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Helper to normalize string locator or candidate object to canonical string locator.
   */
  protected extractLocator(target: DiscoveryCandidate | string): string {
    if (typeof target === 'string') {
      return target;
    }
    return target.source_locator;
  }

  /**
   * Centralized HTTP executor that updates rate limits and normalizes exceptions.
   */
  protected async request<T = any>(url: string, options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    locator?: string;
    skipRobots?: boolean;
  } = {}): Promise<HttpResponse<T>> {
    // Check if client-side rate limit is known to be exhausted
    if (this.rateLimitState.is_exhausted && new Date(this.rateLimitState.reset_at) > new Date()) {
      const retryAfter = Math.max(1, Math.ceil((new Date(this.rateLimitState.reset_at).getTime() - Date.now()) / 1000));
      throw new SourceRateLimitExhaustedError(
        `Rate limit locally exhausted for ${this.sourceType}. Resets at ${this.rateLimitState.reset_at}`,
        {
          sourceType: this.sourceType,
          resetAt: this.rateLimitState.reset_at,
          retryAfterSeconds: retryAfter,
          locator: options.locator,
        }
      );
    }

    try {
      const response = await this.fetcher(url, {
        method: options.method || 'GET',
        headers: options.headers,
        body: options.body,
        timeoutMs: options.timeoutMs,
        skipRobots: options.skipRobots,
      } as any);

      this.updateRateLimitFromHeaders(response.headers);

      if (response.status < 200 || response.status >= 300) {
        throw normalizeSourceHttpError(
          this.sourceType,
          response.status,
          response.statusText,
          response.data,
          options.locator || url
        );
      }

      return response;
    } catch (err: any) {
      if (err instanceof SourceAdapterError || err instanceof FetchGatewayError) {
        throw err;
      }
      throw new SourceNetworkError(`Network request failed for ${this.sourceType} at ${url}: ${err.message}`, {
        sourceType: this.sourceType,
        locator: options.locator,
        cause: err,
      });
    }
  }

  /**
   * Parses rate limit headers from HTTP responses across common API conventions.
   */
  protected updateRateLimitFromHeaders(headers: Record<string, string> = {}) {
    const normalized: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      normalized[k.toLowerCase()] = v;
    }

    const limitHdr = normalized['x-ratelimit-limit'] || normalized['ratelimit-limit'];
    const remHdr = normalized['x-ratelimit-remaining'] || normalized['ratelimit-remaining'];
    const resetHdr = normalized['x-ratelimit-reset'] || normalized['ratelimit-reset'];
    const retryAfterHdr = normalized['retry-after'];

    if (limitHdr) {
      const limit = parseInt(limitHdr, 10);
      if (!isNaN(limit)) this.rateLimitState.limit = limit;
    }

    if (remHdr) {
      const remaining = parseInt(remHdr, 10);
      if (!isNaN(remaining)) {
        this.rateLimitState.remaining = remaining;
        this.rateLimitState.is_exhausted = remaining <= 0;
      }
    }

    if (resetHdr) {
      const resetNum = parseInt(resetHdr, 10);
      if (!isNaN(resetNum)) {
        // Handle unix timestamp in seconds vs ms
        const resetMs = resetNum < 10000000000 ? resetNum * 1000 : resetNum;
        this.rateLimitState.reset_at = new Date(resetMs).toISOString();
      }
    } else if (retryAfterHdr) {
      const retrySec = parseInt(retryAfterHdr, 10);
      if (!isNaN(retrySec)) {
        this.rateLimitState.reset_at = new Date(Date.now() + retrySec * 1000).toISOString();
      }
    }
  }

  /**
   * Centralized Fetch Gateway transport wrapper for untrusted outbound HTTP requests.
   */
  private async defaultFetchTransport(url: string, options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    skipRobots?: boolean;
  } = {}): Promise<HttpResponse> {
    return this.gateway.request(url, {
      method: options.method,
      headers: options.headers,
      body: options.body,
      timeoutMs: options.timeoutMs,
      sourceType: this.sourceType,
      skipRobots: options.skipRobots,
    });
  }
}
