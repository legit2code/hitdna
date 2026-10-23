import { BaseSourceAdapter } from '../base-adapter.ts';
import {
  DiscoveryCriteria,
  DiscoveryResult,
  CursorState,
  SourceMetadataResult,
  ResolvedArtifactLocatorsResult,
  DiscoveryRelationshipsResult,
  ChangeTokenResult,
  SourcePolicy,
  AdapterHealth,
  DiscoveryCandidate,
  HttpFetcher,
  CandidateRelationship,
  ArtifactLocatorEntry,
  ImmutableResolutionResult,
} from '../types.ts';
import { ImmutableVersionResolver } from '../immutable-resolver.ts';
import { FetchGateway } from '../fetch-gateway/index.ts';

export interface ReplicateModelItem {
  url?: string;
  owner: string;
  name: string;
  description?: string;
  visibility?: string;
  github_url?: string;
  paper_url?: string;
  license_url?: string;
  run_count?: number;
  cover_image_url?: string;
  default_example?: Record<string, unknown>;
  latest_version?: {
    id: string;
    created_at: string;
    cog_version?: string;
    openapi_schema?: Record<string, unknown>;
  };
}

export interface ReplicateModelListResponse {
  next?: string | null;
  previous?: string | null;
  results?: ReplicateModelItem[];
}

export interface ReplicateAdapterOptions {
  apiToken?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class ReplicateSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'replicate';
  readonly sourceName = 'Replicate';
  readonly adapterVersion = '1.0.0';

  private readonly apiToken?: string;
  private readonly baseUrl: string;

  constructor(options: ReplicateAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: 600,
        remaining: 600,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.apiToken = options.apiToken || (typeof process !== 'undefined' ? process.env.REPLICATE_API_TOKEN : undefined);
    this.baseUrl = (options.baseUrl || 'https://api.replicate.com').replace(/\/$/, '');
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.apiToken) {
      headers['Authorization'] = `Bearer ${this.apiToken}`;
    }
    return headers;
  }

  private parseModelLocator(locator: string): { owner: string; name: string } {
    let clean = locator.replace(/^replicate:\/\//, '');
    clean = clean.replace(/^https?:\/\/replicate\.com\//, '').replace(/^https?:\/\/api\.replicate\.com\/v1\/models\//, '');
    clean = clean.replace(/\/$/, '');
    const parts = clean.split('/');
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      throw new Error(`Invalid Replicate locator: '${locator}'. Expected format 'owner/model-name'`);
    }
    return { owner: parts[0], name: parts[1] };
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    if (!this.apiToken) {
      throw new Error(
        '[AUTH_REQUIRED] Replicate API strictly requires an authentication token. ' +
        'Set REPLICATE_API_TOKEN environment variable or pass apiToken in options.'
      );
    }

    const url = cursor?.next_url || `${this.baseUrl}/v1/models`;

    const res = await this.request<ReplicateModelListResponse>(url, {
      headers: this.getHeaders(),
    });

    const items = res.data?.results || [];

    const filtered = criteria.query
      ? items.filter((m) => {
          const q = (criteria.query || '').toLowerCase();
          return (
            m.name.toLowerCase().includes(q) ||
            m.owner.toLowerCase().includes(q) ||
            (m.description || '').toLowerCase().includes(q)
          );
        })
      : items;

    // A Replicate model is a discovery candidate, NOT an automatic agent!
    const candidates: DiscoveryCandidate[] = filtered.map((m) => ({
      source_locator: `replicate://${m.owner}/${m.name}`,
      display_name: `${m.owner}/${m.name}`,
      source_type: this.sourceType,
      type_hint: 'MODEL_WEIGHTS',
      confidence: 0.7,
      summary: m.description || `Replicate model ${m.owner}/${m.name}`,
      raw_metadata: m as unknown as Record<string, unknown>,
      created_at: m.latest_version?.created_at,
      updated_at: m.latest_version?.created_at,
      discovered_at: new Date().toISOString(),
    }));

    return {
      candidates,
      next_cursor: res.data?.next ? { next_url: res.data.next } : null,
      has_more: !!res.data?.next,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const { owner, name } = this.parseModelLocator(locator);
    if (!this.apiToken) {
      throw new Error(
        '[AUTH_REQUIRED] Replicate API strictly requires an authentication token. ' +
        'Set REPLICATE_API_TOKEN to fetch metadata for Replicate models.'
      );
    }

    const url = `${this.baseUrl}/v1/models/${owner}/${name}`;
    const res = await this.request<any>(url, {
      headers: this.getHeaders(),
      locator: `replicate://${owner}/${name}`,
    });

    let raw: ReplicateModelItem;
    if (res.data && res.data.results && Array.isArray(res.data.results)) {
      raw = res.data.results.find((m: any) => m.owner === owner && m.name === name) || res.data.results[0];
    } else {
      raw = res.data || ({} as ReplicateModelItem);
    }
    const contentHash = this.hashPayload(raw);

    return {
      source_locator: `replicate://${owner}/${name}`,
      raw_metadata: raw as unknown as Record<string, unknown>,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveReplicate(locator, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const { owner, name } = this.parseModelLocator(locator);
    const locators: ArtifactLocatorEntry[] = [
      {
        locator: `https://replicate.com/${owner}/${name}`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: true,
        metadata: {
          acquisition_supported: false,
          unsupported_reason: 'SOURCE_ACQUISITION_UNSUPPORTED: Replicate hosts API inference endpoints, not raw source bytes',
        },
      },
    ];

    try {
      const model: ReplicateModelItem = (typeof candidate === 'object' && candidate.raw_metadata && (candidate.raw_metadata as any).owner)
        ? (candidate.raw_metadata as unknown as ReplicateModelItem)
        : (await this.fetch_metadata(locator)).raw_metadata as unknown as ReplicateModelItem;

      if (model.github_url) {
        locators.push({
          locator: model.github_url,
          artifact_type: 'GIT_REPOSITORY',
          mime_type: 'application/x-git',
          is_primary: false,
          metadata: {
            canonical_pivot: true,
            provider: 'github',
          },
        });
      }
      if (model.paper_url) {
        locators.push({
          locator: model.paper_url,
          artifact_type: 'DOCUMENTATION',
          mime_type: 'text/html',
          is_primary: false,
        });
      }
    } catch {
      // Primary web locator remains
    }

    return {
      source_locator: locator,
      primary_locator: locator,
      artifacts: locators,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(locators)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const relationships: CandidateRelationship[] = [];

    try {
      const model: ReplicateModelItem = (typeof candidate === 'object' && candidate.raw_metadata && (candidate.raw_metadata as any).owner)
        ? (candidate.raw_metadata as unknown as ReplicateModelItem)
        : (await this.fetch_metadata(locator)).raw_metadata as unknown as ReplicateModelItem;

      if (model.github_url) {
        relationships.push({
          from_locator: locator,
          target_locator: model.github_url,
          relationship_type: 'UPSTREAM_SOURCE',
          target_type_hint: 'AGENT_REPOSITORY',
          depth: 1,
          metadata: { role: 'source_repository' },
        });
      }
      if (model.paper_url) {
        relationships.push({
          from_locator: locator,
          target_locator: model.paper_url,
          relationship_type: 'DOCUMENTATION_LINK',
          depth: 1,
          metadata: { role: 'academic_paper' },
        });
      }
    } catch {
      // Graceful fallback
    }

    return {
      source_locator: locator,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    try {
      const meta = await this.fetch_metadata(locator);
      const model = meta.raw_metadata as unknown as ReplicateModelItem;
      const token = model.latest_version?.id || model.latest_version?.created_at || meta.content_hash;
      return {
        source_locator: locator,
        change_token: token,
        token_type: 'VERSION',
        last_modified: model.latest_version?.created_at,
      };
    } catch {
      return {
        source_locator: locator,
        change_token: 'auth-required-unverified',
        token_type: 'ETAG',
      };
    }
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.apiToken ? 'AUTHENTICATED' : 'DISABLED',
      max_page_size: 100,
      rate_limit_per_minute: 60,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'owner', 'model'],
      capabilities: {
        can_stream: false,
        can_search: false,
        provides_dependencies: false,
        provides_artifacts: true,
        requires_auth: true,
      },
    };
  }

  async health_check(): Promise<AdapterHealth> {
    if (!this.apiToken) {
      return {
        status: 'DEGRADED',
        auth_status: 'MISSING_CREDENTIALS',
        message: '[AUTH_REQUIRED] REPLICATE_API_TOKEN is not configured. Replicate API endpoint /v1/models requires an authentication token.',
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }

    const start = Date.now();
    try {
      const res = await this.request<ReplicateModelListResponse>(`${this.baseUrl}/v1/models`, {
        headers: this.getHeaders(),
        timeoutMs: 8000,
      });
      const latency = Date.now() - start;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: 'AUTHENTICATED',
        message: res.status === 200
          ? '[ACTIVE] Replicate API reachable and authenticated'
          : `[TEMPORARILY_DEGRADED] Unexpected status code: ${res.status}`,
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      if (err.statusCode === 401) {
        return {
          status: 'UNHEALTHY',
          auth_status: 'INVALID_CREDENTIALS',
          message: '[AUTH_REQUIRED] HTTP 401 Unauthenticated: Invalid or expired Replicate API token.',
          rate_limit: this.get_rate_limit_state(),
          checked_at: new Date().toISOString(),
        };
      }
      return {
        status: 'UNHEALTHY',
        auth_status: 'AUTHENTICATED',
        message: `[SOURCE_UNAVAILABLE] Failed to reach Replicate: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
