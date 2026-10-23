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

export interface KaggleKernelItem {
  id?: number;
  ref?: string; // e.g. "username/notebook-name"
  title?: string;
  author?: string;
  slug?: string;
  lastUpdateTime?: string;
  totalVotes?: number;
  views?: number;
  isPrivate?: boolean;
  language?: string;
  kernelType?: string;
  outputUrl?: string;
  categories?: string[];
  keywords?: string[];
}

export interface KaggleAdapterOptions {
  username?: string;
  key?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class KaggleSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'kaggle';
  readonly sourceName = 'Kaggle';
  readonly adapterVersion = '1.0.0';

  private readonly username?: string;
  private readonly key?: string;
  private readonly baseUrl: string;

  constructor(options: KaggleAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: 120,
        remaining: 120,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.username = options.username || (typeof process !== 'undefined' ? process.env.KAGGLE_USERNAME : undefined);
    this.key = options.key || (typeof process !== 'undefined' ? process.env.KAGGLE_KEY : undefined);
    this.baseUrl = (options.baseUrl || 'https://www.kaggle.com').replace(/\/$/, '');
  }

  private getAuthHeader(): string | undefined {
    if (this.username && this.key) {
      const creds = Buffer.from(`${this.username}:${this.key}`).toString('base64');
      return `Basic ${creds}`;
    }
    return undefined;
  }

  private parseKernelRef(locator: string): string {
    let clean = locator.replace(/^kaggle:\/\//, '');
    clean = clean.replace(/^https?:\/\/www\.kaggle\.com\/code\//, '');
    clean = clean.replace(/^https?:\/\/www\.kaggle\.com\//, '');
    clean = clean.replace(/\/$/, '');
    if (!clean.includes('/')) {
      throw new Error(`Invalid Kaggle kernel locator: '${locator}'. Expected format 'username/kernel-slug'`);
    }
    return clean;
  }

  /**
   * Assesses notebook for evidence of tool execution, planning, memory, or agent frameworks.
   * Ordinary notebooks that merely call an LLM for prompt completion are rejected / low confidence.
   */
  private evaluateAgentSignals(kernel: KaggleKernelItem): {
    isAgentCandidate: boolean;
    confidence: number;
    detectedSignals: string[];
    analysis: string;
  } {
    const text = `${kernel.title || ''} ${kernel.ref || ''} ${(kernel.keywords || []).join(' ')} ${(kernel.categories || []).join(' ')}`.toLowerCase();
    const detectedSignals: string[] = [];

    // 1. Tool execution
    if (text.includes('tool') || text.includes('function-calling') || text.includes('api-execution') || text.includes('code-interpreter')) {
      detectedSignals.push('TOOL_EXECUTION');
    }

    // 2. Planning & Reasoning loops
    if (text.includes('planning') || text.includes('react-prompt') || text.includes('cot') || text.includes('chain-of-thought') || text.includes('reflection')) {
      detectedSignals.push('PLANNING_OR_REASONING');
    }

    // 3. Memory systems
    if (text.includes('memory') || text.includes('vector-db') || text.includes('rag-agent') || text.includes('retrieval-augmented')) {
      detectedSignals.push('MEMORY_OR_KNOWLEDGE_STORE');
    }

    // 4. Agent frameworks
    if (text.includes('crewai') || text.includes('autogen') || text.includes('langgraph') || text.includes('smolagents') || text.includes('agentic')) {
      detectedSignals.push('AGENT_FRAMEWORK');
    }

    const isAgentCandidate = detectedSignals.length > 0;
    const confidence = isAgentCandidate ? Math.min(1.0, 0.5 + detectedSignals.length * 0.12) : 0.1;

    return {
      isAgentCandidate,
      confidence,
      detectedSignals,
      analysis: isAgentCandidate
        ? `Verified agent signals: [${detectedSignals.join(', ')}]`
        : 'Ordinary data science / LLM inference notebook without agentic loop or tool use',
    };
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const authHeader = this.getAuthHeader();
    if (!authHeader) {
      throw new Error(
        '[AUTH_REQUIRED] Kaggle API strictly requires username and key. ' +
        'Set KAGGLE_USERNAME and KAGGLE_KEY environment variables.'
      );
    }

    const page = cursor?.page || 1;
    const pageSize = Math.min(criteria.limit || 20, 100);
    const search = criteria.query || 'agent';

    const url = new URL(`${this.baseUrl}/api/v1/kernels/list`);
    url.searchParams.set('search', search);
    url.searchParams.set('page', String(page));
    url.searchParams.set('pageSize', String(pageSize));

    const res = await this.request<KaggleKernelItem[]>(url.toString(), {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'caim-source-adapter/1.0.0',
        'Authorization': authHeader,
      },
    });

    const items = Array.isArray(res.data) ? res.data : [];

    const candidates: DiscoveryCandidate[] = items.map((k) => {
      const evaluation = this.evaluateAgentSignals(k);
      const ref = k.ref || `${k.author}/${k.slug}`;
      return {
        source_locator: `kaggle://${ref}`,
        display_name: `${k.title || ref} by ${k.author || 'unknown'}`,
        source_type: this.sourceType,
        type_hint: evaluation.isAgentCandidate ? 'AGENT_REPOSITORY' : 'UNSPECIFIED',
        confidence: evaluation.confidence,
        summary: `${evaluation.analysis} (Votes: ${k.totalVotes || 0}, Views: ${k.views || 0})`,
        raw_metadata: {
          ...k,
          caim_agent_evaluation: evaluation,
        } as unknown as Record<string, unknown>,
        created_at: k.lastUpdateTime,
        updated_at: k.lastUpdateTime,
        discovered_at: new Date().toISOString(),
      };
    });

    return {
      candidates,
      next_cursor: items.length >= pageSize ? { page: page + 1 } : null,
      has_more: items.length >= pageSize,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const kernelRef = this.parseKernelRef(locator);
    const authHeader = this.getAuthHeader();
    if (!authHeader) {
      throw new Error(
        '[AUTH_REQUIRED] Kaggle API strictly requires username and key to fetch kernel metadata.'
      );
    }

    const url = `${this.baseUrl}/api/v1/kernels/list?search=${encodeURIComponent(kernelRef)}&pageSize=5`;
    const res = await this.request<KaggleKernelItem[]>(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'caim-source-adapter/1.0.0',
        'Authorization': authHeader,
      },
      locator: `kaggle://${kernelRef}`,
    });

    const items = Array.isArray(res.data) ? res.data : [];
    const matched = items.find((k) => k.ref === kernelRef) || items[0];

    if (!matched) {
      throw new Error(`[SOURCE_UNAVAILABLE] Kaggle kernel '${kernelRef}' not found`);
    }

    const evaluation = this.evaluateAgentSignals(matched);
    const enriched = {
      ...matched,
      caim_agent_evaluation: evaluation,
    } as unknown as Record<string, unknown>;
    const contentHash = this.hashPayload(enriched);

    return {
      source_locator: `kaggle://${kernelRef}`,
      raw_metadata: enriched,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveKaggle(locator, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const kernelRef = this.parseKernelRef(locator);

    const locators: ArtifactLocatorEntry[] = [
      {
        locator: `https://www.kaggle.com/code/${kernelRef}`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: true,
        metadata: {
          acquisition_supported: false,
          unsupported_reason: 'SOURCE_ACQUISITION_UNSUPPORTED: Kaggle kernels do not support anonymous direct source archive download. Never fabricate synthetic notebook source.',
        },
      },
    ];

    return {
      source_locator: locator,
      primary_locator: locator,
      artifacts: locators,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(locators)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    return {
      source_locator: locator,
      relationships: [],
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', []),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    try {
      const meta = await this.fetch_metadata(locator);
      const kernel = meta.raw_metadata as unknown as KaggleKernelItem;
      return {
        source_locator: locator,
        change_token: kernel.lastUpdateTime || meta.content_hash,
        token_type: 'TIMESTAMP',
        last_modified: kernel.lastUpdateTime,
      };
    } catch {
      return {
        source_locator: locator,
        change_token: 'auth-required-token',
        token_type: 'TIMESTAMP',
      };
    }
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.username && this.key ? 'AUTHENTICATED' : 'DISABLED',
      max_page_size: 100,
      rate_limit_per_minute: 60,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'author', 'language'],
      capabilities: {
        can_stream: false,
        can_search: true,
        provides_dependencies: false,
        provides_artifacts: true,
        requires_auth: true,
      },
    };
  }

  async health_check(): Promise<AdapterHealth> {
    const authHeader = this.getAuthHeader();
    if (!authHeader) {
      return {
        status: 'DEGRADED',
        auth_status: 'MISSING_CREDENTIALS',
        message: '[NOT_CONFIGURED] Kaggle API requires basic authentication. KAGGLE_USERNAME and KAGGLE_KEY must be configured in environment variables.',
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }

    const start = Date.now();
    try {
      const res = await this.request<KaggleKernelItem[]>(`${this.baseUrl}/api/v1/kernels/list?pageSize=1`, {
        headers: {
          'Accept': 'application/json',
          'Authorization': authHeader,
        },
        timeoutMs: 8000,
      });
      const latency = Date.now() - start;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: 'AUTHENTICATED',
        message: res.status === 200
          ? '[ACTIVE] Kaggle API reachable and authenticated'
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
          message: '[AUTH_REQUIRED] HTTP 401 Unauthenticated: Invalid Kaggle credentials.',
          rate_limit: this.get_rate_limit_state(),
          checked_at: new Date().toISOString(),
        };
      }
      return {
        status: 'UNHEALTHY',
        auth_status: 'AUTHENTICATED',
        message: `[SOURCE_UNAVAILABLE] Failed to reach Kaggle: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
