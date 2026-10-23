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

export interface HFSpaceItem {
  _id: string;
  id: string; // e.g. "agents-course/First_agent_template"
  author?: string;
  likes?: number;
  trendingScore?: number;
  private?: boolean;
  sdk?: string;
  tags?: string[];
  createdAt?: string;
  lastModified?: string;
  cardData?: Record<string, unknown>;
  models?: string[];
  datasets?: string[];
  subdomain?: string;
  runtime?: Record<string, unknown>;
  sha?: string;
}

export interface HFSpacesAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class HuggingFaceSpacesSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'hf_spaces';
  readonly sourceName = 'Hugging Face Spaces';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: HFSpacesAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: options.token ? 5000 : 1000,
        remaining: options.token ? 5000 : 1000,
        window_seconds: 3600,
        is_exhausted: false,
      },
    });
    this.token = options.token || (typeof process !== 'undefined' ? process.env.HF_TOKEN : undefined);
    this.baseUrl = (options.baseUrl || 'https://huggingface.co').replace(/\/$/, '');
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  private parseSpaceLocator(locator: string): string {
    let clean = locator.replace(/^hf_spaces:\/\//, '').replace(/^hf-space:\/\//, '');
    clean = clean.replace(/^https?:\/\/huggingface\.co\/spaces\//, '');
    clean = clean.replace(/\/$/, '');
    if (!clean.includes('/')) {
      throw new Error(`Invalid HF Space locator: '${locator}'. Expected format 'owner/space-name'`);
    }
    return clean;
  }

  /**
   * Evaluates public Space metadata for explicit agent-relevant signals:
   * Tool use, planning, multi-agent orchestration, autonomous loops.
   * Ordinary ML demos or chatbots without tool/planning/orchestration are not classified as agents.
   */
  private evaluateAgentSignals(space: HFSpaceItem): {
    isAgentCandidate: boolean;
    confidence: number;
    detectedSignals: string[];
    summaryHint: string;
  } {
    const detectedSignals: string[] = [];
    const tags = (space?.tags || []).map((t) => (t || '').toLowerCase());
    const cardDataStr = JSON.stringify(space?.cardData || {}).toLowerCase();
    const idLower = (space?.id || '').toLowerCase();

    // 1. Tool Use signals
    const toolKeywords = ['tool', 'tools', 'function-calling', 'mcp', 'tool-use', 'web-search', 'browser-use'];
    if (toolKeywords.some((k) => tags.includes(k) || idLower.includes(k) || cardDataStr.includes(k))) {
      detectedSignals.push('TOOL_USE');
    }

    // 2. Planning & Reasoning loops
    const planningKeywords = ['planning', 'plan-and-execute', 'react', 'tree-of-thought', 'reasoning-loop', 'reflexion'];
    if (planningKeywords.some((k) => tags.includes(k) || idLower.includes(k) || cardDataStr.includes(k))) {
      detectedSignals.push('PLANNING_OR_REASONING');
    }

    // 3. Multi-agent Orchestration
    const orchestrationKeywords = ['multi-agent', 'multiagent', 'autogen', 'crewai', 'langgraph', 'swarm', 'chatdev', 'metagpt'];
    if (orchestrationKeywords.some((k) => tags.includes(k) || idLower.includes(k) || cardDataStr.includes(k))) {
      detectedSignals.push('MULTI_AGENT_ORCHESTRATION');
    }

    // 4. Autonomous Loops / Frameworks
    const frameworkKeywords = ['smolagents', 'crewai', 'langgraph', 'camel-ai', 'phidata', 'superagi', 'agentic'];
    if (frameworkKeywords.some((k) => tags.includes(k) || idLower.includes(k) || cardDataStr.includes(k))) {
      detectedSignals.push('AUTONOMOUS_FRAMEWORK');
    }

    const isAgentCandidate = detectedSignals.length > 0;
    const confidence = isAgentCandidate
      ? Math.min(1.0, 0.6 + detectedSignals.length * 0.1)
      : 0.15; // Low confidence, ordinary ML demo

    return {
      isAgentCandidate,
      confidence,
      detectedSignals,
      summaryHint: isAgentCandidate
        ? `Detected agent signals: [${detectedSignals.join(', ')}]`
        : 'Ordinary ML/LLM demo (no tool/planning/orchestration signals detected)',
    };
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const url = new URL(`${this.baseUrl}/api/spaces`);
    const query = criteria.query || 'agent';
    url.searchParams.set('search', query);
    url.searchParams.set('limit', String(Math.min(criteria.limit || 30, 100)));
    url.searchParams.set('full', 'true');

    const res = await this.request<HFSpaceItem[]>(url.toString(), {
      headers: this.getHeaders(),
    });

    const items = Array.isArray(res.data) ? res.data : [];

    const candidates: DiscoveryCandidate[] = items.map((space) => {
      const evaluation = this.evaluateAgentSignals(space);
      const title = (space.cardData?.title as string) || space.id;
      return {
        source_locator: `hf_spaces://${space.id}`,
        display_name: `${title} (${space.id})`,
        source_type: this.sourceType,
        type_hint: evaluation.isAgentCandidate ? 'AGENT_REPOSITORY' : 'UNSPECIFIED',
        confidence: evaluation.confidence,
        summary: `${evaluation.summaryHint} (SDK: ${space.sdk || 'unknown'}, Likes: ${space.likes || 0})`,
        raw_metadata: {
          ...space,
          caim_agent_evaluation: evaluation,
        } as unknown as Record<string, unknown>,
        created_at: space.createdAt,
        updated_at: space.lastModified,
        discovered_at: new Date().toISOString(),
      };
    });

    return {
      candidates,
      next_cursor: null,
      has_more: false,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const spaceId = this.parseSpaceLocator(locator);
    const url = `${this.baseUrl}/api/spaces/${spaceId}`;

    const res = await this.request<HFSpaceItem | HFSpaceItem[]>(url, {
      headers: this.getHeaders(),
      locator: `hf_spaces://${spaceId}`,
    });

    let raw: HFSpaceItem;
    if (Array.isArray(res.data)) {
      raw = res.data.find((s) => s.id === spaceId) || res.data[0] || ({} as HFSpaceItem);
    } else {
      raw = res.data || ({} as HFSpaceItem);
    }
    const evaluation = this.evaluateAgentSignals(raw);
    const enriched = {
      ...raw,
      caim_agent_evaluation: evaluation,
    } as unknown as Record<string, unknown>;
    const contentHash = this.hashPayload(enriched);

    return {
      source_locator: `hf_spaces://${spaceId}`,
      raw_metadata: enriched,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, revision: string = 'main'): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveHuggingFace(locator, revision, true, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const spaceId = this.parseSpaceLocator(locator);
    const meta = await this.fetch_metadata(locator);
    const space = meta.raw_metadata as unknown as HFSpaceItem;

    const locators: ArtifactLocatorEntry[] = [
      {
        locator: `https://huggingface.co/spaces/${spaceId}`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: true,
      },
      {
        locator: `https://huggingface.co/spaces/${spaceId}.git`,
        artifact_type: 'GIT_REPOSITORY',
        mime_type: 'application/x-git',
        is_primary: false,
      },
    ];

    if (space.subdomain) {
      locators.push({
        locator: `https://${space.subdomain}.hf.space`,
        artifact_type: 'OTHER',
        mime_type: 'text/html',
        is_primary: false,
      });
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
    const meta = await this.fetch_metadata(locator);
    const space = meta.raw_metadata as unknown as HFSpaceItem;

    const relationships: CandidateRelationship[] = [];

    // Underlying models used by this space
    if (Array.isArray(space.models)) {
      for (const modelId of space.models) {
        relationships.push({
          from_locator: locator,
          target_locator: `hf://${modelId}`,
          relationship_type: 'BASE_MODEL',
          target_type_hint: 'MODEL_WEIGHTS',
          depth: 1,
          metadata: { role: 'foundation_model' },
        });
      }
    }

    // Datasets used by this space
    if (Array.isArray(space.datasets)) {
      for (const datasetId of space.datasets) {
        relationships.push({
          from_locator: locator,
          target_locator: `hf_dataset://${datasetId}`,
          relationship_type: 'DATASET_REFERENCE',
          target_type_hint: 'DATASET',
          depth: 1,
          metadata: { role: 'dataset' },
        });
      }
    }

    return {
      source_locator: locator,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const meta = await this.fetch_metadata(locator);
    const space = meta.raw_metadata as unknown as HFSpaceItem;
    const token = space.sha || space.lastModified || meta.content_hash;

    return {
      source_locator: locator,
      change_token: token,
      token_type: 'COMMIT_SHA',
      last_modified: space.lastModified,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
      max_page_size: 100,
      rate_limit_per_minute: this.token ? 80 : 15,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'author', 'sdk', 'tags'],
      capabilities: {
        can_stream: false,
        can_search: true,
        provides_dependencies: true,
        provides_artifacts: true,
        requires_auth: false,
      },
    };
  }

  async health_check(): Promise<AdapterHealth> {
    const start = Date.now();
    try {
      const res = await this.request<HFSpaceItem[]>(`${this.baseUrl}/api/spaces?limit=1`, {
        headers: this.getHeaders(),
        timeoutMs: 8000,
      });
      const latency = Date.now() - start;
      const count = Array.isArray(res.data) ? res.data.length : 0;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
        message: res.status === 200
          ? `[ACTIVE] Hugging Face Spaces reachable (${count} spaces polled)`
          : `[TEMPORARILY_DEGRADED] Unexpected status code: ${res.status}`,
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `[SOURCE_UNAVAILABLE] Failed to reach Hugging Face Spaces: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
