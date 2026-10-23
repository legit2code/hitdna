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

export interface HuggingFaceAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class HuggingFaceSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'huggingface';
  readonly sourceName = 'Hugging Face';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: HuggingFaceAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: options.token ? 5000 : 1000,
        remaining: options.token ? 5000 : 1000,
        window_seconds: 3600,
        is_exhausted: false,
      },
    });
    this.token = 'token' in options ? (options.token || undefined) : (typeof process !== 'undefined' ? (process.env.HUGGINGFACE_API_KEY || process.env.HF_TOKEN) : undefined);
    this.baseUrl = options.baseUrl || 'https://huggingface.co';
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

  private parseModelLocator(locator: string): string {
    let clean = locator.replace(/^hf:\/\/(models\/)?/, '').replace(/^https?:\/\/huggingface\.co\//, '');
    clean = clean.replace(/\.git$/, '').replace(/\/$/, '');
    if (!clean) {
      throw new Error(`Invalid Hugging Face locator: '${locator}'`);
    }
    return clean;
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const limit = Math.min(criteria.limit ?? 20, 100);
    const searchUrl = new URL(`${this.baseUrl}/api/models`);
    if (criteria.query) searchUrl.searchParams.set('search', criteria.query);
    if (criteria.ecosystem) searchUrl.searchParams.set('pipeline_tag', criteria.ecosystem);
    if (criteria.tags && criteria.tags.length > 0) {
      for (const tag of criteria.tags) searchUrl.searchParams.append('filter', tag);
    }
    searchUrl.searchParams.set('limit', String(limit));
    searchUrl.searchParams.set('full', 'true');
    searchUrl.searchParams.set('sort', criteria.sort === 'downloads' ? 'downloads' : criteria.sort === 'updated' ? 'lastModified' : 'likes');
    searchUrl.searchParams.set('direction', criteria.order === 'asc' ? '1' : '-1');

    const res = await this.request<any[]>(searchUrl.toString(), {
      headers: this.getHeaders(),
    });

    const items = Array.isArray(res.data) ? res.data : [];
    const hasMore = items.length === limit;

    const candidates: DiscoveryCandidate[] = items.map((item) => ({
      source_locator: `hf://models/${item.id || item.modelId}`,
      display_name: item.id || item.modelId,
      source_type: this.sourceType,
      type_hint: 'MODEL_WEIGHTS',
      confidence: 1.0,
      summary: item.description || item.cardData?.short_description || undefined,
      raw_metadata: item,
      created_at: item.createdAt,
      updated_at: item.lastModified,
      discovered_at: new Date().toISOString(),
    }));

    return {
      candidates,
      next_cursor: hasMore ? { last_id: items[items.length - 1]?.id } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const modelId = this.parseModelLocator(locator);
    const url = `${this.baseUrl}/api/models/${modelId}`;

    const res = await this.request<Record<string, unknown>>(url, {
      headers: this.getHeaders(),
      locator: `hf://models/${modelId}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `hf://models/${modelId}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, revision: string = 'main'): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveHuggingFace(locator, revision, false, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const modelId = this.parseModelLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    let commitSha: string | undefined = (raw.sha as string) || (raw.commit_sha as string) || (raw.commit as string);

    if (!commitSha || !ImmutableVersionResolver.isCommitSha(commitSha)) {
      try {
        const resolved = await ImmutableVersionResolver.resolveHuggingFace(locator, 'main', false, this.fetcher);
        commitSha = resolved.commit_sha;
      } catch {
        // Fallback
      }
    }

    const refTarget = commitSha || 'main';
    const isImmutable = Boolean(commitSha && ImmutableVersionResolver.isCommitSha(commitSha));
    const gitCloneUrl = `https://huggingface.co/${modelId}.git`;

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'GIT_REPOSITORY',
        locator: gitCloneUrl,
        filename: `${modelId.replace(/\//g, '_')}.git`,
        mime_type: 'application/x-git',
        download_url: gitCloneUrl,
        is_primary: true,
      },
      {
        artifact_type: 'MODEL_WEIGHTS_TREE',
        locator: `https://huggingface.co/${modelId}/tree/${refTarget}`,
        is_primary: false,
        metadata: { is_immutable: isImmutable, commit_sha: commitSha },
      },
      {
        artifact_type: 'DOCUMENTATION',
        locator: `https://huggingface.co/${modelId}/raw/${refTarget}/README.md`,
        filename: 'README.md',
        mime_type: 'text/markdown',
        download_url: `https://huggingface.co/${modelId}/raw/${refTarget}/README.md`,
        is_primary: false,
        metadata: { is_immutable: isImmutable, commit_sha: commitSha },
      },
    ];

    // Siblings files if listed in raw metadata
    const siblings = Array.isArray(raw.siblings) ? raw.siblings : [];
    for (const sib of siblings) {
      if (sib.rfilename && (sib.rfilename.endsWith('.safetensors') || sib.rfilename.endsWith('.bin') || sib.rfilename.endsWith('.json'))) {
        artifacts.push({
          artifact_type: 'MODEL_FILE',
          locator: `https://huggingface.co/${modelId}/resolve/${refTarget}/${sib.rfilename}`,
          filename: sib.rfilename,
          download_url: `https://huggingface.co/${modelId}/resolve/${refTarget}/${sib.rfilename}`,
          is_primary: false,
          metadata: { rfilename: sib.rfilename, is_immutable: isImmutable, commit_sha: commitSha },
        });
      }
    }

    return {
      source_locator: commitSha ? `hf://models/${modelId}#${commitSha}` : `hf://models/${modelId}`,
      primary_locator: gitCloneUrl,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const modelId = this.parseModelLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    const cardData = (raw.cardData as any) || {};

    const relationships: CandidateRelationship[] = [];

    // Base model
    const baseModel = cardData.base_model || raw.base_model;
    if (baseModel) {
      const baseModels = Array.isArray(baseModel) ? baseModel : [baseModel];
      for (const bm of baseModels) {
        if (typeof bm === 'string') {
          relationships.push({
            from_locator: `hf://models/${modelId}`,
            target_locator: `hf://models/${bm}`,
            relationship_type: 'BASE_MODEL',
            target_type_hint: 'MODEL_WEIGHTS',
            depth: 1,
          });
        }
      }
    }

    // Datasets
    const datasets = cardData.datasets || raw.datasets;
    if (datasets) {
      const datasetList = Array.isArray(datasets) ? datasets : [datasets];
      for (const ds of datasetList) {
        if (typeof ds === 'string') {
          relationships.push({
            from_locator: `hf://models/${modelId}`,
            target_locator: `hf://datasets/${ds}`,
            relationship_type: 'DATASET_REFERENCE',
            target_type_hint: 'DATASET',
            depth: 1,
          });
        }
      }
    }

    // Author / Organization
    const author = modelId.split('/')[0];
    if (author) {
      relationships.push({
        from_locator: `hf://models/${modelId}`,
        target_locator: `hf://users/${author}`,
        relationship_type: 'MAINTAINED_BY',
        depth: 1,
      });
    }

    return {
      source_locator: `hf://models/${modelId}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const modelId = this.parseModelLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const sha = (raw.sha as string) || (raw.lastModified as string) || 'unknown-hf-sha';
    return {
      source_locator: `hf://models/${modelId}`,
      change_token: sha,
      token_type: raw.sha ? 'COMMIT_SHA' : 'TIMESTAMP',
      last_modified: raw.lastModified as string,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
      max_page_size: 100,
      rate_limit_per_minute: this.token ? 500 : 100,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['search', 'filter', 'pipeline_tag', 'author'],
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
      const url = `${this.baseUrl}/api/models?limit=1`;
      await this.request(url, { headers: this.getHeaders() });
      const latency = Date.now() - start;

      return {
        status: 'HEALTHY',
        auth_status: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
        message: this.token 
          ? 'Hugging Face adapter authenticated with API key' 
          : 'Hugging Face public anonymous access operational',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `Hugging Face health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
