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

export interface CodebergAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class CodebergSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'codeberg';
  readonly sourceName = 'Codeberg';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: CodebergAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: options.token ? 3000 : 300,
        remaining: options.token ? 3000 : 300,
        window_seconds: 3600,
        is_exhausted: false,
      },
    });
    this.token = 'token' in options ? (options.token || undefined) : (typeof process !== 'undefined' ? process.env.CODEBERG_TOKEN : undefined);
    this.baseUrl = options.baseUrl || 'https://codeberg.org/api/v1';
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.token) {
      headers['Authorization'] = `token ${this.token}`;
    }
    return headers;
  }

  private parseRepoLocator(locator: string): { owner: string; repo: string } {
    let clean = locator.replace(/^codeberg:\/\//, '').replace(/^https?:\/\/codeberg\.org\//, '');
    clean = clean.replace(/\.git$/, '').replace(/\/$/, '');
    const parts = clean.split('/');
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      throw new Error(`Invalid Codeberg locator: '${locator}'`);
    }
    return { owner: parts[0], repo: parts[1] };
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const page = cursor?.page ?? 1;
    const limit = Math.min(criteria.limit ?? 20, 50);

    const searchUrl = new URL(`${this.baseUrl}/repos/search`);
    if (criteria.query) searchUrl.searchParams.set('q', criteria.query);
    if (criteria.tags && criteria.tags.length > 0) searchUrl.searchParams.set('topic', criteria.tags[0]);
    searchUrl.searchParams.set('page', String(page));
    searchUrl.searchParams.set('limit', String(limit));
    searchUrl.searchParams.set('sort', criteria.sort === 'updated' ? 'updated' : 'stars');
    searchUrl.searchParams.set('order', criteria.order || 'desc');

    const res = await this.request<{ data: any[]; ok: boolean }>(searchUrl.toString(), {
      headers: this.getHeaders(),
    });

    const items = Array.isArray(res.data?.data) ? res.data.data : [];
    const totalCountHeader = res.headers['x-total-count'];
    const totalCount = totalCountHeader ? parseInt(totalCountHeader, 10) : items.length;
    const hasMore = items.length === limit && page * limit < (totalCount || 1000);

    const candidates: DiscoveryCandidate[] = items.map((item) => ({
      source_locator: `codeberg://${item.full_name}`,
      display_name: item.full_name,
      source_type: this.sourceType,
      type_hint: 'AGENT_REPOSITORY',
      confidence: 1.0,
      summary: item.description || undefined,
      raw_metadata: item,
      created_at: item.created_at,
      updated_at: item.updated_at,
      discovered_at: new Date().toISOString(),
    }));

    return {
      candidates,
      next_cursor: hasMore ? { page: page + 1 } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const { owner, repo } = this.parseRepoLocator(locator);
    const url = `${this.baseUrl}/repos/${owner}/${repo}`;

    const res = await this.request<Record<string, unknown>>(url, {
      headers: this.getHeaders(),
      locator: `codeberg://${owner}/${repo}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `codeberg://${owner}/${repo}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, ref?: string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveCodeberg(locator, ref, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const { owner, repo } = this.parseRepoLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    let commitSha: string | undefined = (raw.commit_sha as string) || (raw.sha as string) || (raw.commit as string);

    if (!commitSha || !ImmutableVersionResolver.isCommitSha(commitSha)) {
      try {
        const resolved = await ImmutableVersionResolver.resolveCodeberg(locator, raw.default_branch as string, this.fetcher);
        commitSha = resolved.commit_sha;
      } catch {
        // Fallback to explicit ref if resolution fails
      }
    }

    const archiveTarget = commitSha || (raw.default_branch as string) || 'main';
    const isImmutable = Boolean(commitSha && ImmutableVersionResolver.isCommitSha(commitSha));
    const cloneUrl = (raw.clone_url as string) || `https://codeberg.org/${owner}/${repo}.git`;

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'GIT_REPOSITORY',
        locator: cloneUrl,
        filename: `${repo}.git`,
        mime_type: 'application/x-git',
        download_url: cloneUrl,
        is_primary: true,
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `https://codeberg.org/${owner}/${repo}/archive/${archiveTarget}.tar.gz`,
        filename: `${repo}-${archiveTarget}.tar.gz`,
        mime_type: 'application/gzip',
        download_url: `https://codeberg.org/${owner}/${repo}/archive/${archiveTarget}.tar.gz`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `https://codeberg.org/${owner}/${repo}/archive/${archiveTarget}.zip`,
        filename: `${repo}-${archiveTarget}.zip`,
        mime_type: 'application/zip',
        download_url: `https://codeberg.org/${owner}/${repo}/archive/${archiveTarget}.zip`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
    ];

    const primaryLocator = commitSha
      ? `https://codeberg.org/${owner}/${repo}/archive/${commitSha}.tar.gz`
      : cloneUrl;

    return {
      source_locator: commitSha ? `codeberg://${owner}/${repo}#${commitSha}` : `codeberg://${owner}/${repo}`,
      primary_locator: primaryLocator,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const { owner, repo } = this.parseRepoLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const relationships: CandidateRelationship[] = [];

    // Owner / Maintainer
    relationships.push({
      from_locator: `codeberg://${owner}/${repo}`,
      target_locator: `codeberg://users/${owner}`,
      relationship_type: 'MAINTAINED_BY',
      depth: 1,
    });

    // Fork
    if (raw.fork && raw.parent && typeof raw.parent === 'object') {
      const parentFullName = (raw.parent as any).full_name;
      if (parentFullName) {
        relationships.push({
          from_locator: `codeberg://${owner}/${repo}`,
          target_locator: `codeberg://${parentFullName}`,
          relationship_type: 'FORK_OF',
          target_type_hint: 'AGENT_REPOSITORY',
          depth: 1,
        });
      }
    }

    // Website / Homepage
    if (raw.website && typeof raw.website === 'string' && raw.website.startsWith('http')) {
      relationships.push({
        from_locator: `codeberg://${owner}/${repo}`,
        target_locator: raw.website,
        relationship_type: 'HOMEPAGE',
        depth: 1,
      });
    }

    return {
      source_locator: `codeberg://${owner}/${repo}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const { owner, repo } = this.parseRepoLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const token = (raw.updated_at as string) || 'unknown-codeberg-token';
    return {
      source_locator: `codeberg://${owner}/${repo}`,
      change_token: token,
      token_type: 'TIMESTAMP',
      last_modified: raw.updated_at as string,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'DEGRADED',
      max_page_size: 50,
      rate_limit_per_minute: this.token ? 500 : 50,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['search', 'topic', 'language', 'stars'],
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
      const url = `${this.baseUrl}/version`;
      await this.request(url, { headers: this.getHeaders() });
      const latency = Date.now() - start;

      return {
        status: this.token ? 'HEALTHY' : 'DEGRADED',
        auth_status: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
        message: this.token 
          ? 'Codeberg adapter authenticated' 
          : 'Codeberg adapter operational in public anonymous mode',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `Codeberg health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
