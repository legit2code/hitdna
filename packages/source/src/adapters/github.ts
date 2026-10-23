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

export interface GitHubAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class GitHubSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'github';
  readonly sourceName = 'GitHub';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: GitHubAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: options.token ? 5000 : 60,
        remaining: options.token ? 5000 : 60,
        window_seconds: 3600,
        is_exhausted: false,
      },
    });
    this.token = 'token' in options ? (options.token || undefined) : (typeof process !== 'undefined' ? process.env.GITHUB_TOKEN : undefined);
    this.baseUrl = options.baseUrl || 'https://api.github.com';
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  private parseRepoLocator(locator: string): { owner: string; repo: string } {
    let clean = locator.replace(/^github:\/\//, '').replace(/^https?:\/\/github\.com\//, '');
    clean = clean.replace(/\.git$/, '').replace(/\/$/, '');
    const parts = clean.split('/');
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      throw new Error(`Invalid GitHub locator format: '${locator}'. Expected 'github://owner/repo' or 'https://github.com/owner/repo'`);
    }
    return { owner: parts[0], repo: parts[1] };
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const page = cursor?.page ?? 1;
    const perPage = Math.min(criteria.limit ?? 30, 100);

    const queryParts: string[] = [];
    if (criteria.query) queryParts.push(criteria.query);
    if (criteria.ecosystem) queryParts.push(`topic:${criteria.ecosystem}`);
    if (criteria.tags) {
      for (const tag of criteria.tags) queryParts.push(`topic:${tag}`);
    }
    if (criteria.time_window?.since) {
      queryParts.push(`pushed:>=${criteria.time_window.since}`);
    }

    const q = queryParts.length > 0 ? queryParts.join(' ') : 'stars:>1';
    const sortParam = criteria.sort === 'updated' ? 'updated' : criteria.sort === 'stars' ? 'stars' : undefined;
    const orderParam = criteria.order || 'desc';

    const url = new URL(`${this.baseUrl}/search/repositories`);
    url.searchParams.set('q', q);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    if (sortParam) url.searchParams.set('sort', sortParam);
    if (orderParam) url.searchParams.set('order', orderParam);

    const res = await this.request<{ items: any[]; total_count: number }>(url.toString(), {
      headers: this.getHeaders(),
    });

    const items = res.data?.items || [];
    const totalCount = res.data?.total_count || 0;
    const hasMore = page * perPage < Math.min(totalCount, 1000); // GitHub search max 1000 items

    const candidates: DiscoveryCandidate[] = items.map((item) => ({
      source_locator: `github://${item.full_name}`,
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
      locator: `github://${owner}/${repo}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `github://${owner}/${repo}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, ref?: string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveGitHub(locator, ref, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const { owner, repo } = this.parseRepoLocator(locator);

    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    let commitSha: string | undefined = (raw.commit_sha as string) || (raw.sha as string) || (raw.commit as string);

    // If commit SHA is not present, resolve it from the default branch HEAD
    if (!commitSha || !ImmutableVersionResolver.isCommitSha(commitSha)) {
      try {
        const resolved = await ImmutableVersionResolver.resolveGitHub(locator, raw.default_branch as string, this.fetcher);
        commitSha = resolved.commit_sha;
      } catch {
        // Fallback to explicit ref if resolution fails
      }
    }

    const archiveTarget = commitSha || (raw.default_branch as string) || 'main';
    const isImmutable = Boolean(commitSha && ImmutableVersionResolver.isCommitSha(commitSha));

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'GIT_REPOSITORY',
        locator: `https://github.com/${owner}/${repo}.git`,
        filename: `${repo}.git`,
        mime_type: 'application/x-git',
        download_url: `https://github.com/${owner}/${repo}.git`,
        is_primary: true,
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `https://github.com/${owner}/${repo}/archive/${archiveTarget}.zip`,
        filename: `${repo}-${archiveTarget}.zip`,
        mime_type: 'application/zip',
        download_url: `https://github.com/${owner}/${repo}/archive/${archiveTarget}.zip`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `https://github.com/${owner}/${repo}/archive/${archiveTarget}.tar.gz`,
        filename: `${repo}-${archiveTarget}.tar.gz`,
        mime_type: 'application/gzip',
        download_url: `https://github.com/${owner}/${repo}/archive/${archiveTarget}.tar.gz`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
    ];

    const primaryLocator = commitSha
      ? `https://github.com/${owner}/${repo}/archive/${commitSha}.tar.gz`
      : `https://github.com/${owner}/${repo}.git`;

    return {
      source_locator: commitSha ? `github://${owner}/${repo}#${commitSha}` : `github://${owner}/${repo}`,
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

    // Maintainer / Owner
    relationships.push({
      from_locator: `github://${owner}/${repo}`,
      target_locator: `github://users/${owner}`,
      relationship_type: 'MAINTAINED_BY',
      depth: 1,
      metadata: { role: 'owner' },
    });

    // Parent if fork
    if (raw.fork && raw.parent && typeof raw.parent === 'object') {
      const parentFullName = (raw.parent as any).full_name;
      if (parentFullName) {
        relationships.push({
          from_locator: `github://${owner}/${repo}`,
          target_locator: `github://${parentFullName}`,
          relationship_type: 'FORK_OF',
          target_type_hint: 'AGENT_REPOSITORY',
          depth: 1,
        });
      }
    }

    // Homepage link
    if (raw.homepage && typeof raw.homepage === 'string' && raw.homepage.startsWith('http')) {
      relationships.push({
        from_locator: `github://${owner}/${repo}`,
        target_locator: raw.homepage,
        relationship_type: 'HOMEPAGE',
        depth: 1,
      });
    }

    return {
      source_locator: `github://${owner}/${repo}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const { owner, repo } = this.parseRepoLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const token = (raw.pushed_at as string) || (raw.updated_at as string) || 'unknown-github-token';
    return {
      source_locator: `github://${owner}/${repo}`,
      change_token: token,
      token_type: 'TIMESTAMP',
      last_modified: (raw.pushed_at as string) || (raw.updated_at as string),
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'DEGRADED',
      max_page_size: 100,
      rate_limit_per_minute: this.token ? 83 : 1, // 5000/hr vs 60/hr
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'topic', 'language', 'pushed', 'stars'],
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
      const res = await this.request<any>(`${this.baseUrl}/rate_limit`, {
        headers: this.getHeaders(),
      });
      const latency = Date.now() - start;
      const coreLimit = res.data?.resources?.core;
      if (coreLimit) {
        this.rateLimitState.limit = coreLimit.limit;
        this.rateLimitState.remaining = coreLimit.remaining;
        this.rateLimitState.reset_at = new Date(coreLimit.reset * 1000).toISOString();
        this.rateLimitState.is_exhausted = coreLimit.remaining <= 0;
      }

      return {
        status: this.token ? 'HEALTHY' : 'DEGRADED',
        auth_status: this.token ? 'AUTHENTICATED' : 'ANONYMOUS',
        message: this.token 
          ? 'GitHub adapter authenticated with active token' 
          : 'GitHub adapter running in degraded anonymous mode (limited to 60 req/hr)',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `GitHub health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
