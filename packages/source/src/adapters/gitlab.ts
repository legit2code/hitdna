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

export interface GitLabAdapterOptions {
  token?: string;
  baseUrl?: string;
  fetcher?: HttpFetcher;
}

export class GitLabSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'gitlab';
  readonly sourceName = 'GitLab';
  readonly adapterVersion = '1.0.0';

  private readonly token?: string;
  private readonly baseUrl: string;

  constructor(options: GitLabAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      initialRateLimit: {
        limit: options.token ? 2000 : 300,
        remaining: options.token ? 2000 : 300,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.token = 'token' in options ? (options.token || undefined) : (typeof process !== 'undefined' ? process.env.GITLAB_TOKEN : undefined);
    this.baseUrl = options.baseUrl || 'https://gitlab.com/api/v4';
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': 'caim-source-adapter/1.0.0',
    };
    if (this.token) {
      headers['PRIVATE-TOKEN'] = this.token;
    }
    return headers;
  }

  private parseProjectLocator(locator: string): string {
    let clean = locator.replace(/^gitlab:\/\//, '').replace(/^https?:\/\/gitlab\.com\//, '');
    clean = clean.replace(/\.git$/, '').replace(/\/$/, '');
    if (!clean) {
      throw new Error(`Invalid GitLab locator: '${locator}'`);
    }
    return clean;
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const page = cursor?.page ?? 1;
    const perPage = Math.min(criteria.limit ?? 20, 100);

    const url = new URL(`${this.baseUrl}/projects`);
    if (criteria.query) url.searchParams.set('search', criteria.query);
    if (criteria.tags && criteria.tags.length > 0) url.searchParams.set('topic', criteria.tags[0]);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('order_by', criteria.sort === 'updated' ? 'last_activity_at' : 'similarity');
    url.searchParams.set('sort', criteria.order || 'desc');

    const res = await this.request<any[]>(url.toString(), {
      headers: this.getHeaders(),
    });

    const items = Array.isArray(res.data) ? res.data : [];
    const nextPageHeader = res.headers['x-next-page'];
    const hasMore = nextPageHeader ? parseInt(nextPageHeader, 10) > page : items.length === perPage;

    const candidates: DiscoveryCandidate[] = items.map((item) => ({
      source_locator: `gitlab://${item.path_with_namespace}`,
      display_name: item.name_with_namespace || item.path_with_namespace,
      source_type: this.sourceType,
      type_hint: 'AGENT_REPOSITORY',
      confidence: 1.0,
      summary: item.description || undefined,
      raw_metadata: item,
      created_at: item.created_at,
      updated_at: item.last_activity_at,
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
    const pathWithNamespace = this.parseProjectLocator(locator);
    const encoded = encodeURIComponent(pathWithNamespace);
    const url = `${this.baseUrl}/projects/${encoded}`;

    const res = await this.request<Record<string, unknown>>(url, {
      headers: this.getHeaders(),
      locator: `gitlab://${pathWithNamespace}`,
    });

    const rawData = res.data || {};
    const contentHash = this.hashPayload(rawData);

    return {
      source_locator: `gitlab://${pathWithNamespace}`,
      raw_metadata: rawData,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      etag: res.headers['etag'],
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string, ref?: string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    return ImmutableVersionResolver.resolveGitLab(locator, ref, this.fetcher);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const pathWithNamespace = this.parseProjectLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const projectId = raw.id || encodeURIComponent(pathWithNamespace);
    let commitSha: string | undefined = (raw.commit_sha as string) || (raw.sha as string) || (raw.commit as string);

    if (!commitSha || !ImmutableVersionResolver.isCommitSha(commitSha)) {
      try {
        const resolved = await ImmutableVersionResolver.resolveGitLab(locator, raw.default_branch as string, this.fetcher);
        commitSha = resolved.commit_sha;
      } catch {
        // Fallback to explicit ref if resolution fails
      }
    }

    const archiveTarget = commitSha || (raw.default_branch as string) || 'main';
    const isImmutable = Boolean(commitSha && ImmutableVersionResolver.isCommitSha(commitSha));
    const httpCloneUrl = (raw.http_url_to_repo as string) || `https://gitlab.com/${pathWithNamespace}.git`;

    const artifacts: ArtifactLocatorEntry[] = [
      {
        artifact_type: 'GIT_REPOSITORY',
        locator: httpCloneUrl,
        filename: `${pathWithNamespace.split('/').pop()}.git`,
        mime_type: 'application/x-git',
        download_url: httpCloneUrl,
        is_primary: true,
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `${this.baseUrl}/projects/${projectId}/repository/archive.tar.gz?sha=${archiveTarget}`,
        filename: `${pathWithNamespace.split('/').pop()}-${archiveTarget}.tar.gz`,
        mime_type: 'application/gzip',
        download_url: `${this.baseUrl}/projects/${projectId}/repository/archive.tar.gz?sha=${archiveTarget}`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
      {
        artifact_type: 'SOURCE_ARCHIVE',
        locator: `${this.baseUrl}/projects/${projectId}/repository/archive.zip?sha=${archiveTarget}`,
        filename: `${pathWithNamespace.split('/').pop()}-${archiveTarget}.zip`,
        mime_type: 'application/zip',
        download_url: `${this.baseUrl}/projects/${projectId}/repository/archive.zip?sha=${archiveTarget}`,
        is_primary: false,
        metadata: {
          is_immutable: isImmutable,
          commit_sha: commitSha,
        },
      },
    ];

    const primaryLocator = commitSha
      ? `${this.baseUrl}/projects/${projectId}/repository/archive.tar.gz?sha=${commitSha}`
      : httpCloneUrl;

    return {
      source_locator: commitSha ? `gitlab://${pathWithNamespace}#${commitSha}` : `gitlab://${pathWithNamespace}`,
      primary_locator: primaryLocator,
      artifacts,
      provenance: this.generate_provenance('RESOLVE_ARTIFACTS', [this.hashPayload(artifacts)]),
    };
  }

  async enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult> {
    const locator = this.extractLocator(candidate);
    const pathWithNamespace = this.parseProjectLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const relationships: CandidateRelationship[] = [];

    // Namespace / Owner
    if (raw.namespace && typeof raw.namespace === 'object') {
      relationships.push({
        from_locator: `gitlab://${pathWithNamespace}`,
        target_locator: `gitlab://groups/${(raw.namespace as any).full_path || (raw.namespace as any).path}`,
        relationship_type: 'MAINTAINED_BY',
        depth: 1,
      });
    }

    // Fork
    if (raw.forked_from_project && typeof raw.forked_from_project === 'object') {
      const parentPath = (raw.forked_from_project as any).path_with_namespace;
      if (parentPath) {
        relationships.push({
          from_locator: `gitlab://${pathWithNamespace}`,
          target_locator: `gitlab://${parentPath}`,
          relationship_type: 'FORK_OF',
          target_type_hint: 'AGENT_REPOSITORY',
          depth: 1,
        });
      }
    }

    return {
      source_locator: `gitlab://${pathWithNamespace}`,
      relationships,
      provenance: this.generate_provenance('ENUMERATE_RELATIONSHIPS', [this.hashPayload(relationships)]),
    };
  }

  async get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult> {
    const locator = this.extractLocator(candidate);
    const pathWithNamespace = this.parseProjectLocator(locator);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};

    const token = (raw.last_activity_at as string) || (raw.updated_at as string) || 'unknown-gitlab-token';
    return {
      source_locator: `gitlab://${pathWithNamespace}`,
      change_token: token,
      token_type: 'TIMESTAMP',
      last_modified: (raw.last_activity_at as string) || (raw.updated_at as string),
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: this.token ? 'AUTHENTICATED' : 'DEGRADED',
      max_page_size: 100,
      rate_limit_per_minute: this.token ? 2000 : 300,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['search', 'topic', 'membership', 'starred', 'last_activity_at'],
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
          ? 'GitLab adapter authenticated with token'
          : 'GitLab adapter operating in unauthenticated public mode',
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      // Version endpoint might be 401 for anonymous, which is degraded but healthy for public
      if (!this.token && err.statusCode === 401) {
        return {
          status: 'DEGRADED',
          auth_status: 'ANONYMOUS',
          message: 'GitLab public mode operational (anonymous)',
          latency_ms: Date.now() - start,
          rate_limit: this.get_rate_limit_state(),
          checked_at: new Date().toISOString(),
        };
      }
      return {
        status: 'UNHEALTHY',
        auth_status: this.token ? 'INVALID_CREDENTIALS' : 'ANONYMOUS',
        message: `GitLab health check failed: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
