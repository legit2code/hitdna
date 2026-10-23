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

export interface HNItem {
  id: number;
  deleted?: boolean;
  type?: 'job' | 'story' | 'comment' | 'poll' | 'pollopt';
  by?: string;
  time?: number;
  text?: string;
  dead?: boolean;
  parent?: number;
  poll?: number;
  kids?: number[];
  url?: string;
  score?: number;
  title?: string;
  parts?: number[];
  descendants?: number;
}

export interface HNAlgoliaHit {
  objectID: string;
  title?: string;
  url?: string;
  author?: string;
  points?: number;
  story_text?: string;
  comment_text?: string;
  num_comments?: number;
  created_at?: string;
  created_at_i?: number;
}

export interface HNAlgoliaSearchResponse {
  hits?: HNAlgoliaHit[];
  nbHits?: number;
  page?: number;
  nbPages?: number;
  hitsPerPage?: number;
}

export interface HackerNewsAdapterOptions {
  baseUrl?: string;
  searchUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class HackerNewsSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'hackernews';
  readonly sourceName = 'Hacker News';
  readonly adapterVersion = '1.0.0';

  private readonly baseUrl: string;
  private readonly searchUrl: string;

  constructor(options: HackerNewsAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: 300,
        remaining: 300,
        window_seconds: 60,
        is_exhausted: false,
      },
    });
    this.baseUrl = (options.baseUrl || 'https://hacker-news.firebaseio.com').replace(/\/$/, '');
    this.searchUrl = (options.searchUrl || 'https://hn.algolia.com').replace(/\/$/, '');
  }

  private parseItemId(locator: string): number {
    let clean = locator.replace(/^hn:\/\//, '').replace(/^hackernews:\/\//, '');
    clean = clean.replace(/^https?:\/\/news\.ycombinator\.com\/item\?id=/, '');
    clean = clean.replace(/\/$/, '');
    const id = parseInt(clean, 10);
    if (isNaN(id) || id <= 0) {
      throw new Error(`Invalid Hacker News item locator: '${locator}'`);
    }
    return id;
  }

  /**
   * Extracts external candidate URLs (GitHub, documentation, project homepages)
   * from HN story URL and submission text.
   */
  private extractCandidateLeads(item: HNItem | HNAlgoliaHit): string[] {
    const urls = new Set<string>();
    const text = ((item as HNItem).text || (item as HNAlgoliaHit).story_text || '') + ' ' + (item.url || '');

    const urlMatches = text.match(/https?:\/\/[^\s"'<>)]+/g) || [];
    for (let u of urlMatches) {
      u = u.replace(/&amp;/g, '&').replace(/&#x2F;/g, '/').replace(/[\.,;:!]+$/, '');
      if (
        !u.includes('news.ycombinator.com') &&
        !u.includes('ycombinator.com') &&
        !u.includes('firebaseio.com') &&
        !u.includes('algolia.com')
      ) {
        urls.add(u);
      }
    }

    if (item.url && !item.url.includes('news.ycombinator.com')) {
      urls.add(item.url);
    }

    return Array.from(urls);
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const limit = criteria.limit || 20;

    // If a search query is provided, use the official Algolia HN search API for Show HN stories
    if (criteria.query) {
      const page = cursor?.page || 0;
      const url = new URL(`${this.searchUrl}/api/v1/search`);
      url.searchParams.set('tags', 'show_hn');
      url.searchParams.set('query', criteria.query);
      url.searchParams.set('page', String(page));
      url.searchParams.set('hitsPerPage', String(Math.min(limit, 50)));

      const res = await this.request<HNAlgoliaSearchResponse>(url.toString(), {
        headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
      });

      const hits = res.data?.hits || [];
      const candidates: DiscoveryCandidate[] = hits.map((hit) => {
        const leads = this.extractCandidateLeads(hit);
        return {
          source_locator: `hn://${hit.objectID}`,
          display_name: hit.title || `HN Discussion ${hit.objectID}`,
          source_type: this.sourceType,
          type_hint: 'UNSPECIFIED',
          confidence: 0.65, // A post is a lead, not an agent
          summary: `Show HN lead posted by ${hit.author || 'unknown'} (Score: ${hit.points || 0}, Comments: ${hit.num_comments || 0}). Extracted leads: [${leads.slice(0, 3).join(', ')}]`,
          raw_metadata: {
            ...hit,
            extracted_leads: leads,
          } as unknown as Record<string, unknown>,
          created_at: hit.created_at,
          updated_at: hit.created_at,
          discovered_at: new Date().toISOString(),
        };
      });

      const hasMore = (res.data?.page ?? 0) < (res.data?.nbPages ?? 1) - 1;

      return {
        candidates,
        next_cursor: hasMore ? { page: page + 1 } : null,
        has_more: hasMore,
        rate_limit: this.get_rate_limit_state(),
        provenance: this.generate_provenance('DISCOVER', [this.hashPayload(hits)]),
      };
    }

    // Default: Monitor recent "Show HN" submissions via official Firebase showstories endpoint
    const showStoriesRes = await this.request<number[]>(`${this.baseUrl}/v0/showstories.json`, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
    });

    const storyIds = Array.isArray(showStoriesRes.data) ? showStoriesRes.data : [];
    const startIndex = cursor?.offset ? cursor.offset : 0;
    const pageIds = storyIds.slice(startIndex, startIndex + limit);

    const items: HNItem[] = [];
    for (const id of pageIds) {
      try {
        const itemRes = await this.request<HNItem>(`${this.baseUrl}/v0/item/${id}.json`, {
          headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
        });
        if (itemRes.data && !itemRes.data.deleted && !itemRes.data.dead) {
          items.push(itemRes.data);
        }
      } catch {
        // Continue
      }
    }

    // A post is an unverified discovery lead, never an automatic agent
    const candidates: DiscoveryCandidate[] = items.map((item) => {
      const leads = this.extractCandidateLeads(item);
      return {
        source_locator: `hn://${item.id}`,
        display_name: item.title || `HN #${item.id}`,
        source_type: this.sourceType,
        type_hint: 'UNSPECIFIED',
        confidence: 0.6,
        summary: `HN Lead by ${item.by || 'anonymous'} (Score: ${item.score || 0}). Primary URL: ${item.url || 'self-text'}. Leads: [${leads.slice(0, 3).join(', ')}]`,
        raw_metadata: {
          ...item,
          extracted_leads: leads,
        } as unknown as Record<string, unknown>,
        created_at: item.time ? new Date(item.time * 1000).toISOString() : undefined,
        updated_at: item.time ? new Date(item.time * 1000).toISOString() : undefined,
        discovered_at: new Date().toISOString(),
      };
    });

    const nextIndex = startIndex + limit;
    const hasMore = nextIndex < storyIds.length;

    return {
      candidates,
      next_cursor: hasMore ? { offset: nextIndex } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(items)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const id = this.parseItemId(locator);
    const url = `${this.baseUrl}/v0/item/${id}.json`;

    const res = await this.request<any>(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'caim-source-adapter/1.0.0' },
      locator: `hn://${id}`,
    });

    let item: HNItem;
    if (res.data && res.data.hits && Array.isArray(res.data.hits)) {
      const hit = res.data.hits.find((h: any) => String(h.objectID) === String(id)) || res.data.hits[0];
      item = {
        id,
        title: hit?.title,
        url: hit?.url,
        by: hit?.author,
        score: hit?.points,
        text: hit?.story_text || hit?.comment_text,
        time: hit?.created_at_i,
      };
    } else {
      item = res.data || ({} as HNItem);
    }

    const leads = this.extractCandidateLeads(item);
    const enriched = {
      ...item,
      extracted_leads: leads,
    } as unknown as Record<string, unknown>;
    const contentHash = this.hashPayload(enriched);

    return {
      source_locator: `hn://${id}`,
      raw_metadata: enriched,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_canonical_pivot(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    return ImmutableVersionResolver.resolveDiscoveryOnlyPivot('hackernews', locator, raw);
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    return this.resolve_canonical_pivot(candidate);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const id = this.parseItemId(locator);
    const raw = (typeof candidate === 'object' && candidate.raw_metadata && (candidate.raw_metadata as any).extracted_leads)
      ? candidate.raw_metadata
      : (await this.fetch_metadata(locator)).raw_metadata;
    const item = raw as unknown as (HNItem & { extracted_leads?: string[] });

    const locators: ArtifactLocatorEntry[] = [
      {
        locator: `https://news.ycombinator.com/item?id=${id}`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: true,
      },
    ];

    if (item.url && !item.url.includes('news.ycombinator.com')) {
      locators.push({
        locator: item.url,
        artifact_type: item.url.includes('github.com') ? 'GIT_REPOSITORY' : 'DOCUMENTATION',
        mime_type: item.url.includes('github.com') ? 'application/x-git' : 'text/html',
        is_primary: false,
      });
    }

    if (Array.isArray(item.extracted_leads)) {
      for (const lead of item.extracted_leads) {
        if (lead !== item.url) {
          locators.push({
            locator: lead,
            artifact_type: lead.includes('github.com') ? 'GIT_REPOSITORY' : 'DOCUMENTATION',
            mime_type: lead.includes('github.com') ? 'application/x-git' : 'text/html',
            is_primary: false,
          });
        }
      }
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
    const raw = (typeof candidate === 'object' && candidate.raw_metadata && (candidate.raw_metadata as any).extracted_leads)
      ? candidate.raw_metadata
      : (await this.fetch_metadata(locator)).raw_metadata;
    const item = raw as unknown as (HNItem & { extracted_leads?: string[] });

    const relationships: CandidateRelationship[] = [];

    if (Array.isArray(item.extracted_leads)) {
      for (const lead of item.extracted_leads) {
        relationships.push({
          from_locator: locator,
          target_locator: lead,
          relationship_type: 'UPSTREAM_SOURCE',
          depth: 1,
          metadata: {
            role: 'extracted_lead',
            source_hn_thread: `https://news.ycombinator.com/item?id=${item.id}`,
          },
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
    const item = meta.raw_metadata as unknown as HNItem;
    const token = `${item.score || 0}:${item.descendants || 0}`;

    return {
      source_locator: locator,
      change_token: token,
      token_type: 'VERSION',
      last_modified: item.time ? new Date(item.time * 1000).toISOString() : undefined,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: 'ANONYMOUS',
      max_page_size: 50,
      rate_limit_per_minute: 100,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 1000,
      },
      supported_query_families: ['keyword', 'show_hn', 'recent'],
      capabilities: {
        can_stream: false,
        can_search: true,
        provides_dependencies: false,
        provides_artifacts: true,
        requires_auth: false,
      },
    };
  }

  async health_check(): Promise<AdapterHealth> {
    const start = Date.now();
    try {
      const res = await this.request<number>(`${this.baseUrl}/v0/maxitem.json`, {
        timeoutMs: 8000,
      });
      const latency = Date.now() - start;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: 'ANONYMOUS',
        message: res.status === 200
          ? `[ACTIVE] Hacker News API reachable (maxitem: ${res.data})`
          : `[TEMPORARILY_DEGRADED] Unexpected status code: ${res.status}`,
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'ANONYMOUS',
        message: `[SOURCE_UNAVAILABLE] Failed to reach Hacker News API: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
