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

export interface ArxivPaperItem {
  id: string; // e.g. "http://arxiv.org/abs/2304.11817v1"
  arxivId: string; // e.g. "2304.11817"
  title: string;
  summary: string;
  published: string;
  updated: string;
  authors: string[];
  comment?: string;
  doi?: string;
  pdfUrl?: string;
  absUrl?: string;
  extractedRepoUrls: string[];
  extractedProjectUrls: string[];
}

export interface ArxivAdapterOptions {
  baseUrl?: string;
  fetcher?: HttpFetcher;
  gateway?: FetchGateway;
}

export class ArxivSourceAdapter extends BaseSourceAdapter {
  readonly sourceType = 'arxiv';
  readonly sourceName = 'arXiv';
  readonly adapterVersion = '1.0.0';

  private readonly baseUrl: string;

  constructor(options: ArxivAdapterOptions = {}) {
    super({
      fetcher: options.fetcher,
      gateway: options.gateway,
      initialRateLimit: {
        limit: 30, // arXiv requests max 1 req per 3 seconds
        remaining: 30,
        window_seconds: 90,
        is_exhausted: false,
      },
    });
    this.baseUrl = (options.baseUrl || 'https://export.arxiv.org').replace(/\/$/, '');
  }

  private parseArxivId(locator: string): string {
    let clean = locator.replace(/^arxiv:\/\//, '').replace(/^arxiv:/, '');
    clean = clean.replace(/^https?:\/\/arxiv\.org\/abs\//, '').replace(/^https?:\/\/arxiv\.org\/pdf\//, '');
    clean = clean.replace(/\/$/, '').replace(/\.pdf$/, '');
    if (!clean) {
      throw new Error(`Invalid arXiv locator: '${locator}'`);
    }
    return clean;
  }

  /**
   * Safe parsing of arXiv Atom XML feed into structured paper objects.
   */
  private parseAtomFeed(xml: string): ArxivPaperItem[] {
    const papers: ArxivPaperItem[] = [];
    const entryBlocks = xml.split('<entry>');

    for (let i = 1; i < entryBlocks.length; i++) {
      const block = entryBlocks[i].split('</entry>')[0];
      if (!block) continue;

      const idMatch = block.match(/<id>([^<]+)<\/id>/);
      const titleMatch = block.match(/<title>([\s\S]*?)<\/title>/);
      const summaryMatch = block.match(/<summary>([\s\S]*?)<\/summary>/);
      const publishedMatch = block.match(/<published>([^<]+)<\/published>/);
      const updatedMatch = block.match(/<updated>([^<]+)<\/updated>/);
      const commentMatch = block.match(/<arxiv:comment[^>]*>([\s\S]*?)<\/arxiv:comment>/);
      const doiMatch = block.match(/<arxiv:doi[^>]*>([^<]+)<\/arxiv:doi>/);

      // Extract authors
      const authors: string[] = [];
      const authorMatches = block.matchAll(/<author>\s*<name>([^<]+)<\/name>/g);
      for (const m of authorMatches) {
        if (m[1]) authors.push(m[1].trim());
      }

      // Extract links
      let pdfUrl: string | undefined;
      let absUrl: string | undefined;
      const linkMatches = block.matchAll(/<link([^>]+)\/>/g);
      for (const lm of linkMatches) {
        const attrs = lm[1];
        const hrefMatch = attrs.match(/href="([^"]+)"/);
        const titleMatch = attrs.match(/title="([^"]+)"/);
        const relMatch = attrs.match(/rel="([^"]+)"/);
        if (hrefMatch) {
          if (titleMatch && titleMatch[1] === 'pdf') {
            pdfUrl = hrefMatch[1];
          } else if (relMatch && relMatch[1] === 'alternate') {
            absUrl = hrefMatch[1];
          }
        }
      }

      const fullId = idMatch ? idMatch[1].trim() : '';
      const cleanArxivId = fullId.replace(/^https?:\/\/arxiv\.org\/abs\//, '').replace(/v\d+$/, '');
      const rawTitle = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : 'Untitled';
      const rawSummary = summaryMatch ? summaryMatch[1].replace(/\s+/g, ' ').trim() : '';
      const comment = commentMatch ? commentMatch[1].replace(/\s+/g, ' ').trim() : undefined;

      // Extract code repo and project references from abstract and comment
      const fullText = `${rawSummary} ${comment || ''}`;
      const extractedRepoUrls: string[] = [];
      const extractedProjectUrls: string[] = [];

      const repoRegex = /https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|huggingface\.co)\/[a-zA-Z0-9_\-\.\/]+/g;
      const matches = fullText.match(repoRegex) || [];
      for (let url of matches) {
        url = url.replace(/[\.,;:!\)>]+$/, '');
        if (!extractedRepoUrls.includes(url)) {
          extractedRepoUrls.push(url);
        }
      }

      const projectRegex = /https?:\/\/[a-zA-Z0-9_\-\.]+\.(?:io|ai|org|edu|com)\/[a-zA-Z0-9_\-\.\/]+/g;
      const pMatches = fullText.match(projectRegex) || [];
      for (let pUrl of pMatches) {
        pUrl = pUrl.replace(/[\.,;:!\)>]+$/, '');
        if (!pUrl.includes('arxiv.org') && !extractedRepoUrls.includes(pUrl) && !extractedProjectUrls.includes(pUrl)) {
          extractedProjectUrls.push(pUrl);
        }
      }

      papers.push({
        id: fullId,
        arxivId: cleanArxivId,
        title: rawTitle,
        summary: rawSummary,
        published: publishedMatch ? publishedMatch[1].trim() : new Date().toISOString(),
        updated: updatedMatch ? updatedMatch[1].trim() : new Date().toISOString(),
        authors,
        comment,
        doi: doiMatch ? doiMatch[1].trim() : undefined,
        pdfUrl: pdfUrl || (fullId ? fullId.replace('/abs/', '/pdf/') : undefined),
        absUrl: absUrl || fullId,
        extractedRepoUrls,
        extractedProjectUrls,
      });
    }

    return papers;
  }

  async discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult> {
    const start = cursor?.offset ? cursor.offset : (cursor?.page ? (cursor.page - 1) * 20 : 0);
    const maxResults = Math.min(criteria.limit || 20, 50);

    const query = criteria.query
      ? `all:"${encodeURIComponent(criteria.query)}"`
      : 'all:"autonomous agent" OR all:"multi-agent" OR all:"llm agent"';

    const url = new URL(`${this.baseUrl}/api/query`);
    url.searchParams.set('search_query', query);
    url.searchParams.set('start', String(start));
    url.searchParams.set('max_results', String(maxResults));
    url.searchParams.set('sortBy', 'submittedDate');
    url.searchParams.set('sortOrder', 'descending');

    const res = await this.request<string>(url.toString(), {
      headers: {
        'Accept': 'application/atom+xml',
        'User-Agent': 'caim-source-adapter/1.0.0',
      },
      skipRobots: true,
    });

    const xml = typeof res.data === 'string' ? res.data : String(res.data || '');
    const papers = this.parseAtomFeed(xml);

    // A paper is an academic publication seed, NOT an agent directly
    const candidates: DiscoveryCandidate[] = papers.map((p) => ({
      source_locator: `arxiv://${p.arxivId}`,
      display_name: p.title,
      source_type: this.sourceType,
      type_hint: 'UNSPECIFIED', // Academic paper seed toward implementation
      confidence: p.extractedRepoUrls.length > 0 ? 0.8 : 0.5,
      summary: `${p.summary.slice(0, 300)}... (Authors: ${p.authors.slice(0, 3).join(', ')}${p.authors.length > 3 ? ' et al.' : ''}${p.extractedRepoUrls.length > 0 ? ` | Repos: ${p.extractedRepoUrls.join(', ')}` : ''})`,
      raw_metadata: p as unknown as Record<string, unknown>,
      created_at: p.published,
      updated_at: p.updated,
      discovered_at: new Date().toISOString(),
    }));

    const nextStart = start + maxResults;
    const hasMore = papers.length >= maxResults;

    return {
      candidates,
      next_cursor: hasMore ? { offset: nextStart } : null,
      has_more: hasMore,
      rate_limit: this.get_rate_limit_state(),
      provenance: this.generate_provenance('DISCOVER', [this.hashPayload(papers)]),
    };
  }

  async fetch_metadata(locator: string): Promise<SourceMetadataResult> {
    const arxivId = this.parseArxivId(locator);
    const url = `${this.baseUrl}/api/query?id_list=${encodeURIComponent(arxivId)}`;

    const res = await this.request<string>(url, {
      headers: {
        'Accept': 'application/atom+xml',
        'User-Agent': 'caim-source-adapter/1.0.0',
      },
      locator: `arxiv://${arxivId}`,
      skipRobots: true,
    });

    const xml = typeof res.data === 'string' ? res.data : String(res.data || '');
    const papers = this.parseAtomFeed(xml);
    const matched = papers.find((p) => p.arxivId === arxivId) || papers[0];

    if (!matched) {
      throw new Error(`[SOURCE_UNAVAILABLE] arXiv paper '${arxivId}' not found`);
    }

    const contentHash = this.hashPayload(matched);

    return {
      source_locator: `arxiv://${arxivId}`,
      raw_metadata: matched as unknown as Record<string, unknown>,
      content_hash: contentHash,
      observed_at: new Date().toISOString(),
      provenance: this.generate_provenance('FETCH_METADATA', [contentHash]),
    };
  }

  async resolve_canonical_pivot(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    const locator = this.extractLocator(candidate);
    const raw = typeof candidate === 'object' ? candidate.raw_metadata : {};
    return ImmutableVersionResolver.resolveDiscoveryOnlyPivot('arxiv', locator, raw);
  }

  async resolve_immutable_identity(candidate: DiscoveryCandidate | string): Promise<ImmutableResolutionResult> {
    return this.resolve_canonical_pivot(candidate);
  }

  async resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult> {
    const locator = this.extractLocator(candidate);
    const arxivId = this.parseArxivId(locator);
    const meta = await this.fetch_metadata(locator);
    const paper = meta.raw_metadata as unknown as ArxivPaperItem;

    const locators: ArtifactLocatorEntry[] = [
      {
        locator: paper.absUrl || `https://arxiv.org/abs/${arxivId}`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'text/html',
        is_primary: true,
      },
      {
        locator: paper.pdfUrl || `https://arxiv.org/pdf/${arxivId}.pdf`,
        artifact_type: 'DOCUMENTATION',
        mime_type: 'application/pdf',
        is_primary: false,
      },
    ];

    for (const repo of paper.extractedRepoUrls || []) {
      locators.push({
        locator: repo,
        artifact_type: 'GIT_REPOSITORY',
        mime_type: 'application/x-git',
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
    const paper = meta.raw_metadata as unknown as ArxivPaperItem;

    const relationships: CandidateRelationship[] = [];

    // Link paper seeds to their implementations!
    for (const repo of paper.extractedRepoUrls || []) {
      relationships.push({
        from_locator: locator,
        target_locator: repo,
        relationship_type: 'UPSTREAM_SOURCE',
        target_type_hint: 'AGENT_REPOSITORY',
        depth: 1,
        metadata: {
          role: 'code_implementation',
          paper_title: paper.title,
        },
      });
    }

    for (const proj of paper.extractedProjectUrls || []) {
      relationships.push({
        from_locator: locator,
        target_locator: proj,
        relationship_type: 'HOMEPAGE',
        depth: 1,
        metadata: {
          role: 'project_page',
          paper_title: paper.title,
        },
      });
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
    const paper = meta.raw_metadata as unknown as ArxivPaperItem;
    const token = `${paper.updated || paper.published}:${meta.content_hash}`;

    return {
      source_locator: locator,
      change_token: token,
      token_type: 'TIMESTAMP',
      last_modified: paper.updated || paper.published,
    };
  }

  get_source_policy(): SourcePolicy {
    return {
      source_type: this.sourceType,
      source_name: this.sourceName,
      auth_mode: 'ANONYMOUS',
      max_page_size: 50,
      rate_limit_per_minute: 20,
      retry_policy: {
        max_retries: 3,
        backoff_factor: 2.0,
        initial_delay_ms: 3000,
      },
      supported_query_families: ['keyword', 'id_list', 'author', 'title'],
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
      const res = await this.request<string>(`${this.baseUrl}/api/query?id_list=2304.11817`, {
        timeoutMs: 8000,
        skipRobots: true,
      });
      const latency = Date.now() - start;
      return {
        status: res.status === 200 ? 'HEALTHY' : 'DEGRADED',
        auth_status: 'ANONYMOUS',
        message: res.status === 200
          ? '[ACTIVE] arXiv API reachable'
          : `[TEMPORARILY_DEGRADED] Unexpected status code: ${res.status}`,
        latency_ms: latency,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        status: 'UNHEALTHY',
        auth_status: 'ANONYMOUS',
        message: `[SOURCE_UNAVAILABLE] Failed to reach arXiv: ${err.message}`,
        rate_limit: this.get_rate_limit_state(),
        checked_at: new Date().toISOString(),
      };
    }
  }
}
