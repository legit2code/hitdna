/**
 * Architecture V2.0.1 — Discovery Pivot Extractor
 * Step 5 of 6: Pivot Extraction & Relevance Gate
 *
 * Extracts real pivot signals from a verified agent's acquired content:
 * 1. README/documentation: related-projects, inspired-by, built-with, integrations, companion repos, referenced MCP servers, demo/deployment URLs
 * 2. Package manifests (package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml): agent-relevant frameworks vs. general libraries
 * 3. Maintainer's other public repositories: filtered by relevance before queuing (never queue every repo a large org owns)
 * 4. Fork relationships: substantive divergence signals (independent releases, active development, code delta) vs. stale forks
 * 5. MCP references (agent -> MCP server, MCP server -> repository)
 * 6. Demo/deployment links (repository -> Space/extension/hosted-demo) — recorded, never executed
 *
 * Real edge_type, real evidence_location, and real evidence_snippet_hash on every pivot.
 */

import crypto from 'crypto';
import { ExtractedPivot, DiscoveryEdgeType } from './types.ts';
import { UrlNormalizer } from './url-normalizer.ts';
import { RelevanceGate } from './relevance-gate.ts';
import { SourceAdapter } from '../types.ts';

export interface PivotExtractorOptions {
  maxLinksPerText?: number;
  skipRelevanceGate?: boolean;
}

export interface VerifiedAgentManifests {
  package_json?: Record<string, any> | string;
  requirements_txt?: string;
  pyproject_toml?: string;
  go_mod?: string;
  cargo_toml?: string;
}

export interface MaintainerRepoInfo {
  name: string;
  full_name?: string;
  html_url: string;
  description?: string;
  topics?: string[];
  stargazers_count?: number;
}

export interface ForkDivergenceInfo {
  is_fork: boolean;
  parent_url?: string;
  parent_name?: string;
  commits_ahead?: number;
  commits_behind?: number;
  independent_releases?: boolean;
  releases_count?: number;
  substantive_delta?: boolean;
}

export interface McpReferenceInfo {
  server_name: string;
  url?: string;
  command?: string;
  target_repository?: string;
  env?: Record<string, string>;
}

export interface DemoLinkInfo {
  url: string;
  type?: string;
  title?: string;
}

export interface VerifiedAgentContent {
  locator: string;
  source_type: string;
  source_agent_id?: string;
  source_candidate_id?: string;
  root_seed_id?: string;
  metadata?: Record<string, any>;
  readme?: string;
  manifests?: VerifiedAgentManifests;
  maintainer_repos?: MaintainerRepoInfo[];
  fork_metadata?: ForkDivergenceInfo;
  mcp_references?: McpReferenceInfo[];
  demo_links?: DemoLinkInfo[];
}

export class PivotExtractor {
  /**
   * Primary entrypoint: Extracts all pivot signals from a verified agent's acquired content,
   * evaluates each against the deterministic Relevance Gate, and generates rich provenance metadata.
   */
  public static extractFromVerifiedAgent(
    agent: VerifiedAgentContent,
    options: PivotExtractorOptions = {}
  ): { pivots: ExtractedPivot[]; source_content_hash: string } {
    const rawPayload = JSON.stringify(agent);
    const sourceContentHash = crypto.createHash('sha256').update(rawPayload).digest('hex');
    const pivots: ExtractedPivot[] = [];
    const seenNormalized = new Set<string>();

    const parentNorm = UrlNormalizer.normalize(agent.locator).normalized_url;
    seenNormalized.add(parentNorm);

    // Helper to register a pivot with deduplication and RelevanceGate evaluation
    const addPivot = (pivot: ExtractedPivot) => {
      if (seenNormalized.has(pivot.normalized_url)) {
        return;
      }
      seenNormalized.add(pivot.normalized_url);

      if (!options.skipRelevanceGate) {
        pivot.relevance_gate_decision = RelevanceGate.evaluate(pivot);
      }

      pivots.push(pivot);
    };

    // ------------------------------------------------------------------------
    // 1. README / DOCUMENTATION EXTRACTION
    // ------------------------------------------------------------------------
    const readmeContent = agent.readme || (agent.metadata?.readme as string) || (agent.metadata?.description as string) || '';
    if (readmeContent) {
      this.extractFromReadme(readmeContent, agent.locator, addPivot, options);
    }

    // ------------------------------------------------------------------------
    // 2. PACKAGE MANIFEST EXTRACTION (agent-relevant frameworks vs general libraries)
    // ------------------------------------------------------------------------
    if (agent.manifests) {
      this.extractFromManifests(agent.manifests, agent.locator, addPivot);
    }

    // ------------------------------------------------------------------------
    // 3. MAINTAINER'S OTHER PUBLIC REPOSITORIES
    // ------------------------------------------------------------------------
    if (agent.maintainer_repos && agent.maintainer_repos.length > 0) {
      this.extractFromMaintainerRepos(agent.maintainer_repos, agent.locator, addPivot);
    }

    // ------------------------------------------------------------------------
    // 4. FORK RELATIONSHIPS (substantive divergence check)
    // ------------------------------------------------------------------------
    if (agent.fork_metadata && agent.fork_metadata.is_fork && agent.fork_metadata.parent_url) {
      this.extractFromForkMetadata(agent.fork_metadata, agent.locator, addPivot);
    }

    // ------------------------------------------------------------------------
    // 5. MCP REFERENCES (agent -> MCP server or MCP server -> repository)
    // ------------------------------------------------------------------------
    if (agent.mcp_references && agent.mcp_references.length > 0) {
      this.extractFromMcpReferences(agent.mcp_references, agent.locator, addPivot);
    }

    // ------------------------------------------------------------------------
    // 6. DEMO / DEPLOYMENT LINKS (Space / Extension / Hosted Demo - Never Execute)
    // ------------------------------------------------------------------------
    if (agent.demo_links && agent.demo_links.length > 0) {
      this.extractFromDemoLinks(agent.demo_links, agent.locator, addPivot);
    }

    // ------------------------------------------------------------------------
    // 7. PROJECT URLS / RAW METADATA ATTRIBUTES
    // ------------------------------------------------------------------------
    if (agent.metadata) {
      this.extractFromRawMetadata(agent.metadata, agent.locator, addPivot);
    }

    return {
      pivots,
      source_content_hash: sourceContentHash,
    };
  }

  /**
   * Adapter-compatible wrapper for backwards-compatibility with DiscoveryGraphWorker.
   */
  public static async extractPivots(
    parentLocator: string,
    adapter: SourceAdapter,
    rawMetadata: Record<string, any>,
    options: PivotExtractorOptions = {}
  ): Promise<{ pivots: ExtractedPivot[]; source_content_hash: string }> {
    // Construct verified agent content from adapter and metadata
    const verifiedAgent: VerifiedAgentContent = {
      locator: parentLocator,
      source_type: adapter.sourceType,
      metadata: rawMetadata,
      readme: rawMetadata.readme || rawMetadata.description || '',
      manifests: {
        package_json: rawMetadata.package_json,
        requirements_txt: rawMetadata.requirements_txt,
        pyproject_toml: rawMetadata.pyproject_toml,
        go_mod: rawMetadata.go_mod,
        cargo_toml: rawMetadata.cargo_toml,
      },
      maintainer_repos: rawMetadata.maintainer_repos,
      fork_metadata: rawMetadata.fork_metadata,
      mcp_references: rawMetadata.mcp_references,
      demo_links: rawMetadata.demo_links,
    };

    // If adapter has enumerate_relationships, include them as well
    const result = this.extractFromVerifiedAgent(verifiedAgent, options);

    try {
      const relResult = await adapter.enumerate_relationships({
        source_type: adapter.sourceType,
        source_locator: parentLocator,
        display_name: parentLocator,
        type_hint: 'PACKAGE_DISTRIBUTION',
        confidence: 1.0,
        discovered_at: new Date().toISOString(),
        raw_metadata: rawMetadata,
      });

      const existingNorms = new Set(result.pivots.map(p => p.normalized_url));
      existingNorms.add(UrlNormalizer.normalize(parentLocator).normalized_url);

      for (const rel of relResult.relationships || []) {
        const target = rel.target_locator;
        if (!target) continue;

        const normalized = UrlNormalizer.normalize(target);
        if (existingNorms.has(normalized.normalized_url)) continue;
        existingNorms.add(normalized.normalized_url);

        let edgeType: DiscoveryEdgeType = 'DEPENDENCY';
        let confidence = 0.70;

        if (rel.relationship_type === 'UPSTREAM_SOURCE') {
          edgeType = 'UPSTREAM_SOURCE';
          confidence = 0.85;
        } else if (rel.relationship_type === 'DEV_DEPENDENCY') {
          edgeType = 'DEV_DEPENDENCY';
          confidence = 0.50;
        } else if (rel.relationship_type === 'MAINTAINED_BY') {
          edgeType = 'MAINTAINER_OTHER_REPO';
          confidence = 0.65;
        } else if (rel.relationship_type === 'FORK_OF') {
          edgeType = 'FORK';
          confidence = 0.80;
        }

        const snippet = `${rel.relationship_type}:${target}:${JSON.stringify(rel.metadata || {})}`;
        const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

        const pivot: ExtractedPivot = {
          discovered_url: target,
          normalized_url: normalized.normalized_url,
          canonical_url: normalized.canonical_url,
          candidate_type: normalized.candidate_type,
          domain: normalized.domain,
          edge_type: edgeType,
          extractor: 'ADAPTER_RELATIONSHIP_ENUMERATOR',
          evidence_type: rel.relationship_type,
          evidence_location: `adapter:${adapter.sourceType}:relationships`,
          evidence_snippet_hash: snippetHash,
          discovery_confidence: confidence,
          metadata: rel.metadata,
        };

        if (!options.skipRelevanceGate) {
          pivot.relevance_gate_decision = RelevanceGate.evaluate(pivot);
        }

        result.pivots.push(pivot);
      }
    } catch (err) {
      console.warn(`[PivotExtractor] Notice enumerating relationships for ${parentLocator}:`, err);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: README / Markdown
  // --------------------------------------------------------------------------
  private static extractFromReadme(
    readme: string,
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void,
    options: PivotExtractorOptions
  ) {
    const lines = readme.split(/\r?\n/);
    let currentSection = 'general';
    let currentSectionHeading = '';
    const maxLinks = options.maxLinksPerText ?? 30;
    let totalLinksFound = 0;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      if (totalLinksFound >= maxLinks) break;

      const line = lines[lineIndex];

      // Track markdown section headings
      const headingMatch = line.match(/^#{1,4}\s+(.*)$/);
      if (headingMatch) {
        currentSectionHeading = headingMatch[1].trim();
        const lowerH = currentSectionHeading.toLowerCase();
        if (/related(\s*projects|\s*work)?|alternatives?|similar/i.test(lowerH)) {
          currentSection = 'related_projects';
        } else if (/inspired\s*by/i.test(lowerH)) {
          currentSection = 'inspired_by';
        } else if (/built\s*with|powered\s*by|tech\s*stack|dependencies/i.test(lowerH)) {
          currentSection = 'built_with';
        } else if (/integrations?|companion|extensions?/i.test(lowerH)) {
          currentSection = 'integrations';
        } else if (/model\s*context\s*protocol|mcp/i.test(lowerH)) {
          currentSection = 'mcp';
        } else if (/demo|playground|try\s*it|live\s*app|deployment/i.test(lowerH)) {
          currentSection = 'demo';
        } else {
          currentSection = 'general';
        }
        continue;
      }

      // Match markdown links: [anchor](url)
      const linkRegex = /\[([^\]]+)\]\((https?:\/\/[^\s\)\'\"]+)\)/g;
      let match: RegExpExecArray | null;

      while ((match = linkRegex.exec(line)) !== null && totalLinksFound < maxLinks) {
        const anchor = match[1].trim();
        const url = match[2].trim();
        totalLinksFound++;

        const normalized = UrlNormalizer.normalize(url);
        let edgeType: DiscoveryEdgeType = 'README_LINK';
        let confidence = 0.60;
        let evidenceType = 'MARKDOWN_ANCHOR';

        // Categorize by section context or link signature
        if (currentSection === 'related_projects' || currentSection === 'inspired_by' || /related|alternative|inspired/i.test(anchor)) {
          edgeType = 'RELATED_PROJECT';
          confidence = 0.85;
          evidenceType = 'README_RELATED_SECTION';
        } else if (currentSection === 'mcp' || /mcp|model\s*context\s*protocol/i.test(anchor) || /mcp/i.test(url)) {
          edgeType = 'MCP_REFERENCE';
          confidence = 0.90;
          evidenceType = 'README_MCP_SECTION';
        } else if (currentSection === 'demo' || /demo|playground|live|try/i.test(anchor) || /huggingface\.co\/spaces|streamlit\.app|\.hf\.space/i.test(url)) {
          edgeType = 'DEMO_LINK';
          confidence = 0.80;
          evidenceType = 'README_DEMO_SECTION';
        } else if (currentSection === 'built_with' || currentSection === 'integrations' || /integration|companion/i.test(anchor)) {
          edgeType = 'DEPENDENCY';
          confidence = 0.75;
          evidenceType = 'README_INTEGRATIONS_SECTION';
        } else if (/agent|autonomous|langchain|crew|autogen|llm/i.test(anchor)) {
          confidence = 0.80;
        }

        const snippet = `[${anchor}](${url})`;
        const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

        addPivot({
          discovered_url: url,
          normalized_url: normalized.normalized_url,
          canonical_url: normalized.canonical_url,
          candidate_type: normalized.candidate_type,
          domain: normalized.domain,
          edge_type: edgeType,
          extractor: 'README_DOCUMENTATION_EXTRACTOR',
          evidence_type: evidenceType,
          evidence_location: `readme:section_${currentSection}:line_${lineIndex + 1}`,
          evidence_snippet_hash: snippetHash,
          discovery_confidence: confidence,
          metadata: {
            anchor_text: anchor,
            section_heading: currentSectionHeading || currentSection,
            line_number: lineIndex + 1,
          },
        });
      }
    }
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: Package Manifests
  // --------------------------------------------------------------------------
  private static extractFromManifests(
    manifests: VerifiedAgentManifests,
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    // A. package.json (Node/TS)
    if (manifests.package_json) {
      try {
        const pkg = typeof manifests.package_json === 'string'
          ? JSON.parse(manifests.package_json)
          : manifests.package_json;

        const depTypes: Array<{ key: string; edge: DiscoveryEdgeType }> = [
          { key: 'dependencies', edge: 'DEPENDENCY' },
          { key: 'devDependencies', edge: 'DEV_DEPENDENCY' },
          { key: 'peerDependencies', edge: 'PEER_DEPENDENCY' },
        ];

        for (const { key, edge } of depTypes) {
          const deps = pkg[key];
          if (deps && typeof deps === 'object') {
            for (const [depName, versionSpec] of Object.entries(deps)) {
              const locator = `npm://${depName}`;
              const normalized = UrlNormalizer.normalize(locator);
              const snippet = `"${depName}": "${versionSpec}"`;
              const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

              addPivot({
                discovered_url: locator,
                normalized_url: normalized.normalized_url,
                canonical_url: normalized.canonical_url,
                candidate_type: 'PACKAGE',
                domain: 'npmjs.com',
                edge_type: edge,
                extractor: 'MANIFEST_DEPENDENCY_EXTRACTOR',
                evidence_type: 'PACKAGE_JSON_DEPENDENCY',
                evidence_location: `package.json:${key}:${depName}`,
                evidence_snippet_hash: snippetHash,
                discovery_confidence: edge === 'DEPENDENCY' ? 0.85 : 0.60,
                metadata: {
                  manifest_file: 'package.json',
                  dependency_type: key,
                  package_name: depName,
                  version_spec: String(versionSpec),
                },
              });
            }
          }
        }
      } catch (err) {
        console.warn('[PivotExtractor] Notice parsing package.json:', err);
      }
    }

    // B. requirements.txt (Python)
    if (manifests.requirements_txt) {
      const lines = manifests.requirements_txt.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const rawLine = lines[i].trim();
        if (!rawLine || rawLine.startsWith('#') || rawLine.startsWith('-')) continue;

        // Parse package name (e.g. langchain>=0.1.0 -> langchain)
        const match = rawLine.match(/^([a-zA-Z0-9_\-\.]+)/);
        if (!match) continue;

        const pkgName = match[1].toLowerCase();
        const locator = `pypi://${pkgName}`;
        const normalized = UrlNormalizer.normalize(locator);
        const snippetHash = crypto.createHash('sha256').update(rawLine).digest('hex');

        addPivot({
          discovered_url: locator,
          normalized_url: normalized.normalized_url,
          canonical_url: normalized.canonical_url,
          candidate_type: 'PACKAGE',
          domain: 'pypi.org',
          edge_type: 'DEPENDENCY',
          extractor: 'MANIFEST_DEPENDENCY_EXTRACTOR',
          evidence_type: 'REQUIREMENTS_TXT_DEPENDENCY',
          evidence_location: `requirements.txt:line_${i + 1}:${pkgName}`,
          evidence_snippet_hash: snippetHash,
          discovery_confidence: 0.85,
          metadata: {
            manifest_file: 'requirements.txt',
            package_name: pkgName,
            raw_requirement: rawLine,
            line_number: i + 1,
          },
        });
      }
    }

    // C. pyproject.toml (Python)
    if (manifests.pyproject_toml) {
      const lines = manifests.pyproject_toml.split(/\r?\n/);
      let inDepsSection = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('[') && line.endsWith(']')) {
          inDepsSection = /dependencies|tool\.poetry\.dependencies/i.test(line);
          continue;
        }

        if (inDepsSection && line && !line.startsWith('#')) {
          const match = line.match(/^([a-zA-Z0-9_\-\.]+)\s*=/);
          if (match) {
            const pkgName = match[1].toLowerCase();
            if (pkgName === 'python') continue;

            const locator = `pypi://${pkgName}`;
            const normalized = UrlNormalizer.normalize(locator);
            const snippetHash = crypto.createHash('sha256').update(line).digest('hex');

            addPivot({
              discovered_url: locator,
              normalized_url: normalized.normalized_url,
              canonical_url: normalized.canonical_url,
              candidate_type: 'PACKAGE',
              domain: 'pypi.org',
              edge_type: 'DEPENDENCY',
              extractor: 'MANIFEST_DEPENDENCY_EXTRACTOR',
              evidence_type: 'PYPROJECT_TOML_DEPENDENCY',
              evidence_location: `pyproject.toml:line_${i + 1}:${pkgName}`,
              evidence_snippet_hash: snippetHash,
              discovery_confidence: 0.85,
              metadata: {
                manifest_file: 'pyproject.toml',
                package_name: pkgName,
                raw_requirement: line,
                line_number: i + 1,
              },
            });
          }
        }
      }
    }

    // D. go.mod (Go)
    if (manifests.go_mod) {
      const lines = manifests.go_mod.split(/\r?\n/);
      let inRequire = false;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === 'require (') {
          inRequire = true;
          continue;
        }
        if (inRequire && line === ')') {
          inRequire = false;
          continue;
        }

        if ((inRequire || line.startsWith('require ')) && line && !line.startsWith('//')) {
          const clean = line.replace(/^require\s+/, '').trim();
          const parts = clean.split(/\s+/);
          if (parts.length >= 1) {
            const modPath = parts[0];
            const url = modPath.startsWith('http') ? modPath : `https://${modPath}`;
            const normalized = UrlNormalizer.normalize(url);
            const snippetHash = crypto.createHash('sha256').update(line).digest('hex');

            addPivot({
              discovered_url: url,
              normalized_url: normalized.normalized_url,
              canonical_url: normalized.canonical_url,
              candidate_type: 'REPOSITORY',
              domain: normalized.domain,
              edge_type: 'DEPENDENCY',
              extractor: 'MANIFEST_DEPENDENCY_EXTRACTOR',
              evidence_type: 'GO_MOD_REQUIRE',
              evidence_location: `go.mod:line_${i + 1}:${modPath}`,
              evidence_snippet_hash: snippetHash,
              discovery_confidence: 0.80,
              metadata: {
                manifest_file: 'go.mod',
                module_path: modPath,
                version: parts[1] || '',
                line_number: i + 1,
              },
            });
          }
        }
      }
    }

    // E. Cargo.toml (Rust)
    if (manifests.cargo_toml) {
      const lines = manifests.cargo_toml.split(/\r?\n/);
      let inDeps = false;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '[dependencies]') {
          inDeps = true;
          continue;
        }
        if (line.startsWith('[') && inDeps) {
          inDeps = false;
          continue;
        }

        if (inDeps && line && !line.startsWith('#')) {
          const match = line.match(/^([a-zA-Z0-9_\-]+)\s*=/);
          if (match) {
            const crateName = match[1];
            const url = `crates://${crateName}`;
            const normalized = UrlNormalizer.normalize(url);
            const snippetHash = crypto.createHash('sha256').update(line).digest('hex');

            addPivot({
              discovered_url: url,
              normalized_url: normalized.normalized_url,
              canonical_url: normalized.canonical_url,
              candidate_type: 'PACKAGE',
              domain: 'crates.io',
              edge_type: 'DEPENDENCY',
              extractor: 'MANIFEST_DEPENDENCY_EXTRACTOR',
              evidence_type: 'CARGO_TOML_DEPENDENCY',
              evidence_location: `Cargo.toml:line_${i + 1}:${crateName}`,
              evidence_snippet_hash: snippetHash,
              discovery_confidence: 0.80,
              metadata: {
                manifest_file: 'Cargo.toml',
                crate_name: crateName,
                line_number: i + 1,
              },
            });
          }
        }
      }
    }
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: Maintainer's Other Repositories
  // --------------------------------------------------------------------------
  private static extractFromMaintainerRepos(
    repos: MaintainerRepoInfo[],
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    for (const repo of repos) {
      const url = repo.html_url;
      if (!url) continue;

      const normalized = UrlNormalizer.normalize(url);
      const snippet = JSON.stringify({
        name: repo.name,
        full_name: repo.full_name,
        description: repo.description,
        topics: repo.topics,
      });
      const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

      addPivot({
        discovered_url: url,
        normalized_url: normalized.normalized_url,
        canonical_url: normalized.canonical_url,
        candidate_type: 'REPOSITORY',
        domain: normalized.domain,
        edge_type: 'MAINTAINER_OTHER_REPO',
        extractor: 'MAINTAINER_REPO_EXTRACTOR',
        evidence_type: 'MAINTAINER_REPOSITORY_LIST',
        evidence_location: `maintainer:repos:${repo.full_name || repo.name}`,
        evidence_snippet_hash: snippetHash,
        discovery_confidence: 0.70,
        metadata: {
          name: repo.name,
          full_name: repo.full_name,
          description: repo.description,
          topics: repo.topics || [],
          stars: repo.stargazers_count,
        },
      });
    }
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: Fork Relationships (Divergence Check)
  // --------------------------------------------------------------------------
  private static extractFromForkMetadata(
    fork: ForkDivergenceInfo,
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    if (!fork.parent_url) return;

    const normalized = UrlNormalizer.normalize(fork.parent_url);
    const snippet = JSON.stringify({
      parent_url: fork.parent_url,
      commits_ahead: fork.commits_ahead,
      commits_behind: fork.commits_behind,
      independent_releases: fork.independent_releases,
    });
    const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

    addPivot({
      discovered_url: fork.parent_url,
      normalized_url: normalized.normalized_url,
      canonical_url: normalized.canonical_url,
      candidate_type: 'REPOSITORY',
      domain: normalized.domain,
      edge_type: 'FORK',
      extractor: 'FORK_RELATIONSHIP_EXTRACTOR',
      evidence_type: 'UPSTREAM_FORK_PARENT',
      evidence_location: `fork:parent:${fork.parent_name || 'upstream'}`,
      evidence_snippet_hash: snippetHash,
      discovery_confidence: 0.85,
      metadata: {
        commits_ahead: fork.commits_ahead ?? 0,
        commits_behind: fork.commits_behind ?? 0,
        independent_releases: Boolean(fork.independent_releases || fork.releases_count),
        substantive_delta: Boolean(fork.substantive_delta || (fork.commits_ahead && fork.commits_ahead > 0)),
      },
    });
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: MCP References
  // --------------------------------------------------------------------------
  private static extractFromMcpReferences(
    refs: McpReferenceInfo[],
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    for (const ref of refs) {
      const targetUrl = ref.target_repository || ref.url || `mcp://${ref.server_name}`;
      const normalized = UrlNormalizer.normalize(targetUrl);
      const snippet = JSON.stringify(ref);
      const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

      addPivot({
        discovered_url: targetUrl,
        normalized_url: normalized.normalized_url,
        canonical_url: normalized.canonical_url,
        candidate_type: ref.target_repository ? 'REPOSITORY' : 'MCP_SERVER',
        domain: normalized.domain,
        edge_type: 'MCP_REFERENCE',
        extractor: 'MCP_REFERENCE_EXTRACTOR',
        evidence_type: 'MODEL_CONTEXT_PROTOCOL_CONFIG',
        evidence_location: `mcp:servers:${ref.server_name}`,
        evidence_snippet_hash: snippetHash,
        discovery_confidence: 0.95,
        metadata: {
          server_name: ref.server_name,
          command: ref.command,
          target_repository: ref.target_repository,
        },
      });
    }
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: Demo Links (Never Execute Target)
  // --------------------------------------------------------------------------
  private static extractFromDemoLinks(
    demos: DemoLinkInfo[],
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    for (const demo of demos) {
      if (!demo.url) continue;

      const normalized = UrlNormalizer.normalize(demo.url);
      const snippet = `${demo.title || 'demo'}:${demo.type || 'space'}:${demo.url}`;
      const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

      addPivot({
        discovered_url: demo.url,
        normalized_url: normalized.normalized_url,
        canonical_url: normalized.canonical_url,
        candidate_type: 'DEMO_APPLICATION',
        domain: normalized.domain,
        edge_type: 'DEMO_LINK',
        extractor: 'DEMO_LINK_EXTRACTOR',
        evidence_type: 'DEPLOYED_DEMO_REFERENCE',
        evidence_location: `demo:${demo.type || 'web'}:${demo.title || 'preview'}`,
        evidence_snippet_hash: snippetHash,
        discovery_confidence: 0.85,
        metadata: {
          title: demo.title,
          demo_type: demo.type,
          execute_target_forbidden: true, // Invariant: Never execute deployed target
        },
      });
    }
  }

  // --------------------------------------------------------------------------
  // Sub-extractor: Project URLs in Metadata
  // --------------------------------------------------------------------------
  private static extractFromRawMetadata(
    metadata: Record<string, any>,
    parentLocator: string,
    addPivot: (p: ExtractedPivot) => void
  ) {
    const projectUrls = metadata.project_urls || metadata.info?.project_urls;
    if (projectUrls && typeof projectUrls === 'object') {
      for (const [key, val] of Object.entries(projectUrls)) {
        if (typeof val !== 'string' || !val.startsWith('http')) continue;

        const normalized = UrlNormalizer.normalize(val);
        let edgeType: DiscoveryEdgeType = 'README_LINK';
        let confidence = 0.60;

        if (/repo|source|code|github/i.test(key)) {
          edgeType = 'UPSTREAM_SOURCE';
          confidence = 0.85;
        } else if (/demo|app/i.test(key)) {
          edgeType = 'DEMO_LINK';
          confidence = 0.75;
        }

        const snippet = `${key}:${val}`;
        const snippetHash = crypto.createHash('sha256').update(snippet).digest('hex');

        addPivot({
          discovered_url: val,
          normalized_url: normalized.normalized_url,
          canonical_url: normalized.canonical_url,
          candidate_type: normalized.candidate_type,
          domain: normalized.domain,
          edge_type: edgeType,
          extractor: 'METADATA_URL_EXTRACTOR',
          evidence_type: 'PROJECT_URLS',
          evidence_location: `metadata:project_urls:${key}`,
          evidence_snippet_hash: snippetHash,
          discovery_confidence: confidence,
          metadata: { label: key },
        });
      }
    }
  }
}
