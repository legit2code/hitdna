/**
 * Architecture V2.0.1 — Deterministic Relevance Gate
 * Cheap deterministic first-pass heuristic filter that eliminates obvious noise
 * (licenses, documentation, social links, image/badge assets, donation links,
 * corporate portals, terms/privacy, analytics/ads, general non-agent libraries, stale forks)
 * BEFORE consuming discovery-worker cycles or calling expensive LLM models.
 *
 * GUARANTEE: Never invokes an LLM. Purely deterministic and CPU-cheap.
 */

import { ExtractedPivot, RelevanceGateDecision, RejectionReason } from './types.ts';

// Known Agent Frameworks and Tooling (Always Accepted by Gate)
export const AGENT_FRAMEWORK_WHITELIST = new Set<string>([
  'langchain',
  '@langchain/core',
  '@langchain/community',
  '@langchain/langgraph',
  'langgraph',
  'langchain-core',
  'langchain-community',
  'langserve',
  'langsmith',
  'autogen',
  'pyautogen',
  'autogen-agentchat',
  'autogen-ext',
  'semantic-kernel',
  'crewai',
  'crewai-tools',
  'smolagents',
  'llama-index',
  'llama-index-core',
  'llamaindex',
  '@modelcontextprotocol/sdk',
  'mcp',
  'mcp-server',
  'instructor',
  'guidance',
  'dspy',
  'dspy-ai',
  'openai',
  'anthropic',
  '@google/genai',
  '@google/generative-ai',
  'browser-use',
  'open-interpreter',
  'gpt-researcher',
  'autogpt',
  'babyagi',
  'superagi',
  'chatdev',
  'metagpt',
  'swarm',
  'haystack-ai',
  'camel-ai',
  'chromadb',
  'qdrant-client',
  'weaviate-client',
]);

// Known General Libraries (Rejected as GENERAL_LIBRARY)
export const GENERAL_UTILITY_LIBRARIES = new Set<string>([
  'lodash',
  'underscore',
  'ramda',
  'express',
  'koa',
  'fastify',
  'react',
  'react-dom',
  'vue',
  'angular',
  'svelte',
  'next',
  'nuxt',
  'axios',
  'node-fetch',
  'got',
  'superagent',
  'typescript',
  'tslib',
  'jest',
  'vitest',
  'mocha',
  'chai',
  'eslint',
  'prettier',
  'babel',
  'webpack',
  'vite',
  'rollup',
  'esbuild',
  'pydantic',
  'requests',
  'urllib3',
  'httpx',
  'numpy',
  'pandas',
  'scipy',
  'matplotlib',
  'seaborn',
  'pytest',
  'unittest',
  'black',
  'flake8',
  'mypy',
  'uvicorn',
  'click',
  'argparse',
  'chalk',
  'commander',
  'yargs',
  'dotenv',
  'cors',
  'helmet',
  'body-parser',
  'glob',
  'rimraf',
  'fs-extra',
  'zod',
  'nodemon',
  'concurrently',
  'cross-env',
  'husky',
  'lint-staged',
  'moment',
  'dayjs',
  'date-fns',
  'uuid',
  'bcrypt',
  'jsonwebtoken',
  'multer',
  'cookie-parser',
  'torch',
  'torchvision',
  'scikit-learn',
  'scikit-image',
  'pillow',
  'tqdm',
  'packaging',
  'setuptools',
  'wheel',
]);

export class RelevanceGate {
  /**
   * Deterministically evaluates whether an extracted pivot candidate is worth queuing.
   * STRICT GUARANTEE: Never invokes an LLM.
   */
  public static evaluate(pivot: ExtractedPivot): RelevanceGateDecision {
    const rawUrl = pivot.discovered_url.toLowerCase();
    const domain = (pivot.domain || '').toLowerCase();
    const edgeType = pivot.edge_type;

    // 1. Asset / Badge / CDN Filter (e.g. .svg, .png, shields.io, codecov)
    if (this.isAssetOrBadge(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'ASSET_OR_BADGE',
        gate_reason: 'URL targets image asset, CI/build badge, or static media resource',
        heuristic_used: 'ASSET_BADGE_PATTERN',
        is_llm_used: false,
      };
    }

    // 2. Social Profile / Community Channels
    if (this.isSocialProfile(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'SOCIAL_PROFILE',
        gate_reason: 'URL targets social network profile or community chat channel',
        heuristic_used: 'SOCIAL_PLATFORM_PATTERN',
        is_llm_used: false,
      };
    }

    // 3. License Pages
    if (this.isLicensePage(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'LICENSE_PAGE',
        gate_reason: 'URL targets legal license document or license selector',
        heuristic_used: 'LICENSE_DOCUMENT_PATTERN',
        is_llm_used: false,
      };
    }

    // 4. Generic Documentation / Reference Platforms
    if (this.isGenericDocumentation(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'DOCUMENTATION_ONLY',
        gate_reason: 'URL targets standard language/platform documentation or encyclopedia reference',
        heuristic_used: 'GENERIC_DOCS_PATTERN',
        is_llm_used: false,
      };
    }

    // 5. Donation / Sponsorship Links
    if (this.isDonationLink(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'DONATION_LINK',
        gate_reason: 'URL targets financial donation, tipping, or crowdsponsorship page',
        heuristic_used: 'DONATION_PORTAL_PATTERN',
        is_llm_used: false,
      };
    }

    // 6. Analytics / Tracker / Telemetry Domains
    if (this.isAnalyticsOrAd(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'ANALYTICS_OR_AD',
        gate_reason: 'URL targets web analytics, telemetry, or advertising endpoint',
        heuristic_used: 'ANALYTICS_TELEMETRY_PATTERN',
        is_llm_used: false,
      };
    }

    // 7. Corporate Portals / Terms / Privacy / Legal
    if (this.isCorporateOrTerms(rawUrl, domain)) {
      return {
        accepted: false,
        rejection_reason: 'CORPORATE_OR_TERMS',
        gate_reason: 'URL targets generic corporate landing homepage or legal terms/privacy policy',
        heuristic_used: 'CORPORATE_LEGAL_PATTERN',
        is_llm_used: false,
      };
    }

    // 8. Package Manifest Dependency Filter (General Library vs. Agent Framework)
    if (edgeType === 'DEPENDENCY' || edgeType === 'DEV_DEPENDENCY' || pivot.candidate_type === 'PACKAGE') {
      const pkgDecision = this.evaluatePackageDependency(pivot);
      if (!pkgDecision.accepted) {
        return pkgDecision;
      }
    }

    // 9. Fork Divergence Check
    if (edgeType === 'FORK') {
      const forkMeta = pivot.metadata || {};
      const commitsAhead = forkMeta.commits_ahead ?? forkMeta.ahead_by ?? 0;
      const independentReleases = Boolean(forkMeta.independent_releases || forkMeta.releases_count);
      const substantiveDelta = Boolean(forkMeta.substantive_delta);

      if (commitsAhead === 0 && !independentReleases && !substantiveDelta) {
        return {
          accepted: false,
          rejection_reason: 'STALE_FORK',
          gate_reason: 'Fork exhibits zero commits ahead of upstream and no independent releases',
          heuristic_used: 'FORK_STALENESS_CHECK',
          is_llm_used: false,
        };
      }
    }

    // 10. Maintainer Other Repos Relevance Filter
    if (edgeType === 'MAINTAINER_OTHER_REPO') {
      const repoMeta = pivot.metadata || {};
      const textCorpus = [
        repoMeta.name || '',
        repoMeta.description || '',
        ...(Array.isArray(repoMeta.topics) ? repoMeta.topics : []),
      ].join(' ').toLowerCase();

      const isAgentRelevant = /agent|autonomous|llm|mcp|langchain|langgraph|crewai|autogen|orchestrat|reasoning|tool|prompt|caim/i.test(textCorpus);
      if (!isAgentRelevant) {
        return {
          accepted: false,
          rejection_reason: 'UNRELATED_DOMAIN',
          gate_reason: 'Maintainer repository metadata has zero agent, LLM, or reasoning indicators in topics/description',
          heuristic_used: 'MAINTAINER_RELEVANCE_FILTER',
          is_llm_used: false,
        };
      }
    }

    // 11. Positive Match / Agent Framework Acceptance
    return {
      accepted: true,
      rejection_reason: null,
      gate_reason: 'Passed deterministic relevance gate with agent-relevant signals',
      heuristic_used: 'DETERMINISTIC_PASS',
      is_llm_used: false,
    };
  }

  private static isAssetOrBadge(url: string, domain: string): boolean {
    const assetExtensions = /\.(png|jpe?g|gif|svg|ico|webp|bmp|tiff|css|woff2?|ttf|mp4|mp3)(\?.*)?$/i;
    if (assetExtensions.test(url)) return true;

    const badgeDomains = [
      'shields.io',
      'badge.fury.io',
      'codecov.io',
      'pepy.tech',
      'travis-ci.org',
      'travis-ci.com',
      'circleci.com',
      'david-dm.org',
      'badges.gitter.im',
    ];
    if (badgeDomains.some(d => domain.includes(d))) return true;

    if (url.includes('/badge.svg') || url.includes('/workflows/') && url.includes('/badge')) {
      return true;
    }
    return false;
  }

  private static isSocialProfile(url: string, domain: string): boolean {
    const socialDomains = [
      'twitter.com',
      'x.com',
      'linkedin.com',
      'youtube.com',
      'youtu.be',
      'discord.gg',
      'discord.com',
      'reddit.com',
      'instagram.com',
      'facebook.com',
      'medium.com',
      'substack.com',
      't.me',
      'telegram.me',
      'mastodon.social',
      'bsky.app',
      'twitch.tv',
    ];
    return socialDomains.some(d => domain === d || domain.endsWith('.' + d));
  }

  private static isLicensePage(url: string, domain: string): boolean {
    if (
      domain === 'choosealicense.com' ||
      url.includes('apache.org/licenses') ||
      url.includes('gnu.org/licenses') ||
      url.includes('opensource.org/licenses') ||
      url.includes('creativecommons.org/licenses')
    ) {
      return true;
    }

    if (
      /\/blob\/[^\/]+\/[^\/]+\/(license|licence|copying)(\.(md|txt))?$/i.test(url) ||
      /\/(license|licence|copying)(\.(md|txt|html?))?$/i.test(url)
    ) {
      return true;
    }
    return false;
  }

  private static isGenericDocumentation(url: string, domain: string): boolean {
    if (
      domain.startsWith('docs.') ||
      domain.endsWith('.gitbook.io') ||
      domain.endsWith('.readthedocs.io') ||
      domain.endsWith('.readme.io') ||
      domain === 'readthedocs.org' ||
      domain === 'gitbook.io'
    ) {
      return true;
    }

    const genericDocDomains = [
      'docs.python.org',
      'developer.mozilla.org',
      'developer.chrome.com',
      'git-scm.com',
      'en.wikipedia.org',
      'wikipedia.org',
      'w3schools.com',
      'geeksforgeeks.org',
      'stackoverflow.com',
      'stackexchange.com',
      'react.dev',
      'reactjs.org',
      'nodejs.org',
      'docs.github.com',
      'rust-lang.org',
      'go.dev',
    ];
    return genericDocDomains.some(d => domain === d || domain.endsWith('.' + d));
  }

  private static isDonationLink(url: string, domain: string): boolean {
    const donationDomains = [
      'buymeacoffee.com',
      'patreon.com',
      'opencollective.com',
      'paypal.me',
      'ko-fi.com',
    ];
    if (donationDomains.some(d => domain === d || domain.endsWith('.' + d))) {
      return true;
    }
    if (domain === 'github.com' && url.includes('/sponsors/')) {
      return true;
    }
    return false;
  }

  private static isAnalyticsOrAd(url: string, domain: string): boolean {
    const analyticsDomains = [
      'google-analytics.com',
      'googletagmanager.com',
      'doubleclick.net',
      'hotjar.com',
      'segment.io',
      'segment.com',
      'mixpanel.com',
      'sentry.io',
      'datadoghq.com',
      'newrelic.com',
    ];
    return analyticsDomains.some(d => domain === d || domain.endsWith('.' + d));
  }

  private static isCorporateOrTerms(url: string, domain: string): boolean {
    // Check root corporate domains without specific project path
    const corporateRoots = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com'];
    for (const corp of corporateRoots) {
      if (domain === corp || domain === 'www.' + corp) {
        try {
          const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
          if (parsed.pathname === '/' || parsed.pathname === '') {
            return true;
          }
        } catch {
          return true;
        }
      }
    }

    // Check terms / privacy / legal paths
    const legalPaths = /\/(terms|terms-of-service|privacy|privacy-policy|tos|legal|security|cookies|disclaimer)\/?$/i;
    if (legalPaths.test(url)) {
      return true;
    }

    return false;
  }

  private static evaluatePackageDependency(pivot: ExtractedPivot): RelevanceGateDecision {
    // Extract normalized package name (e.g. npm://@langchain/core -> @langchain/core, pypi://crewai -> crewai)
    let pkgName = pivot.discovered_url;
    if (pkgName.startsWith('npm://')) {
      pkgName = pkgName.replace('npm://', '');
    } else if (pkgName.startsWith('pypi://')) {
      pkgName = pkgName.replace('pypi://', '');
    } else if (pkgName.includes('npmjs.com/package/')) {
      const match = pkgName.match(/npmjs\.com\/package\/([^/?#]+(\/[^/?#]+)?)/);
      if (match) pkgName = match[1];
    } else if (pkgName.includes('pypi.org/project/')) {
      const match = pkgName.match(/pypi\.org\/project\/([^/?#]+)/);
      if (match) pkgName = match[1];
    }
    pkgName = pkgName.toLowerCase().trim();

    // 1. Explicit Agent Framework Whitelist
    if (AGENT_FRAMEWORK_WHITELIST.has(pkgName)) {
      return {
        accepted: true,
        rejection_reason: null,
        gate_reason: `Recognized agent framework/SDK: ${pkgName}`,
        heuristic_used: 'AGENT_FRAMEWORK_WHITELIST',
        is_llm_used: false,
      };
    }

    // 2. Keyword heuristic for specialized agent packages
    if (/agent|langgraph|langchain|autogen|crewai|semantic-kernel|smolagents|llama-index|mcp|dspy|swarm|reasoning/i.test(pkgName)) {
      return {
        accepted: true,
        rejection_reason: null,
        gate_reason: `Package name exhibits agent architecture signature: ${pkgName}`,
        heuristic_used: 'AGENT_NAME_PATTERN',
        is_llm_used: false,
      };
    }

    // 3. Known General Utility Libraries
    if (GENERAL_UTILITY_LIBRARIES.has(pkgName)) {
      return {
        accepted: false,
        rejection_reason: 'GENERAL_LIBRARY',
        gate_reason: `Non-agent utility library filtered out: ${pkgName}`,
        heuristic_used: 'GENERAL_LIBRARY_CATALOG',
        is_llm_used: false,
      };
    }

    // 4. Default: If not matching any agent framework or signature, reject as GENERAL_LIBRARY
    return {
      accepted: false,
      rejection_reason: 'GENERAL_LIBRARY',
      gate_reason: `Package is not recognized as an agent-relevant framework: ${pkgName}`,
      heuristic_used: 'NON_AGENT_PACKAGE_DEFAULT',
      is_llm_used: false,
    };
  }
}
