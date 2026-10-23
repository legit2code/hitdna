import { RobotsDisallowedError } from './errors.ts';

export interface RobotsRule {
  path: string;
  allow: boolean;
}

export interface DomainRobotsCache {
  rules: RobotsRule[];
  crawlDelaySeconds?: number;
  fetchedAt: number;
  expiresAt: number;
}

export class RobotsPolicyEnforcer {
  private cache = new Map<string, DomainRobotsCache>();
  private inFlightFetches = new Map<string, Promise<DomainRobotsCache>>();
  private readonly defaultTtlMs = 3600 * 1000; // 1 hour

  constructor(
    private readonly userAgent: string = 'caim-bot',
    private readonly robotsFetcher?: (robotsUrl: string) => Promise<string | null>
  ) {}

  /**
   * Checks whether the given target URL path is permitted under the domain's robots.txt policy.
   * Throws RobotsDisallowedError if disallowed.
   */
  async checkAllowed(urlStr: string): Promise<void> {
    const parsed = new URL(urlStr);
    const domainKey = `${parsed.protocol}//${parsed.host}`;
    const pathname = parsed.pathname + parsed.search;

    const cache = await this.getRulesForDomain(domainKey);
    const isAllowed = this.evaluateRules(cache.rules, pathname);

    if (!isAllowed) {
      throw new RobotsDisallowedError(
        `Access to path '${pathname}' on domain '${domainKey}' is prohibited by robots.txt policy.`,
        {
          url: urlStr,
          domain: domainKey,
          pathname,
        }
      );
    }
  }

  /**
   * Injects explicit rules for a domain (useful for testing or manual policy overrides).
   */
  setDomainRules(domainKey: string, rules: RobotsRule[], crawlDelaySeconds?: number): void {
    const now = Date.now();
    this.cache.set(domainKey, {
      rules,
      crawlDelaySeconds,
      fetchedAt: now,
      expiresAt: now + this.defaultTtlMs,
    });
  }

  /**
   * Clears cached robots rules.
   */
  clearCache(): void {
    this.cache.clear();
    this.inFlightFetches.clear();
  }

  private async getRulesForDomain(domainKey: string): Promise<DomainRobotsCache> {
    const now = Date.now();
    const existing = this.cache.get(domainKey);
    if (existing && existing.expiresAt > now) {
      return existing;
    }

    if (this.inFlightFetches.has(domainKey)) {
      return this.inFlightFetches.get(domainKey)!;
    }

    const fetchPromise = this.fetchAndParseRobots(domainKey).finally(() => {
      this.inFlightFetches.delete(domainKey);
    });

    this.inFlightFetches.set(domainKey, fetchPromise);
    return fetchPromise;
  }

  private async fetchAndParseRobots(domainKey: string): Promise<DomainRobotsCache> {
    const robotsUrl = `${domainKey}/robots.txt`;
    const now = Date.now();
    let text: string | null = null;

    try {
      if (this.robotsFetcher) {
        text = await this.robotsFetcher(robotsUrl);
      } else {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const res = await fetch(robotsUrl, {
          signal: controller.signal,
          headers: { 'User-Agent': this.userAgent },
        });
        clearTimeout(timeout);
        if (res.ok) {
          text = await res.text();
        }
      }
    } catch {
      // If fetching robots.txt fails or 404s, allow by default
      text = null;
    }

    const rules = text ? this.parseRobotsTxt(text, this.userAgent) : [];
    const cacheEntry: DomainRobotsCache = {
      rules,
      fetchedAt: now,
      expiresAt: now + this.defaultTtlMs,
    };

    this.cache.set(domainKey, cacheEntry);
    return cacheEntry;
  }

  /**
   * Parses robots.txt content according to RFC 9309 rules.
   */
  parseRobotsTxt(content: string, targetAgent: string): RobotsRule[] {
    const lines = content.split(/\r?\n/);
    const agentLower = targetAgent.toLowerCase();

    let inMatchingGroup = false;
    let inStarGroup = false;
    const specificRules: RobotsRule[] = [];
    const starRules: RobotsRule[] = [];

    for (let rawLine of lines) {
      // Strip comments
      const commentIndex = rawLine.indexOf('#');
      if (commentIndex !== -1) {
        rawLine = rawLine.substring(0, commentIndex);
      }
      const line = rawLine.trim();
      if (!line) continue;

      const colonIndex = line.indexOf(':');
      if (colonIndex === -1) continue;

      const field = line.substring(0, colonIndex).trim().toLowerCase();
      const value = line.substring(colonIndex + 1).trim();

      if (field === 'user-agent') {
        const agentVal = value.toLowerCase();
        if (agentVal === agentLower || agentVal === 'caim' || agentVal === 'caim-bot') {
          inMatchingGroup = true;
          inStarGroup = false;
        } else if (agentVal === '*') {
          inStarGroup = true;
          inMatchingGroup = false;
        } else {
          inMatchingGroup = false;
          inStarGroup = false;
        }
        continue;
      }

      if (inMatchingGroup) {
        if (field === 'disallow' && value) {
          specificRules.push({ path: value, allow: false });
        } else if (field === 'allow' && value) {
          specificRules.push({ path: value, allow: true });
        }
      } else if (inStarGroup) {
        if (field === 'disallow' && value) {
          starRules.push({ path: value, allow: false });
        } else if (field === 'allow' && value) {
          starRules.push({ path: value, allow: true });
        }
      }
    }

    // Specific agent rules take full precedence over star rules
    return specificRules.length > 0 ? specificRules : starRules;
  }

  /**
   * Evaluates path against ordered rules. Longest matching rule wins; allow wins ties.
   */
  evaluateRules(rules: RobotsRule[], pathname: string): boolean {
    if (rules.length === 0) {
      return true; // No restrictions
    }

    let bestMatchLength = -1;
    let bestMatchAllow = true;

    for (const rule of rules) {
      if (this.pathMatches(rule.path, pathname)) {
        const ruleLength = rule.path.length;
        if (ruleLength > bestMatchLength) {
          bestMatchLength = ruleLength;
          bestMatchAllow = rule.allow;
        } else if (ruleLength === bestMatchLength && rule.allow) {
          // Allow takes precedence over disallow on equal length
          bestMatchAllow = true;
        }
      }
    }

    return bestMatchLength === -1 ? true : bestMatchAllow;
  }

  private pathMatches(pattern: string, path: string): boolean {
    if (!pattern) return false;

    // Convert robots.txt pattern to regex:
    // '*' matches any sequence of characters
    // '$' at the end matches the end of the URL
    let escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    escaped = escaped.replace(/\\\*/g, '.*');
    if (escaped.endsWith('\\$')) {
      escaped = escaped.substring(0, escaped.length - 2) + '$';
    } else {
      escaped = '^' + (escaped.startsWith('/') ? '' : '/') + escaped;
    }

    try {
      const regex = new RegExp(escaped);
      return regex.test(path);
    } catch {
      return path.startsWith(pattern);
    }
  }
}
