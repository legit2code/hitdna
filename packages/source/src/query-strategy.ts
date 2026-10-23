import { QueryRule, QueryFamily } from './types.ts';

export class QueryStrategyRegistry {
  private rules = new Map<string, QueryRule>();

  constructor(initialRules?: QueryRule[]) {
    if (initialRules) {
      initialRules.forEach(r => this.registerRule(r));
    } else {
      this.registerDefaultRules();
    }
  }

  registerRule(rule: QueryRule): this {
    this.rules.set(rule.id, { ...rule });
    return this;
  }

  unregisterRule(id: string): boolean {
    return this.rules.delete(id);
  }

  getRule(id: string): QueryRule | undefined {
    return this.rules.get(id);
  }

  getAllRules(): QueryRule[] {
    return Array.from(this.rules.values());
  }

  getRulesByFamily(family: QueryFamily): QueryRule[] {
    return this.getAllRules().filter(r => r.family === family && r.enabled);
  }

  setRuleEnabled(id: string, enabled: boolean): boolean {
    const rule = this.rules.get(id);
    if (!rule) return false;
    rule.enabled = enabled;
    return true;
  }

  /**
   * Generates formatted search queries from a seed string across active rules or a specific family.
   */
  generateQueries(seed: string, options: { family?: QueryFamily; targetSource?: string } = {}): Array<{
    ruleId: string;
    family: QueryFamily;
    query: string;
    priority: number;
    targetSources?: string[];
  }> {
    const cleanSeed = seed.trim();
    if (!cleanSeed) return [];

    let activeRules = this.getAllRules().filter(r => r.enabled);
    if (options.family) {
      activeRules = activeRules.filter(r => r.family === options.family);
    }
    if (options.targetSource) {
      activeRules = activeRules.filter(r => 
        !r.target_sources || r.target_sources.includes(options.targetSource!)
      );
    }

    // Sort by priority ascending (1 is highest priority)
    activeRules.sort((a, b) => a.priority - b.priority);

    return activeRules.map(rule => ({
      ruleId: rule.id,
      family: rule.family,
      query: rule.template.replace(/\{seed\}/g, cleanSeed),
      priority: rule.priority,
      targetSources: rule.target_sources,
    }));
  }

  private registerDefaultRules(): void {
    const defaults: QueryRule[] = [
      {
        id: 'RULE_AGENT_DISCOVERY_PRIMARY',
        name: 'Autonomous Agent Discovery',
        family: 'AGENT_DISCOVERY',
        template: '"{seed}" autonomous agent OR "AI agent"',
        description: 'Discovers autonomous AI agents and runtime orchestrators',
        priority: 1,
        tags: ['agent', 'autonomous', 'core'],
        enabled: true,
      },
      {
        id: 'RULE_TOOL_ECOSYSTEM_MCP',
        name: 'Tool & MCP Ecosystem',
        family: 'TOOL_ECOSYSTEM',
        template: '"{seed}" MCP server OR tool specification plugin',
        description: 'Discovers Model Context Protocol tools and agent capabilities',
        priority: 2,
        tags: ['mcp', 'tools', 'plugins'],
        enabled: true,
      },
      {
        id: 'RULE_MODEL_WEIGHTS_HF',
        name: 'Model Weights & Safetensors',
        family: 'MODEL_WEIGHTS',
        template: 'site:huggingface.co "{seed}" safetensors OR model',
        description: 'Discovers fine-tuned model checkpoints and model cards',
        target_sources: ['huggingface', 'web'],
        priority: 2,
        tags: ['huggingface', 'safetensors', 'weights'],
        enabled: true,
      },
      {
        id: 'RULE_CODE_REPO_SEARCH',
        name: 'Code Repository Search',
        family: 'CODE_REPOSITORY',
        template: 'site:github.com OR site:gitlab.com OR site:codeberg.org "{seed}"',
        description: 'Targets public source code repositories and agent implementations',
        target_sources: ['github', 'gitlab', 'codeberg', 'web'],
        priority: 2,
        tags: ['git', 'repositories'],
        enabled: true,
      },
      {
        id: 'RULE_PACKAGE_DIST_PYPI_NPM',
        name: 'Package Registry Search',
        family: 'PACKAGE_DISTRIBUTION',
        template: 'site:pypi.org OR site:npmjs.com "{seed}"',
        description: 'Discovers distributed Python wheels and npm packages',
        target_sources: ['pypi', 'npm', 'web'],
        priority: 3,
        tags: ['pypi', 'npm', 'package'],
        enabled: true,
      },
      {
        id: 'RULE_CONTAINER_SANDBOX_OCI',
        name: 'Container Sandbox & OCI Images',
        family: 'CONTAINER_SANDBOX',
        template: 'site:hub.docker.com "{seed}" sandbox OR agent',
        description: 'Discovers Docker Hub container images and sandbox runners',
        target_sources: ['dockerhub', 'web'],
        priority: 3,
        tags: ['docker', 'oci', 'sandbox'],
        enabled: true,
      },
      {
        id: 'RULE_SPEC_STANDARD_CAIM',
        name: 'Ontology & Spec Standard Search',
        family: 'SPECIFICATION_STANDARD',
        template: '"{seed}" CAIM specification OR ontology manifest schema',
        description: 'Discovers agent specification schemas and ontologies',
        priority: 4,
        tags: ['caim', 'ontology', 'spec'],
        enabled: true,
      },
      {
        id: 'RULE_FRESHNESS_SWEEP_RECENT',
        name: 'Freshness Sweep & Changelogs',
        family: 'FRESHNESS_SWEEP',
        template: '"{seed}" release changelog OR update 2026',
        description: 'Queries recent updates, versions, and security patches',
        priority: 5,
        tags: ['freshness', 'releases'],
        enabled: true,
      },
    ];

    defaults.forEach(r => this.registerRule(r));
  }
}
