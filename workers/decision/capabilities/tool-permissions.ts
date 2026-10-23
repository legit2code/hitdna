/**
 * E37: Tool Permission & Access Scope Engine
 * Architecture V2.0.1 - Capability Analysis Subsystem
 *
 * Analyzes tool bindings, MCP/OpenAPI function declarations, parameter schemas,
 * and downstream resource access requirements against least-privilege security boundaries.
 * Detects excessive privileges, wildcard scopes, unauthenticated write sinks,
 * and privilege escalation risks in agent tool definitions.
 */

export interface ToolPermissionDefinition {
  toolName: string;
  functionName: string;
  description: string;
  requiredScopes: string[];
  effectivePermissions: Array<'READ' | 'WRITE' | 'DELETE' | 'EXECUTE' | 'ADMIN' | 'IMPERSONATE'>;
  resourceTargets: string[]; // e.g. ["db:users", "filesystem:/etc", "aws:s3:*"]
  hasAuthenticationGuard: boolean;
  hasRateLimitOrBudget: boolean;
  isSandboxed: boolean;
}

export interface ScopePolicyRule {
  forbiddenScopes: string[];
  forbiddenWildcards: string[];
  requiresAdminApproval: string[];
  maxWriteOperationsPerTool: number;
}

export interface ToolSecurityFinding {
  toolName: string;
  findingType: 
    | 'WILDCARD_RESOURCE_ACCESS'
    | 'UNBOUNDED_EXECUTION_PERMISSION'
    | 'MISSING_AUTHENTICATION_GUARD'
    | 'UNRESTRICTED_DESTRUCTIVE_ACTION'
    | 'OVER_PRIVILEGED_SCOPE';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  violatingScopes: string[];
  violatingPermissions: string[];
  remediationRecommendation: string;
}

export interface ToolPermissionAnalysisReport {
  analysisRunId: string;
  totalToolsAnalyzed: number;
  leastPrivilegeScore: number; // 0.0 to 1.0 (1.0 = strictly scoped least-privilege)
  findings: ToolSecurityFinding[];
  highRiskTools: string[];
  allowedTools: string[];
  quarantinedTools: string[];
  policyViolationCount: number;
  status: 'COMPLIANT' | 'WARNING' | 'QUARANTINE_REQUIRED';
}

export class ToolPermissionAccessScopeEngine {
  private defaultPolicy: ScopePolicyRule = {
    forbiddenScopes: ['root', 'admin:super', 'aws:*', 'gcp:*'],
    forbiddenWildcards: ['*', 'all', '*:*'],
    requiresAdminApproval: ['db:drop', 'iam:grant', 'filesystem:write:/etc', 'k8s:exec'],
    maxWriteOperationsPerTool: 2,
  };

  public analyzeTools(
    analysisRunId: string,
    tools: ToolPermissionDefinition[],
    customPolicy?: Partial<ScopePolicyRule>
  ): ToolPermissionAnalysisReport {
    const policy = { ...this.defaultPolicy, ...customPolicy };
    const findings: ToolSecurityFinding[] = [];
    const highRiskTools = new Set<string>();
    const quarantinedTools = new Set<string>();
    const allowedTools = new Set<string>();

    for (const tool of tools) {
      let toolHasViolation = false;

      // 1. Wildcard resource targeting
      for (const target of tool.resourceTargets) {
        if (policy.forbiddenWildcards.includes(target) || target.endsWith(':*')) {
          findings.push({
            toolName: tool.toolName,
            findingType: 'WILDCARD_RESOURCE_ACCESS',
            severity: 'HIGH',
            message: `Tool '${tool.toolName}' requests dangerous wildcard resource access '${target}'.`,
            violatingScopes: tool.requiredScopes,
            violatingPermissions: tool.effectivePermissions,
            remediationRecommendation: `Constrain '${target}' to specific resource identifiers or path prefixes.`,
          });
          toolHasViolation = true;
          highRiskTools.add(tool.toolName);
        }
      }

      // 2. Unbounded Execution permission without sandboxing
      if (tool.effectivePermissions.includes('EXECUTE') && !tool.isSandboxed) {
        findings.push({
          toolName: tool.toolName,
          findingType: 'UNBOUNDED_EXECUTION_PERMISSION',
          severity: 'CRITICAL',
          message: `Tool '${tool.toolName}' possesses EXECUTE permissions without an isolated execution sandbox.`,
          violatingScopes: tool.requiredScopes,
          violatingPermissions: ['EXECUTE'],
          remediationRecommendation: `Enforce isolated ephemeral container execution sandbox for '${tool.toolName}'.`,
        });
        toolHasViolation = true;
        quarantinedTools.add(tool.toolName);
      }

      // 3. Missing authentication guard on destructive operations
      const hasDestructive = tool.effectivePermissions.some((p) => p === 'DELETE' || p === 'ADMIN' || p === 'IMPERSONATE');
      if (hasDestructive && !tool.hasAuthenticationGuard) {
        findings.push({
          toolName: tool.toolName,
          findingType: 'MISSING_AUTHENTICATION_GUARD',
          severity: 'CRITICAL',
          message: `Tool '${tool.toolName}' executes destructive/admin actions (${tool.effectivePermissions.join(', ')}) without verified authentication/authorization guards.`,
          violatingScopes: tool.requiredScopes,
          violatingPermissions: tool.effectivePermissions.filter((p) => p === 'DELETE' || p === 'ADMIN' || p === 'IMPERSONATE'),
          remediationRecommendation: `Require caller authentication and approval tokens prior to '${tool.toolName}' dispatch.`,
        });
        toolHasViolation = true;
        quarantinedTools.add(tool.toolName);
      }

      // 4. Over-privileged forbidden scopes
      for (const scope of tool.requiredScopes) {
        if (policy.forbiddenScopes.includes(scope.toLowerCase())) {
          findings.push({
            toolName: tool.toolName,
            findingType: 'OVER_PRIVILEGED_SCOPE',
            severity: 'HIGH',
            message: `Tool '${tool.toolName}' requests forbidden high-privilege scope '${scope}'.`,
            violatingScopes: [scope],
            violatingPermissions: tool.effectivePermissions,
            remediationRecommendation: `Remove '${scope}' from tool manifest and substitute fine-grained tenant-scoped permissions.`,
          });
          toolHasViolation = true;
          highRiskTools.add(tool.toolName);
        }
      }

      if (!toolHasViolation) {
        allowedTools.add(tool.toolName);
      }
    }

    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;

    let score = tools.length === 0 ? 1.0 : Math.max(0, 1.0 - (criticalCount * 0.4) - (highCount * 0.15));
    score = Math.round(score * 100) / 100;

    let status: 'COMPLIANT' | 'WARNING' | 'QUARANTINE_REQUIRED' = 'COMPLIANT';
    if (criticalCount > 0 || quarantinedTools.size > 0) {
      status = 'QUARANTINE_REQUIRED';
    } else if (highCount > 0) {
      status = 'WARNING';
    }

    return {
      analysisRunId,
      totalToolsAnalyzed: tools.length,
      leastPrivilegeScore: score,
      findings,
      highRiskTools: Array.from(highRiskTools),
      allowedTools: Array.from(allowedTools),
      quarantinedTools: Array.from(quarantinedTools),
      policyViolationCount: findings.length,
      status,
    };
  }
}
