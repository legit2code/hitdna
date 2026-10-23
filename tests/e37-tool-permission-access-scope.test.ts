import { describe, it, expect } from 'vitest';
import { 
  ToolPermissionAccessScopeEngine, 
  ToolPermissionDefinition 
} from '../workers/decision/capabilities/tool-permissions.ts';

describe('E37: Tool Permission & Access Scope Engine', () => {
  const engine = new ToolPermissionAccessScopeEngine();

  it('detects wildcard resource access and unauthenticated write operations', () => {
    const tools: ToolPermissionDefinition[] = [
      {
        toolName: 's3_wildcard_dumper',
        functionName: 'dumpBuckets',
        description: 'Dumps all S3 buckets',
        requiredScopes: ['s3:read'],
        effectivePermissions: ['READ'],
        resourceTargets: ['aws:s3:*'],
        hasAuthenticationGuard: true,
        hasRateLimitOrBudget: true,
        isSandboxed: true
      },
      {
        toolName: 'unprotected_db_writer',
        functionName: 'rawQuery',
        description: 'Executes direct mutations on database',
        requiredScopes: ['db:write'],
        effectivePermissions: ['WRITE', 'DELETE'],
        resourceTargets: ['db:prod_accounts'],
        hasAuthenticationGuard: false,
        hasRateLimitOrBudget: false,
        isSandboxed: true
      }
    ];

    const report = engine.analyzeTools('run-e37-001', tools);

    expect(report.findings.some(f => f.findingType === 'WILDCARD_RESOURCE_ACCESS')).toBe(true);
    expect(report.findings.some(f => f.findingType === 'MISSING_AUTHENTICATION_GUARD')).toBe(true);
    expect(report.highRiskTools).toContain('s3_wildcard_dumper');
    expect(report.quarantinedTools).toContain('unprotected_db_writer');
    expect(report.status).toBe('QUARANTINE_REQUIRED');
  });

  it('detects unsandboxed execution tools as unbounded risk', () => {
    const tools: ToolPermissionDefinition[] = [
      {
        toolName: 'bash_shell_executor',
        functionName: 'execCmd',
        description: 'Executes arbitrary shell strings',
        requiredScopes: ['os:exec'],
        effectivePermissions: ['EXECUTE'],
        resourceTargets: ['os:system'],
        hasAuthenticationGuard: true,
        hasRateLimitOrBudget: true,
        isSandboxed: false
      }
    ];

    const report = engine.analyzeTools('run-e37-002', tools);

    expect(report.findings.some(f => f.findingType === 'UNBOUNDED_EXECUTION_PERMISSION' && f.severity === 'CRITICAL')).toBe(true);
    expect(report.quarantinedTools).toContain('bash_shell_executor');
  });

  it('approves properly scoped, authenticated, rate-limited sandboxed tools', () => {
    const tools: ToolPermissionDefinition[] = [
      {
        toolName: 'github_issue_reader',
        functionName: 'getIssues',
        description: 'Reads issues from a specific repository',
        requiredScopes: ['repo:read'],
        effectivePermissions: ['READ'],
        resourceTargets: ['github:org/repo'],
        hasAuthenticationGuard: true,
        hasRateLimitOrBudget: true,
        isSandboxed: true
      }
    ];

    const report = engine.analyzeTools('run-e37-003', tools);

    expect(report.findings.length).toBe(0);
    expect(report.allowedTools).toContain('github_issue_reader');
    expect(report.leastPrivilegeScore).toBe(1.0);
    expect(report.status).toBe('COMPLIANT');
  });
});
