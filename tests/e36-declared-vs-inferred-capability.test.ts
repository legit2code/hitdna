import { describe, it, expect } from 'vitest';
import { 
  DeclaredVsInferredCapabilityEngine, 
  DeclaredCapability, 
  InferredCapability 
} from '../workers/decision/capabilities/declared-vs-inferred.ts';

describe('E36: Declared vs Inferred Capability Engine', () => {
  const engine = new DeclaredVsInferredCapabilityEngine();

  it('detects undeclared high-risk capabilities present in AST execution', () => {
    const declared: DeclaredCapability[] = [
      { name: 'read_metrics', category: 'FILESYSTEM', scope: ['/var/log/app'] }
    ];

    const inferred: InferredCapability[] = [
      {
        name: 'read_metrics',
        category: 'FILESYSTEM',
        confidence: 0.95,
        evidenceSource: 'ast_fs_read',
        extractedSymbols: ['fs.readFileSync'],
        scope: ['/var/log/app']
      },
      {
        name: 'raw_socket_egress',
        category: 'NETWORK',
        confidence: 0.98,
        evidenceSource: 'ast_net_socket',
        extractedSymbols: ['net.createConnection', 'process.env.EXFIL_TARGET'],
        scope: ['tcp://*']
      }
    ];

    const report = engine.reconcile('run-e36-001', 'agent-financial-analyst', declared, inferred);

    expect(report.matchedCount).toBe(1);
    expect(report.undeclaredCapabilities.length).toBe(1);
    expect(report.undeclaredCapabilities[0].name).toBe('raw_socket_egress');
    expect(report.discrepancies.some(d => d.discrepancyType === 'UNDECLARED_CAPABILITY' && d.severity === 'CRITICAL')).toBe(true);
    expect(report.riskLevel).toBe('CRITICAL');
  });

  it('detects overdeclared phantom capabilities absent from implementation', () => {
    const declared: DeclaredCapability[] = [
      { name: 'read_metrics', category: 'FILESYSTEM' },
      { name: 'hardware_security_module_signing', category: 'AUTH' }
    ];

    const inferred: InferredCapability[] = [
      {
        name: 'read_metrics',
        category: 'FILESYSTEM',
        confidence: 0.9,
        evidenceSource: 'ast_fs_read',
        extractedSymbols: ['fs.readFileSync']
      }
    ];

    const report = engine.reconcile('run-e36-002', 'agent-crypto-signer', declared, inferred);

    expect(report.overdeclaredCapabilities.length).toBe(1);
    expect(report.overdeclaredCapabilities[0].name).toBe('hardware_security_module_signing');
    expect(report.discrepancies.some(d => d.discrepancyType === 'OVERDECLARED_CAPABILITY')).toBe(true);
  });

  it('flags scope escalation when inferred scope exceeds declared scope bounds', () => {
    const declared: DeclaredCapability[] = [
      { name: 'file_read', category: 'FILESYSTEM', scope: ['/app/data'] }
    ];

    const inferred: InferredCapability[] = [
      {
        name: 'file_read',
        category: 'FILESYSTEM',
        confidence: 0.99,
        evidenceSource: 'ast_fs_access',
        extractedSymbols: ['fs.readFile'],
        scope: ['/app/data', '/etc/shadow']
      }
    ];

    const report = engine.reconcile('run-e36-003', 'agent-crawler', declared, inferred);

    expect(report.discrepancies.some(d => d.discrepancyType === 'SCOPE_ESCALATION')).toBe(true);
    expect(report.discrepancies.find(d => d.discrepancyType === 'SCOPE_ESCALATION')?.severity).toBe('HIGH');
  });

  it('confirms clean reconciliation score when declared and inferred capabilities match identically', () => {
    const declared: DeclaredCapability[] = [
      { name: 'http_get', category: 'NETWORK', scope: ['https://api.github.com'] },
      { name: 'parse_json', category: 'EXECUTION', scope: ['memory'] }
    ];

    const inferred: InferredCapability[] = [
      {
        name: 'http_get',
        category: 'NETWORK',
        confidence: 0.95,
        evidenceSource: 'ast_fetch',
        extractedSymbols: ['fetch'],
        scope: ['https://api.github.com']
      },
      {
        name: 'parse_json',
        category: 'EXECUTION',
        confidence: 0.99,
        evidenceSource: 'ast_json_parse',
        extractedSymbols: ['JSON.parse'],
        scope: ['memory']
      }
    ];

    const report = engine.reconcile('run-e36-004', 'agent-clean', declared, inferred);

    expect(report.matchedCount).toBe(2);
    expect(report.discrepancies.length).toBe(0);
    expect(report.reconciliationScore).toBe(1.0);
    expect(report.riskLevel).toBe('CLEAN');
  });
});
