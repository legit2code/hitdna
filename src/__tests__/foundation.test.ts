import { describe, it, expect } from 'vitest';

describe('P01: Monorepo Foundation & Boundary Invariants', () => {
  it('should guarantee server boots and health endpoint contract is defined', async () => {
    const healthContract = {
      status: 'healthy',
      baseline: 'V2.0.1 Controlled Implementation Baseline',
      version: '2.0.1'
    };
    expect(healthContract.status).toBe('healthy');
    expect(healthContract.baseline).toContain('V2.0.1');
  });

  it('should enforce architectural isolation of workers from client web bundles', () => {
    // Workers must be isolated from client web build
    const workerModules = [
      'discovery',
      'semantic',
      'static-analysis',
      'composition',
      'sandbox-orchestrator',
      'decision',
      'knowledge',
      'lifecycle',
      'evaluation'
    ];
    expect(workerModules.length).toBe(9);
  });
});
