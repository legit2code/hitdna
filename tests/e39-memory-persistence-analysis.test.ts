import { describe, it, expect } from 'vitest';
import { 
  MemoryPersistenceAnalysisEngine, 
  MemoryStoreDefinition 
} from '../workers/decision/capabilities/memory-persistence.ts';

describe('E39: Memory Persistence Analysis Engine', () => {
  const engine = new MemoryPersistenceAnalysisEngine();

  it('detects unencrypted storage holding PII and missing multi-tenant user isolation', () => {
    const stores: MemoryStoreDefinition[] = [
      {
        storeId: 'vector_index_users',
        storeType: 'VECTOR_DB',
        isEncryptedAtRest: false,
        hasTtlOrRetentionPolicy: true,
        retentionPeriodDays: 30,
        supportsUserIsolation: false, // Critical cross-tenant leakage vulnerability
        supportsRightToBeForgotten: true,
        storesSensitivePiiOrTokens: true,
        observedOperations: ['READ', 'WRITE', 'SEARCH']
      },
      {
        storeId: 'local_disk_cache',
        storeType: 'LOCAL_FILE',
        isEncryptedAtRest: false,
        hasTtlOrRetentionPolicy: false,
        supportsUserIsolation: false,
        supportsRightToBeForgotten: false, // Missing GDPR right to be forgotten
        storesSensitivePiiOrTokens: true,
        observedOperations: ['WRITE', 'READ']
      }
    ];

    const report = engine.analyzeMemoryStores('run-e39-001', stores);

    expect(report.findings.some(f => f.riskType === 'UNENCRYPTED_PERSISTENT_STORAGE' && f.severity === 'CRITICAL')).toBe(true);
    expect(report.findings.some(f => f.riskType === 'MISSING_USER_ISOLATION_KEY' && f.severity === 'CRITICAL')).toBe(true);
    expect(report.findings.some(f => f.riskType === 'NO_RIGHT_TO_BE_FORGOTTEN_SUPPORT')).toBe(true);
    expect(report.quarantinedStores).toContain('vector_index_users');
    expect(report.quarantinedStores).toContain('local_disk_cache');
    expect(report.isCompliantWithPrivacyStandards).toBe(false);
  });

  it('detects missing data retention policies leading to permanent storage buildup', () => {
    const stores: MemoryStoreDefinition[] = [
      {
        storeId: 'redis_session_history',
        storeType: 'REDIS_KV',
        isEncryptedAtRest: true,
        hasTtlOrRetentionPolicy: false, // No TTL
        supportsUserIsolation: true,
        supportsRightToBeForgotten: true,
        storesSensitivePiiOrTokens: false,
        observedOperations: ['READ', 'WRITE']
      }
    ];

    const report = engine.analyzeMemoryStores('run-e39-002', stores);

    expect(report.findings.some(f => f.riskType === 'MISSING_DATA_RETENTION_POLICY')).toBe(true);
  });

  it('validates compliant, encrypted, isolated, ephemeral memory architecture', () => {
    const stores: MemoryStoreDefinition[] = [
      {
        storeId: 'isolated_vault_vector_db',
        storeType: 'VECTOR_DB',
        isEncryptedAtRest: true,
        hasTtlOrRetentionPolicy: true,
        retentionPeriodDays: 14,
        supportsUserIsolation: true,
        supportsRightToBeForgotten: true,
        storesSensitivePiiOrTokens: true,
        observedOperations: ['SEARCH', 'APPEND', 'DELETE']
      }
    ];

    const report = engine.analyzeMemoryStores('run-e39-003', stores);

    expect(report.findings.length).toBe(0);
    expect(report.safeStores).toContain('isolated_vault_vector_db');
    expect(report.privacyComplianceScore).toBe(1.0);
    expect(report.isCompliantWithPrivacyStandards).toBe(true);
  });
});
