/**
 * E39: Memory Persistence Analysis Engine
 * Architecture V2.0.1 - Capability Analysis Subsystem
 *
 * Scans agent memory architectures, state stores, vector indices, conversation history
 * buffers, and caching layers for privacy risks, cross-session leakage, insecure persistence,
 * and lack of retention/forgetting policies (GDPR/compliance violations).
 */

export interface MemoryStoreDefinition {
  storeId: string;
  storeType: 'VECTOR_DB' | 'REDIS_KV' | 'SQL_DATABASE' | 'LOCAL_FILE' | 'IN_MEMORY' | 'BROWSER_LOCALSTORAGE';
  isEncryptedAtRest: boolean;
  hasTtlOrRetentionPolicy: boolean;
  retentionPeriodDays?: number;
  supportsUserIsolation: boolean; // Multitenant / user_id partition
  supportsRightToBeForgotten: boolean; // Deletion by user_id
  storesSensitivePiiOrTokens: boolean;
  observedOperations: Array<'READ' | 'WRITE' | 'APPEND' | 'SEARCH' | 'DELETE' | 'EXPORT'>;
}

export type MemoryPersistenceRiskType =
  | 'CROSS_SESSION_PII_LEAKAGE'
  | 'UNENCRYPTED_PERSISTENT_STORAGE'
  | 'MISSING_DATA_RETENTION_POLICY'
  | 'MISSING_USER_ISOLATION_KEY'
  | 'NO_RIGHT_TO_BE_FORGOTTEN_SUPPORT'
  | 'PERMANENT_CREDENTIAL_CACHING';

export interface MemorySecurityFinding {
  storeId: string;
  storeType: string;
  riskType: MemoryPersistenceRiskType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  remediation: string;
}

export interface MemoryPersistenceAnalysisReport {
  analysisRunId: string;
  totalStoresAnalyzed: number;
  privacyComplianceScore: number; // 0.0 to 1.0 (1.0 = fully compliant, isolated, ephemeral/encrypted)
  findings: MemorySecurityFinding[];
  isCompliantWithPrivacyStandards: boolean;
  quarantinedStores: string[];
  safeStores: string[];
}

export class MemoryPersistenceAnalysisEngine {
  public analyzeMemoryStores(
    analysisRunId: string,
    stores: MemoryStoreDefinition[]
  ): MemoryPersistenceAnalysisReport {
    const findings: MemorySecurityFinding[] = [];
    const quarantined = new Set<string>();
    const safe = new Set<string>();

    for (const store of stores) {
      let storeHasIssue = false;

      // 1. Unencrypted persistent storage containing sensitive data
      if (store.storeType !== 'IN_MEMORY' && store.storesSensitivePiiOrTokens && !store.isEncryptedAtRest) {
        findings.push({
          storeId: store.storeId,
          storeType: store.storeType,
          riskType: 'UNENCRYPTED_PERSISTENT_STORAGE',
          severity: 'CRITICAL',
          title: `Unencrypted Persistent Storage with Sensitive Data (${store.storeId})`,
          description: `Memory store '${store.storeId}' persists sensitive PII or credentials in unencrypted format.`,
          remediation: 'Enable AES-256 or KMS envelope encryption at rest for all persistent memory layers.',
        });
        storeHasIssue = true;
        quarantined.add(store.storeId);
      }

      // 2. Missing user isolation keys (Cross-session / Cross-tenant memory bleed)
      if (store.storeType !== 'IN_MEMORY' && !store.supportsUserIsolation) {
        findings.push({
          storeId: store.storeId,
          storeType: store.storeType,
          riskType: 'MISSING_USER_ISOLATION_KEY',
          severity: 'CRITICAL',
          title: `Lack of Multi-Tenant User Isolation Partitioning (${store.storeId})`,
          description: `Persistent memory layer '${store.storeId}' lacks strict user_id partitioning, creating cross-tenant conversation leakage risks.`,
          remediation: 'Enforce tenant_id and user_id scoping on all memory keys and vector similarity queries.',
        });
        storeHasIssue = true;
        quarantined.add(store.storeId);
      }

      // 3. Right to be forgotten (GDPR) missing
      if (store.storeType !== 'IN_MEMORY' && !store.supportsRightToBeForgotten) {
        findings.push({
          storeId: store.storeId,
          storeType: store.storeType,
          riskType: 'NO_RIGHT_TO_BE_FORGOTTEN_SUPPORT',
          severity: 'HIGH',
          title: `No Deletion / Right to be Forgotten Mechanism (${store.storeId})`,
          description: `Memory store '${store.storeId}' does not support user-directed purge or targeted record deletion.`,
          remediation: 'Implement user-scoped cascade deletion handlers for stored memory embeddings and conversation records.',
        });
        storeHasIssue = true;
      }

      // 4. Missing retention / TTL policy (Indefinite unbounded data hoarding)
      if (store.storeType !== 'IN_MEMORY' && !store.hasTtlOrRetentionPolicy) {
        findings.push({
          storeId: store.storeId,
          storeType: store.storeType,
          riskType: 'MISSING_DATA_RETENTION_POLICY',
          severity: 'MEDIUM',
          title: `Indefinite Data Retention Policy (${store.storeId})`,
          description: `Memory store '${store.storeId}' accumulates historical state indefinitely without automated TTL pruning.`,
          remediation: 'Configure maximum retention period (e.g. 30/90 days) or sliding window conversation eviction.',
        });
        storeHasIssue = true;
      }

      if (!storeHasIssue) {
        safe.add(store.storeId);
      }
    }

    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;

    let score = stores.length === 0 ? 1.0 : Math.max(0, 1.0 - (criticalCount * 0.45) - (highCount * 0.2) - (findings.length * 0.05));
    score = Math.round(score * 100) / 100;

    return {
      analysisRunId,
      totalStoresAnalyzed: stores.length,
      privacyComplianceScore: score,
      findings,
      isCompliantWithPrivacyStandards: criticalCount === 0 && highCount === 0,
      quarantinedStores: Array.from(quarantined),
      safeStores: Array.from(safe),
    };
  }
}
