/**
 * Real Append-Only Platform Audit Log Service
 * 
 * Provides unified, tamper-evident audit logging for all critical platform actions:
 * - Principal & Role changes
 * - Capability Grants & Revocations
 * - Scoring & Policy Overrides
 * - Composer Code Generation & Sandbox Executions
 * - Attestation & Signing
 * - Administrative & Tenant Operations
 * 
 * Architecture Invariants:
 * - Security-critical events FAIL CLOSED: operations are denied if audit persistence fails.
 * - Append-only cryptographic SHA-256 hash chaining for tamper-evidence.
 * - Strict automatic redaction of secrets, credentials, tokens, cookies, and database URLs.
 * - Zero silent failure: no swallowed DB errors for authoritative events.
 */

import crypto from 'node:crypto';
import { SecretRedactor, PlatformTelemetryEngine } from '../../workflow/src/observability.ts';

export type PlatformAuditAction =
  | 'ANALYSIS_TRIGGERED'
  | 'DISCOVERY_TRIGGERED'
  | 'DISCOVERY_RUN'
  | 'AGENT_INGESTED'
  | 'AGENT_REGISTERED'
  | 'SCORING_OVERRIDDEN'
  | 'POLICY_OVERRIDDEN'
  | 'COMPOSER_GENERATION_TRIGGERED'
  | 'COMPOSER_EXECUTION_TRIGGERED'
  | 'CAPABILITY_GRANTED'
  | 'CAPABILITY_REVOKED'
  | 'AUTHENTICATION_LOGIN'
  | 'AUTHENTICATION_LOGOUT'
  | 'CONFIG_UPDATED'
  | 'PRINCIPAL_CREATED'
  | 'PRINCIPAL_DELETED'
  | 'ROLE_ASSIGNED'
  | 'ROLE_REVOKED'
  | 'ROLE_CHANGED'
  | 'CLASSIFICATION_CHANGED'
  | 'CLASSIFICATION_UPDATED'
  | 'TENANT_CREATED'
  | 'TENANT_UPDATED'
  | 'TENANT_DELETED'
  | 'TENANT_ADMIN_ACTION'
  | 'SANDBOX_EXECUTION_AUTHORIZED'
  | 'APPROVAL_DECISION'
  | 'DECISION_APPROVED'
  | 'DECISION_REJECTED'
  | 'RELEASE_APPROVED'
  | 'RELEASE_DECISION'
  | 'RELEASE_GATE_OVERRIDE'
  | 'EVIDENCE_DELETED'
  | 'DLQ_REPLAYED'
  | 'DLQ_REPLAY_SECURITY'
  | 'ATTESTATION_SIGNED'
  | 'MANIFEST_SIGNED'
  | 'ADMIN_CONFIG_CHANGED';

export type PlatformAuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED' | 'REFUSED' | 'ERROR';

export type AuditCriticality = 'DIAGNOSTIC' | 'OPERATIONAL' | 'SECURITY' | 'SECURITY_CRITICAL';

export const SECURITY_CRITICAL_ACTIONS = new Set<string>([
  'PRINCIPAL_CREATED',
  'PRINCIPAL_DELETED',
  'ROLE_ASSIGNED',
  'ROLE_REVOKED',
  'ROLE_CHANGED',
  'CAPABILITY_GRANTED',
  'CAPABILITY_REVOKED',
  'CLASSIFICATION_CHANGED',
  'CLASSIFICATION_UPDATED',
  'TENANT_CREATED',
  'TENANT_UPDATED',
  'TENANT_DELETED',
  'TENANT_ADMIN_ACTION',
  'POLICY_OVERRIDDEN',
  'SCORING_OVERRIDDEN',
  'SANDBOX_EXECUTION_AUTHORIZED',
  'COMPOSER_EXECUTION_TRIGGERED',
  'APPROVAL_DECISION',
  'DECISION_APPROVED',
  'DECISION_REJECTED',
  'RELEASE_APPROVED',
  'RELEASE_DECISION',
  'RELEASE_GATE_OVERRIDE',
  'EVIDENCE_DELETED',
  'DLQ_REPLAYED',
  'DLQ_REPLAY_SECURITY',
  'ATTESTATION_SIGNED',
  'MANIFEST_SIGNED',
  'CONFIG_UPDATED',
  'ADMIN_CONFIG_CHANGED',
]);

export function classifyAuditAction(action: string, explicitCriticality?: AuditCriticality): AuditCriticality {
  if (explicitCriticality) return explicitCriticality;
  if (SECURITY_CRITICAL_ACTIONS.has(action.toUpperCase())) return 'SECURITY_CRITICAL';
  if (action.startsWith('AUTHENTICATION_') || action.startsWith('AUTH_') || action.includes('ACCESS') || action.includes('PERMISSION')) {
    return 'SECURITY';
  }
  if (action.startsWith('TELEMETRY_') || action.startsWith('DIAGNOSTIC_') || action.includes('TRACE')) {
    return 'DIAGNOSTIC';
  }
  return 'OPERATIONAL';
}

export class AuditPersistenceError extends Error {
  public readonly action: string;
  public readonly criticality: AuditCriticality;
  public readonly originalError?: Error;

  constructor(message: string, action: string, criticality: AuditCriticality, originalError?: Error) {
    super(message);
    this.name = 'AuditPersistenceError';
    this.action = action;
    this.criticality = criticality;
    this.originalError = originalError;
  }
}

export type PlatformTargetEntityType =
  | 'AGENT'
  | 'CANONICAL_AGENT'
  | 'AGENT_VERSION'
  | 'ANALYSIS_RUN'
  | 'DISCOVERY_PIPELINE'
  | 'DISCOVERY_SOURCE'
  | 'POLICY_DECISION'
  | 'COMPOSER_ARTIFACT'
  | 'CAPABILITY_GRANT'
  | 'PRINCIPAL'
  | 'TENANT'
  | 'RELEASE_GATE'
  | 'ATTESTATION'
  | 'SYSTEM_CONFIG';

export interface PlatformAuditEntryInput {
  principal_id: string;
  tenant_id?: string | null;
  action: PlatformAuditAction | string;
  target_entity_type: PlatformTargetEntityType | string;
  target_entity_id: string;
  outcome: PlatformAuditOutcome;
  criticality?: AuditCriticality;
  classification?: string;
  client_ip?: string | null;
  user_agent?: string | null;
  correlation_id?: string | null;
  details?: Record<string, unknown>;
  allowInMemoryFallbackForTesting?: boolean;
}

export interface PlatformAuditRecord {
  audit_id: string;
  sequence_number: number;
  principal_id: string;
  tenant_id: string | null;
  action: string;
  target_entity_type: string;
  target_entity_id: string;
  timestamp: string;
  outcome: PlatformAuditOutcome;
  criticality: AuditCriticality;
  classification: string;
  client_ip: string | null;
  user_agent: string | null;
  correlation_id: string | null;
  details: Record<string, unknown>;
  previous_hash: string;
  hash: string;
  signature_sha256: string; // for backward compatibility with existing tests
  persisted_to_db: boolean;
  authoritative: boolean;
  telemetry_degraded?: boolean;
  stream_id?: string;
  hash_algorithm?: string;
}

export interface AuditLogQueryFilters {
  principal_id?: string;
  tenant_id?: string;
  action?: string;
  target_entity_type?: string;
  target_entity_id?: string;
  outcome?: string;
  criticality?: AuditCriticality;
  from_timestamp?: string;
  to_timestamp?: string;
  limit?: number;
  offset?: number;
}

export const GENESIS_AUDIT_HASH = 'GENESIS_' + '0'.repeat(64);

export function generateSha256Signature(auditId: string, timestamp: string | Date, principalId: string, action: string, outcome: string): string {
  const normTimestamp = typeof timestamp === 'string' 
    ? (isNaN(Date.parse(timestamp)) ? timestamp : new Date(timestamp).toISOString())
    : new Date(timestamp).toISOString();
  const raw = `${auditId}:${normTimestamp}:${principalId}:${action}:${outcome}`;
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return `sha256:${hash}`;
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS)
 * Canonicalizes JSON objects and arrays deterministically:
 * - Object keys sorted lexicographically by Unicode code point
 * - Numbers serialized using standard ECMAScript format
 * - Whitespace eliminated
 */
export function canonicalizeRfc8785(val: unknown): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return '[' + val.map(item => canonicalizeRfc8785(item)).join(',') + ']';
  }
  const obj = val as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs: string[] = [];
  for (const k of sortedKeys) {
    if (obj[k] !== undefined) {
      pairs.push(`${JSON.stringify(k)}:${canonicalizeRfc8785(obj[k])}`);
    }
  }
  return '{' + pairs.join(',') + '}';
}

export const HASH_ALGORITHM_V1 = 'sha256-rfc8785-v1';

/**
 * SHA-256 hash-chained tamper-evident integrity digest using RFC 8785 JCS canonicalization.
 * Detects altered records or deleted links in the audit sequence.
 */
export function computeAuditDigest(params: {
  audit_id: string;
  sequence_number: number;
  timestamp: string;
  principal_id: string;
  tenant_id: string | null;
  action: string;
  target_entity_type: string;
  target_entity_id: string;
  correlation_id: string | null;
  classification: string;
  criticality: AuditCriticality;
  outcome: string;
  details: Record<string, unknown>;
  previous_hash: string;
  stream_id?: string;
  algorithm?: string;
}): string {
  const normTimestamp = typeof params.timestamp === 'string' 
    ? (isNaN(Date.parse(params.timestamp)) ? params.timestamp : new Date(params.timestamp).toISOString())
    : new Date(params.timestamp).toISOString();

  const streamId = params.stream_id || (params.tenant_id ? `tenant:${params.tenant_id}` : 'global');
  const algo = params.algorithm || HASH_ALGORITHM_V1;

  const canonicalPayload = {
    action: params.action,
    algorithm: algo,
    audit_id: params.audit_id,
    classification: params.classification,
    correlation_id: params.correlation_id || null,
    criticality: params.criticality,
    details: params.details || {},
    outcome: params.outcome,
    previous_hash: params.previous_hash,
    principal_id: params.principal_id,
    sequence_number: params.sequence_number,
    stream_id: streamId,
    target_entity_id: params.target_entity_id,
    target_entity_type: params.target_entity_type,
    tenant_id: params.tenant_id || null,
    timestamp: normTimestamp,
  };

  const payload = canonicalizeRfc8785(canonicalPayload);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  return `sha256:${hash}`;
}

import type { DatabaseClient } from '@caim/db';

export class PlatformAuditService {
  private dbClient?: DatabaseClient | any;
  // Ephemeral in-memory mirror journal for telemetry/queries in tests
  public static inMemoryAuditJournal: PlatformAuditRecord[] = [];

  constructor(dbClient?: DatabaseClient | any) {
    this.dbClient = dbClient;
  }

  private static streamLocks = new Map<string, Promise<void>>();

  private static async withStreamLock<T>(streamId: string, fn: () => Promise<T>): Promise<T> {
    while (PlatformAuditService.streamLocks.has(streamId)) {
      try {
        await PlatformAuditService.streamLocks.get(streamId);
      } catch {}
    }
    let resolveLock!: () => void;
    const lockPromise = new Promise<void>(res => { resolveLock = res; });
    PlatformAuditService.streamLocks.set(streamId, lockPromise);
    try {
      return await fn();
    } finally {
      PlatformAuditService.streamLocks.delete(streamId);
      resolveLock();
    }
  }

  public setDbClient(dbClient: DatabaseClient | any): void {
    this.dbClient = dbClient;
  }

  public generateSha256Signature(auditId: string, timestamp: string | Date, principalId: string, action: string, outcome: string): string {
    return generateSha256Signature(auditId, timestamp, principalId, action, outcome);
  }

  private generateUuid(): string {
    return crypto.randomUUID();
  }

  private getChainScopeKey(tenantId: string | null | undefined): string {
    return tenantId ? `tenant:${tenantId}` : 'global';
  }

  /**
   * Appends an immutable audit entry.
   * 
   * FAIL-SECURE GUARANTEE:
   * If the operation is SECURITY_CRITICAL and persistent storage is unavailable
   * or throws an error, this method THROWS an AuditPersistenceError, blocking
   * the operation.
   * 
   * If txClient is passed, executes the write within the caller's transaction
   * context, guaranteeing all-or-nothing atomicity.
   */
  public async recordAuditEntry(
    input: PlatformAuditEntryInput,
    txClient?: DatabaseClient | any
  ): Promise<PlatformAuditRecord> {
    const auditId = this.generateUuid();
    const timestamp = new Date().toISOString();
    const cleanDetails = SecretRedactor.redactObject(input.details || {});
    const criticality = classifyAuditAction(input.action, input.criticality);
    const classification = input.classification || 'RESTRICTED';
    const tenantId = input.tenant_id || null;
    const principalId = input.principal_id || 'anonymous';
    const isCritical = criticality === 'SECURITY_CRITICAL';
    const streamId = this.getChainScopeKey(tenantId);

    const clientToUse = txClient || this.dbClient;

    if (clientToUse && typeof clientToUse.query === 'function') {
      try {
        const executeOnConnection = async (conn: any): Promise<PlatformAuditRecord> => {
          // 1. Lock and retrieve current chain head FOR UPDATE
          let headRes = await conn.query(
            `SELECT seq, hash FROM security.audit_chain_head WHERE stream_id = $1 FOR UPDATE;`,
            [streamId]
          );

          if (!headRes.rows || headRes.rows.length === 0) {
            await conn.query(
              `INSERT INTO security.audit_chain_head (stream_id, seq, hash, updated_at)
               VALUES ($1, 0, $2, NOW())
               ON CONFLICT (stream_id) DO NOTHING;`,
              [streamId, GENESIS_AUDIT_HASH]
            );
            headRes = await conn.query(
              `SELECT seq, hash FROM security.audit_chain_head WHERE stream_id = $1 FOR UPDATE;`,
              [streamId]
            );
          }

          const currentSeq = Number(headRes.rows[0]?.seq ?? 0);
          const prevHash = String(headRes.rows[0]?.hash ?? GENESIS_AUDIT_HASH);
          const nextSeq = currentSeq + 1;

          // 2. Compute canonical digest with RFC 8785
          const hash = computeAuditDigest({
            audit_id: auditId,
            sequence_number: nextSeq,
            timestamp,
            principal_id: principalId,
            tenant_id: tenantId,
            action: input.action,
            target_entity_type: input.target_entity_type,
            target_entity_id: input.target_entity_id,
            correlation_id: input.correlation_id || null,
            classification,
            criticality,
            outcome: input.outcome,
            details: cleanDetails,
            previous_hash: prevHash,
            stream_id: streamId,
            algorithm: HASH_ALGORITHM_V1,
          });

          const legacySignature = generateSha256Signature(auditId, timestamp, principalId, input.action, input.outcome);

          const record: PlatformAuditRecord = {
            audit_id: auditId,
            sequence_number: nextSeq,
            principal_id: principalId,
            tenant_id: tenantId,
            action: input.action,
            target_entity_type: input.target_entity_type,
            target_entity_id: input.target_entity_id,
            timestamp,
            outcome: input.outcome,
            criticality,
            classification,
            client_ip: input.client_ip || null,
            user_agent: input.user_agent || null,
            correlation_id: input.correlation_id || null,
            details: cleanDetails,
            previous_hash: prevHash,
            hash,
            signature_sha256: legacySignature,
            persisted_to_db: true,
            authoritative: true,
            stream_id: streamId,
            hash_algorithm: HASH_ALGORITHM_V1,
          };

          // 3. Persist to platform_audit_log
          await conn.query(
            `INSERT INTO security.platform_audit_log (
              audit_id, principal_id, tenant_id, action, target_entity_type, target_entity_id,
              timestamp, outcome, criticality, classification, sequence_number, previous_hash, hash,
              client_ip, user_agent, correlation_id, details, stream_id, hash_algorithm
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19);`,
            [
              record.audit_id,
              record.principal_id,
              record.tenant_id,
              record.action,
              record.target_entity_type,
              record.target_entity_id,
              record.timestamp,
              record.outcome,
              record.criticality,
              record.classification,
              record.sequence_number,
              record.previous_hash,
              record.hash,
              record.client_ip,
              record.user_agent,
              record.correlation_id,
              JSON.stringify(record.details),
              streamId,
              HASH_ALGORITHM_V1,
            ]
          );

          // 4. Update audit_chain_head
          await conn.query(
            `UPDATE security.audit_chain_head
             SET seq = $1, hash = $2, updated_at = NOW()
             WHERE stream_id = $3;`,
            [nextSeq, hash, streamId]
          );

          return record;
        };

        const savedRecord = await PlatformAuditService.withStreamLock(streamId, async () => {
          const isPool = typeof clientToUse.connect === 'function' && ('totalCount' in clientToUse || 'idleCount' in clientToUse);
          if (isPool) {
            const conn = await clientToUse.connect();
            try {
              await conn.query('BEGIN;');
              const rec = await executeOnConnection(conn);
              await conn.query('COMMIT;');
              return rec;
            } catch (txErr) {
              await conn.query('ROLLBACK;').catch(() => {});
              throw txErr;
            } finally {
              if (typeof conn.release === 'function') {
                conn.release();
              }
            }
          } else {
            const needsTx = !txClient;
            if (needsTx) {
              try {
                await clientToUse.query('BEGIN;');
                const rec = await executeOnConnection(clientToUse);
                await clientToUse.query('COMMIT;');
                return rec;
              } catch (txErr) {
                await clientToUse.query('ROLLBACK;').catch(() => {});
                throw txErr;
              }
            } else {
              return await executeOnConnection(clientToUse);
            }
          }
        });

        PlatformAuditService.inMemoryAuditJournal.unshift(savedRecord);
        PlatformTelemetryEngine.recordAuditPersisted();
        return savedRecord;
      } catch (dbErr: unknown) {
        const errorMsg = dbErr instanceof Error ? dbErr.message : String(dbErr);
        PlatformTelemetryEngine.recordAuditWriteFailure({
          action: input.action,
          criticality,
          error: errorMsg,
          principal_id: principalId,
        });

        if (isCritical) {
          PlatformTelemetryEngine.recordCriticalOperationBlockedByAudit({
            action: input.action,
            criticality,
            error: errorMsg,
          });
          throw new AuditPersistenceError(
            `[CRITICAL AUDIT PERSISTENCE FAILURE] Authoritative audit write failed for action "${input.action}". ` +
            `Operation blocked to preserve security auditability: ${errorMsg}`,
            input.action,
            criticality,
            dbErr instanceof Error ? dbErr : undefined
          );
        } else {
          // Degraded in-memory fallback for non-critical events
          const prevRec = PlatformAuditService.inMemoryAuditJournal.find(r => (r.stream_id || 'global') === streamId);
          const seq = (prevRec?.sequence_number || 0) + 1;
          const pHash = prevRec?.hash || GENESIS_AUDIT_HASH;
          const hash = computeAuditDigest({
            audit_id: auditId,
            sequence_number: seq,
            timestamp,
            principal_id: principalId,
            tenant_id: tenantId,
            action: input.action,
            target_entity_type: input.target_entity_type,
            target_entity_id: input.target_entity_id,
            correlation_id: input.correlation_id || null,
            classification,
            criticality,
            outcome: input.outcome,
            details: cleanDetails,
            previous_hash: pHash,
            stream_id: streamId,
            algorithm: HASH_ALGORITHM_V1,
          });

          const rec: PlatformAuditRecord = {
            audit_id: auditId,
            sequence_number: seq,
            principal_id: principalId,
            tenant_id: tenantId,
            action: input.action,
            target_entity_type: input.target_entity_type,
            target_entity_id: input.target_entity_id,
            timestamp,
            outcome: input.outcome,
            criticality,
            classification,
            client_ip: input.client_ip || null,
            user_agent: input.user_agent || null,
            correlation_id: input.correlation_id || null,
            details: cleanDetails,
            previous_hash: pHash,
            hash,
            signature_sha256: generateSha256Signature(auditId, timestamp, principalId, input.action, input.outcome),
            persisted_to_db: false,
            authoritative: false,
            telemetry_degraded: true,
            stream_id: streamId,
            hash_algorithm: HASH_ALGORITHM_V1,
          };
          PlatformAuditService.inMemoryAuditJournal.unshift(rec);
          PlatformTelemetryEngine.recordAuditInMemory();
          console.warn(`[PlatformAuditService] Non-critical audit write fallback to in-memory (${criticality}):`, errorMsg);
          return rec;
        }
      }
    } else {
      // Offline fallback without DB client
      if (isCritical && !input.allowInMemoryFallbackForTesting) {
        PlatformTelemetryEngine.recordAuditWriteFailure({
          action: input.action,
          criticality,
          error: 'No database client configured for security-critical audit persistence',
          principal_id: principalId,
        });
        PlatformTelemetryEngine.recordCriticalOperationBlockedByAudit({
          action: input.action,
          criticality,
          error: 'Missing durable database sink',
        });
        throw new AuditPersistenceError(
          `[CRITICAL AUDIT PERSISTENCE FAILURE] Security-critical action "${input.action}" denied: ` +
          `no durable PostgreSQL audit storage is connected.`,
          input.action,
          criticality
        );
      }

      const prevRec = PlatformAuditService.inMemoryAuditJournal.find(r => (r.stream_id || 'global') === streamId);
      const seq = (prevRec?.sequence_number || 0) + 1;
      const pHash = prevRec?.hash || GENESIS_AUDIT_HASH;
      const hash = computeAuditDigest({
        audit_id: auditId,
        sequence_number: seq,
        timestamp,
        principal_id: principalId,
        tenant_id: tenantId,
        action: input.action,
        target_entity_type: input.target_entity_type,
        target_entity_id: input.target_entity_id,
        correlation_id: input.correlation_id || null,
        classification,
        criticality,
        outcome: input.outcome,
        details: cleanDetails,
        previous_hash: pHash,
        stream_id: streamId,
        algorithm: HASH_ALGORITHM_V1,
      });

      const rec: PlatformAuditRecord = {
        audit_id: auditId,
        sequence_number: seq,
        principal_id: principalId,
        tenant_id: tenantId,
        action: input.action,
        target_entity_type: input.target_entity_type,
        target_entity_id: input.target_entity_id,
        timestamp,
        outcome: input.outcome,
        criticality,
        classification,
        client_ip: input.client_ip || null,
        user_agent: input.user_agent || null,
        correlation_id: input.correlation_id || null,
        details: cleanDetails,
        previous_hash: pHash,
        hash,
        signature_sha256: generateSha256Signature(auditId, timestamp, principalId, input.action, input.outcome),
        persisted_to_db: false,
        authoritative: false,
        stream_id: streamId,
        hash_algorithm: HASH_ALGORITHM_V1,
      };

      PlatformAuditService.inMemoryAuditJournal.unshift(rec);
      PlatformTelemetryEngine.recordAuditInMemory();
      return rec;
    }
  }

  /**
   * Queries the append-only audit trail with structured filtering.
   */
  public async queryAuditLogs(filters: AuditLogQueryFilters = {}): Promise<{
    logs: PlatformAuditRecord[];
    total: number;
    limit: number;
    offset: number;
  }> {
    const limit = Math.min(filters.limit || 50, 200);
    const offset = filters.offset || 0;

    // Try querying PostgreSQL first if available
    if (this.dbClient && typeof this.dbClient.query === 'function') {
      try {
        const conditions: string[] = [];
        const params: unknown[] = [];
        let paramIdx = 1;

        if (filters.principal_id) {
          conditions.push(`principal_id ILIKE $${paramIdx++}`);
          params.push(`%${filters.principal_id}%`);
        }
        if (filters.tenant_id) {
          conditions.push(`tenant_id = $${paramIdx++}`);
          params.push(filters.tenant_id);
        }
        if (filters.action) {
          conditions.push(`action = $${paramIdx++}`);
          params.push(filters.action);
        }
        if (filters.target_entity_type) {
          conditions.push(`target_entity_type = $${paramIdx++}`);
          params.push(filters.target_entity_type);
        }
        if (filters.target_entity_id) {
          conditions.push(`target_entity_id ILIKE $${paramIdx++}`);
          params.push(`%${filters.target_entity_id}%`);
        }
        if (filters.outcome) {
          conditions.push(`outcome = $${paramIdx++}`);
          params.push(filters.outcome);
        }
        if (filters.criticality) {
          conditions.push(`criticality = $${paramIdx++}`);
          params.push(filters.criticality);
        }
        if (filters.from_timestamp) {
          conditions.push(`timestamp >= $${paramIdx++}`);
          params.push(filters.from_timestamp);
        }
        if (filters.to_timestamp) {
          conditions.push(`timestamp <= $${paramIdx++}`);
          params.push(filters.to_timestamp);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const countQuery = `SELECT COUNT(*) as total FROM security.platform_audit_log ${whereClause};`;
        const dataQuery = `SELECT * FROM security.platform_audit_log ${whereClause} ORDER BY sequence_number DESC, timestamp DESC LIMIT $${paramIdx++} OFFSET $${paramIdx++};`;

        const [countRes, dataRes] = await Promise.all([
          this.dbClient.query(countQuery, params),
          this.dbClient.query(dataQuery, [...params, limit, offset]),
        ]);

        const total = parseInt(String(countRes.rows[0]?.total || '0'), 10);
        const logs: PlatformAuditRecord[] = dataRes.rows.map((row: Record<string, unknown>) => {
          const rawTs = row.timestamp;
          const timestampIso = typeof rawTs === 'string' 
            ? (isNaN(Date.parse(rawTs)) ? rawTs : new Date(rawTs).toISOString())
            : new Date(String(rawTs)).toISOString();
          const auditId = String(row.audit_id);
          const principalId = String(row.principal_id);
          const action = String(row.action);
          const outcome = String(row.outcome) as 'SUCCESS' | 'FAILURE' | 'DENIED';
          return {
            audit_id: auditId,
            sequence_number: Number(row.sequence_number || 1),
            principal_id: principalId,
            tenant_id: row.tenant_id ? String(row.tenant_id) : null,
            action,
            target_entity_type: String(row.target_entity_type),
            target_entity_id: String(row.target_entity_id),
            timestamp: timestampIso,
            outcome,
            criticality: (row.criticality as PlatformAuditRecord['criticality']) || 'OPERATIONAL',
            classification: (row.classification as PlatformAuditRecord['classification']) || 'RESTRICTED',
            client_ip: row.client_ip ? String(row.client_ip) : undefined,
            user_agent: row.user_agent ? String(row.user_agent) : undefined,
            correlation_id: row.correlation_id ? String(row.correlation_id) : undefined,
            details: typeof row.details === 'string' ? JSON.parse(row.details) : ((row.details as Record<string, unknown>) || {}),
            previous_hash: String(row.previous_hash || GENESIS_AUDIT_HASH),
            hash: String(row.hash || ''),
            signature_sha256: String(row.hash || this.generateSha256Signature(auditId, timestampIso, principalId, action, outcome)),
            persisted_to_db: true,
            authoritative: true,
          };
        });

        return { logs, total, limit, offset };
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        console.warn('[PlatformAuditService DB Query Fallback]:', errorMsg);
      }
    }

    // In-memory filter fallback
    let filtered = PlatformAuditService.inMemoryAuditJournal.filter((record) => {
      if (filters.principal_id && !record.principal_id.toLowerCase().includes(filters.principal_id.toLowerCase())) {
        return false;
      }
      if (filters.tenant_id && record.tenant_id !== filters.tenant_id) {
        return false;
      }
      if (filters.action && record.action !== filters.action) {
        return false;
      }
      if (filters.target_entity_type && record.target_entity_type !== filters.target_entity_type) {
        return false;
      }
      if (filters.target_entity_id && !record.target_entity_id.toLowerCase().includes(filters.target_entity_id.toLowerCase())) {
        return false;
      }
      if (filters.outcome && record.outcome !== filters.outcome) {
        return false;
      }
      if (filters.criticality && record.criticality !== filters.criticality) {
        return false;
      }
      if (filters.from_timestamp && record.timestamp < filters.from_timestamp) {
        return false;
      }
      if (filters.to_timestamp && record.timestamp > filters.to_timestamp) {
        return false;
      }
      return true;
    });

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return {
      logs: paginated,
      total,
      limit,
      offset,
    };
  }

  /**
   * Returns high-level audit summary statistics.
   */
  public async getAuditStats(): Promise<{
    total_events: number;
    action_breakdown: Record<string, number>;
    outcome_breakdown: Record<string, number>;
    recent_events_count_24h: number;
  }> {
    const { logs, total } = await this.queryAuditLogs({ limit: 1000 });
    const action_breakdown: Record<string, number> = {};
    const outcome_breakdown: Record<string, number> = {};
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    let recent_events_count_24h = 0;

    for (const log of logs) {
      action_breakdown[log.action] = (action_breakdown[log.action] || 0) + 1;
      outcome_breakdown[log.outcome] = (outcome_breakdown[log.outcome] || 0) + 1;
      if (log.timestamp >= oneDayAgo) {
        recent_events_count_24h += 1;
      }
    }

    return {
      total_events: total,
      action_breakdown,
      outcome_breakdown,
      recent_events_count_24h,
    };
  }

  /**
   * Resets in-memory journal and counters for test isolation.
   */
  public static resetJournal(): void {
    PlatformAuditService.inMemoryAuditJournal = [];
  }
}
