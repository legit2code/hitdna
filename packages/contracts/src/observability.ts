/**
 * CAIM Observability, Telemetry, Audit & Cost Contracts
 * Specification conforming to P30 requirements
 */

export type SpanKind = 'INTERNAL' | 'SERVER' | 'CLIENT' | 'PRODUCER' | 'CONSUMER';
export type SpanStatusCode = 'UNSET' | 'OK' | 'ERROR';

export interface SpanEvent {
  name: string;
  timestamp: string;
  attributes?: Record<string, string | number | boolean | null>;
}

export interface TelemetrySpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: SpanKind;
  statusCode: SpanStatusCode;
  statusMessage?: string;
  startTime: string; // ISO string or timestamp
  endTime?: string;
  durationMs?: number;
  attributes: Record<string, string | number | boolean | null | undefined>;
  events: SpanEvent[];
  // CAIM Correlation Context Linkage
  correlation: CorrelationContext;
}

export interface CorrelationContext {
  traceId: string;
  requestId: string;
  spanId?: string;
  workflowRunId?: string;
  stageRunId?: string;
  jobId?: string;
  agentId?: string;
  versionId?: string;
  actorId?: string;
  serviceId?: string;
  causationId?: string;
}

export type AuditActorType = 'USER' | 'SERVICE' | 'SYSTEM' | 'VAULT' | 'KMS_ENCLAVE';

export type AuditActionType =
  | 'AUTH_LOGIN'
  | 'AUTH_TOKEN_REFRESH'
  | 'VAULT_SECRET_ACCESS'
  | 'VAULT_SECRET_ROTATED'
  | 'POLICY_OVERRIDE_REQUESTED'
  | 'POLICY_OVERRIDE_APPROVED'
  | 'POLICY_OVERRIDE_REJECTED'
  | 'MODIFICATION_PATCH_PROPOSED'
  | 'MODIFICATION_DUAL_APPROVED'
  | 'PACKAGE_SIGNED_KMS'
  | 'BUNDLE_SHIPPED_PROD'
  | 'SANDBOX_EVASION_TRIPPED'
  | 'DLQ_JOB_REPLAYED'
  | 'CONFIG_UPDATED';

export interface AuditEventRecord {
  auditId: string;
  timestamp: string;
  actorType: AuditActorType;
  actorId: string;
  actorIp?: string;
  action: AuditActionType;
  targetType: string;
  targetId: string;
  correlation: CorrelationContext;
  status: 'SUCCESS' | 'DENIED' | 'FAILURE';
  details: Record<string, unknown>;
  redactedFields: string[];
  signatureSha256: string;
}

export interface RedactionResult {
  sanitizedText: string;
  redactionsCount: number;
  detectedCategories: string[];
}

export interface MetricDistribution {
  p50: number;
  p90: number;
  p95: number;
  p99: number;
  avg: number;
  min: number;
  max: number;
  count: number;
}

export interface CostAttribution {
  computeCostUsd: number;
  geminiTokenCostUsd: number;
  sandboxCostUsd: number;
  storageCostUsd: number;
  totalCostUsd: number;
  promptTokens: number;
  candidateTokens: number;
  cachedTokens: number;
}

export interface AlertCondition {
  id: string;
  name: string;
  category: 'LATENCY' | 'DLQ' | 'SECURITY' | 'COST' | 'CAPACITY' | 'SANDBOX';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  metricKey: string;
  operator: 'GT' | 'LT' | 'EQ' | 'GTE' | 'LTE';
  threshold: number;
  unit: string;
  currentValue: number;
  status: 'FIRING' | 'RESOLVED' | 'MUTED';
  triggeredAt?: string;
  description: string;
}

export interface CapacityMetric {
  resource: string;
  pool: string;
  allocated: number;
  capacity: number;
  utilizationPct: number;
  status: 'HEALTHY' | 'WARN' | 'SATURATED';
  rateLimitPerMin?: number;
  consumedPerMin?: number;
}
