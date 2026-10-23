import { z } from 'zod';

/**
 * Architecture V2.0.1 — Standard API Error Codes & Taxonomy
 */
export const ApiErrorCodeEnum = z.enum([
  'VALIDATION_FAILED',
  'UNAUTHENTICATED',
  'FORBIDDEN',
  'RESOURCE_NOT_FOUND',
  'CONFLICT_IDEMPOTENCY',
  'POLICY_BLOCKED',
  'PARTIAL_ANALYSIS',
  'DEPENDENCY_FAILURE',
  'RATE_LIMITED',
  'INTERNAL_SERVER_ERROR',
]);
export type ApiErrorCode = z.infer<typeof ApiErrorCodeEnum>;

export interface EnvelopePaginationMeta {
  page: number;
  limit: number;
  total?: number;
  has_more?: boolean;
  cursor?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  [key: string]: unknown;
}

export interface EnvelopeMeta extends Partial<EnvelopePaginationMeta> {
  request_id: string;
  timestamp: string;
  idempotency_replayed?: boolean;
  version?: string;
  [key: string]: unknown;
}

export interface ApiSuccessEnvelope<T = unknown> {
  success: true;
  data: T;
  meta: EnvelopeMeta;
}

export interface ApiErrorDetail {
  code: ApiErrorCode;
  message: string;
  details?: Record<string, unknown> | Array<unknown> | null;
  retryable: boolean;
  retry_after_ms?: number;
  request_id: string;
  timestamp: string;
  help_url?: string;
}

export interface ApiErrorEnvelope {
  success: false;
  error: ApiErrorDetail;
}

export type ApiResponseEnvelope<T = unknown> = ApiSuccessEnvelope<T> | ApiErrorEnvelope;

/**
 * Standard Envelope Builders
 */
export function createSuccessEnvelope<T>(
  data: T,
  metaParams?: Partial<EnvelopeMeta>
): ApiSuccessEnvelope<T> {
  const now = new Date().toISOString();
  return {
    success: true,
    data,
    meta: {
      request_id: metaParams?.request_id || `req-${crypto.randomUUID()}`,
      timestamp: metaParams?.timestamp || now,
      version: metaParams?.version || '2.0.1',
      ...(metaParams || {}),
    },
  };
}

export function createErrorEnvelope(params: {
  code: ApiErrorCode;
  message: string;
  details?: Record<string, unknown> | Array<unknown> | null;
  retryable?: boolean;
  retry_after_ms?: number;
  request_id?: string;
  timestamp?: string;
  help_url?: string;
}): ApiErrorEnvelope {
  const now = new Date().toISOString();
  return {
    success: false,
    error: {
      code: params.code,
      message: params.message,
      details: params.details ?? null,
      retryable: params.retryable ?? isDefaultRetryable(params.code),
      ...(params.retry_after_ms ? { retry_after_ms: params.retry_after_ms } : {}),
      request_id: params.request_id || `req-${crypto.randomUUID()}`,
      timestamp: params.timestamp || now,
      ...(params.help_url ? { help_url: params.help_url } : {}),
    },
  };
}

export function isDefaultRetryable(code: ApiErrorCode): boolean {
  switch (code) {
    case 'DEPENDENCY_FAILURE':
    case 'RATE_LIMITED':
      return true;
    case 'PARTIAL_ANALYSIS':
    case 'VALIDATION_FAILED':
    case 'UNAUTHENTICATED':
    case 'FORBIDDEN':
    case 'RESOURCE_NOT_FOUND':
    case 'CONFLICT_IDEMPOTENCY':
    case 'POLICY_BLOCKED':
    case 'INTERNAL_SERVER_ERROR':
    default:
      return false;
  }
}
