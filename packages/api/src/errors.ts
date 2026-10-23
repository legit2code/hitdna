import { ZodError } from 'zod';
import { ApiErrorCode, ApiErrorEnvelope, createErrorEnvelope } from './envelopes.ts';

/**
 * Base Application API Error
 */
export class ApiError extends Error {
  public readonly code: ApiErrorCode;
  public readonly statusCode: number;
  public readonly retryable: boolean;
  public readonly retryAfterMs?: number;
  public readonly details?: Record<string, unknown> | Array<unknown>;

  constructor(params: {
    code: ApiErrorCode;
    message: string;
    statusCode: number;
    retryable?: boolean;
    retryAfterMs?: number;
    details?: Record<string, unknown> | Array<unknown>;
  }) {
    super(params.message);
    this.name = 'ApiError';
    this.code = params.code;
    this.statusCode = params.statusCode;
    this.retryable = params.retryable ?? false;
    this.retryAfterMs = params.retryAfterMs;
    this.details = params.details;
  }
}

export class ValidationError extends ApiError {
  constructor(message: string, details?: Record<string, unknown> | Array<unknown>) {
    super({
      code: 'VALIDATION_FAILED',
      message,
      statusCode: 400,
      retryable: false,
      details,
    });
    this.name = 'ValidationError';
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message: string = 'Authentication required', details?: Record<string, unknown>) {
    super({
      code: 'UNAUTHENTICATED',
      message,
      statusCode: 401,
      retryable: false,
      details,
    });
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends ApiError {
  constructor(message: string = 'Permission denied for requested resource or operation', details?: Record<string, unknown>) {
    super({
      code: 'FORBIDDEN',
      message,
      statusCode: 403,
      retryable: false,
      details,
    });
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends ApiError {
  constructor(resource: string, identifier?: string) {
    super({
      code: 'RESOURCE_NOT_FOUND',
      message: identifier ? `${resource} '${identifier}' not found` : `${resource} not found`,
      statusCode: 404,
      retryable: false,
      details: { resource, identifier },
    });
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends ApiError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'CONFLICT_IDEMPOTENCY',
      message,
      statusCode: 409,
      retryable: false,
      details,
    });
    this.name = 'ConflictError';
  }
}

export class PolicyBlockedError extends ApiError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'POLICY_BLOCKED',
      message,
      statusCode: 422,
      retryable: false,
      details,
    });
    this.name = 'PolicyBlockedError';
  }
}

export class PartialAnalysisError extends ApiError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'PARTIAL_ANALYSIS',
      message,
      statusCode: 422,
      retryable: false,
      details,
    });
    this.name = 'PartialAnalysisError';
  }
}

export class DependencyFailureError extends ApiError {
  constructor(serviceName: string, message: string, retryAfterMs: number = 1000) {
    super({
      code: 'DEPENDENCY_FAILURE',
      message: `Downstream dependency failure from '${serviceName}': ${message}`,
      statusCode: 503,
      retryable: true,
      retryAfterMs,
      details: { serviceName, retry_after_ms: retryAfterMs },
    });
    this.name = 'DependencyFailureError';
  }
}

export class RateLimitedError extends ApiError {
  constructor(message: string = 'Too many requests, rate limit exceeded', retryAfterMs: number = 5000) {
    super({
      code: 'RATE_LIMITED',
      message,
      statusCode: 429,
      retryable: true,
      retryAfterMs,
      details: { retry_after_ms: retryAfterMs },
    });
    this.name = 'RateLimitedError';
  }
}

/**
 * Safe Client Error Mapper
 * Strips internal stack traces, DB connection details, internal SQL queries, and produces standard error envelopes.
 */
export function mapErrorToEnvelope(
  error: unknown,
  requestId: string = `req-${crypto.randomUUID()}`
): { statusCode: number; envelope: ApiErrorEnvelope } {
  if (error instanceof ApiError) {
    return {
      statusCode: error.statusCode,
      envelope: createErrorEnvelope({
        code: error.code,
        message: error.message,
        details: sanitizeDetails(error.details),
        retryable: error.retryable,
        retry_after_ms: error.retryAfterMs,
        request_id: requestId,
      }),
    };
  }

  if (error instanceof ZodError) {
    const formattedIssues = error.issues.map((issue) => ({
      path: issue.path.join('.'),
      code: issue.code,
      message: issue.message,
    }));
    return {
      statusCode: 400,
      envelope: createErrorEnvelope({
        code: 'VALIDATION_FAILED',
        message: 'Request schema validation failed',
        details: formattedIssues,
        retryable: false,
        request_id: requestId,
      }),
    };
  }

  // Handle errors from @caim/auth or standard Error types
  if (error instanceof Error) {
    if (error.name === 'UnauthorizedAccessError' || error.name === 'UnauthorizedVaultAccessError' || error.name === 'ScopeBoundaryViolationError') {
      return {
        statusCode: 403,
        envelope: createErrorEnvelope({
          code: 'FORBIDDEN',
          message: error.message || 'Access denied by security boundary policy',
          details: sanitizeDetails((error as any).details),
          retryable: false,
          request_id: requestId,
        }),
      };
    }

    if (error.message.includes('FATAL PRODUCTION ERROR') || error.message.includes('FATAL SECURITY VIOLATION')) {
      return {
        statusCode: 500,
        envelope: createErrorEnvelope({
          code: 'INTERNAL_SERVER_ERROR',
          message: error.message,
          details: null,
          retryable: false,
          request_id: requestId,
        }),
      };
    }

    if (error.message.includes('not found') || error.message.includes('NOT_FOUND')) {
      return {
        statusCode: 404,
        envelope: createErrorEnvelope({
          code: 'RESOURCE_NOT_FOUND',
          message: error.message,
          retryable: false,
          request_id: requestId,
        }),
      };
    }

    if (error.message.includes('policy') || error.message.includes('blocked') || error.message.includes('DENY')) {
      return {
        statusCode: 422,
        envelope: createErrorEnvelope({
          code: 'POLICY_BLOCKED',
          message: error.message,
          retryable: false,
          request_id: requestId,
        }),
      };
    }

    // Default internal error sanitization
    return {
      statusCode: 500,
      envelope: createErrorEnvelope({
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred. Request has been logged.',
        details: null,
        retryable: false,
        request_id: requestId,
      }),
    };
  }

  return {
    statusCode: 500,
    envelope: createErrorEnvelope({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected non-error exception occurred',
      retryable: false,
      request_id: requestId,
    }),
  };
}

function sanitizeDetails(details: unknown): Record<string, unknown> | Array<unknown> | null {
  if (!details) return null;
  if (Array.isArray(details)) return details;
  if (typeof details === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(details)) {
      if (['password', 'secret', 'token', 'apiKey', 'connectionString', 'stack'].includes(key)) {
        continue;
      }
      sanitized[key] = value;
    }
    return sanitized;
  }
  return null;
}
