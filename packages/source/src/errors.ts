import { SourceAuthMode, SourceAuthStatus } from './types.ts';

export class SourceAdapterError extends Error {
  readonly sourceType: string;
  readonly locator?: string;
  readonly statusCode?: number;
  readonly isRetryable: boolean;

  constructor(message: string, options: {
    sourceType: string;
    locator?: string;
    statusCode?: number;
    isRetryable?: boolean;
    cause?: unknown;
  }) {
    super(message);
    this.name = this.constructor.name;
    this.sourceType = options.sourceType;
    this.locator = options.locator;
    this.statusCode = options.statusCode;
    this.isRetryable = options.isRetryable ?? false;
    if (options.cause) {
      (this as any).cause = options.cause;
    }
  }
}

export class SourceAuthenticationError extends SourceAdapterError {
  readonly authStatus: SourceAuthStatus;

  constructor(message: string, options: {
    sourceType: string;
    locator?: string;
    statusCode?: number;
    authStatus?: SourceAuthStatus;
    cause?: unknown;
  }) {
    super(message, {
      ...options,
      statusCode: options.statusCode ?? 401,
      isRetryable: false,
    });
    this.authStatus = options.authStatus ?? 'INVALID_CREDENTIALS';
  }
}

export class SourceMissingCredentialsError extends SourceAdapterError {
  readonly authMode: SourceAuthMode;
  readonly authStatus: SourceAuthStatus;
  readonly credentialKey: string;

  constructor(message: string, options: {
    sourceType: string;
    credentialKey: string;
    authMode: SourceAuthMode;
    locator?: string;
  }) {
    super(message, {
      sourceType: options.sourceType,
      locator: options.locator,
      statusCode: 401,
      isRetryable: false,
    });
    this.credentialKey = options.credentialKey;
    this.authMode = options.authMode;
    this.authStatus = 'MISSING_CREDENTIALS';
  }
}

export class SourceRateLimitExhaustedError extends SourceAdapterError {
  readonly resetAt: string;
  readonly retryAfterSeconds: number;

  constructor(message: string, options: {
    sourceType: string;
    resetAt: string;
    retryAfterSeconds: number;
    locator?: string;
    cause?: unknown;
  }) {
    super(message, {
      sourceType: options.sourceType,
      locator: options.locator,
      statusCode: 429,
      isRetryable: true,
      cause: options.cause,
    });
    this.resetAt = options.resetAt;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export class SourceNotFoundError extends SourceAdapterError {
  constructor(message: string, options: {
    sourceType: string;
    locator: string;
    cause?: unknown;
  }) {
    super(message, {
      sourceType: options.sourceType,
      locator: options.locator,
      statusCode: 404,
      isRetryable: false,
      cause: options.cause,
    });
  }
}

export class SourceNetworkError extends SourceAdapterError {
  constructor(message: string, options: {
    sourceType: string;
    locator?: string;
    cause?: unknown;
  }) {
    super(message, {
      sourceType: options.sourceType,
      locator: options.locator,
      isRetryable: true,
      cause: options.cause,
    });
  }
}

export class SourceTransientError extends SourceAdapterError {
  constructor(message: string, options: {
    sourceType: string;
    statusCode: number;
    locator?: string;
    cause?: unknown;
  }) {
    super(message, {
      sourceType: options.sourceType,
      statusCode: options.statusCode,
      locator: options.locator,
      isRetryable: true,
      cause: options.cause,
    });
  }
}

export class SourceMalformedResponseError extends SourceAdapterError {
  constructor(message: string, options: {
    sourceType: string;
    locator?: string;
    cause?: unknown;
  }) {
    super(message, {
      sourceType: options.sourceType,
      locator: options.locator,
      statusCode: 502,
      isRetryable: false,
      cause: options.cause,
    });
  }
}

/**
 * Normalizes an arbitrary error or HTTP status into a typed SourceAdapterError.
 */
export function normalizeSourceHttpError(
  sourceType: string,
  statusCode: number,
  statusText: string,
  responseBody: any,
  locator?: string
): SourceAdapterError {
  const errMsg = typeof responseBody === 'object' && responseBody?.message 
    ? responseBody.message 
    : typeof responseBody === 'string' && responseBody.length > 0
    ? responseBody
    : statusText || `HTTP ${statusCode}`;

  if (statusCode === 401 || statusCode === 403) {
    if (typeof errMsg === 'string' && errMsg.toLowerCase().includes('rate limit')) {
      return new SourceRateLimitExhaustedError(`Rate limit reached for ${sourceType}: ${errMsg}`, {
        sourceType,
        locator,
        resetAt: new Date(Date.now() + 3600 * 1000).toISOString(),
        retryAfterSeconds: 3600,
      });
    }
    return new SourceAuthenticationError(`Authentication failed for ${sourceType}: ${errMsg}`, {
      sourceType,
      locator,
      statusCode,
      authStatus: statusCode === 401 ? 'INVALID_CREDENTIALS' : 'MISSING_CREDENTIALS',
    });
  }

  if (statusCode === 404) {
    return new SourceNotFoundError(`Entity not found in ${sourceType}: ${locator || errMsg}`, {
      sourceType,
      locator: locator || 'unknown',
    });
  }

  if (statusCode === 429) {
    return new SourceRateLimitExhaustedError(`Rate limit exceeded for ${sourceType}: ${errMsg}`, {
      sourceType,
      locator,
      resetAt: new Date(Date.now() + 60 * 1000).toISOString(),
      retryAfterSeconds: 60,
    });
  }

  if (statusCode >= 500 && statusCode <= 599) {
    return new SourceTransientError(`Transient upstream error from ${sourceType} (${statusCode}): ${errMsg}`, {
      sourceType,
      statusCode,
      locator,
    });
  }

  return new SourceAdapterError(`Source operation error from ${sourceType} (${statusCode}): ${errMsg}`, {
    sourceType,
    statusCode,
    locator,
    isRetryable: false,
  });
}
