import { HttpResponse } from '../types.ts';
import type { ResolvedTarget } from './ssrf-filter.ts';

export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  domain: string;
  resolvedIp?: string;
  statusCode?: number;
  durationMs: number;
  bytesReceived: number;
  outcome: 'SUCCESS' | 'SSRF_BLOCKED' | 'ROBOTS_DISALLOWED' | 'RATE_LIMITED' | 'CIRCUIT_OPEN' | 'SIZE_EXCEEDED' | 'TIMEOUT' | 'REDIRECT_BLOCKED' | 'ERROR';
  details?: string;
}

export interface DomainRateLimitConfig {
  tokensPerSecond: number;
  burstCapacity: number;
  maxConcurrency: number;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  cooldownMs: number;
  halfOpenMaxProbes: number;
}

export interface DownloadSafetyLimits {
  maxResponseBytes: number;
  maxArchiveBytes: number;
  maxExpandedBytes: number;
  maxDecompressionRatio: number;
  maxFileCount: number;
  maxNestedArchiveDepth: number;
  timeoutMs: number;
}

export interface FetchGatewayConfig {
  maxRedirects: number;
  defaultTimeoutMs: number;
  maxResponseBytes: number;
  allowedProtocols: string[];
  safetyLimits: DownloadSafetyLimits;
  circuitBreaker: CircuitBreakerConfig;
  defaultRateLimit: DomainRateLimitConfig;
  domainRateLimits?: Record<string, Partial<DomainRateLimitConfig>>;
}

export interface GatewayRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  sourceType?: string;
  skipRobots?: boolean;
  bypassRateLimit?: boolean;
  maxResponseBytes?: number;
  allowedContentTypes?: string[];
  blockedContentTypes?: string[];
  pinnedTarget?: ResolvedTarget;
}
