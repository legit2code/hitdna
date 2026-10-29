/**
 * System and Architecture Foundation Contracts
 * Architecture Engine: PF-02 (Repository & Tooling Foundation)
 * Architecture Version: 5.0.0
 */

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptimeSeconds: number;
  timestamp: string;
  version: string;
  architectureVersion: string;
  environment: 'development' | 'production' | 'test';
  checks: {
    server: boolean;
    config: boolean;
    storage: boolean;
  };
}

export interface ReadinessState {
  ready: boolean;
  phase: string;
  engineId: string;
  missingRequirements: string[];
  timestamp: string;
}

export interface DiagnosticInfo {
  engineId: string;
  moduleCoverageCount: number;
  runtimeNodeVersion: string;
  activePort: number;
  platform: string;
  memoryUsage: NodeJS.MemoryUsage;
}

export interface ErrorEnvelope<T = unknown> {
  success: false;
  error: {
    code: string;
    message: string;
    phase: string;
    details?: T;
    timestamp: string;
  };
}

export interface SuccessEnvelope<T = unknown> {
  success: true;
  data: T;
  meta?: {
    phase: string;
    timestamp: string;
    [key: string]: unknown;
  };
}

export type ApiResponseEnvelope<T> = SuccessEnvelope<T> | ErrorEnvelope;
