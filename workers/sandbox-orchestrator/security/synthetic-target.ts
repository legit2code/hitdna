/**
 * Synthetic Target Mock Service & Sandbox Network Enforcement
 * Architecture V2.0.1 - Composer Sandbox Isolation
 */

import { NetworkPolicy } from '../types.ts';
import { NetworkPolicyEngine, EgressEvaluationResult } from './network-policy.ts';

export interface SyntheticTargetRequest {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  body?: any;
}

export interface SyntheticTargetResponse {
  status: number;
  data: Record<string, any>;
  headers: Record<string, string>;
}

export class SyntheticTargetService {
  public static readonly SYNTHETIC_DOMAINS = [
    'synthetic-target.local',
    'auth.synthetic-sandbox.internal',
    'api.synthetic-sandbox.internal',
    'sandbox.caim.internal',
  ];

  public static readonly SYNTHETIC_SANDBOX_POLICY: NetworkPolicy = {
    type: 'WHITELIST_ONLY',
    allowedDomains: SyntheticTargetService.SYNTHETIC_DOMAINS,
    allowedPorts: [80, 443, 8080],
    allowDns: true,
    interceptEgress: true,
  };

  /**
   * Evaluates network access attempt for a composer-generated agent in sandbox.
   * Under DEFAULT_DENY egress, real-world hostnames are strictly blocked;
   * only configured synthetic targets are reachable.
   */
  public static evaluateEgress(
    destinationHost: string,
    port: number = 443,
    protocol: 'HTTP' | 'HTTPS' | 'TCP' = 'HTTPS'
  ): EgressEvaluationResult {
    return NetworkPolicyEngine.evaluateConnection(
      SyntheticTargetService.SYNTHETIC_SANDBOX_POLICY,
      destinationHost,
      port,
      protocol,
      'SCN-COMPOSER-SANDBOX',
      '2.0.1'
    );
  }

  /**
   * Simulates an in-sandbox mock API response for synthetic test execution
   */
  public static handleSyntheticRequest(request: SyntheticTargetRequest): SyntheticTargetResponse {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('[FATAL PRODUCTION ERROR] SyntheticTargetService.handleSyntheticRequest is strictly prohibited in production mode.');
    }
    const p = request.path.toLowerCase();

    if (p.includes('/auth') || p.includes('/login')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: {
          success: true,
          token_type: 'Bearer',
          access_token: 'synth_jwt_e2b_safe_token_2026',
          expires_in: 3600,
          synthetic_environment: true,
        },
      };
    }

    if (p.includes('/health')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: {
          status: 'healthy',
          sandbox_isolation: 'STRICT_DEFAULT_DENY',
          synthetic_target: 'synthetic-target.local',
        },
      };
    }

    if (p.includes('/extract') || p.includes('/data') || p.includes('/ingest')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: {
          items_processed: 42,
          schema: 'synthetic.v1',
          data_signature: 'sha256:synth-mock-record-digest',
        },
      };
    }

    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      data: {
        message: 'Synthetic target execution confirmed.',
        path: request.path,
        method: request.method,
        timestamp: new Date().toISOString(),
      },
    };
  }
}
