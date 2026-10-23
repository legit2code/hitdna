/**
 * Default-Deny Network Policy & Egress Inspector
 */

import { NetworkPolicy, RuntimeEvent } from '../types.ts';

export interface EgressEvaluationResult {
  allowed: boolean;
  reason: string;
  ruleMatched: string;
  event: RuntimeEvent;
}

export class NetworkPolicyEngine {
  public static readonly DEFAULT_DENY_POLICY: NetworkPolicy = {
    type: 'DEFAULT_DENY',
    allowedDomains: [],
    allowedPorts: [80, 443],
    allowDns: false,
    interceptEgress: true,
  };

  public static readonly TEST_WHITELIST_POLICY: NetworkPolicy = {
    type: 'WHITELIST_ONLY',
    allowedDomains: ['api.github.com', 'registry.npmjs.org', 'pypi.org', 'test-mock.local'],
    allowedPorts: [80, 443],
    allowDns: true,
    interceptEgress: true,
  };

  /**
   * Evaluates an outbound connection attempt against the active NetworkPolicy.
   */
  public static evaluateConnection(
    policy: NetworkPolicy,
    destination: string,
    port: number,
    protocol: 'HTTP' | 'HTTPS' | 'TCP' | 'UDP' | 'DNS' = 'HTTPS',
    scenarioId: string = 'SCN-NET',
    scenarioVersion: string = '1.0.0'
  ): EgressEvaluationResult {
    const eventId = `evt-net-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const timestamp = new Date().toISOString();

    // 1. Check DNS policy
    if (protocol === 'DNS' && !policy.allowDns) {
      return {
        allowed: false,
        reason: 'DNS lookups are blocked by NetworkPolicy',
        ruleMatched: 'DNS_RESTRICTION',
        event: {
          event_id: eventId,
          timestamp,
          scenario_id: scenarioId,
          scenario_version: scenarioVersion,
          category: 'NETWORK',
          action: 'DNS_BLOCKED',
          target: destination,
          status: 'BLOCKED',
          severity: 'HIGH',
          metadata: { protocol, port, reason: 'DNS query forbidden in default-deny' },
        },
      };
    }

    // 2. DEFAULT_DENY policy check
    if (policy.type === 'DEFAULT_DENY') {
      const cleanHost = destination.toLowerCase().trim().split(':')[0];
      const isAllowed = policy.allowedDomains && policy.allowedDomains.length > 0 && policy.allowedDomains.some(domain => {
        const cleanDomain = domain.toLowerCase().trim().split(':')[0];
        return cleanHost === cleanDomain || cleanHost.endsWith('.' + cleanDomain);
      });

      if (!isAllowed) {
        return {
          allowed: false,
          reason: `Outbound connection to ${destination}:${port} denied by DEFAULT_DENY policy`,
          ruleMatched: 'DEFAULT_DENY_RULE',
          event: {
            event_id: eventId,
            timestamp,
            scenario_id: scenarioId,
            scenario_version: scenarioVersion,
            category: 'NETWORK',
            action: 'EGRESS_BLOCKED',
            target: `${destination}:${port}`,
            status: 'BLOCKED',
            severity: 'HIGH',
            metadata: { 
              protocol, 
              destination, 
              port, 
              policyType: policy.type,
              enforcementMechanism: 'FORCED_EGRESS_PROXY',
            },
          },
        };
      }
    }

    // 3. WHITELIST_ONLY policy check
    if (policy.type === 'WHITELIST_ONLY') {
      const cleanHost = destination.toLowerCase().trim().split(':')[0];
      const isAllowed = policy.allowedDomains.some(domain => {
        const cleanDomain = domain.toLowerCase().trim().split(':')[0];
        return cleanHost === cleanDomain || cleanHost.endsWith('.' + cleanDomain);
      });

      if (!isAllowed) {
        return {
          allowed: false,
          reason: `Host ${destination} is not in the whitelist (${policy.allowedDomains.join(', ')})`,
          ruleMatched: 'WHITELIST_DENY',
          event: {
            event_id: eventId,
            timestamp,
            scenario_id: scenarioId,
            scenario_version: scenarioVersion,
            category: 'NETWORK',
            action: 'EGRESS_BLOCKED',
            target: `${destination}:${port}`,
            status: 'BLOCKED',
            severity: 'MEDIUM',
            metadata: { protocol, destination, port, allowedList: policy.allowedDomains },
          },
        };
      }
    }

    // 4. Port validation
    if (policy.allowedPorts && policy.allowedPorts.length > 0 && !policy.allowedPorts.includes(port)) {
      return {
        allowed: false,
        reason: `Port ${port} is not allowed`,
        ruleMatched: 'PORT_RESTRICTION',
        event: {
          event_id: eventId,
          timestamp,
          scenario_id: scenarioId,
          scenario_version: scenarioVersion,
          category: 'NETWORK',
          action: 'EGRESS_BLOCKED',
          target: `${destination}:${port}`,
          status: 'BLOCKED',
          severity: 'HIGH',
          metadata: { port, allowedPorts: policy.allowedPorts },
        },
      };
    }

    // Allowed
    return {
      allowed: true,
      reason: 'Connection permitted by network whitelist',
      ruleMatched: 'WHITELIST_PERMIT',
      event: {
        event_id: eventId,
        timestamp,
        scenario_id: scenarioId,
        scenario_version: scenarioVersion,
        category: 'NETWORK',
        action: 'EGRESS_ALLOWED',
        target: `${destination}:${port}`,
        status: 'ALLOWED',
        severity: 'INFO',
        metadata: { protocol, destination, port },
      },
    };
  }
}
