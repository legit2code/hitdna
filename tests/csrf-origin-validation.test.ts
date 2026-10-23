import { describe, it, expect } from 'vitest';
import { CsrfProtectionEngine } from '@caim/auth/csrf-protection.ts';

/**
 * Historical/Vulnerable Substring Matching Implementation
 * This represents the exact logic prior to the fix:
 *   const cleanHost = hostHeader.toLowerCase().trim();
 *   if (cleanOrigin.includes(cleanHost)) { return true; }
 */
function legacySubstringOriginCheck(originHeader: string | undefined, hostHeader: string | undefined): boolean {
  if (!originHeader) return true;
  const cleanOrigin = originHeader.toLowerCase().trim();
  if (hostHeader) {
    const cleanHost = hostHeader.toLowerCase().trim();
    if (cleanOrigin.includes(cleanHost)) {
      return true;
    }
  }
  return false;
}

describe('CSRF Origin Validation Vulnerability Proof & URL Constructor Hardening', () => {
  const host = 'app.example.com';
  const hostWithPort = 'app.example.com:3000';
  const engine = new CsrfProtectionEngine({ allowedOrigins: [] });

  describe('1. Vulnerability Proof: Old Substring-Matching vs New URL Constructor Logic', () => {
    // Attack Scenario A: Attacker controls an arbitrary subdomain on their own domain ending with target host
    const attackerSubdomainOrigin = 'https://app.example.com.evil-attacker.com';

    // Attack Scenario B: Attacker embeds target host string in origin path or query parameter
    const attackerPathTrickOrigin = 'https://evil-attacker.com/app.example.com';

    // Attack Scenario C: Attacker registers a domain with the target host as a prefix or substring
    const attackerPrefixOrigin = 'https://attacker-app.example.com';

    // Attack Scenario D: Attacker targets host with port using appended port or domain
    const attackerPortDomainOrigin = 'http://app.example.com:3000.attacker.com';

    // Attack Scenario E: Attacker runs on an unauthorized adjacent port (e.g. 30000 matching 3000)
    const attackerAdjacentPortOrigin = 'http://app.example.com:30000';

    it('PROVES VULNERABILITY: Old substring matching permits attacker-crafted malicious origins', () => {
      // The legacy cleanOrigin.includes(cleanHost) checks return true for all attacker-crafted origins!
      expect(legacySubstringOriginCheck(attackerSubdomainOrigin, host)).toBe(true);
      expect(legacySubstringOriginCheck(attackerPathTrickOrigin, host)).toBe(true);
      expect(legacySubstringOriginCheck(attackerPrefixOrigin, host)).toBe(true);
      expect(legacySubstringOriginCheck(attackerPortDomainOrigin, hostWithPort)).toBe(true);
      expect(legacySubstringOriginCheck(attackerAdjacentPortOrigin, hostWithPort)).toBe(true);
    });

    it('PROVES REMEDIATION: New URL constructor logic strictly rejects every crafted malicious origin', () => {
      // The new URL constructor exact comparison rejects each and every crafted origin!
      expect(engine.isOriginAllowed(attackerSubdomainOrigin, host)).toBe(false);
      expect(engine.isOriginAllowed(attackerPathTrickOrigin, host)).toBe(false);
      expect(engine.isOriginAllowed(attackerPrefixOrigin, host)).toBe(false);
      expect(engine.isOriginAllowed(attackerPortDomainOrigin, hostWithPort)).toBe(false);
      expect(engine.isOriginAllowed(attackerAdjacentPortOrigin, hostWithPort)).toBe(false);
    });
  });

  describe('2. Exact Protocol, Hostname, and Port Comparison via URL Constructor', () => {
    it('allows legitimate same-origin requests matching protocol, hostname, and port', () => {
      // HTTPS default port 443
      expect(engine.isOriginAllowed('https://app.example.com', 'app.example.com')).toBe(true);
      expect(engine.isOriginAllowed('https://app.example.com:443', 'app.example.com')).toBe(true);

      // Explicit port
      expect(engine.isOriginAllowed('https://app.example.com:3000', 'app.example.com:3000')).toBe(true);
      expect(engine.isOriginAllowed('http://localhost:3000', 'localhost:3000')).toBe(true);
    });

    it('rejects protocol mismatches (e.g., plaintext http origin trying to impersonate https host)', () => {
      // Host expects https, attacker provides http
      const isAllowed = engine.isOriginAllowed('http://app.example.com:3000', 'app.example.com:3000');
      // If host is accessed via https, http origin is cross-protocol
      expect(engine.isOriginAllowed('http://app.example.com', 'app.example.com:443')).toBe(false);
    });

    it('rejects port mismatches against the host header', () => {
      // Host is on port 3000, origin is on port 8080
      expect(engine.isOriginAllowed('https://app.example.com:8080', 'app.example.com:3000')).toBe(false);
      expect(engine.isOriginAllowed('https://app.example.com:3001', 'app.example.com:3000')).toBe(false);
    });

    it('rejects malformed or unparseable origin headers safely (fails closed)', () => {
      expect(engine.isOriginAllowed('not-a-valid-url', host)).toBe(false);
      expect(engine.isOriginAllowed('://invalid', host)).toBe(false);
      expect(engine.isOriginAllowed('javascript:alert(1)', host)).toBe(false);
      expect(engine.isOriginAllowed('data:text/html,test', host)).toBe(false);
    });
  });

  describe('3. Explicit Allowlist Validation with URL Constructor', () => {
    it('accurately matches allowlisted origins by protocol, hostname, and port', () => {
      const customEngine = new CsrfProtectionEngine({
        allowedOrigins: [
          'https://partner-portal.corp.com:8443',
          'https://console.cloud-provider.internal',
        ],
      });

      // Exact matches must pass
      expect(customEngine.isOriginAllowed('https://partner-portal.corp.com:8443', undefined)).toBe(true);
      expect(customEngine.isOriginAllowed('https://console.cloud-provider.internal', undefined)).toBe(true);

      // Malicious variants must be rejected
      expect(customEngine.isOriginAllowed('http://partner-portal.corp.com:8443', undefined)).toBe(false); // protocol mismatch
      expect(customEngine.isOriginAllowed('https://partner-portal.corp.com:8444', undefined)).toBe(false); // port mismatch
      expect(customEngine.isOriginAllowed('https://partner-portal.corp.com', undefined)).toBe(false); // port mismatch
      expect(customEngine.isOriginAllowed('https://partner-portal.corp.com.attacker.com:8443', undefined)).toBe(false); // hostname mismatch
      expect(customEngine.isOriginAllowed('https://evil-partner-portal.corp.com:8443', undefined)).toBe(false); // hostname mismatch
    });
  });

  describe('4. Full Request Lifecycle (evaluateRequest)', () => {
    it('blocks state-changing requests from crafted malicious origins even if preflight JSON headers are sent', () => {
      const evaluation = engine.evaluateRequest({
        method: 'POST',
        headers: {
          host: 'app.example.com',
          origin: 'https://app.example.com.evil-attacker.com',
          'content-type': 'application/json',
        },
        path: '/api/composer/execute',
      } as any);

      expect(evaluation.allowed).toBe(false);
      expect(evaluation.reason).toContain("untrusted origin 'https://app.example.com.evil-attacker.com'");
    });

    it('blocks state-changing requests from crafted malicious origins even when carrying Bearer tokens', () => {
      const evaluation = engine.evaluateRequest({
        method: 'POST',
        headers: {
          host: 'app.example.com',
          origin: 'https://attacker-app.example.com',
          authorization: 'Bearer valid-jwt-token-string',
        },
        path: '/api/analysis/trigger',
      } as any);

      expect(evaluation.allowed).toBe(false);
      expect(evaluation.reason).toContain("untrusted origin 'https://attacker-app.example.com'");
    });

    it('allows state-changing requests from legitimate origin matching host', () => {
      const evaluation = engine.evaluateRequest({
        method: 'POST',
        headers: {
          host: 'app.example.com',
          origin: 'https://app.example.com',
          'content-type': 'application/json',
          authorization: 'Bearer valid-jwt-token-string',
        },
        path: '/api/analysis/trigger',
      } as any);

      expect(evaluation.allowed).toBe(true);
      expect(evaluation.authType).toBe('BEARER_JWT');
    });
  });
});
