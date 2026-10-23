import { describe, it, expect } from 'vitest';
import { validateWaiver, evaluateAuditReport, AuditWaiver } from '../scripts/audit-with-waivers.ts';

describe('Dependency Audit Waiver Mechanism', () => {
  const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const pastDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

  describe('validateWaiver', () => {
    it('approves well-formed waiver with future expiration', () => {
      const waiver: AuditWaiver = {
        affectedDependency: 'lodash',
        approver: 'security-lead@caim.internal',
        reason: 'Internal build tool only; not exposed to network runtime',
        expiration: futureDate,
        ticket: 'SEC-1049',
      };
      const res = validateWaiver(waiver);
      expect(res.valid).toBe(true);
      expect(res.error).toBeUndefined();
    });

    it('rejects waiver missing affectedDependency', () => {
      const res = validateWaiver({
        affectedDependency: '',
        approver: 'lead',
        reason: 'testing',
        expiration: futureDate,
      });
      expect(res.valid).toBe(false);
      expect(res.error).toContain('affectedDependency');
    });

    it('rejects waiver missing approver', () => {
      const res = validateWaiver({
        affectedDependency: 'lodash',
        approver: '',
        reason: 'testing',
        expiration: futureDate,
      });
      expect(res.valid).toBe(false);
      expect(res.error).toContain('approver');
    });

    it('rejects waiver missing reason', () => {
      const res = validateWaiver({
        affectedDependency: 'lodash',
        approver: 'lead',
        reason: '',
        expiration: futureDate,
      });
      expect(res.valid).toBe(false);
      expect(res.error).toContain('reason');
    });

    it('rejects expired waiver', () => {
      const res = validateWaiver({
        affectedDependency: 'lodash',
        approver: 'lead',
        reason: 'temporary waiver',
        expiration: pastDate,
      });
      expect(res.valid).toBe(false);
      expect(res.error).toContain('EXPIRED');
    });
  });

  describe('evaluateAuditReport', () => {
    const mockAudit = {
      vulnerabilities: {
        'vulnerable-lib': {
          name: 'vulnerable-lib',
          severity: 'high',
          isDirect: true,
          via: [{ title: 'Remote Code Execution in Parser', url: 'https://example.com/advisory' }],
        },
        'minor-lib': {
          name: 'minor-lib',
          severity: 'low',
          via: ['Info issue'],
        },
      },
    };

    it('fails when high severity finding has no waiver', () => {
      const res = evaluateAuditReport(mockAudit, [], 'high');
      expect(res.passed).toBe(false);
      expect(res.unwaivedCount).toBe(1);
      expect(res.unwaivedFindings[0].name).toBe('vulnerable-lib');
    });

    it('passes when high severity finding has a valid active waiver', () => {
      const validWaivers: AuditWaiver[] = [
        {
          affectedDependency: 'vulnerable-lib',
          approver: 'sec-officer@caim.internal',
          reason: 'Sandboxed offline runner with air-gapped container isolation',
          expiration: futureDate,
        },
      ];
      const res = evaluateAuditReport(mockAudit, validWaivers, 'high');
      expect(res.passed).toBe(true);
      expect(res.unwaivedCount).toBe(0);
      expect(res.waivedCount).toBe(1);
    });

    it('fails when waiver errors exist (e.g. expired waiver detected)', () => {
      const res = evaluateAuditReport(mockAudit, [], 'high', ['Waiver for "vulnerable-lib" EXPIRED']);
      expect(res.passed).toBe(false);
      expect(res.waiverValidationErrors).toHaveLength(1);
    });

    it('ignores vulnerabilities below threshold level (e.g. low when threshold is high)', () => {
      const lowOnlyAudit = {
        vulnerabilities: {
          'minor-lib': {
            name: 'minor-lib',
            severity: 'low',
            via: ['Info issue'],
          },
        },
      };
      const res = evaluateAuditReport(lowOnlyAudit, [], 'high');
      expect(res.passed).toBe(true);
      expect(res.findingsAtOrAboveLevel).toBe(0);
    });
  });
});
