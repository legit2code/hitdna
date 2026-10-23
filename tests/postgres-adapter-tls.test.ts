import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { PostgresDatabaseAdapter, resolveCaBundle } from '@caim/db/postgres-adapter.ts';

describe('PostgresDatabaseAdapter TLS & CA Bundle Hardening', () => {
  it('resolves a proper CA bundle including system roots and managed provider bundles', () => {
    const bundle = resolveCaBundle({
      connectionString: 'postgres://user:pass@db.example.amazonaws.com:5432/caim',
    });

    expect(bundle).toBeDefined();
    expect(Array.isArray(bundle)).toBe(true);
    const bundleArray = bundle as Array<string | Buffer>;
    expect(bundleArray.length).toBeGreaterThan(0);

    // Verify presence of Amazon RDS Root CA or certificates via X.509 subject
    const bundleStr = bundleArray.map(c => c.toString()).join('\n');
    expect(bundleStr).toContain('BEGIN CERTIFICATE');
    
    // Parse the first certificate from the bundle to verify X.509 subject
    const firstCert = bundleStr.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----';
    const x509 = new crypto.X509Certificate(firstCert);
    expect(x509.subject).toContain('Amazon');
  });

  it('configures rejectUnauthorized: true for managed providers (AWS RDS, Supabase, Neon, production)', () => {
    // 1. AWS RDS
    const rdsAdapter = new PostgresDatabaseAdapter({
      connectionString: 'postgres://user:pass@mydb.xyz.us-east-1.rds.amazonaws.com:5432/caim_prod',
    });
    const rdsPool = (rdsAdapter as any).pool;
    expect(rdsPool.options.ssl).toBeDefined();
    expect(rdsPool.options.ssl.rejectUnauthorized).toBe(true);
    expect(rdsPool.options.ssl.ca).toBeDefined();

    // 2. Supabase
    const supabaseAdapter = new PostgresDatabaseAdapter({
      connectionString: 'postgresql://postgres:secret@db.abcxyz.supabase.co:5432/postgres',
    });
    const supabasePool = (supabaseAdapter as any).pool;
    expect(supabasePool.options.ssl).toBeDefined();
    expect(supabasePool.options.ssl.rejectUnauthorized).toBe(true);
    expect(supabasePool.options.ssl.ca).toBeDefined();

    // 3. Neon
    const neonAdapter = new PostgresDatabaseAdapter({
      connectionString: 'postgresql://user:pass@ep-cool-flower-123456.neon.tech/neondb',
    });
    const neonPool = (neonAdapter as any).pool;
    expect(neonPool.options.ssl).toBeDefined();
    expect(neonPool.options.ssl.rejectUnauthorized).toBe(true);
    expect(neonPool.options.ssl.ca).toBeDefined();
  });

  it('allows explicit custom CA bundle and strictly enforces rejectUnauthorized: true', () => {
    const customCa = '-----BEGIN CERTIFICATE-----\nMIIFakeTestCertForUnitTestingOnly==\n-----END CERTIFICATE-----';
    const adapter = new PostgresDatabaseAdapter({
      connectionString: 'postgres://user:pass@custom-db.internal:5432/caim',
      ssl: {
        ca: customCa,
      } as any,
    });

    const pool = (adapter as any).pool;
    expect(pool.options.ssl).toBeDefined();
    expect(pool.options.ssl.rejectUnauthorized).toBe(true);
    expect(pool.options.ssl.ca).toBeDefined();
  });

  it('disables SSL only when sslmode=disable or DB_SSL=false is explicitly specified', () => {
    const disabledAdapter = new PostgresDatabaseAdapter({
      connectionString: 'postgres://user:pass@localhost:5432/caim?sslmode=disable',
    });
    const pool = (disabledAdapter as any).pool;
    expect(pool.options.ssl).toBe(false);
  });
});
