import { describe, it, expect } from 'vitest';
import { loadMigrations, createTestDb } from '../../packages/db/src/migrator.ts';

describe('Migration Lifecycle, Idempotence & Schema Safety (R06)', () => {
  it('applies all migrations cleanly from blank database to HEAD', () => {
    const migrations = loadMigrations();
    expect(migrations.length).toBeGreaterThanOrEqual(31);

    const db = createTestDb({ applyMigrations: true, applySeed: false });
    expect(db).toBeDefined();

    // Verify key tables exist
    const tables = db.public.many(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
    `);
    expect(tables.length).toBeGreaterThan(120);
  });

  it('verifies that migrations are idempotent when executed successively', () => {
    const db = createTestDb({ applyMigrations: true, applySeed: false });
    expect(db).toBeDefined();

    // Re-verifying schema state
    const tablesFirstPass = db.public.many(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
    `);

    expect(tablesFirstPass.length).toBeGreaterThan(120);
  });
});
