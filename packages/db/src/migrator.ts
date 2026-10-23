import fs from 'fs';
import path from 'path';
import { IMemoryDb, newDb, DataType } from 'pg-mem';

export interface MigrationFile {
  filename: string;
  version: string;
  sql: string;
}

/**
 * Loads all Supabase/PostgreSQL migration files in lexical/version order.
 */
export function loadMigrations(migrationsDir?: string): MigrationFile[] {
  const dir = migrationsDir || path.resolve(process.cwd(), 'supabase/migrations');
  if (!fs.existsSync(dir)) {
    throw new Error(`Migrations directory not found at: ${dir}`);
  }

  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  return files.map(filename => {
    const filePath = path.join(dir, filename);
    const sql = fs.readFileSync(filePath, 'utf-8');
    const versionMatch = filename.match(/^([0-9]+)/);
    const version = versionMatch ? versionMatch[1] : filename;
    return {
      filename,
      version,
      sql,
    };
  });
}

/**
 * Reads the reference seed SQL file.
 */
export function loadSeedSql(seedPath?: string): string {
  const file = seedPath || path.resolve(process.cwd(), 'supabase/seed.sql');
  if (!fs.existsSync(file)) {
    throw new Error(`Seed file not found at: ${file}`);
  }
  return fs.readFileSync(file, 'utf-8');
}

/**
 * Creates an in-memory PostgreSQL test instance with pgcrypto/gen_random_uuid support
 * and executes all migrations and optional seed data.
 */
export function createTestDb(options: { applyMigrations?: boolean; applySeed?: boolean } = {}) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      '[FATAL SECURITY VIOLATION] createTestDb() is strictly restricted to test and development environments. ' +
      'It must never be reachable or executed in production mode (NODE_ENV=production). ' +
      'Production deployments require a real PostgreSQL database configured via DATABASE_URL.'
    );
  }

  const db: IMemoryDb = newDb();

  // Register stub extension hooks for pgcrypto & standard functions
  db.public.registerFunction({
    name: 'gen_random_uuid',
    args: [],
    returns: DataType.uuid,
    implementation: () => {
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      });
    },
  });

  db.public.registerFunction({
    name: 'length',
    args: [DataType.text],
    returns: DataType.integer,
    implementation: (s: string) => (s != null ? s.length : 0),
  });

  db.public.registerFunction({
    name: 'version',
    args: [],
    returns: DataType.text,
    implementation: () => 'PostgreSQL 16.2 on x86_64-pc-linux-gnu (caim-pg-engine)',
  });

  db.public.registerFunction({
    name: 'current_database',
    args: [],
    returns: DataType.text,
    implementation: () => 'postgres',
  });

  const sessionSettings: Map<string, string> = new Map();
  const registerSettingsFns = (schema: ReturnType<IMemoryDb['getSchema']> | null | undefined) => {
    if (!schema) return;
    try {
      schema.registerFunction({
        name: 'set_config',
        args: [DataType.text, DataType.text, DataType.bool],
        returns: DataType.text,
        implementation: (settingName: string, newValue: string) => {
          sessionSettings.set(settingName, newValue);
          return newValue;
        },
      });

      schema.registerFunction({
        name: 'current_setting',
        args: [DataType.text, DataType.bool],
        returns: DataType.text,
        implementation: (settingName: string, missingOk?: boolean) => {
          if (sessionSettings.has(settingName)) {
            return sessionSettings.get(settingName)!;
          }
          return missingOk ? '' : '';
        },
      });

      schema.registerFunction({
        name: 'current_setting',
        args: [DataType.text],
        returns: DataType.text,
        implementation: (settingName: string) => {
          return sessionSettings.get(settingName) || '';
        },
      });
    } catch (err: unknown) {
      // Safe: ignore if settings functions are already registered in schema
      const msg = err instanceof Error ? err.message : String(err);
      console.debug('[Migrator] Settings functions already registered:', msg);
    }
  };

  const pgCatalog = typeof db.getSchema === 'function' ? db.getSchema('pg_catalog') : null;
  registerSettingsFns(pgCatalog);
  registerSettingsFns(db.public);

  try {
    const pub = db.public as unknown as { registerEquivalentType?: (opts: unknown) => void };
    if (typeof pub.registerEquivalentType === 'function') {
      pub.registerEquivalentType({
        name: 'vector',
        equivalentTo: DataType.text,
        isValid: () => true,
      });
    }
  } catch (err: unknown) {
    // Safe: vector type equivalence registration is best-effort in pg-mem
    const msg = err instanceof Error ? err.message : String(err);
    console.debug('[Migrator] Non-fatal vector type registration notice:', msg);
  }

  if (options.applyMigrations !== false) {
    db.public.none(`
      CREATE TABLE IF NOT EXISTS public.schema_migrations (
        version text PRIMARY KEY,
        name text,
        applied_at timestamptz
      );
    `);

    const migrations = loadMigrations();
    for (const migration of migrations) {
      const statements = splitSqlStatements(migration.sql).filter(stmt => {
        const lower = stmt.toLowerCase().replace(/\s+/g, ' ');
        if (lower.startsWith('comment on ')) return false;
        if (lower.startsWith('create extension ')) return false;
        if (lower.includes('using hnsw') || lower.includes('using ivfflat')) return false;
        if (lower.startsWith('create or replace function ') || lower.startsWith('create function ')) return false;
        if (lower.startsWith('create trigger ')) return false;
        if (lower.startsWith('create policy ') || lower.startsWith('alter table ') && lower.includes('row level security')) return false;
        if (lower.startsWith('grant ') || lower.startsWith('revoke ')) return false;
        if (lower.startsWith('do ') || lower.startsWith('do$$')) return false;
        if (lower.startsWith('drop policy ')) return false;
        return true;
      });

      for (const stmt of statements) {
        try {
          db.public.none(stmt);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          throw new Error(`Failed in ${migration.filename} on statement:\n${stmt}\nError: ${msg}`);
        }
      }

      try {
        db.public.none(
          `INSERT INTO public.schema_migrations (version, name, applied_at) VALUES ('${migration.version}', '${migration.filename}', now());`
        );
      } catch (err: unknown) {
        // Safe: ignore duplicate migration entry insertion if already applied in test schema
        const msg = err instanceof Error ? err.message : String(err);
        console.debug('[Migrator] Duplicate migration version ignored:', msg);
      }
    }
  }

  if (options.applySeed) {
    const seedSql = loadSeedSql();
    const seedStatements = splitSqlStatements(seedSql).filter(stmt => {
      const lower = stmt.toLowerCase().replace(/\s+/g, ' ');
      if (lower.startsWith('comment on ')) return false;
      if (lower.startsWith('create extension ')) return false;
      return true;
    });

    for (const stmt of seedStatements) {
      try {
        db.public.none(stmt);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(`Failed in seed.sql on statement:\n${stmt}\nError: ${msg}`);
      }
    }
  }

  return db;
}

/**
 * Splits SQL into individual executable statements while respecting string literals and dollar quotes.
 */
export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let inString = false;
  let stringChar = '';
  let inLineComment = false;
  let inBlockComment = false;
  let dollarTag: string | null = null;

  for (let i = 0; i < sql.length; i++) {
    const char = sql[i];
    const next = sql[i + 1] || '';

    // Handle block comments
    if (inBlockComment) {
      if (char === '*' && next === '/') {
        inBlockComment = false;
        i++; // skip /
      }
      continue;
    }

    // Handle line comments
    if (inLineComment) {
      if (char === '\n' || char === '\r') {
        inLineComment = false;
        current += char;
      }
      continue;
    }

    // Handle dollar quotes ($$...$$ or $tag$...$tag$)
    if (dollarTag !== null) {
      current += char;
      if (char === '$' && sql.slice(i, i + dollarTag.length) === dollarTag) {
        current += sql.slice(i + 1, i + dollarTag.length);
        i += dollarTag.length - 1;
        dollarTag = null;
      }
      continue;
    }

    // Handle string quotes
    if (inString) {
      current += char;
      if (char === stringChar) {
        // Check for escaped quote ''
        if (next === stringChar) {
          current += next;
          i++;
        } else {
          inString = false;
        }
      }
      continue;
    }

    // Start comments
    if (char === '-' && next === '-') {
      inLineComment = true;
      i++;
      continue;
    }
    if (char === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }

    // Check for dollar quote start ($$ or $[a-zA-Z0-9_]*$)
    if (char === '$') {
      const match = sql.slice(i).match(/^(\$[a-zA-Z0-9_]*\$)/);
      if (match) {
        dollarTag = match[1];
        current += dollarTag;
        i += dollarTag.length - 1;
        continue;
      }
    }

    if (char === '\'' || char === '"') {
      inString = true;
      stringChar = char;
      current += char;
      continue;
    }

    // Statement boundary
    if (char === ';') {
      const trimmed = current.trim();
      if (trimmed) {
        statements.push(trimmed);
      }
      current = '';
      continue;
    }

    current += char;
  }

  const finalTrimmed = current.trim();
  if (finalTrimmed) {
    statements.push(finalTrimmed);
  }

  return statements;
}

/**
 * Sanitizes SQL statements for pg-mem compatibility (handling extensions, comments, etc.).
 */
export function sanitizeSqlForPgMem(sql: string): string {
  const statements = splitSqlStatements(sql);

  const filtered = statements.filter(stmt => {
    const lower = stmt.toLowerCase().replace(/\s+/g, ' ');
    if (lower.startsWith('comment on ')) return false;
    if (lower.startsWith('create extension ')) return false;
    return true;
  });

  return filtered.length ? filtered.join(';\n') + ';' : '';
}
