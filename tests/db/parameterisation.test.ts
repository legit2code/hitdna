import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgresDatabaseAdapter } from '../../packages/db/src/postgres-adapter.ts';

const DATABASE_URL = process.env.DATABASE_URL;

describe.skipIf(!DATABASE_URL)('Database Parameterisation & SQL Injection Immunity (R05)', () => {
  let adapter: PostgresDatabaseAdapter;

  beforeAll(async () => {
    adapter = new PostgresDatabaseAdapter({
      connectionString: DATABASE_URL,
      applicationName: 'test-parameterisation',
    });
  });

  afterAll(async () => {
    await adapter.close();
  });

  it('round-trips single quotes without altering SQL syntax', async () => {
    const value = "O'Connor's test of 'nested' and '''triple''' quotes";
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('round-trips double quotes without altering SQL identifiers or syntax', async () => {
    const value = 'A "quoted string" with "nested ""identifiers""';
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('round-trips backslashes and escape sequences without interpretation', async () => {
    const value = 'C:\\Program Files\\CAIM\\app\\config.json \\n \\t \\r \\\\';
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('round-trips parameter markers ($1, $2, etc.) without parameter substitution confusion', async () => {
    const value = 'Cost is $1 and total is $2 with $99 parameter token';
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('round-trips dollar quoting ($$ and $tag$) without syntax disruption', async () => {
    const value = '$$dollar-quoted-body$$ and $tag$tagged-content$tag$';
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('round-trips SQL line comment tokens (--) without truncating statement', async () => {
    const value = "valid_prefix' -- DROP TABLE security.tenants; SELECT 'injected";
    const res = await adapter.query('SELECT $1::text AS val, 42 AS trailing_col;', [value]);
    expect(res.rows[0].val).toBe(value);
    expect(res.rows[0].trailing_col).toBe(42);
  });

  it('round-trips SQL block comment tokens (/* */) without closing syntax', async () => {
    const value = 'start /* comment body */ end; SELECT /* nested */ 99;';
    const res = await adapter.query('SELECT $1::text AS val;', [value]);
    expect(res.rows[0].val).toBe(value);
  });

  it('handles NUL characters safely', async () => {
    // In PostgreSQL text type, raw \0 is not representable in UTF-8 text literals, but bytea or escaped NUL is
    const value = 'null_byte_test_\u0000_escaped';
    try {
      const res = await adapter.query('SELECT $1::text AS val;', [value]);
      expect(res.rows[0].val).toBe(value);
    } catch (err: any) {
      // Postgres natively rejects 0x00 in UTF-8 text strings: "invalid byte sequence for encoding UTF8: 0x00"
      // Verify that it is safely rejected by the parser, NOT causing SQL statement execution or injection
      expect(err.message).toMatch(/0x00|null/i);
    }
  });

  it('round-trips 1 MB large strings without buffer corruption or truncation', async () => {
    const mbString = 'A'.repeat(1024 * 1024);
    const res = await adapter.query('SELECT length($1::text) AS len, $1::text AS val;', [mbString]);
    expect(res.rows[0].len).toBe(1024 * 1024);
    expect(res.rows[0].val).toBe(mbString);
  });

  it('round-trips PostgreSQL arrays with complex string contents', async () => {
    const arrayVal = [
      "item 'one'",
      'item "two"',
      'item with -- comment',
      'item with $1 token',
      'item\\with\\backslash',
    ];
    const res = await adapter.query('SELECT $1::text[] AS arr;', [arrayVal]);
    expect(res.rows[0].arr).toEqual(arrayVal);
  });

  it('round-trips nested JSON with arbitrary SQL injection payloads intact', async () => {
    const jsonPayload = {
      user_id: 'usr-12345',
      injection_attempt: "'; DROP TABLE security.tenants; --",
      nested: {
        sql_comment: '/* block comment */',
        dollar_sign: '$1 and $$quote$$',
        quotes: { single: "it's fine", double: 'said "hello"' },
        counts: [1, 2, 3],
      },
    };
    const res = await adapter.query('SELECT $1::jsonb AS doc;', [JSON.stringify(jsonPayload)]);
    expect(res.rows[0].doc).toEqual(jsonPayload);
  });
});
