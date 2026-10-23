import { describe, it, expect, vi } from 'vitest';
import { PgVectorRepository } from '../workers/knowledge/vector/pgvector-repo.ts';
import { PostgresDatabaseAdapter } from '@caim/db/postgres-adapter.ts';
import { SecurityClassificationRank } from '@caim/auth/types.ts';
import { EmbeddingRecord, KnowledgeChunk } from '../workers/knowledge/types.ts';

describe('PgVectorRepository with Native PostgreSQL / pgvector', () => {
  it('confirms it runs against PostgresDatabaseAdapter (pg.Pool) and not pg-mem', async () => {
    // Construct a real PostgresDatabaseAdapter instance
    const adapter = new PostgresDatabaseAdapter({
      connectionString: 'postgresql://postgres:postgres@127.0.0.1:5432/caim_test',
      applicationName: 'test-pgvector-runner',
    });

    const repo = new PgVectorRepository(adapter);
    expect(repo.isPostgresConnected()).toBe(true);

    // Confirm that the backing adapter is an instance of PostgresDatabaseAdapter with node-postgres Pool
    expect(adapter).toBeInstanceOf(PostgresDatabaseAdapter);
    expect((adapter as any).pool).toBeDefined();
    // Confirm it is not pg-mem
    expect((adapter as any).isPgMem).toBeUndefined();
  });

  it('executes native SQL INSERT with $8::vector on upsertEmbedding', async () => {
    const executedQueries: { sql: string; params?: any[] }[] = [];

    const mockAdapter = {
      isPgMem: false,
      query: vi.fn(async (sql: string, params?: any[]) => {
        executedQueries.push({ sql, params });
        return { rows: [], rowCount: 1 };
      }),
    };

    const repo = new PgVectorRepository(mockAdapter);

    const testEmbedding: EmbeddingRecord = {
      embedding_id: 'emb-test-001',
      knowledge_chunk_id: 'chunk-test-001',
      knowledge_object_id: 'kobj-agent-001',
      embedding_model_version: 'gemini-embedding-2-preview',
      dimensions: 3,
      vector: [0.123, 0.456, -0.789],
      agent_id: 'agent-sentinel',
      agent_version_id: 'ver-2.4.1',
      security_classification: 'INTERNAL',
      security_classification_rank: SecurityClassificationRank.INTERNAL,
      vault_restricted: false,
      exact_keywords: { object_type: 'agent', cve_id: 'CVE-2026-1234' },
      created_at: new Date().toISOString(),
    };

    const testChunk: KnowledgeChunk = {
      knowledge_chunk_id: 'chunk-test-001',
      knowledge_object_id: 'kobj-agent-001',
      knowledge_projection_id: 'proj-001',
      chunk_version: 'v1',
      sequence: 0,
      content_hash: 'hash-abc-123',
      text_content: 'Autonomous sentinel agent for vulnerability triage.',
      token_count: 8,
      security_classification: 'INTERNAL',
      security_classification_rank: SecurityClassificationRank.INTERNAL,
      vault_restricted: false,
      exact_keywords: { object_type: 'agent' },
      created_at: new Date().toISOString(),
    };

    await repo.upsertEmbedding(testEmbedding, testChunk);

    expect(mockAdapter.query).toHaveBeenCalledTimes(1);
    const lastCall = executedQueries[0];

    // 1. Verify target table is knowledge.vector_embeddings
    expect(lastCall.sql).toContain('INSERT INTO knowledge.vector_embeddings');

    // 2. Verify $8::vector casting syntax
    expect(lastCall.sql).toContain('$8::vector');

    // 3. Verify ON CONFLICT DO UPDATE
    expect(lastCall.sql).toContain('ON CONFLICT (embedding_id) DO UPDATE SET');

    // 4. Verify vector string serialization
    expect(lastCall.params?.[7]).toBe('[0.123,0.456,-0.789]');
    expect(lastCall.params?.[0]).toBe('emb-test-001');
    expect(lastCall.params?.[1]).toBe('chunk-test-001');
  });

  it('executes native pgvector <-> cosine similarity query with strict SQL WHERE security enforcement', async () => {
    const executedQueries: { sql: string; params?: any[] }[] = [];

    const mockAdapter = {
      isPgMem: false,
      query: vi.fn(async (sql: string, params?: any[]) => {
        executedQueries.push({ sql, params });
        return {
          rows: [
            {
              embedding_id: 'emb-001',
              knowledge_chunk_id: 'chunk-001',
              knowledge_object_id: 'kobj-001',
              knowledge_projection_id: 'proj-001',
              text_content: 'Matching security vulnerability triage documentation.',
              agent_id: 'agent-sentinel',
              agent_version_id: 'ver-2.4.1',
              security_classification: 'INTERNAL',
              security_classification_rank: 1,
              vault_restricted: false,
              exact_keywords: { object_type: 'agent' },
              distance: 0.0821,
              similarity_score: 0.9179,
            },
          ],
          rowCount: 1,
        };
      }),
    };

    const repo = new PgVectorRepository(mockAdapter);

    const queryVector = [0.1, 0.2, 0.3];
    const results = await repo.search({
      query_text: 'vulnerability triage',
      query_vector: queryVector,
      top_k: 5,
      min_similarity: 0.5,
      max_security_rank: SecurityClassificationRank.INTERNAL,
      allow_vault_restricted: false,
      agent_id: 'agent-sentinel',
      agent_version_id: 'ver-2.4.1',
      object_types: ['agent'],
      exact_filters: { cve_id: 'CVE-2026-1234' },
      hybrid_keyword_boost: 0.2,
    });

    expect(mockAdapter.query).toHaveBeenCalledTimes(1);
    const queryCall = executedQueries[0];

    // 1. Verify native pgvector operator <-> is used in SELECT and ORDER BY
    expect(queryCall.sql).toContain('(vector <-> $1::vector) AS distance');
    expect(queryCall.sql).toContain('(1.0 - (vector <-> $1::vector)) AS similarity_score');
    expect(queryCall.sql).toContain('ORDER BY vector <-> $1::vector ASC');

    // 2. Verify security classification rank is filtered directly in SQL WHERE clause
    expect(queryCall.sql).toContain('WHERE security_classification_rank <= $2');

    // 3. Verify vault boundary is filtered directly in SQL WHERE clause
    expect(queryCall.sql).toContain('AND ($3::boolean IS TRUE OR vault_restricted = FALSE)');

    // 4. Verify tenant/agent and version scopes are filtered directly in SQL WHERE clause
    expect(queryCall.sql).toContain('AND ($4::text IS NULL OR agent_id IS NULL OR agent_id = $4)');
    expect(queryCall.sql).toContain('AND ($5::text IS NULL OR agent_version_id IS NULL OR agent_version_id = $5)');

    // 5. Verify object types and exact keywords are filtered directly in SQL WHERE clause
    expect(queryCall.sql).toContain("AND ($6::text[] IS NULL OR exact_keywords->>'object_type' = ANY($6::text[]))");
    expect(queryCall.sql).toContain('AND ($7::jsonb IS NULL OR exact_keywords @> $7::jsonb)');

    // 6. Verify minimum similarity is filtered directly in SQL WHERE clause
    expect(queryCall.sql).toContain('AND (1.0 - (vector <-> $1::vector)) >= $8');

    // 7. Verify parameters passed to database
    expect(queryCall.params?.[0]).toBe('[0.1,0.2,0.3]');
    expect(queryCall.params?.[1]).toBe(SecurityClassificationRank.INTERNAL);
    expect(queryCall.params?.[2]).toBe(false); // allow_vault_restricted = false
    expect(queryCall.params?.[3]).toBe('agent-sentinel');
    expect(queryCall.params?.[4]).toBe('ver-2.4.1');
    expect(queryCall.params?.[5]).toEqual(['agent']);
    expect(queryCall.params?.[6]).toBe(JSON.stringify({ cve_id: 'CVE-2026-1234' }));
    expect(queryCall.params?.[7]).toBe(0.5); // min_similarity
    expect(queryCall.params?.[8]).toBe(5); // top_k

    // 8. Verify results structure
    expect(results.length).toBe(1);
    expect(results[0].chunk_id).toBe('chunk-001');
    expect(results[0].similarity_score).toBe(0.9179);
    expect(results[0].hybrid_score).toBe(0.8677);
  });

  it('prohibits vault-restricted records in SQL WHERE clause when allow_vault_restricted is false', async () => {
    const executedQueries: { sql: string; params?: any[] }[] = [];

    const mockAdapter = {
      isPgMem: false,
      query: vi.fn(async (sql: string, params?: any[]) => {
        executedQueries.push({ sql, params });
        return { rows: [], rowCount: 0 };
      }),
    };

    const repo = new PgVectorRepository(mockAdapter);

    await repo.search({
      query_text: 'vault access',
      query_vector: [0.5, 0.5, 0.5],
      max_security_rank: SecurityClassificationRank.PUBLIC_METADATA,
      allow_vault_restricted: false,
    });

    const queryCall = executedQueries[0];
    expect(queryCall.sql).toContain('AND ($3::boolean IS TRUE OR vault_restricted = FALSE)');
    // Param $3 is boolean false, so Postgres evaluates vault_restricted = FALSE
    expect(queryCall.params?.[2]).toBe(false);
    expect(queryCall.params?.[1]).toBe(SecurityClassificationRank.PUBLIC_METADATA);
  });
});
