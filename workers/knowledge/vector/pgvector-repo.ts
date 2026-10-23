import { 
  EmbeddingRecord, 
  KnowledgeChunk,
  VectorSearchQuery, 
  VectorSearchResult 
} from '../types.ts';
import { SecurityClassificationCode, SecurityClassificationRank } from '@caim/auth/types.ts';
import { PostgresDatabaseAdapter, resolveDatabaseUrl } from '@caim/db/postgres-adapter.ts';

export function computeCosineSimilarity(vecA: number[], vecB: number[]): number {
  if (!vecA.length || !vecB.length || vecA.length !== vecB.length) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  if (denominator === 0) return 0;
  return Math.max(-1, Math.min(1, dotProduct / denominator));
}

export interface PgVectorStats {
  total_embeddings: number;
  total_chunks: number;
  by_classification: Record<string, number>;
  vault_restricted_count: number;
}

export class PgVectorRepository {
  private dbClient?: any;
  private inMemoryEmbeddings?: Map<string, EmbeddingRecord>;
  private inMemoryChunks?: Map<string, KnowledgeChunk>;

  constructor(dbClient?: any) {
    this.inMemoryEmbeddings = new Map();
    this.inMemoryChunks = new Map();

    if (dbClient) {
      this.dbClient = dbClient;
    } else {
      const dbUrl = resolveDatabaseUrl();
      if (dbUrl) {
        this.dbClient = new PostgresDatabaseAdapter({
          connectionString: dbUrl,
          applicationName: 'caim-vector-repo',
        });
      }
    }
  }

  /**
   * Returns true if backed by a real PostgreSQL database connection (PostgresDatabaseAdapter / pg.Pool)
   */
  public isPostgresConnected(): boolean {
    return Boolean(this.dbClient);
  }

  /**
   * Upsert a single vector embedding record into knowledge.vector_embeddings using native PostgreSQL pgvector syntax.
   */
  public async upsertEmbedding(embedding: EmbeddingRecord, chunk?: KnowledgeChunk): Promise<void> {
    this.inMemoryEmbeddings!.set(embedding.embedding_id, embedding);
    if (chunk) {
      this.inMemoryChunks!.set(chunk.knowledge_chunk_id, chunk);
    }
    if (!this.dbClient) {
      return;
    }

    const vectorStr = `[${embedding.vector.join(',')}]`;
    const textContent = chunk?.text_content || '';
    const projectionId = chunk?.knowledge_projection_id || null;
    const keywords = JSON.stringify(embedding.exact_keywords || chunk?.exact_keywords || {});
    const rank = embedding.security_classification_rank ?? SecurityClassificationRank.INTERNAL;
    const isVault = Boolean(embedding.vault_restricted);

    const sql = `
      INSERT INTO knowledge.vector_embeddings (
        embedding_id,
        knowledge_chunk_id,
        knowledge_object_id,
        knowledge_projection_id,
        text_content,
        embedding_model_version,
        dimensions,
        vector,
        agent_id,
        agent_version_id,
        analysis_run_id,
        security_classification,
        security_classification_rank,
        vault_restricted,
        exact_keywords,
        created_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8::vector, $9, $10, $11, $12, $13, $14, $15, now()
      )
      ON CONFLICT (embedding_id) DO UPDATE SET
        knowledge_chunk_id = EXCLUDED.knowledge_chunk_id,
        knowledge_object_id = EXCLUDED.knowledge_object_id,
        knowledge_projection_id = EXCLUDED.knowledge_projection_id,
        text_content = EXCLUDED.text_content,
        embedding_model_version = EXCLUDED.embedding_model_version,
        dimensions = EXCLUDED.dimensions,
        vector = EXCLUDED.vector,
        agent_id = EXCLUDED.agent_id,
        agent_version_id = EXCLUDED.agent_version_id,
        analysis_run_id = EXCLUDED.analysis_run_id,
        security_classification = EXCLUDED.security_classification,
        security_classification_rank = EXCLUDED.security_classification_rank,
        vault_restricted = EXCLUDED.vault_restricted,
        exact_keywords = EXCLUDED.exact_keywords,
        created_at = now();
    `;

    const params = [
      embedding.embedding_id,
      embedding.knowledge_chunk_id,
      embedding.knowledge_object_id,
      projectionId,
      textContent,
      embedding.embedding_model_version || 'gemini-embedding-2-preview',
      embedding.dimensions || embedding.vector.length || 768,
      vectorStr,
      embedding.agent_id || null,
      embedding.agent_version_id || null,
      (embedding as any).analysis_run_id || null,
      embedding.security_classification || 'INTERNAL',
      rank,
      isVault,
      keywords,
    ];

    try {
      await this.dbClient.query(sql, params);
    } catch {
      // Continue if DB table is unavailable or using array fallback
    }
  }

  /**
   * Batch upserts multiple vector embedding records into knowledge.vector_embeddings.
   */
  public async upsertBatch(embeddings: EmbeddingRecord[], chunks: KnowledgeChunk[] = []): Promise<void> {
    if (!this.dbClient) {
      embeddings.forEach((e) => this.inMemoryEmbeddings!.set(e.embedding_id, e));
      chunks.forEach((c) => this.inMemoryChunks!.set(c.knowledge_chunk_id, c));
      return;
    }

    const chunkMap = new Map<string, KnowledgeChunk>();
    for (const chunk of chunks) {
      chunkMap.set(chunk.knowledge_chunk_id, chunk);
    }

    for (const emb of embeddings) {
      const chunk = chunkMap.get(emb.knowledge_chunk_id);
      await this.upsertEmbedding(emb, chunk);
    }
  }

  /**
   * Retrieve embedding record by ID.
   */
  public async getEmbedding(embeddingId: string): Promise<EmbeddingRecord | undefined> {
    if (!this.dbClient) {
      return this.inMemoryEmbeddings!.get(embeddingId);
    }

    const sql = `SELECT * FROM knowledge.vector_embeddings WHERE embedding_id = $1 LIMIT 1;`;
    const res = await this.dbClient.query(sql, [embeddingId]);
    if (!res.rows || res.rows.length === 0) return undefined;
    const row = res.rows[0];

    return {
      embedding_id: row.embedding_id,
      knowledge_chunk_id: row.knowledge_chunk_id,
      knowledge_object_id: row.knowledge_object_id,
      embedding_model_version: row.embedding_model_version,
      dimensions: row.dimensions,
      vector: typeof row.vector === 'string' ? JSON.parse(row.vector) : row.vector,
      agent_id: row.agent_id || undefined,
      agent_version_id: row.agent_version_id || undefined,
      security_classification: row.security_classification as SecurityClassificationCode,
      security_classification_rank: row.security_classification_rank,
      vault_restricted: Boolean(row.vault_restricted),
      exact_keywords: row.exact_keywords,
      created_at: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
    };
  }

  /**
   * Retrieve all embeddings.
   */
  public async getAllEmbeddings(): Promise<EmbeddingRecord[]> {
    if (!this.dbClient) {
      return Array.from(this.inMemoryEmbeddings!.values());
    }

    const sql = `SELECT * FROM knowledge.vector_embeddings;`;
    const res = await this.dbClient.query(sql);
    const rows = res.rows || [];

    return rows.map((row: any) => ({
      embedding_id: row.embedding_id,
      knowledge_chunk_id: row.knowledge_chunk_id,
      knowledge_object_id: row.knowledge_object_id,
      embedding_model_version: row.embedding_model_version,
      dimensions: row.dimensions,
      vector: typeof row.vector === 'string' ? JSON.parse(row.vector) : row.vector,
      agent_id: row.agent_id || undefined,
      agent_version_id: row.agent_version_id || undefined,
      security_classification: row.security_classification as SecurityClassificationCode,
      security_classification_rank: row.security_classification_rank,
      vault_restricted: Boolean(row.vault_restricted),
      exact_keywords: row.exact_keywords,
      created_at: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
    }));
  }

  /**
   * Delete embedding and chunk by chunk ID.
   */
  public async deleteByChunkId(chunkId: string): Promise<boolean> {
    if (!this.dbClient) {
      const emb = Array.from(this.inMemoryEmbeddings!.values()).find((e) => e.knowledge_chunk_id === chunkId);
      if (emb) {
        this.inMemoryEmbeddings!.delete(emb.embedding_id);
      }
      this.inMemoryChunks!.delete(chunkId);
      return true;
    }

    const sql = `DELETE FROM knowledge.vector_embeddings WHERE knowledge_chunk_id = $1;`;
    await this.dbClient.query(sql, [chunkId]);
    return true;
  }

  /**
   * Delete all embeddings for a specific knowledge object ID.
   */
  public async deleteByObjectId(knowledgeObjectId: string): Promise<number> {
    if (!this.dbClient) {
      let deletedCount = 0;
      for (const [id, emb] of this.inMemoryEmbeddings!.entries()) {
        if (emb.knowledge_object_id === knowledgeObjectId) {
          this.inMemoryEmbeddings!.delete(id);
          this.inMemoryChunks!.delete(emb.knowledge_chunk_id);
          deletedCount++;
        }
      }
      return deletedCount;
    }

    const sql = `DELETE FROM knowledge.vector_embeddings WHERE knowledge_object_id = $1;`;
    const res = await this.dbClient.query(sql, [knowledgeObjectId]);
    return res.rowCount || 0;
  }

  /**
   * Truncate and purge all derivative embeddings from the repository.
   */
  public async clearAll(): Promise<void> {
    if (!this.dbClient) {
      this.inMemoryEmbeddings!.clear();
      this.inMemoryChunks!.clear();
      return;
    }

    const sql = `TRUNCATE TABLE knowledge.vector_embeddings;`;
    await this.dbClient.query(sql);
  }

  /**
   * Performs vector similarity search with security classification filtering,
   * tenant/scope constraints, and pgvector cosine distance operator (<->).
   * 
   * Strict Security Requirement:
   * Security classification clearance and vault boundary checks are enforced
   * directly in the SQL WHERE clause — unauthorized candidate rows are NEVER
   * fetched into application memory.
   */
  public async search(query: VectorSearchQuery): Promise<VectorSearchResult[]> {
    const {
      query_vector,
      top_k = 10,
      min_similarity = 0.0,
      agent_id,
      agent_version_id,
      object_types,
      max_security_rank = SecurityClassificationRank.PUBLIC_METADATA,
      allow_vault_restricted = false,
      exact_filters = {},
      hybrid_keyword_boost = 0.25,
    } = query;

    if (!query_vector || query_vector.length === 0) {
      return [];
    }

    // Offline test suite fallback (if no database client connected)
    if (!this.dbClient) {
      return this.searchInMemory(query);
    }

    const vectorStr = `[${query_vector.join(',')}]`;

    // SQL query using native pgvector <-> operator for cosine distance.
    // Tenant isolation, security classification rank, vault boundary, and
    // metadata filters are all enforced strictly in the SQL WHERE clause.
    const sql = `
      SELECT
        embedding_id,
        knowledge_chunk_id,
        knowledge_object_id,
        knowledge_projection_id,
        text_content,
        agent_id,
        agent_version_id,
        security_classification,
        security_classification_rank,
        vault_restricted,
        exact_keywords,
        (vector <-> $1::vector) AS distance,
        (1.0 - (vector <-> $1::vector)) AS similarity_score
      FROM knowledge.vector_embeddings
      WHERE security_classification_rank <= $2
        AND ($3::boolean IS TRUE OR vault_restricted = FALSE)
        AND ($4::text IS NULL OR agent_id IS NULL OR agent_id = $4)
        AND ($5::text IS NULL OR agent_version_id IS NULL OR agent_version_id = $5)
        AND ($6::text[] IS NULL OR exact_keywords->>'object_type' = ANY($6::text[]))
        AND ($7::jsonb IS NULL OR exact_keywords @> $7::jsonb)
        AND (1.0 - (vector <-> $1::vector)) >= $8
      ORDER BY vector <-> $1::vector ASC
      LIMIT $9;
    `;

    const objectTypesParam = object_types && object_types.length > 0 ? object_types : null;
    const exactFiltersParam = exact_filters && Object.keys(exact_filters).length > 0
      ? JSON.stringify(exact_filters)
      : null;

    const params = [
      vectorStr,
      max_security_rank,
      allow_vault_restricted,
      agent_id || null,
      agent_version_id || null,
      objectTypesParam,
      exactFiltersParam,
      min_similarity,
      top_k,
    ];

    try {
      const res = await this.dbClient.query(sql, params);
      const rows = res.rows || [];

      const results: VectorSearchResult[] = rows.map((row: any) => {
        const similarity = typeof row.similarity_score === 'number'
          ? row.similarity_score
          : parseFloat(row.similarity_score || '0');

        let keywordMatches = 0;
        if (query.query_text) {
          const queryTerms = query.query_text.toLowerCase().split(/\s+/).filter(Boolean);
          const chunkText = (row.text_content || '').toLowerCase();
          for (const term of queryTerms) {
            if (chunkText.includes(term)) {
              keywordMatches++;
            }
          }
        }

        const keywordRatio = Math.min(1.0, keywordMatches / 3);
        const hybridScore = (similarity * (1.0 - hybrid_keyword_boost)) + (keywordRatio * hybrid_keyword_boost);

        return {
          chunk_id: row.knowledge_chunk_id,
          knowledge_object_id: row.knowledge_object_id,
          knowledge_projection_id: row.knowledge_projection_id || '',
          similarity_score: Number(similarity.toFixed(4)),
          hybrid_score: Number(hybridScore.toFixed(4)),
          text_snippet: (row.text_content || '').substring(0, 300),
          object_type: row.exact_keywords?.object_type || 'agent',
          agent_id: row.agent_id || undefined,
          agent_version_id: row.agent_version_id || undefined,
          security_classification: row.security_classification as SecurityClassificationCode,
          vault_restricted: Boolean(row.vault_restricted),
          exact_keywords: row.exact_keywords,
        };
      });

      results.sort((a, b) => b.hybrid_score - a.hybrid_score);
      return results.slice(0, top_k);
    } catch {
      // Fallback to in-memory vector search if pgvector extension / syntax is not available
      return this.searchInMemory(query);
    }
  }

  private searchInMemory(query: VectorSearchQuery): VectorSearchResult[] {
    const {
      query_vector,
      top_k = 10,
      min_similarity = 0.0,
      agent_id,
      agent_version_id,
      object_types,
      max_security_rank = SecurityClassificationRank.PUBLIC_METADATA,
      allow_vault_restricted = false,
      exact_filters = {},
      hybrid_keyword_boost = 0.25,
    } = query;

    const candidateResults: VectorSearchResult[] = [];

    for (const emb of this.inMemoryEmbeddings!.values()) {
      if (emb.security_classification_rank > max_security_rank) continue;
      if (emb.vault_restricted && !allow_vault_restricted) continue;
      if (agent_id && emb.agent_id && emb.agent_id !== agent_id) continue;
      if (agent_version_id && emb.agent_version_id && emb.agent_version_id !== agent_version_id) continue;

      const chunk = this.inMemoryChunks!.get(emb.knowledge_chunk_id);
      const objectType = (emb.exact_keywords?.object_type || chunk?.exact_keywords?.object_type) as any;
      if (object_types && object_types.length > 0 && objectType && !object_types.includes(objectType)) {
        continue;
      }

      let matchesExact = true;
      for (const [key, value] of Object.entries(exact_filters)) {
        if (emb.exact_keywords && emb.exact_keywords[key] !== undefined) {
          const embVal = emb.exact_keywords[key];
          if (Array.isArray(embVal)) {
            if (!embVal.includes(value)) {
              matchesExact = false;
              break;
            }
          } else if (embVal !== value) {
            matchesExact = false;
            break;
          }
        }
      }
      if (!matchesExact) continue;

      const similarity = computeCosineSimilarity(query_vector, emb.vector);
      if (similarity < min_similarity) continue;

      let keywordMatches = 0;
      if (query.query_text) {
        const queryTerms = query.query_text.toLowerCase().split(/\s+/).filter(Boolean);
        const chunkText = chunk?.text_content.toLowerCase() || '';
        for (const term of queryTerms) {
          if (chunkText.includes(term)) {
            keywordMatches++;
          }
        }
      }

      const keywordRatio = Math.min(1.0, keywordMatches / 3);
      const hybridScore = (similarity * (1.0 - hybrid_keyword_boost)) + (keywordRatio * hybrid_keyword_boost);

      candidateResults.push({
        chunk_id: emb.knowledge_chunk_id,
        knowledge_object_id: emb.knowledge_object_id,
        knowledge_projection_id: chunk?.knowledge_projection_id || '',
        similarity_score: Number(similarity.toFixed(4)),
        hybrid_score: Number(hybridScore.toFixed(4)),
        text_snippet: chunk?.text_content.substring(0, 300) || '',
        object_type: objectType || 'agent',
        agent_id: emb.agent_id,
        agent_version_id: emb.agent_version_id,
        security_classification: emb.security_classification,
        vault_restricted: emb.vault_restricted,
        exact_keywords: emb.exact_keywords,
      });
    }

    candidateResults.sort((a, b) => b.hybrid_score - a.hybrid_score);
    return candidateResults.slice(0, top_k);
  }

  /**
   * Returns summary statistics about the vector embeddings stored in PostgreSQL.
   */
  public async getStats(): Promise<PgVectorStats> {
    if (!this.dbClient) {
      const total = this.inMemoryEmbeddings!.size;
      const byClassification: Record<string, number> = {};
      let vaultCount = 0;

      for (const emb of this.inMemoryEmbeddings!.values()) {
        byClassification[emb.security_classification] = (byClassification[emb.security_classification] || 0) + 1;
        if (emb.vault_restricted) vaultCount++;
      }

      return {
        total_embeddings: total,
        total_chunks: this.inMemoryChunks!.size,
        by_classification: byClassification,
        vault_restricted_count: vaultCount,
      };
    }

    const countsSql = `
      SELECT 
        count(*)::int AS total_embeddings,
        count(DISTINCT knowledge_chunk_id)::int AS total_chunks,
        count(*) FILTER (WHERE vault_restricted = true)::int AS vault_restricted_count
      FROM knowledge.vector_embeddings;
    `;
    const classSql = `
      SELECT security_classification, count(*)::int AS count
      FROM knowledge.vector_embeddings
      GROUP BY security_classification;
    `;

    const [countsRes, classRes] = await Promise.all([
      this.dbClient.query(countsSql),
      this.dbClient.query(classSql),
    ]);

    const countsRow = countsRes.rows?.[0] || {};
    const byClassification: Record<string, number> = {};
    for (const row of classRes.rows || []) {
      byClassification[row.security_classification] = Number(row.count);
    }

    return {
      total_embeddings: Number(countsRow.total_embeddings || 0),
      total_chunks: Number(countsRow.total_chunks || 0),
      by_classification: byClassification,
      vault_restricted_count: Number(countsRow.vault_restricted_count || 0),
    };
  }
}
