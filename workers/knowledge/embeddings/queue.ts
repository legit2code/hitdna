import { 
  KnowledgeChunk, 
  EmbeddingRecord, 
  EmbeddingProvider 
} from '../types.ts';

export interface QueueJob {
  jobId: string;
  chunk: KnowledgeChunk;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  retryCount: number;
  maxRetries: number;
  result?: EmbeddingRecord;
  error?: string;
  enqueuedAt: string;
  processedAt?: string;
}

export class EmbeddingQueue {
  private queue: Map<string, QueueJob> = new Map();
  private provider: EmbeddingProvider;
  private batchSize: number;
  private isProcessing: boolean = false;

  constructor(provider: EmbeddingProvider, batchSize: number = 16) {
    this.provider = provider;
    this.batchSize = batchSize;
  }

  public enqueueChunk(chunk: KnowledgeChunk, maxRetries: number = 3): string {
    const jobId = `emb-job-${chunk.knowledge_chunk_id}-${Date.now()}`;
    const job: QueueJob = {
      jobId,
      chunk,
      status: 'PENDING',
      retryCount: 0,
      maxRetries,
      enqueuedAt: new Date().toISOString(),
    };
    this.queue.set(jobId, job);
    return jobId;
  }

  public enqueueChunks(chunks: KnowledgeChunk[]): string[] {
    return chunks.map((c) => this.enqueueChunk(c));
  }

  public async processBatch(): Promise<EmbeddingRecord[]> {
    if (this.isProcessing) return [];
    this.isProcessing = true;

    try {
      const pendingJobs = Array.from(this.queue.values())
        .filter((j) => j.status === 'PENDING')
        .slice(0, this.batchSize);

      if (pendingJobs.length === 0) {
        return [];
      }

      pendingJobs.forEach((j) => (j.status = 'PROCESSING'));

      const texts = pendingJobs.map((j) => j.chunk.text_content);
      const embeddings = await this.provider.generateEmbeddings(texts);

      const records: EmbeddingRecord[] = [];

      for (let i = 0; i < pendingJobs.length; i++) {
        const job = pendingJobs[i];
        const emb = embeddings[i];

        if (emb && emb.vector) {
          const rec: EmbeddingRecord = {
            embedding_id: `emb-${job.chunk.knowledge_chunk_id}`,
            knowledge_chunk_id: job.chunk.knowledge_chunk_id,
            knowledge_object_id: job.chunk.knowledge_object_id,
            embedding_model_version: emb.model,
            dimensions: emb.dimensions,
            vector: emb.vector,
            agent_id: job.chunk.agent_id,
            agent_version_id: job.chunk.agent_version_id,
            analysis_run_id: job.chunk.analysis_run_id,
            security_classification: job.chunk.security_classification,
            security_classification_rank: job.chunk.security_classification_rank,
            vault_restricted: job.chunk.vault_restricted,
            exact_keywords: job.chunk.exact_keywords,
            created_at: new Date().toISOString(),
          };

          job.status = 'COMPLETED';
          job.result = rec;
          job.processedAt = new Date().toISOString();
          records.push(rec);
        } else {
          job.retryCount++;
          if (job.retryCount >= job.maxRetries) {
            job.status = 'FAILED';
            job.error = 'Exceeded maximum retry attempts';
          } else {
            job.status = 'PENDING';
          }
        }
      }

      return records;
    } finally {
      this.isProcessing = false;
    }
  }

  public async drainAll(): Promise<EmbeddingRecord[]> {
    const allRecords: EmbeddingRecord[] = [];
    while (Array.from(this.queue.values()).some((j) => j.status === 'PENDING')) {
      const batch = await this.processBatch();
      allRecords.push(...batch);
      if (batch.length === 0) break;
    }
    return allRecords;
  }

  public getMetrics() {
    const jobs = Array.from(this.queue.values());
    return {
      total_enqueued: jobs.length,
      pending: jobs.filter((j) => j.status === 'PENDING').length,
      processing: jobs.filter((j) => j.status === 'PROCESSING').length,
      completed: jobs.filter((j) => j.status === 'COMPLETED').length,
      failed: jobs.filter((j) => j.status === 'FAILED').length,
    };
  }

  public clearQueue(): void {
    this.queue.clear();
  }
}
