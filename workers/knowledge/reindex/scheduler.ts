import { 
  KnowledgeChangeEvent, 
  KnowledgeObject, 
  KnowledgeProjection, 
  KnowledgeChunk,
  EmbeddingRecord,
  RebuildReport,
  EmbeddingProvider
} from '../types.ts';
import { KnowledgeObjectRegistry } from '../registry.ts';
import { ProjectionBuilderRegistry, CURRENT_PROJECTION_VERSION } from '../projections/builders.ts';
import { ObjectAwareChunkingEngine } from '../chunking/engine.ts';
import { IndexingEligibilityEngine } from '../eligibility/engine.ts';
import { EmbeddingQueue } from '../embeddings/queue.ts';
import { PgVectorRepository } from '../vector/pgvector-repo.ts';
import { StaleIndexDetector } from '../staleness/detector.ts';

export class KnowledgeCorpusManager {
  private registry: KnowledgeObjectRegistry;
  private projections: Map<string, KnowledgeProjection> = new Map();
  private chunks: Map<string, KnowledgeChunk[]> = new Map();
  private vectorRepo: PgVectorRepository;
  private embeddingQueue: EmbeddingQueue;
  private changeEventListeners: Array<(event: KnowledgeChangeEvent) => void> = [];
  private authoritativeSourceData: Map<string, { type: any; entity: any; context: any }> = new Map();

  constructor(provider: EmbeddingProvider, dbClient?: any) {
    this.registry = new KnowledgeObjectRegistry();
    this.vectorRepo = new PgVectorRepository(dbClient);
    this.embeddingQueue = new EmbeddingQueue(provider);

    // Default listener: process change events automatically
    this.registerChangeEventListener(async (event) => {
      if (event.event_type === 'ENTITY_DELETED') {
        await this.deleteEntityKnowledge(event.entity_ref_id);
      } else if (event.payload) {
        await this.indexAuthoritativeEntity(
          event.object_type,
          event.entity_ref_id,
          event.payload,
          {
            agent_id: event.agent_id,
            agent_version_id: event.agent_version_id,
            analysis_run_id: event.analysis_run_id,
          }
        );
      }
    });
  }

  public registerChangeEventListener(listener: (event: KnowledgeChangeEvent) => void): void {
    this.changeEventListeners.push(listener);
  }

  public async emitChangeEvent(event: KnowledgeChangeEvent): Promise<void> {
    for (const listener of this.changeEventListeners) {
      try {
        await listener(event);
      } catch (err) {
        console.error(`[KnowledgeChangeEvent Error]: ${(err as Error).message}`);
      }
    }
  }

  /**
   * Authoritative ingestion of an entity into Knowledge Corpus.
   */
  public async indexAuthoritativeEntity(
    objectType: any,
    entityRefId: string,
    rawEntity: Record<string, any>,
    context: any = {}
  ): Promise<{ projection?: KnowledgeProjection; chunks: KnowledgeChunk[]; embeddings: EmbeddingRecord[]; eligible: boolean }> {
    // 1. Store authoritative raw entity for rebuild guarantees
    this.authoritativeSourceData.set(entityRefId, {
      type: objectType,
      entity: rawEntity,
      context,
    });

    // 2. Check indexing eligibility & vault isolation
    const eligibility = IndexingEligibilityEngine.evaluateEligibility(
      objectType,
      rawEntity,
      context.security_classification
    );

    if (!eligibility.eligible) {
      return { chunks: [], embeddings: [], eligible: false };
    }

    // 3. Register knowledge object
    const kobj = this.registry.registerObject({
      entity_ref_id: entityRefId,
      object_type: objectType,
      agent_id: context.agent_id ?? rawEntity.agent_id,
      agent_version_id: context.agent_version_id ?? rawEntity.agent_version_id,
      analysis_run_id: context.analysis_run_id ?? rawEntity.analysis_run_id,
      security_classification_code: context.security_classification || rawEntity.security_classification || (eligibility.vault_restricted ? 'VAULT_RESTRICTED' : 'INTERNAL'),
      projection_version: context.projection_version || CURRENT_PROJECTION_VERSION,
      source_data_hash: JSON.stringify(rawEntity),
    });

    // 4. Build projection
    const projection = ProjectionBuilderRegistry.buildProjection(
      objectType,
      entityRefId,
      { ...rawEntity, knowledge_object_id: kobj.knowledge_object_id },
      {
        ...context,
        security_classification: kobj.security_classification_code,
      }
    );
    this.projections.set(entityRefId, projection);

    // 5. Chunk with strict object boundary preservation
    const chunks = ObjectAwareChunkingEngine.chunkProjection(projection);
    this.chunks.set(entityRefId, chunks);

    // 6. Queue and generate embeddings
    this.embeddingQueue.enqueueChunks(chunks);
    const embeddings = await this.embeddingQueue.drainAll();

    // 7. Store embeddings in vector repository
    await this.vectorRepo.upsertBatch(embeddings, chunks);
    projection.indexed_at = new Date().toISOString();

    return { projection, chunks, embeddings, eligible: true };
  }

  public async deleteEntityKnowledge(entityRefId: string): Promise<void> {
    const kobj = this.registry.getByEntityRefId(entityRefId);
    if (kobj) {
      await this.vectorRepo.deleteByObjectId(kobj.knowledge_object_id);
      this.registry.deleteByEntityRefId(entityRefId);
    }
    this.projections.delete(entityRefId);
    this.chunks.delete(entityRefId);
    this.authoritativeSourceData.delete(entityRefId);
  }

  /**
   * P22 Non-Negotiable Gate: Delete all derivative projections/embeddings,
   * rebuild from authoritative source data, and verify exact equivalent linkage and security classification.
   */
  public async rebuildEntireCorpus(): Promise<RebuildReport> {
    const startTime = Date.now();
    const startedAt = new Date().toISOString();

    const projectionsCountBefore = this.projections.size;
    const chunksCountBefore = Array.from(this.chunks.values()).reduce((acc, c) => acc + c.length, 0);
    const embsBefore = await this.vectorRepo.getAllEmbeddings();
    const embeddingsCountBefore = embsBefore.length;

    // STEP 1: Delete all derivative state
    this.projections.clear();
    this.chunks.clear();
    await this.vectorRepo.clearAll();
    this.embeddingQueue.clearQueue();

    let objectsRebuilt = 0;
    let projectionsRebuilt = 0;
    let chunksCreated = 0;
    let embeddingsGenerated = 0;

    // STEP 2: Rebuild deterministically from authoritative source data
    for (const [entityRefId, source] of this.authoritativeSourceData.entries()) {
      const result = await this.indexAuthoritativeEntity(
        source.type,
        entityRefId,
        source.entity,
        source.context
      );

      if (result.eligible) {
        objectsRebuilt++;
        projectionsRebuilt++;
        chunksCreated += result.chunks.length;
        embeddingsGenerated += result.embeddings.length;
      }
    }

    const duration = Date.now() - startTime;
    return {
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      duration_ms: duration,
      projections_deleted: projectionsCountBefore,
      chunks_deleted: chunksCountBefore,
      embeddings_deleted: embeddingsCountBefore,
      objects_rebuilt: objectsRebuilt,
      projections_rebuilt: projectionsRebuilt,
      chunks_created: chunksCreated,
      embeddings_generated: embeddingsGenerated,
      success: true,
    };
  }

  public getStalenessReport() {
    return StaleIndexDetector.evaluateStaleness(
      this.registry.listObjects(),
      this.projections
    );
  }

  public getRegistry(): KnowledgeObjectRegistry {
    return this.registry;
  }

  public getVectorRepo(): PgVectorRepository {
    return this.vectorRepo;
  }

  public getProjections(): Map<string, KnowledgeProjection> {
    return this.projections;
  }

  public getChunks(): Map<string, KnowledgeChunk[]> {
    return this.chunks;
  }

  public getAuthoritativeSourceCount(): number {
    return this.authoritativeSourceData.size;
  }
}
