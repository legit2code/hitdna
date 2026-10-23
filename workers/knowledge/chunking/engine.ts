import crypto from 'crypto';
import { 
  KnowledgeChunk, 
  KnowledgeProjection 
} from '../types.ts';

export const CURRENT_CHUNKING_VERSION = 'chunk-v1-boundary';

export interface ChunkingOptions {
  maxChunkSizeChars?: number;
  overlapChars?: number;
  chunkVersion?: string;
}

export class ObjectAwareChunkingEngine {
  /**
   * Chunks a knowledge projection without ever mixing agents, versions, or security classifications.
   */
  public static chunkProjection(
    projection: KnowledgeProjection,
    options: ChunkingOptions = {}
  ): KnowledgeChunk[] {
    const maxChunkSize = options.maxChunkSizeChars || 1200;
    const overlap = options.overlapChars || 100;
    const chunkVersion = options.chunkVersion || CURRENT_CHUNKING_VERSION;

    const fullText = projection.document_text;
    const header = `[Context: Object=${projection.object_type} | Ref=${projection.entity_ref_id} | Agent=${projection.agent_id || 'none'} | Ver=${projection.agent_version_id || 'none'} | Security=${projection.security_classification}]`;

    const chunks: KnowledgeChunk[] = [];

    // If text is short, create single chunk
    if (fullText.length <= maxChunkSize) {
      const combinedText = `${header}\n${fullText}`;
      const contentHash = crypto.createHash('sha256').update(combinedText).digest('hex');
      chunks.push({
        knowledge_chunk_id: `chk-${projection.knowledge_projection_id}-0`,
        knowledge_projection_id: projection.knowledge_projection_id,
        knowledge_object_id: projection.knowledge_object_id,
        sequence: 0,
        chunk_version: chunkVersion,
        content_hash: contentHash,
        text_content: combinedText,
        token_count: Math.ceil(combinedText.length / 4),
        agent_id: projection.agent_id,
        agent_version_id: projection.agent_version_id,
        analysis_run_id: projection.analysis_run_id,
        security_classification: projection.security_classification,
        security_classification_rank: projection.security_classification_rank,
        vault_restricted: projection.vault_restricted,
        exact_keywords: { ...projection.exact_keywords, object_type: projection.object_type },
        created_at: new Date().toISOString(),
      });
      return chunks;
    }

    // Split text cleanly on paragraph / newline boundaries if possible
    let currentPos = 0;
    let seq = 0;

    while (currentPos < fullText.length) {
      let endPos = currentPos + maxChunkSize;
      if (endPos >= fullText.length) {
        endPos = fullText.length;
      } else {
        // Look for newline or whitespace near endPos
        const lastNewline = fullText.lastIndexOf('\n', endPos);
        if (lastNewline > currentPos + maxChunkSize * 0.6) {
          endPos = lastNewline;
        } else {
          const lastSpace = fullText.lastIndexOf(' ', endPos);
          if (lastSpace > currentPos + maxChunkSize * 0.6) {
            endPos = lastSpace;
          }
        }
      }

      const slice = fullText.substring(currentPos, endPos).trim();
      if (slice.length > 0) {
        const combinedText = `${header} [Part ${seq + 1}]\n${slice}`;
        const contentHash = crypto.createHash('sha256').update(combinedText).digest('hex');
        chunks.push({
          knowledge_chunk_id: `chk-${projection.knowledge_projection_id}-${seq}`,
          knowledge_projection_id: projection.knowledge_projection_id,
          knowledge_object_id: projection.knowledge_object_id,
          sequence: seq,
          chunk_version: chunkVersion,
          content_hash: contentHash,
          text_content: combinedText,
          token_count: Math.ceil(combinedText.length / 4),
          agent_id: projection.agent_id,
          agent_version_id: projection.agent_version_id,
          analysis_run_id: projection.analysis_run_id,
          security_classification: projection.security_classification,
          security_classification_rank: projection.security_classification_rank,
          vault_restricted: projection.vault_restricted,
          exact_keywords: { ...projection.exact_keywords, object_type: projection.object_type, chunk_sequence: seq },
          created_at: new Date().toISOString(),
        });
        seq++;
      }

      if (endPos >= fullText.length) {
        break;
      }
      currentPos = Math.max(endPos - overlap, currentPos + 1);
    }

    return chunks;
  }
}
