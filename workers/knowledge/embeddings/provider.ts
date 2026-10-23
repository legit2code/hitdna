import crypto from 'crypto';
import { 
  EmbeddingProvider, 
  EmbeddingOptions, 
  EmbeddingResult,
  EmbeddingProviderStatus
} from '../types.ts';
import { GoogleGenAI } from '@google/genai';

export const GEMINI_EMBEDDING_MODEL = 'gemini-embedding-2-preview';
export const DEFAULT_EMBEDDING_DIMENSIONS = 768;

/**
 * Deterministic semantic hashing fallback when API keys are absent or running in offline test mode.
 */
export function generateDeterministicVector(text: string, dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS): number[] {
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
  const vector = new Array(dimensions).fill(0);

  if (words.length === 0) {
    vector[0] = 1.0;
    return vector;
  }

  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const hash = crypto.createHash('sha256').update(word).digest();
    
    // Distribute hash bytes into dimensions
    for (let b = 0; b < hash.length; b += 2) {
      const idx = (hash[b] * 256 + hash[b + 1]) % dimensions;
      const weight = ((hash[b % 16] - 128) / 128) * (1 / Math.sqrt(i + 1));
      vector[idx] += weight;
    }
  }

  // Normalize vector to unit length (L2 norm)
  let normSq = 0;
  for (let d = 0; d < dimensions; d++) {
    normSq += vector[d] * vector[d];
  }
  const norm = Math.sqrt(normSq) || 1.0;
  for (let d = 0; d < dimensions; d++) {
    vector[d] = Number((vector[d] / norm).toFixed(6));
  }

  return vector;
}

/**
 * Gemini Embedding Provider implementing Google GenAI SDK.
 */
export class GeminiEmbeddingProvider implements EmbeddingProvider {
  public readonly modelName: string;
  public readonly dimensions: number;
  public readonly status: EmbeddingProviderStatus;
  private client: GoogleGenAI | null = null;

  constructor(apiKey?: string, modelName: string = GEMINI_EMBEDDING_MODEL, dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS) {
    this.modelName = modelName;
    this.dimensions = dimensions;
    const key = apiKey || process.env.GEMINI_API_KEY;
    if (process.env.NODE_ENV === 'production' && !key) {
      throw new Error('[FATAL PRODUCTION ERROR] Gemini API key is missing. Production mode requires a valid GEMINI_API_KEY.');
    }
    if (key) {
      this.client = new GoogleGenAI({ apiKey: key });
      this.status = 'CONFIGURED';
    } else {
      this.status = 'NOT_CONFIGURED';
    }
  }

  public isConfigured(): boolean {
    return this.status === 'CONFIGURED' && this.client !== null;
  }

  public async generateEmbedding(text: string, options: EmbeddingOptions = {}): Promise<EmbeddingResult> {
    const results = await this.generateEmbeddings([text], options);
    return results[0];
  }

  public async generateEmbeddings(texts: string[], options: EmbeddingOptions = {}): Promise<EmbeddingResult[]> {
    if (!texts.length) return [];

    const dim = options.outputDimensionality || this.dimensions;

    if (this.status === 'NOT_CONFIGURED' || !this.client) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('[FATAL PRODUCTION ERROR] Gemini embedding provider is NOT_CONFIGURED. Silent substitution of mock embeddings is forbidden in production.');
      }
      throw new Error('[EMBEDDING_NOT_CONFIGURED] Gemini embedding provider is NOT_CONFIGURED. Semantic embeddings cannot be generated without an API key.');
    }

    // Use Gemini client
    try {
      const results: EmbeddingResult[] = [];
      for (const text of texts) {
        // Call modern @google/genai embedding endpoint
        const response = await (this.client as any).models.embedContent({
          model: this.modelName,
          contents: text,
          config: {
            outputDimensionality: dim,
            taskType: options.taskType || 'RETRIEVAL_DOCUMENT',
          },
        });

        const values: number[] = response.embedding?.values || [];
        if (values.length !== dim) {
          if (process.env.NODE_ENV === 'production') {
            throw new Error(`[FATAL PRODUCTION ERROR] Gemini embedding returned dimension mismatch: expected ${dim}, got ${values.length}`);
          }
        }
        results.push({
          vector: values,
          dimensions: dim,
          tokenCount: Math.ceil(text.length / 4),
          model: this.modelName,
        });
      }
      return results;
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error(`[FATAL PRODUCTION ERROR] Gemini embedding generation failed in production: ${(err as Error).message}`);
      }
      throw err;
    }
  }
}

/**
 * Explicit Deterministic Provider for unit testing and offline development.
 */
export class DeterministicMockEmbeddingProvider implements EmbeddingProvider {
  public readonly modelName = 'mock-gemini-emb-v1';
  public readonly dimensions: number;
  public readonly status: EmbeddingProviderStatus = 'MOCK_TEST_ONLY';

  constructor(dimensions: number = DEFAULT_EMBEDDING_DIMENSIONS) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('[FATAL PRODUCTION ERROR] DeterministicMockEmbeddingProvider is strictly prohibited in production mode.');
    }
    this.dimensions = dimensions;
  }

  public isConfigured(): boolean {
    return process.env.NODE_ENV !== 'production';
  }

  public async generateEmbedding(text: string, options: EmbeddingOptions = {}): Promise<EmbeddingResult> {
    const dim = options.outputDimensionality || this.dimensions;
    return {
      vector: generateDeterministicVector(text, dim),
      dimensions: dim,
      tokenCount: Math.ceil(text.length / 4),
      model: this.modelName,
    };
  }

  public async generateEmbeddings(texts: string[], options: EmbeddingOptions = {}): Promise<EmbeddingResult[]> {
    return Promise.all(texts.map((t) => this.generateEmbedding(t, options)));
  }
}
