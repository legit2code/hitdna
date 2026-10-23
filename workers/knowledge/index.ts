export * from './types.ts';
export * from './registry.ts';
export * from './projections/builders.ts';
export * from './chunking/engine.ts';
export * from './eligibility/engine.ts';
export * from './embeddings/provider.ts';
export * from './embeddings/queue.ts';
export * from './vector/pgvector-repo.ts';
export * from './staleness/detector.ts';
export * from './reindex/scheduler.ts';
export * from './bootstrap.ts';

// Retrieval Plane (P23)
export * from './retrieval/types.ts';
export * from './retrieval/understanding.ts';
export * from './retrieval/planning.ts';
export * from './retrieval/retrievers.ts';
export * from './retrieval/reranker.ts';
export * from './retrieval/service.ts';

// Context Assembly & Synthesis Plane (P24)
export * from './context/types.ts';
export * from './context/budget.ts';
export * from './context/serializer.ts';
export * from './context/bundler.ts';
export * from './context/grouping.ts';
export * from './context/isolation.ts';
export * from './context/assembler.ts';

export * from './synthesis/types.ts';
export * from './synthesis/citations.ts';
export * from './synthesis/claims.ts';
export * from './synthesis/grounding.ts';
export * from './synthesis/epistemic.ts';
export * from './synthesis/audit.ts';
export * from './synthesis/engine.ts';
export * from './synthesis/pipeline.ts';

