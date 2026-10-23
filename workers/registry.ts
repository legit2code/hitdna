export interface WorkerContract {
  name: string;
  domain: string;
  status: 'IDLE' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  isHeavyWorker: boolean;
}

export const WORKER_REGISTRY: Record<string, WorkerContract> = {
  discovery: { name: 'discovery-worker', domain: 'Discovery', status: 'IDLE', isHeavyWorker: false },
  semantic: { name: 'semantic-worker', domain: 'Semantic', status: 'IDLE', isHeavyWorker: true },
  'static-analysis': { name: 'static-analysis-worker', domain: 'StaticAnalysis', status: 'IDLE', isHeavyWorker: true },
  composition: { name: 'composition-worker', domain: 'Composition', status: 'IDLE', isHeavyWorker: false },
  'sandbox-orchestrator': { name: 'sandbox-orchestrator-worker', domain: 'DynamicSandbox', status: 'IDLE', isHeavyWorker: true },
  decision: { name: 'decision-worker', domain: 'EvidenceRisk', status: 'IDLE', isHeavyWorker: false },
  knowledge: { name: 'knowledge-worker', domain: 'KnowledgeRAG', status: 'IDLE', isHeavyWorker: true },
  lifecycle: { name: 'lifecycle-worker', domain: 'LifecycleShipping', status: 'IDLE', isHeavyWorker: false },
  evaluation: { name: 'evaluation-worker', domain: 'Evaluation', status: 'IDLE', isHeavyWorker: true },
};
