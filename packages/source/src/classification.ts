import crypto from 'crypto';
import {
  ArtifactClassification,
  ArtifactTaxonomyCategory,
  ClassificationSignal,
  DiscoveryCandidate,
  SourceMetadataResult,
  ResolvedArtifactLocatorsResult,
} from './types.ts';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

export interface ClassificationInput {
  candidate: DiscoveryCandidate | {
    source_locator: string;
    display_name?: string;
    source_type?: string;
    summary?: string;
    raw_metadata?: Record<string, unknown>;
  };
  metadata?: SourceMetadataResult;
  artifacts?: ResolvedArtifactLocatorsResult;
}

export class ArtifactClassifier {
  readonly classifierVersion = '1.0.0';

  /**
   * Classifies an artifact or discovery candidate into the CAIM taxonomy with confidence breakdown.
   */
  classify(input: ClassificationInput): ArtifactClassification {
    const cand = input.candidate;
    const meta = input.metadata?.raw_metadata || cand.raw_metadata || {};
    const textBlob = [
      cand.source_locator || '',
      cand.display_name || '',
      cand.summary || '',
      JSON.stringify(meta),
    ].join(' ').toLowerCase();

    const artifactFilenames = input.artifacts?.artifacts.map(a => (a.filename || a.locator).toLowerCase()) || [];

    const signals: ClassificationSignal[] = [];
    const scores: Record<ArtifactTaxonomyCategory, number> = {
      AUTONOMOUS_AGENT: 0,
      AGENT_FRAMEWORK_SDK: 0,
      REASONING_MODEL: 0,
      TOOL_OR_PLUGIN: 0,
      CONTAINER_SANDBOX: 0,
      AGENT_SPECIFICATION: 0,
      EVALUATION_BENCHMARK: 0,
      UNKNOWN_OR_UNCLASSIFIED: 0.1,
    };

    // 1. REASONING_MODEL Signals
    const isModelSource = cand.source_type === 'huggingface' || (cand.source_locator && cand.source_locator.startsWith('hf://'));
    const hasSafetensors = artifactFilenames.some(f => f.endsWith('.safetensors') || f.endsWith('.gguf') || f.endsWith('.bin'));
    const hasModelTag = textBlob.includes('safetensors') || textBlob.includes('base_model') || textBlob.includes('pipeline_tag');

    if (isModelSource) {
      signals.push({ feature: 'SOURCE_HUGGINGFACE', weight: 0.4, matched: true, evidence: 'Originates from Hugging Face model repository' });
      scores.REASONING_MODEL += 0.4;
    }
    if (hasSafetensors) {
      signals.push({ feature: 'WEIGHTS_ARTIFACTS', weight: 0.45, matched: true, evidence: `Contains weights file: ${artifactFilenames.find(f => f.endsWith('.safetensors') || f.endsWith('.gguf'))}` });
      scores.REASONING_MODEL += 0.45;
    }
    if (hasModelTag) {
      signals.push({ feature: 'MODEL_TAGS', weight: 0.25, matched: true, evidence: 'Metadata contains model tags/pipeline metadata' });
      scores.REASONING_MODEL += 0.25;
    }

    // 2. CONTAINER_SANDBOX Signals
    const isDockerSource = cand.source_type === 'dockerhub' || (cand.source_locator && cand.source_locator.startsWith('docker://'));
    const hasDockerTerms = textBlob.includes('docker') || textBlob.includes('sandbox') || textBlob.includes('container') || textBlob.includes('oci');

    if (isDockerSource) {
      signals.push({ feature: 'SOURCE_DOCKERHUB', weight: 0.6, matched: true, evidence: 'Originates from Docker Hub / OCI container registry' });
      scores.CONTAINER_SANDBOX += 0.6;
    }
    if (hasDockerTerms && isDockerSource) {
      signals.push({ feature: 'SANDBOX_CONTAINER_META', weight: 0.35, matched: true, evidence: 'Metadata references container sandbox runtime' });
      scores.CONTAINER_SANDBOX += 0.35;
    }

    // 3. AGENT_SPECIFICATION Signals
    const hasSpecTerms = textBlob.includes('caim specification') || textBlob.includes('ontology') || textBlob.includes('schema.json') || textBlob.includes('manifest');
    const hasSpecFile = artifactFilenames.some(f => f.includes('caim.json') || f.includes('schema') || f.includes('ontology'));

    if (hasSpecTerms) {
      signals.push({ feature: 'ONTOLOGY_TERMS', weight: 0.45, matched: true, evidence: 'Text references CAIM specification or ontology standards' });
      scores.AGENT_SPECIFICATION += 0.45;
    }
    if (hasSpecFile) {
      signals.push({ feature: 'SPEC_FILE', weight: 0.4, matched: true, evidence: 'Artifacts include ontology/schema definition files' });
      scores.AGENT_SPECIFICATION += 0.4;
    }

    // 4. TOOL_OR_PLUGIN Signals
    const hasMcpTerms = textBlob.includes('mcp') || textBlob.includes('model context protocol') || textBlob.includes('plugin') || textBlob.includes('tool server');
    if (hasMcpTerms) {
      signals.push({ feature: 'MCP_OR_TOOL_TERMS', weight: 0.55, matched: true, evidence: 'Discovered Model Context Protocol or plugin tool indicators' });
      scores.TOOL_OR_PLUGIN += 0.55;
    }

    // 5. EVALUATION_BENCHMARK Signals
    const hasEvalTerms = textBlob.includes('benchmark') || textBlob.includes('evaluation corpus') || textBlob.includes('eval suite') || textBlob.includes('golden dataset');
    if (hasEvalTerms) {
      signals.push({ feature: 'EVAL_TERMS', weight: 0.5, matched: true, evidence: 'Contains benchmark and evaluation corpus terminology' });
      scores.EVALUATION_BENCHMARK += 0.5;
    }

    // 6. AGENT_FRAMEWORK_SDK Signals
    const isPackageSource = cand.source_type === 'pypi' || cand.source_type === 'npm';
    const hasSdkTerms = textBlob.includes('sdk') || textBlob.includes('framework') || textBlob.includes('client library') || textBlob.includes('toolkit');

    if (isPackageSource && hasSdkTerms) {
      signals.push({ feature: 'PACKAGE_SDK', weight: 0.5, matched: true, evidence: 'Package registry distribution with SDK/framework classification' });
      scores.AGENT_FRAMEWORK_SDK += 0.5;
    } else if (isPackageSource) {
      signals.push({ feature: 'PACKAGE_SOURCE', weight: 0.3, matched: true, evidence: 'Distributed via PyPI or npm registry' });
      scores.AGENT_FRAMEWORK_SDK += 0.3;
    }

    // 7. AUTONOMOUS_AGENT Signals
    const hasAutonomousTerms = textBlob.includes('autonomous agent') || textBlob.includes('autonomous caim agent') || textBlob.includes('planning') || textBlob.includes('reasoning agent');
    const isGitRepo = cand.source_type === 'github' || cand.source_type === 'gitlab' || cand.source_type === 'codeberg';

    if (hasAutonomousTerms) {
      signals.push({ feature: 'AUTONOMOUS_TERMS', weight: 0.55, matched: true, evidence: 'Explicitly declares autonomous agent architecture' });
      scores.AUTONOMOUS_AGENT += 0.55;
    }
    if (isGitRepo && hasAutonomousTerms) {
      signals.push({ feature: 'AGENT_REPO_COMPOSITE', weight: 0.35, matched: true, evidence: 'Source repository with autonomous agent implementation' });
      scores.AUTONOMOUS_AGENT += 0.35;
    }

    // Rank categories by computed score
    const entries = (Object.entries(scores) as Array<[ArtifactTaxonomyCategory, number]>)
      .map(([cat, rawScore]) => ({ category: cat, confidence: Math.min(1.0, Number(rawScore.toFixed(2))) }))
      .sort((a, b) => b.confidence - a.confidence);

    const primary = entries[0].confidence > 0.3 ? entries[0] : { category: 'UNKNOWN_OR_UNCLASSIFIED' as ArtifactTaxonomyCategory, confidence: 0.3 };
    const secondary = entries.slice(1).filter(e => e.confidence >= 0.25 && e.category !== primary.category);

    const rationale = `Classified as ${primary.category} (confidence: ${(primary.confidence * 100).toFixed(0)}%) based on ${signals.filter(s => s.matched).length} matching signal(s).`;

    const inputHash = crypto.createHash('sha256').update(cand.source_locator + ':' + primary.category).digest('hex');

    const provenance: ProvenanceRecord = ProvenanceRecordSchema.parse({
      provenance_id: crypto.randomUUID(),
      source_spans: [],
      input_hashes: [inputHash],
      rule_id: 'ARTIFACT_CLASSIFICATION_TAXONOMY_V1',
      ruleset_version: this.classifierVersion,
      transformation_type: 'CALIBRATED_INFERENCE',
      confidence: primary.confidence,
      derived_at: new Date().toISOString(),
      engine_signature: `caim:classifier:taxonomy:v${this.classifierVersion}`,
    });

    return {
      primary_category: primary.category,
      confidence: primary.confidence,
      secondary_categories: secondary,
      signals,
      rationale,
      classified_at: new Date().toISOString(),
      provenance,
    };
  }
}
