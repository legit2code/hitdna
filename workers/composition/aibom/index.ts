/**
 * AI-BOM (AI Bill of Materials) Model Card, Dataset, Framework & Prompt Extraction Engine
 * Standard: CycloneDX AI/ML Extension / CAIM AI-BOM Specification
 */

import { 
  AIBOMReport, 
  AIModelDescriptor, 
  AIDatasetDescriptor, 
  AIFrameworkDescriptor, 
  AIPromptTemplateDescriptor,
  DependencyGraph 
} from '../types.ts';
import { SourceSpan } from '@caim/syntax/types.ts';

function makeSpan(
  filePath: string,
  startLine: number,
  startCol: number,
  endLine: number,
  endCol: number,
  textSlice?: string,
  symbolHint?: string
): SourceSpan {
  return {
    file_path: filePath,
    start_line: startLine,
    start_col: startCol,
    end_line: endLine,
    end_col: endCol,
    byte_offset_start: 0,
    byte_offset_end: 0,
    text_slice: textSlice,
    symbol_hint: symbolHint,
  };
}

export class AIBOMExtractor {
  private static readonly KNOWN_FRAMEWORKS: Array<{ name: AIFrameworkDescriptor['name']; regex: RegExp }> = [
    { name: 'langchain', regex: /(?:from|import)\s+['"]?langchain/i },
    { name: 'llamaindex', regex: /(?:from|import)\s+['"]?(?:llama_index|llamaindex)/i },
    { name: 'transformers', regex: /(?:from|import)\s+['"]?transformers/i },
    { name: 'pytorch', regex: /(?:from|import)\s+['"]?torch/i },
    { name: 'tensorflow', regex: /(?:from|import)\s+['"]?tensorflow/i },
    { name: 'vllm', regex: /(?:from|import)\s+['"]?vllm/i },
    { name: 'ollama', regex: /(?:from|import)\s+['"]?ollama/i },
    { name: 'litellm', regex: /(?:from|import)\s+['"]?litellm/i },
    { name: 'dspy', regex: /(?:from|import)\s+['"]?dspy/i },
    { name: 'crewai', regex: /(?:from|import)\s+['"]?crewai/i },
    { name: 'autogen', regex: /(?:from|import)\s+['"]?autogen/i },
  ];

  private static readonly MODEL_PATTERNS: Array<{
    provider: AIModelDescriptor['provider'];
    regex: RegExp;
    family: string;
    task: AIModelDescriptor['task_type'];
  }> = [
    { provider: 'openai', regex: /['"](?:gpt-4o|gpt-4-turbo|gpt-4|gpt-3\.5-turbo|o1-preview|o1-mini|text-embedding-3-small|text-embedding-3-large)['"]/i, family: 'GPT', task: 'chat' },
    { provider: 'anthropic', regex: /['"](?:claude-3-5-sonnet|claude-3-opus|claude-3-haiku|claude-2\.1)['"]/i, family: 'Claude', task: 'chat' },
    { provider: 'google', regex: /['"](?:gemini-1\.5-pro|gemini-1\.5-flash|gemini-2\.0-flash|text-embedding-004)['"]/i, family: 'Gemini', task: 'multimodal' },
    { provider: 'meta', regex: /['"](?:meta-llama\/Llama-3-8B|meta-llama\/Llama-3-70B|llama-2-7b|llama-3-8b-instruct)['"]/i, family: 'Llama', task: 'chat' },
    { provider: 'mistral', regex: /['"](?:mistral-7b|mixtral-8x7b|mistral-large|codestral)['"]/i, family: 'Mistral', task: 'chat' },
    { provider: 'huggingface', regex: /['"]([a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-\.]+)['"]/i, family: 'HuggingFace', task: 'completion' },
  ];

  /**
   * Extracts AI-BOM metadata from file contents and dependency graphs
   */
  public static extract(
    files: Map<string, string>,
    depGraph?: DependencyGraph
  ): AIBOMReport {
    const modelsMap: Map<string, AIModelDescriptor> = new Map();
    const datasetsMap: Map<string, AIDatasetDescriptor> = new Map();
    const frameworksMap: Map<string, AIFrameworkDescriptor> = new Map();
    const promptTemplates: AIPromptTemplateDescriptor[] = [];
    let hasLocalWeights = false;

    // 1. Framework discovery from Dependencies
    if (depGraph) {
      for (const comp of depGraph.all_components) {
        const cName = comp.name.toLowerCase();
        for (const kw of AIBOMExtractor.KNOWN_FRAMEWORKS) {
          if (cName.includes(kw.name)) {
            frameworksMap.set(kw.name, {
              framework_id: `fw-${kw.name}`,
              name: kw.name,
              version: comp.resolved_version || comp.version,
              source_file: 'manifest',
              purl: comp.purl,
              modules_used: [],
            });
          }
        }
      }
    }

    // 2. Scan file contents
    for (const [filePath, content] of files.entries()) {
      const lines = content.split('\n');

      // Check for local weights file formats
      const lowPath = filePath.toLowerCase();
      if (lowPath.endsWith('.gguf') || lowPath.endsWith('.safetensors') || lowPath.endsWith('.onnx') || lowPath.endsWith('.pt') || lowPath.endsWith('.bin')) {
        hasLocalWeights = true;
        const format = lowPath.split('.').pop() as any;
        const modelName = filePath.split('/').pop() || filePath;
        modelsMap.set(filePath, {
          model_id: `model-${modelName}`,
          name: modelName,
          provider: 'local',
          source_file: filePath,
          is_local_weight: true,
          format,
          task_type: 'chat',
        });
      }

      // Framework discovery in code
      for (const kw of AIBOMExtractor.KNOWN_FRAMEWORKS) {
        if (kw.regex.test(content)) {
          if (!frameworksMap.has(kw.name)) {
            frameworksMap.set(kw.name, {
              framework_id: `fw-${kw.name}`,
              name: kw.name,
              source_file: filePath,
              modules_used: [],
            });
          }
        }
      }

      // Line-by-line model, dataset & prompt extraction
      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        const lineNum = i + 1;

        // Model references
        for (const pattern of AIBOMExtractor.MODEL_PATTERNS) {
          const match = lineText.match(pattern.regex);
          if (match) {
            const rawModel = match[0].replace(/['"]/g, '');
            // Filter common false positives for huggingface regex
            if (pattern.provider === 'huggingface' && (rawModel.startsWith('http') || rawModel.includes('@') || rawModel.startsWith('src/'))) {
              continue;
            }

            if (!modelsMap.has(rawModel)) {
              modelsMap.set(rawModel, {
                model_id: `model-${rawModel.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
                name: rawModel,
                provider: pattern.provider,
                family: pattern.family,
                source_file: filePath,
                span: makeSpan(filePath, lineNum, 1, lineNum, lineText.length + 1, lineText.trim(), rawModel),
                is_local_weight: false,
                task_type: pattern.task,
              });
            }
          }
        }

        // Dataset references (e.g. load_dataset("imdb"), datasets.load_dataset("squad"))
        const datasetMatch = lineText.match(/(?:load_dataset|Dataset\.from_)\s*\(\s*['"]([a-zA-Z0-9_\-\/]+)['"]/i);
        if (datasetMatch) {
          const dsName = datasetMatch[1];
          if (!datasetsMap.has(dsName)) {
            datasetsMap.set(dsName, {
              dataset_id: `ds-${dsName.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
              name: dsName,
              source: dsName.includes('/') ? 'HuggingFace Hub' : 'Standard Library / Custom',
              source_file: filePath,
              span: makeSpan(filePath, lineNum, 1, lineNum, lineText.length + 1, lineText.trim(), dsName),
            });
          }
        }

        // System prompt and template detection
        if (/system_message|system_prompt|ChatPromptTemplate|PromptTemplate|\bSYSTEM\b/i.test(lineText)) {
          const templateMatch = lineText.match(/(?:system_prompt|template|prompt)\s*=\s*(?:["'`]{1,3})([\s\S]*?)(?:["'`]{1,3})/i);
          const snippet = templateMatch ? templateMatch[1] : lineText.trim();
          
          // Extract {var} or {{var}} variable placeholders
          const varMatches = snippet.match(/\{+([a-zA-Z0-9_]+)\}+/g) || [];
          const variables = Array.from(new Set(varMatches.map(v => v.replace(/[\{\}]/g, ''))));

          if (snippet.length > 10) {
            promptTemplates.push({
              template_id: `prompt-tmpl-${promptTemplates.length + 1}`,
              name: `Prompt Template (${filePath}:${lineNum})`,
              role: /system/i.test(lineText) ? 'system' : 'user',
              source_file: filePath,
              span: makeSpan(filePath, lineNum, 1, lineNum, lineText.length + 1, snippet.slice(0, 80), 'PromptTemplate'),
              variables,
              snippet: snippet.slice(0, 160),
            });
          }
        }
      }
    }

    const models = Array.from(modelsMap.values());
    const datasets = Array.from(datasetsMap.values());
    const frameworks = Array.from(frameworksMap.values());

    return {
      models,
      datasets,
      frameworks,
      prompt_templates: promptTemplates,
      total_models: models.length,
      total_frameworks: frameworks.length,
      total_datasets: datasets.length,
      has_local_weights: hasLocalWeights,
      ai_bill_of_materials_version: '1.0.0',
    };
  }
}
