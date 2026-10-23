import { 
  FrameworkFingerprint, 
  FrameworkCategory, 
  FrameworkEvidence, 
  SourceSpan 
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

interface FrameworkRule {
  name: string;
  category: FrameworkCategory;
  matchers: Array<{
    type: 'IMPORT' | 'MANIFEST_DEPENDENCY' | 'DECORATOR' | 'API_USAGE' | 'CONFIG_FILE';
    pattern: RegExp | string;
    description: string;
  }>;
}

export class FrameworkDetector {
  private static readonly RULES: FrameworkRule[] = [
    // 1. LangChain
    {
      name: 'LangChain',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?(@langchain\/|langchain)/, description: 'Import from LangChain package' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:@langchain\/core|langchain|langchain-community)/, description: 'LangChain in manifest dependencies' },
        { type: 'API_USAGE', pattern: /(?:ChatOpenAI|LLMChain|AgentExecutor|RunnableSequence)/, description: 'LangChain core abstractions invocation' },
      ],
    },
    // 2. LlamaIndex
    {
      name: 'LlamaIndex',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?(llama_index|llama-index|llamaindex)/, description: 'Import from LlamaIndex package' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:llama-index|llama_index|llamaindex)/, description: 'LlamaIndex in manifest dependencies' },
        { type: 'API_USAGE', pattern: /(?:VectorStoreIndex|SimpleDirectoryReader|OpenAIAgent)/, description: 'LlamaIndex index and agent usage' },
      ],
    },
    // 3. AutoGen
    {
      name: 'AutoGen',
      category: 'MULTI_AGENT',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?(autogen|pyautogen)/, description: 'Import from AutoGen package' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:pyautogen|autogen-agentchat)/, description: 'AutoGen manifest dependency' },
        { type: 'API_USAGE', pattern: /(?:ConversableAgent|UserProxyAgent|AssistantAgent|GroupChat)/, description: 'AutoGen multi-agent chat architecture' },
      ],
    },
    // 4. CrewAI
    {
      name: 'CrewAI',
      category: 'MULTI_AGENT',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?crewai/, description: 'Import from CrewAI package' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /crewai/, description: 'CrewAI manifest dependency' },
        { type: 'API_USAGE', pattern: /(?:Agent\(|Task\(|Crew\(|Process\.sequential)/, description: 'CrewAI Agent, Task, and Crew definitions' },
      ],
    },
    // 5. Semantic Kernel
    {
      name: 'Semantic Kernel',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?(semantic_kernel|semantic-kernel|microsoft-semantic-kernel)/, description: 'Semantic Kernel package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:semantic-kernel|microsoft-semantic-kernel)/, description: 'Semantic Kernel dependency in manifest' },
        { type: 'API_USAGE', pattern: /(?:Kernel\(|kernel\.add_service|sk_function)/, description: 'Semantic Kernel orchestration API' },
      ],
    },
    // 6. LangGraph
    {
      name: 'LangGraph',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?(langgraph|@langchain\/langgraph)/, description: 'LangGraph package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:langgraph|@langchain\/langgraph)/, description: 'LangGraph dependency' },
        { type: 'API_USAGE', pattern: /(?:StateGraph|END|START|compile\(|add_node)/, description: 'StateGraph cyclic graph execution' },
      ],
    },
    // 7. Haystack
    {
      name: 'Haystack',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?haystack/, description: 'Haystack package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:farm-haystack|haystack-ai)/, description: 'Haystack manifest dependency' },
        { type: 'API_USAGE', pattern: /(?:Pipeline\(|component\(|OpenAIGenerator)/, description: 'Haystack 2.x pipeline orchestration' },
      ],
    },
    // 8. DSPy
    {
      name: 'DSPy',
      category: 'LLM_ORCHESTRATOR',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?dspy/, description: 'DSPy package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /(?:dspy|dspy-ai)/, description: 'DSPy manifest dependency' },
        { type: 'API_USAGE', pattern: /(?:dspy\.Signature|dspy\.Predict|dspy\.ChainOfThought)/, description: 'DSPy signature programming abstractions' },
      ],
    },
    // 9. Smolagents
    {
      name: 'Smolagents',
      category: 'AGENT_FRAMEWORK',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?smolagents/, description: 'Hugging Face Smolagents package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /smolagents/, description: 'Smolagents manifest dependency' },
        { type: 'API_USAGE', pattern: /(?:CodeAgent|ToolCallingAgent|HfApiModel)/, description: 'Smolagents CodeAgent execution' },
      ],
    },
    // 10. FastAPI
    {
      name: 'FastAPI',
      category: 'BACKEND_WEB',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?fastapi/, description: 'FastAPI package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /fastapi/, description: 'FastAPI dependency in requirements/pyproject' },
        { type: 'API_USAGE', pattern: /(?:FastAPI\(|APIRouter\(|@app\.get|@router\.post)/, description: 'FastAPI application router and decorators' },
      ],
    },
    // 11. Express
    {
      name: 'Express',
      category: 'BACKEND_WEB',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|require\()\s*['"]express['"]/, description: 'Express module import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /^express$/, description: 'Express dependency in package.json' },
        { type: 'API_USAGE', pattern: /(?:express\(|app\.use\(|app\.listen\()/, description: 'Express server instance and middleware' },
      ],
    },
    // 12. NestJS
    {
      name: 'NestJS',
      category: 'BACKEND_WEB',
      matchers: [
        { type: 'IMPORT', pattern: /@nestjs\//, description: 'NestJS module import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /@nestjs\/core/, description: 'NestJS core dependency' },
        { type: 'DECORATOR', pattern: /(?:@Controller|@Injectable|@Module)/, description: 'NestJS IoC and Controller decorators' },
      ],
    },
    // 13. Flask
    {
      name: 'Flask',
      category: 'BACKEND_WEB',
      matchers: [
        { type: 'IMPORT', pattern: /(?:from|import)\s+['"]?flask/, description: 'Flask package import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /^flask$/i, description: 'Flask dependency' },
        { type: 'API_USAGE', pattern: /(?:Flask\(__name__\)|@app\.route)/, description: 'Flask application and route decorator' },
      ],
    },
    // 14. Gin (Go)
    {
      name: 'Gin',
      category: 'BACKEND_WEB',
      matchers: [
        { type: 'IMPORT', pattern: /github\.com\/gin-gonic\/gin/, description: 'Gin HTTP web framework import' },
        { type: 'MANIFEST_DEPENDENCY', pattern: /github\.com\/gin-gonic\/gin/, description: 'Gin in go.mod' },
        { type: 'API_USAGE', pattern: /(?:gin\.Default\(\)|gin\.New\(\)|r\.GET\(|r\.POST\()/, description: 'Gin engine and route bindings' },
      ],
    },
  ];

  /**
   * Scans source code and manifest dependencies to identify active frameworks
   */
  public static detect(
    filePath: string,
    sourceText: string,
    dependencies: Array<{ name: string; version: string; kind: string }> = []
  ): FrameworkFingerprint[] {
    const fingerprints: FrameworkFingerprint[] = [];
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);

    for (const rule of this.RULES) {
      const evidenceList: FrameworkEvidence[] = [];
      let detectedVersion: string | undefined;

      // 1. Check manifest dependencies
      for (const dep of dependencies) {
        const depMatcher = rule.matchers.find(m => m.type === 'MANIFEST_DEPENDENCY');
        if (depMatcher) {
          const isMatch = typeof depMatcher.pattern === 'string'
            ? dep.name === depMatcher.pattern
            : depMatcher.pattern.test(dep.name);

          if (isMatch) {
            detectedVersion = dep.version;
            evidenceList.push({
              type: 'MANIFEST_DEPENDENCY',
              description: `Dependency "${dep.name}" (${dep.version}) declared in manifest`,
            });
          }
        }
      }

      // 2. Check source text matchers
      for (const matcher of rule.matchers) {
        if (matcher.type === 'MANIFEST_DEPENDENCY') continue;

        if (typeof matcher.pattern === 'string') {
          if (sourceText.includes(matcher.pattern)) {
            const idx = sourceText.indexOf(matcher.pattern);
            const span = SourceSpanUtil.offsetToSpan(filePath, sourceText, idx, idx + matcher.pattern.length, lineStarts, rule.name);
            evidenceList.push({
              type: matcher.type,
              description: matcher.description,
              span,
            });
          }
        } else {
          const regex = new RegExp(matcher.pattern.source, 'g');
          const match = regex.exec(sourceText);
          if (match) {
            const span = SourceSpanUtil.offsetToSpan(filePath, sourceText, match.index, match.index + match[0].length, lineStarts, rule.name);
            evidenceList.push({
              type: matcher.type,
              description: matcher.description,
              span,
            });
          }
        }
      }

      if (evidenceList.length > 0) {
        // Calculate confidence based on evidence richness
        let confidence = 0.7;
        if (evidenceList.some(e => e.type === 'MANIFEST_DEPENDENCY')) confidence += 0.2;
        if (evidenceList.some(e => e.type === 'IMPORT')) confidence += 0.1;
        if (evidenceList.some(e => e.type === 'API_USAGE' || e.type === 'DECORATOR')) confidence += 0.1;
        confidence = Math.min(1.0, confidence);

        fingerprints.push({
          framework_name: rule.name,
          framework_category: rule.category,
          detected_version: detectedVersion,
          confidence,
          evidence: evidenceList,
        });
      }
    }

    return fingerprints;
  }
}
