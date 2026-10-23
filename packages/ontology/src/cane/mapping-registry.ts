/**
 * CANE Source → Canonical Mapping Registry
 * P14 — Canonicalization
 * 
 * Versioned catalog of mapping rules translating language/framework AST constructs
 * into canonical CAIM entities and Ontology concepts with deterministic confidence.
 */

import { CaneMappingRule, CaneMappingMatch } from './types.ts';
import { STANDARD_CONCEPTS } from '../concepts.ts';
import { CallSiteFact, ImportFact, SymbolFact, ProtocolFact } from '../../../syntax/src/index.ts';
import { ProvenanceRecord } from '../../../contracts/src/index.ts';

export const CANE_REGISTRY_VERSION = '1.0.0';

export class CaneMappingRegistry {
  public static readonly rules: CaneMappingRule[] = [
    // -------------------------------------------------------------
    // 1. Process Execution Capability (JS/TS, Python, Go, Rust)
    // -------------------------------------------------------------
    {
      rule_id: 'CANE_MAP_EXEC_JS_CHILD_PROCESS',
      rule_name: 'Node.js child_process Execution',
      source_ecosystems: ['javascript', 'typescript'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:child_process\\.)?(?:exec|spawn|execSync|spawnSync|execFile|execFileSync|fork)$',
      target_canonical_key: 'capability.tools.exec',
      target_concept_id: STANDARD_CONCEPTS['capability.tools.exec'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.98,
      description: 'Maps Node.js child_process invocation to canonical subprocess execution capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_EXEC_PYTHON_SUBPROCESS',
      rule_name: 'Python subprocess / os.system Execution',
      source_ecosystems: ['python'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:subprocess\\.(?:Popen|run|call|check_output|check_call)|os\\.(?:system|popen|execv|execvp|execl))$',
      target_canonical_key: 'capability.tools.exec',
      target_concept_id: STANDARD_CONCEPTS['capability.tools.exec'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.98,
      description: 'Maps Python subprocess and os.system to canonical subprocess execution capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_EXEC_GO_OS_EXEC',
      rule_name: 'Go os/exec Command Execution',
      source_ecosystems: ['go'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:exec\\.(?:Command|CommandContext)|os/exec\\.(?:Command|CommandContext)|syscall\\.(?:Exec|ForkExec))$',
      target_canonical_key: 'capability.tools.exec',
      target_concept_id: STANDARD_CONCEPTS['capability.tools.exec'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.98,
      description: 'Maps Go os/exec Command execution to canonical subprocess execution capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_EXEC_RUST_COMMAND',
      rule_name: 'Rust std::process::Command Execution',
      source_ecosystems: ['rust'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:Command::new|std::process::Command::new)$',
      target_canonical_key: 'capability.tools.exec',
      target_concept_id: STANDARD_CONCEPTS['capability.tools.exec'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.98,
      description: 'Maps Rust Command execution to canonical subprocess execution capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },

    // -------------------------------------------------------------
    // 2. Network Egress / HTTP Capability
    // -------------------------------------------------------------
    {
      rule_id: 'CANE_MAP_NET_JS_FETCH_AXIOS',
      rule_name: 'JavaScript / TypeScript Outbound HTTP Call',
      source_ecosystems: ['javascript', 'typescript'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:fetch|axios(?:\\.(?:get|post|put|delete|patch|request))?|https?\\.request|got(?:\\.(?:get|post))?)$',
      target_canonical_key: 'capability.network.egress',
      target_concept_id: STANDARD_CONCEPTS['capability.network.egress'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps JS HTTP clients to canonical outbound network connectivity capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_NET_PYTHON_REQUESTS',
      rule_name: 'Python requests / httpx / urllib Outbound HTTP',
      source_ecosystems: ['python'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:requests\\.(?:get|post|put|delete|patch|request)|httpx\\.(?:get|post|put|delete|Client|AsyncClient)|urllib\\.request\\.urlopen|aiohttp\\.ClientSession)$',
      target_canonical_key: 'capability.network.egress',
      target_concept_id: STANDARD_CONCEPTS['capability.network.egress'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps Python HTTP clients to canonical outbound network connectivity capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_NET_GO_HTTP',
      rule_name: 'Go net/http Outbound Client',
      source_ecosystems: ['go'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:http\\.(?:Get|Post|Head|PostForm)|net/http\\.(?:Get|Post)|(?:client|Client)\\.Do)$',
      target_canonical_key: 'capability.network.egress',
      target_concept_id: STANDARD_CONCEPTS['capability.network.egress'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps Go net/http client requests to canonical outbound network capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },

    // -------------------------------------------------------------
    // 3. Filesystem Read / Write
    // -------------------------------------------------------------
    {
      rule_id: 'CANE_MAP_FS_READ_JS',
      rule_name: 'JS fs.readFile / readFileSync',
      source_ecosystems: ['javascript', 'typescript'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:fs(?:\\.promises)?\\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync|stat|statSync))$',
      target_canonical_key: 'capability.fs.read',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.read'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps JS fs read operations to canonical filesystem read capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_FS_WRITE_JS',
      rule_name: 'JS fs.writeFile / writeFileSync / unlink',
      source_ecosystems: ['javascript', 'typescript'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:fs(?:\\.promises)?\\.(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmdir|mkdir|mkdirSync))$',
      target_canonical_key: 'capability.fs.write',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.write'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps JS fs write operations to canonical filesystem write capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_FS_READ_PYTHON',
      rule_name: 'Python open / Path.read_text',
      source_ecosystems: ['python'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:open|Path\\.read_text|Path\\.read_bytes|os\\.listdir|os\\.walk)$',
      target_canonical_key: 'capability.fs.read',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.read'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.92,
      description: 'Maps Python open and pathlib read operations to canonical filesystem read capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_FS_WRITE_PYTHON',
      rule_name: 'Python Path.write_text / os.remove',
      source_ecosystems: ['python'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:Path\\.write_text|Path\\.write_bytes|os\\.(?:remove|unlink|mkdir|makedirs|rmdir|rename)|shutil\\.(?:rmtree|move|copy))$',
      target_canonical_key: 'capability.fs.write',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.write'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps Python write and remove operations to canonical filesystem write capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_FS_READ_GO',
      rule_name: 'Go os.ReadFile / ioutil.ReadFile',
      source_ecosystems: ['go'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:os\\.(?:ReadFile|Open|ReadDir|Stat)|ioutil\\.ReadFile)$',
      target_canonical_key: 'capability.fs.read',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.read'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps Go file read operations to canonical filesystem read capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_FS_WRITE_GO',
      rule_name: 'Go os.WriteFile / os.Create',
      source_ecosystems: ['go'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:os\\.(?:WriteFile|Create|OpenFile|Remove|RemoveAll|Mkdir|MkdirAll)|ioutil\\.WriteFile)$',
      target_canonical_key: 'capability.fs.write',
      target_concept_id: STANDARD_CONCEPTS['capability.fs.write'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.95,
      description: 'Maps Go file write operations to canonical filesystem write capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },

    // -------------------------------------------------------------
    // 4. Dynamic Code Evaluation
    // -------------------------------------------------------------
    {
      rule_id: 'CANE_MAP_CODE_EVAL_JS',
      rule_name: 'JavaScript eval / Function / vm.runInContext',
      source_ecosystems: ['javascript', 'typescript'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:eval|Function|vm\\.(?:runInContext|runInNewContext|runInThisContext|compileFunction))$',
      target_canonical_key: 'capability.code.eval',
      target_concept_id: STANDARD_CONCEPTS['capability.code.eval'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.99,
      description: 'Maps JS eval and vm execution to canonical dynamic code evaluation capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },
    {
      rule_id: 'CANE_MAP_CODE_EVAL_PYTHON',
      rule_name: 'Python eval / exec / compile',
      source_ecosystems: ['python'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:eval|exec|compile)$',
      target_canonical_key: 'capability.code.eval',
      target_concept_id: STANDARD_CONCEPTS['capability.code.eval'].concept_id,
      target_entity_type: 'CAPABILITY',
      base_confidence: 0.98,
      description: 'Maps Python eval and exec to canonical dynamic code evaluation capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: true,
    },

    // -------------------------------------------------------------
    // 5. Model Context Protocol (MCP) Tools & Registrations
    // -------------------------------------------------------------
    {
      rule_id: 'CANE_MAP_MCP_TOOL_REGISTRATION',
      rule_name: 'MCP Tool Registration (server.tool / @mcp.tool)',
      source_ecosystems: ['javascript', 'typescript', 'python', 'generic'],
      match_type: 'REGEX_CALLEE',
      source_pattern: '^(?:server\\.tool|mcp\\.tool|McpServer\\.tool|@mcp\\.tool)$',
      target_canonical_key: 'capability.tools.mcp',
      target_concept_id: STANDARD_CONCEPTS['capability.tools.mcp'].concept_id,
      target_entity_type: 'TOOL',
      base_confidence: 0.99,
      description: 'Maps MCP tool declarations to canonical tool and MCP capability',
      version: CANE_REGISTRY_VERSION,
      security_sensitive: false,
    },
  ];

  /**
   * Matches a call site against the mapping registry
   */
  public static matchCallSite(
    call: CallSiteFact, 
    ecosystem?: string, 
    filePath?: string
  ): CaneMappingMatch | null {
    const fullCallee = call.receiver ? `${call.receiver}.${call.callee_name}` : call.callee_name;
    const resolvedPath = filePath || (call as any).file_path || call.span?.file_path || 'unknown';
    
    let resolvedEco = ecosystem || (call as any).ecosystem;
    if (!resolvedEco || resolvedEco === 'generic') {
      const lower = resolvedPath.toLowerCase();
      if (lower.endsWith('.ts') || lower.endsWith('.tsx')) resolvedEco = 'typescript';
      else if (lower.endsWith('.js') || lower.endsWith('.jsx')) resolvedEco = 'javascript';
      else if (lower.endsWith('.py')) resolvedEco = 'python';
      else if (lower.endsWith('.go')) resolvedEco = 'go';
      else if (lower.endsWith('.rs')) resolvedEco = 'rust';
      else resolvedEco = 'generic';
    }

    for (const rule of this.rules) {
      if (
        resolvedEco !== 'generic' && 
        !rule.source_ecosystems.includes(resolvedEco as any) && 
        !rule.source_ecosystems.includes('generic')
      ) {
        continue;
      }

      if (rule.match_type === 'REGEX_CALLEE') {
        const regex = new RegExp(rule.source_pattern);
        if (regex.test(fullCallee) || regex.test(call.callee_name)) {
          const provenance: ProvenanceRecord = {
            provenance_id: crypto.randomUUID(),
            source_spans: call.span ? [{
              file_path: resolvedPath,
              start_line: call.span.start_line,
              start_col: call.span.start_col,
              end_line: call.span.end_line,
              end_col: call.span.end_col,
              byte_offset_start: call.span.byte_offset_start,
              byte_offset_end: call.span.byte_offset_end,
              symbol_hint: call.span.symbol_hint || fullCallee,
            }] : [],
            input_hashes: [],
            rule_id: rule.rule_id,
            ruleset_version: rule.version,
            transformation_type: 'SYNTAX_TRANSFORMATION',
            confidence: rule.base_confidence,
            derived_at: new Date().toISOString(),
            engine_signature: `caim:cane-mapping-registry:v${rule.version}`,
          };

          return {
            rule_id: rule.rule_id,
            rule_version: rule.version,
            source_fact_id: `call_${resolvedPath}_${call.span?.start_line || 0}_${call.callee_name}`,
            source_ecosystem: resolvedEco,
            file_path: resolvedPath,
            matched_construct: fullCallee,
            target_canonical_key: rule.target_canonical_key,
            target_concept_id: rule.target_concept_id,
            target_entity_type: rule.target_entity_type,
            confidence: rule.base_confidence,
            span: call.span,
            provenance,
          };
        }
      }
    }

    return null;
  }

  /**
   * Matches protocol facts against canonical concepts
   */
  public static matchProtocol(proto: ProtocolFact, filePath: string): CaneMappingMatch[] {
    const matches: CaneMappingMatch[] = [];

    if (proto.protocol_kind === 'MCP') {
      const concept = STANDARD_CONCEPTS['capability.tools.mcp'];
      const toolCount = proto.mcp_details?.tools.length || 0;
      const transports = proto.mcp_details?.transports.join('/') || 'stdio';

      const provenance: ProvenanceRecord = {
        provenance_id: crypto.randomUUID(),
        source_spans: proto.span ? [{
          file_path: filePath,
          start_line: proto.span.start_line,
          start_col: proto.span.start_col,
          end_line: proto.span.end_line,
          end_col: proto.span.end_col,
          symbol_hint: 'MCP Protocol Server/Client',
        }] : [],
        input_hashes: [],
        rule_id: 'CANE_MAP_MCP_PROTOCOL_DIRECT',
        ruleset_version: CANE_REGISTRY_VERSION,
        transformation_type: 'DIRECT_EXTRACTION',
        confidence: 0.99,
        derived_at: new Date().toISOString(),
        engine_signature: 'caim:cane-mapping-registry:v1.0.0',
      };

      matches.push({
        rule_id: 'CANE_MAP_MCP_PROTOCOL_DIRECT',
        rule_version: CANE_REGISTRY_VERSION,
        source_fact_id: `proto_${filePath}_${proto.protocol_kind}`,
        source_ecosystem: 'generic',
        file_path: filePath,
        matched_construct: `mcp (${toolCount} tools, ${transports})`,
        target_canonical_key: concept.canonical_key,
        target_concept_id: concept.concept_id,
        target_entity_type: 'PROTOCOL',
        confidence: 0.99,
        span: proto.span,
        provenance,
      });
    }

    return matches;
  }
}
