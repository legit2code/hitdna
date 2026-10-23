/**
 * Versioned Taint Sink Registry
 * P16 — Dataflow / Taint Intelligence
 */

import { TaintSinkDefinition, TAINT_SINK_REGISTRY_VERSION } from './types.ts';

export class TaintSinkRegistry {
  public static readonly REGISTRY_VERSION = TAINT_SINK_REGISTRY_VERSION;

  public static readonly SINKS: TaintSinkDefinition[] = [
    // 1. Network Egress Sinks
    {
      sink_id: 'SNK-NET-001',
      category: 'NETWORK_EGRESS',
      name: 'HTTP Client Request / Egress',
      description: 'Outbound network request dispatch (fetch, axios, http.request, requests.post, http.Post).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'fetch', 'axios', 'axios.get', 'axios.post', 'axios.put',
        'http.request', 'https.request', 'http.get',
        'requests.get', 'requests.post', 'urllib.request.urlopen',
        'http.Get', 'http.Post'
      ],
      base_confidence: 0.98,
      risk_level: 'HIGH',
      caim_capability_key: 'capability.network.egress',
    },
    {
      sink_id: 'SNK-NET-002',
      category: 'NETWORK_EGRESS',
      name: 'Raw Socket / WebSocket Transmission',
      description: 'Low-level socket write or WebSocket message transmission (ws.send, socket.write, net.Dial).',
      pattern_type: 'MEMBER_ACCESS',
      match_member_methods: ['send', 'write', 'sendall', 'sendBytes'],
      match_functions: ['ws.send', 'socket.write', 'net.Dial'],
      base_confidence: 0.95,
      risk_level: 'CRITICAL',
      caim_capability_key: 'capability.network.egress',
    },

    // 2. Process Execution Sinks
    {
      sink_id: 'SNK-PROC-001',
      category: 'PROCESS_EXECUTION',
      name: 'Shell / Subprocess Command Execution',
      description: 'Host command execution API (exec, execSync, spawn, subprocess.Popen, os.system, exec.Command).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'exec', 'execSync', 'spawn', 'spawnSync',
        'child_process.exec', 'child_process.spawn', 'child_process.execSync',
        'os.system', 'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output',
        'exec.Command'
      ],
      base_confidence: 0.99,
      risk_level: 'CRITICAL',
      caim_capability_key: 'capability.tools.exec',
    },

    // 3. Dynamic Code Evaluation Sinks
    {
      sink_id: 'SNK-EVAL-001',
      category: 'DYNAMIC_CODE_EVAL',
      name: 'Dynamic Code Evaluation Construct',
      description: 'Runtime dynamic code string evaluation (eval, Function, vm.runInContext, exec).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: ['eval', 'Function', 'vm.runInContext', 'vm.runInThisContext', 'exec'],
      base_confidence: 0.99,
      risk_level: 'CRITICAL',
      caim_capability_key: 'capability.code.eval',
    },

    // 4. Filesystem Write Sinks
    {
      sink_id: 'SNK-FS-001',
      category: 'FILESYSTEM_WRITE',
      name: 'Local Filesystem Write / Storage Mutation',
      description: 'Writing data to local file or persistent disk (fs.writeFileSync, fs.appendFile, open w, os.WriteFile).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'fs.writeFileSync', 'fs.writeFile', 'fs.appendFileSync', 'fs.appendFile',
        'fs.promises.writeFile', 'f.write', 'os.WriteFile', 'ioutil.WriteFile'
      ],
      base_confidence: 0.96,
      risk_level: 'MEDIUM',
      caim_capability_key: 'capability.fs.write',
    },

    // 5. Filesystem Deletion Sinks
    {
      sink_id: 'SNK-FS-002',
      category: 'FILESYSTEM_DELETE',
      name: 'Filesystem Unlink / Removal',
      description: 'Destructive deletion of file or directory (fs.unlinkSync, fs.rmSync, os.remove, os.RemoveAll).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'fs.unlinkSync', 'fs.unlink', 'fs.rmSync', 'fs.rmdirSync', 'fs.rm',
        'os.remove', 'os.unlink', 'shutil.rmtree', 'os.Remove', 'os.RemoveAll'
      ],
      base_confidence: 0.97,
      risk_level: 'HIGH',
      caim_capability_key: 'capability.fs.write',
    },

    // 6. Tool / MCP Execution Sinks
    {
      sink_id: 'SNK-TOOL-001',
      category: 'TOOL_INVOCATION',
      name: 'MCP Action / External Tool Dispatch',
      description: 'Invoking remote tool handler, MCP protocol call, or agent action dispatcher.',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'mcpClient.callTool', 'client.invokeTool', 'call_tool', 'execute_action', 'agent.dispatch'
      ],
      base_confidence: 0.92,
      risk_level: 'MEDIUM',
      caim_capability_key: 'capability.tools.invocation',
    },

    // 7. Sensitive Logging Sinks
    {
      sink_id: 'SNK-LOG-001',
      category: 'LOGGING_OUTPUT',
      name: 'Unmasked Console / Logger Output',
      description: 'Outputting data directly to standard stdout or diagnostic logs without redaction.',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'console.log', 'console.info', 'console.warn', 'console.error',
        'logger.info', 'logger.debug', 'logger.error', 'print', 'fmt.Println'
      ],
      base_confidence: 0.88,
      risk_level: 'LOW',
    },

    // 8. Database Query Sinks
    {
      sink_id: 'SNK-DB-001',
      category: 'DATABASE_QUERY',
      name: 'Raw SQL Execution / Query Sink',
      description: 'Execution of SQL queries or database commands (client.query, db.query, pool.query, rawQuery).',
      pattern_type: 'FUNCTION_CALL',
      match_functions: [
        'client.query', 'db.query', 'pool.query', 'rawQuery', 'db.raw', 'connection.query'
      ],
      base_confidence: 0.99,
      risk_level: 'CRITICAL',
      caim_capability_key: 'capability.database.write',
    }
  ];

  public static getSinkById(id: string): TaintSinkDefinition | undefined {
    return this.SINKS.find(s => s.sink_id === id);
  }

  public static getAllSinks(): TaintSinkDefinition[] {
    return [...this.SINKS];
  }
}
