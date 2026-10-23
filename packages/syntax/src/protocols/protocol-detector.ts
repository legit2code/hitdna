import { 
  ProtocolFact, 
  ProtocolKind, 
  SourceSpan, 
  OpenApiEndpoint, 
  McpDetails, 
  A2aDetails, 
  GrpcService 
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

export class ProtocolDetector {
  /**
   * Detects and parses communication protocols in source files or specifications
   */
  public static detect(filePath: string, sourceText: string, parsedData?: any): ProtocolFact[] {
    const protocols: ProtocolFact[] = [];
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const fileName = filePath.split('/').pop() || filePath;
    const lowerName = fileName.toLowerCase();

    // 1. Model Context Protocol (MCP) Detection
    const mcpFact = this.detectMcp(filePath, sourceText, lineStarts, parsedData);
    if (mcpFact) protocols.push(mcpFact);

    // 2. Agent-to-Agent (A2A) Detection
    const a2aFact = this.detectA2a(filePath, sourceText, lineStarts, parsedData);
    if (a2aFact) protocols.push(a2aFact);

    // 3. OpenAPI / Swagger Specification Detection
    const openapiFact = this.detectOpenApi(filePath, sourceText, lineStarts, parsedData);
    if (openapiFact) protocols.push(openapiFact);

    // 4. AsyncAPI Specification Detection
    const asyncapiFact = this.detectAsyncApi(filePath, sourceText, lineStarts, parsedData);
    if (asyncapiFact) protocols.push(asyncapiFact);

    // 5. JSON-RPC Detection
    const jsonrpcFact = this.detectJsonRpc(filePath, sourceText, lineStarts);
    if (jsonrpcFact) protocols.push(jsonrpcFact);

    // 6. gRPC / Protobuf Detection
    const grpcFact = this.detectGrpcProtobuf(filePath, sourceText, lineStarts);
    if (grpcFact) protocols.push(grpcFact);

    // 7. GraphQL Detection
    const graphqlFact = this.detectGraphQL(filePath, sourceText, lineStarts);
    if (graphqlFact) protocols.push(graphqlFact);

    // 8. WebSocket & REST Handlers Detection
    const wsRestFact = this.detectWebSocketAndRest(filePath, sourceText, lineStarts);
    if (wsRestFact) protocols.push(wsRestFact);

    return protocols;
  }

  private static detectMcp(
    filePath: string,
    source: string,
    lineStarts: number[],
    parsedData?: any
  ): ProtocolFact | null {
    const isMcpSdk = source.includes('@modelcontextprotocol/sdk') || 
                     source.includes('from mcp') || 
                     source.includes('import mcp') ||
                     source.includes('FastMCP') ||
                     source.includes('McpServer');

    const hasMcpPatterns = source.includes('ListToolsRequestSchema') || 
                           source.includes('CallToolRequestSchema') || 
                           source.includes('ListPromptsRequestSchema') ||
                           source.includes('ListResourcesRequestSchema') ||
                           source.includes('StdioServerTransport') ||
                           source.includes('SSEServerTransport') ||
                           source.includes('@mcp.tool()') ||
                           source.includes('mcp.tool()');

    if (!isMcpSdk && !hasMcpPatterns) return null;

    const tools: Array<{ name: string; description?: string; parameters_schema?: Record<string, any>; span?: SourceSpan }> = [];
    const prompts: Array<{ name: string; description?: string; arguments: Array<{ name: string; required: boolean }>; span?: SourceSpan }> = [];
    const resources: Array<{ uri: string; name?: string; mime_type?: string; span?: SourceSpan }> = [];
    const transports: Array<'stdio' | 'sse' | 'streamable_http' | 'custom'> = [];

    // Extract transports
    if (source.includes('StdioServerTransport') || source.includes('stdio')) transports.push('stdio');
    if (source.includes('SSEServerTransport') || source.includes('sse')) transports.push('sse');
    if (source.includes('streamable_http') || source.includes('StreamableHttpTransport')) transports.push('streamable_http');
    if (transports.length === 0) transports.push('stdio');

    // Extract tool registrations: server.tool("tool_name", ...), @mcp.tool(), FastMCP.tool()
    const toolRegex = /(?:server\.tool|mcp\.tool|@mcp\.tool|@fastmcp\.tool|mcpServer\.tool)\s*\(\s*["']([^"']+)["'](?:\s*,\s*["']([^"']*)["'])?/g;
    let match: RegExpExecArray | null;

    while ((match = toolRegex.exec(source)) !== null) {
      const toolName = match[1];
      const desc = match[2];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, toolName);
      tools.push({
        name: toolName,
        description: desc || undefined,
        span,
      });
    }

    // Extract prompt registrations: server.prompt("prompt_name", ...)
    const promptRegex = /(?:server\.prompt|mcp\.prompt)\s*\(\s*["']([^"']+)["'](?:\s*,\s*["']([^"']*)["'])?/g;
    while ((match = promptRegex.exec(source)) !== null) {
      const promptName = match[1];
      const desc = match[2];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, promptName);
      prompts.push({
        name: promptName,
        description: desc || undefined,
        arguments: [],
        span,
      });
    }

    // Extract resource registrations: server.resource("uri", ...)
    const resourceRegex = /(?:server\.resource|mcp\.resource)\s*\(\s*["']([^"']+)["'](?:\s*,\s*["']([^"']*)["'])?/g;
    while ((match = resourceRegex.exec(source)) !== null) {
      const uri = match[1];
      const name = match[2];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, match.index, match.index + match[0].length, lineStarts, uri);
      resources.push({
        uri,
        name: name || undefined,
        span,
      });
    }

    const isClient = source.includes('Client(') || source.includes('new Client(') || source.includes('connect(');
    const isServer = source.includes('Server(') || source.includes('new Server(') || source.includes('FastMCP(');
    const role = isClient && isServer ? 'DUAL' : (isClient ? 'CLIENT' : 'SERVER');

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'Model Context Protocol (MCP)');

    return {
      protocol_kind: 'MCP',
      version: '2024-11-05',
      title: 'Model Context Protocol Server / Client',
      mcp_details: {
        role,
        tools,
        prompts,
        resources,
        transports,
      },
      grpc_services: [],
      endpoints: [],
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 0.98,
      detection_evidence: [
        isMcpSdk ? 'MCP SDK imports detected' : '',
        hasMcpPatterns ? 'MCP Request/Response schemas detected' : '',
        `Transports: ${transports.join(', ')}`,
      ].filter(Boolean),
    };
  }

  private static detectA2a(
    filePath: string,
    source: string,
    lineStarts: number[],
    parsedData?: any
  ): ProtocolFact | null {
    const isA2aFile = filePath.toLowerCase().includes('agent.json') || 
                      filePath.toLowerCase().includes('a2a.json') ||
                      filePath.toLowerCase().includes('agent-card.json');

    const hasA2aKeywords = source.includes('a2a_version') || 
                           source.includes('agent_card') || 
                           source.includes('task_delegation') ||
                           source.includes('agent_handshake') ||
                           source.includes('did:agent:');

    if (!isA2aFile && !hasA2aKeywords) return null;

    const handshakeMethods: string[] = [];
    const delegationInterfaces: string[] = [];
    const cards: Array<{ name: string; capabilities: string[]; endpoint?: string }> = [];

    if (source.includes('handshake')) handshakeMethods.push('ECDSA_DID_HANDSHAKE');
    if (source.includes('task_delegation') || source.includes('delegate_task')) delegationInterfaces.push('DIRECT_TASK_DELEGATION_V1');

    if (parsedData && typeof parsedData === 'object') {
      if (parsedData.name && parsedData.capabilities) {
        cards.push({
          name: parsedData.name,
          capabilities: Array.isArray(parsedData.capabilities) ? parsedData.capabilities : [],
          endpoint: parsedData.endpoint,
        });
      }
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'A2A Protocol');

    return {
      protocol_kind: 'A2A',
      version: parsedData?.a2a_version || '1.0.0',
      title: 'Agent-to-Agent (A2A) Protocol Specification',
      a2a_details: {
        agent_id: parsedData?.agent_id || parsedData?.id,
        protocol_version: parsedData?.a2a_version || '1.0.0',
        handshake_methods: handshakeMethods,
        task_delegation_interfaces: delegationInterfaces,
        signing_methods: ['ED25519_SIG', 'SECP256K1'],
        agent_cards: cards,
      },
      grpc_services: [],
      endpoints: [],
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 0.95,
      detection_evidence: ['Agent-to-Agent protocol signatures and communication interfaces detected'],
    };
  }

  private static detectOpenApi(
    filePath: string,
    source: string,
    lineStarts: number[],
    parsedData?: any
  ): ProtocolFact | null {
    const isOpenApiSpec = source.includes('openapi:') || 
                          source.includes('"openapi"') || 
                          source.includes('swagger:') || 
                          source.includes('"swagger"');

    if (!isOpenApiSpec) return null;

    const endpoints: OpenApiEndpoint[] = [];
    let version = '3.0.0';
    let title = 'OpenAPI Specification';

    if (parsedData && typeof parsedData === 'object') {
      version = parsedData.openapi || parsedData.swagger || version;
      title = parsedData.info?.title || title;

      if (parsedData.paths && typeof parsedData.paths === 'object') {
        for (const [pathKey, methodsObj] of Object.entries(parsedData.paths)) {
          if (methodsObj && typeof methodsObj === 'object') {
            for (const [method, details] of Object.entries(methodsObj as any)) {
              if (['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method.toLowerCase())) {
                const op = details as any;
                endpoints.push({
                  path: pathKey,
                  method: method.toUpperCase(),
                  operation_id: op?.operationId,
                  summary: op?.summary,
                  description: op?.description,
                  parameters: Array.isArray(op?.parameters) ? op.parameters.map((p: any) => p.name || '') : [],
                  security_requirements: Array.isArray(op?.security) ? op.security.map((s: any) => Object.keys(s)[0]) : [],
                });
              }
            }
          }
        }
      }
    } else {
      // Regex fallback for paths
      const pathRegex = /["']?(\/[a-zA-Z0-9_\-\/{}]*)["']?\s*:\s*\{[\s\S]*?(get|post|put|delete|patch)\s*:/gi;
      let match: RegExpExecArray | null;
      while ((match = pathRegex.exec(source)) !== null) {
        endpoints.push({
          path: match[1],
          method: match[2].toUpperCase(),
          parameters: [],
          security_requirements: [],
        });
      }
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'OpenAPI Spec');

    return {
      protocol_kind: 'OPENAPI',
      version,
      title,
      endpoints,
      grpc_services: [],
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 1.0,
      detection_evidence: [`Detected OpenAPI/Swagger version ${version} with ${endpoints.length} defined endpoints`],
    };
  }

  private static detectAsyncApi(
    filePath: string,
    source: string,
    lineStarts: number[],
    parsedData?: any
  ): ProtocolFact | null {
    const isAsyncApi = source.includes('asyncapi:') || source.includes('"asyncapi"');
    if (!isAsyncApi) return null;

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'AsyncAPI Spec');

    return {
      protocol_kind: 'ASYNCAPI',
      version: parsedData?.asyncapi || '2.6.0',
      title: parsedData?.info?.title || 'AsyncAPI Event Specification',
      endpoints: [],
      grpc_services: [],
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 1.0,
      detection_evidence: ['AsyncAPI channels and message event bindings detected'],
    };
  }

  private static detectJsonRpc(filePath: string, source: string, lineStarts: number[]): ProtocolFact | null {
    const hasJsonRpc = source.includes('jsonrpc') || source.includes('JSON-RPC') || source.includes('2.0');
    if (!hasJsonRpc) return null;

    const methods: string[] = [];
    const methodRegex = /["']method["']\s*:\s*["']([^"']+)["']/g;
    let match: RegExpExecArray | null;

    while ((match = methodRegex.exec(source)) !== null) {
      if (!methods.includes(match[1])) methods.push(match[1]);
    }

    if (methods.length === 0 && !source.includes('"jsonrpc": "2.0"') && !source.includes('jsonrpc: "2.0"')) {
      return null;
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'JSON-RPC');

    return {
      protocol_kind: 'JSON_RPC',
      version: '2.0',
      title: 'JSON-RPC Protocol Dispatcher',
      endpoints: [],
      grpc_services: [],
      jsonrpc_methods: methods,
      graphql_types: [],
      span,
      confidence: 0.9,
      detection_evidence: [`JSON-RPC 2.0 signatures detected with methods: ${methods.join(', ') || 'Dynamic dispatch'}`],
    };
  }

  private static detectGrpcProtobuf(filePath: string, source: string, lineStarts: number[]): ProtocolFact | null {
    const isProtoFile = filePath.endsWith('.proto') || source.includes('syntax = "proto3"') || source.includes('syntax = "proto2"');
    const isGrpcCode = source.includes('@grpc/grpc-js') || source.includes('grpc.NewServer') || source.includes('grpc.Server');

    if (!isProtoFile && !isGrpcCode) return null;

    const services: GrpcService[] = [];
    const serviceRegex = /service\s+([\w]+)\s*\{([\s\S]*?)\}/g;
    let match: RegExpExecArray | null;

    while ((match = serviceRegex.exec(source)) !== null) {
      const svcName = match[1];
      const body = match[2];
      const methods: Array<{ name: string; input_type: string; output_type: string; client_streaming: boolean; server_streaming: boolean }> = [];

      const rpcRegex = /rpc\s+([\w]+)\s*\(\s*(stream\s+)?([\w.]+)\s*\)\s*returns\s*\(\s*(stream\s+)?([\w.]+)\s*\)/g;
      let rpcMatch: RegExpExecArray | null;

      while ((rpcMatch = rpcRegex.exec(body)) !== null) {
        methods.push({
          name: rpcMatch[1],
          client_streaming: Boolean(rpcMatch[2]),
          input_type: rpcMatch[3],
          server_streaming: Boolean(rpcMatch[4]),
          output_type: rpcMatch[5],
        });
      }

      services.push({
        name: svcName,
        methods,
      });
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'gRPC / Protobuf');

    return {
      protocol_kind: 'GRPC_PROTOBUF',
      version: source.includes('proto3') ? 'proto3' : 'proto2',
      title: 'gRPC & Protocol Buffers Definition',
      endpoints: [],
      grpc_services: services,
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 0.98,
      detection_evidence: [`gRPC service definitions: ${services.map(s => s.name).join(', ') || 'gRPC Client/Server invocation'}`],
    };
  }

  private static detectGraphQL(filePath: string, source: string, lineStarts: number[]): ProtocolFact | null {
    const isGraphqlFile = filePath.endsWith('.graphql') || filePath.endsWith('.gql');
    const hasGraphQLCode = source.includes('gql`') || source.includes('type Query {') || source.includes('type Mutation {') || source.includes('buildSchema(');

    if (!isGraphqlFile && !hasGraphQLCode) return null;

    const types: string[] = [];
    const typeRegex = /type\s+([\w]+)(?:\s+implements\s+[\w\s&]+)?\s*\{/g;
    let match: RegExpExecArray | null;

    while ((match = typeRegex.exec(source)) !== null) {
      types.push(match[1]);
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, 'GraphQL Schema');

    return {
      protocol_kind: 'GRAPHQL',
      title: 'GraphQL Schema & Query Definitions',
      endpoints: [],
      grpc_services: [],
      jsonrpc_methods: [],
      graphql_types: types,
      span,
      confidence: 0.95,
      detection_evidence: [`GraphQL schema types: ${types.join(', ') || 'Query/Mutation blocks'}`],
    };
  }

  private static detectWebSocketAndRest(filePath: string, source: string, lineStarts: number[]): ProtocolFact | null {
    const hasWebSocket = source.includes('new WebSocket(') || 
                         source.includes('ws.on(') || 
                         source.includes('websocket.receive_text()') ||
                         source.includes('socket.io') ||
                         source.includes('@WebSocketGateway');

    const hasRest = source.includes('app.get(') || 
                    source.includes('app.post(') || 
                    source.includes('@router.get(') ||
                    source.includes('@router.post(') ||
                    source.includes('http.HandleFunc(');

    if (!hasWebSocket && !hasRest) return null;

    const endpoints: OpenApiEndpoint[] = [];
    const routeRegex = /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/g;
    let match: RegExpExecArray | null;

    while ((match = routeRegex.exec(source)) !== null) {
      endpoints.push({
        method: match[1].toUpperCase(),
        path: match[2],
        parameters: [],
        security_requirements: [],
      });
    }

    const span = SourceSpanUtil.offsetToSpan(filePath, source, 0, source.length, lineStarts, hasWebSocket ? 'WebSocket & REST' : 'REST HTTP');

    return {
      protocol_kind: hasWebSocket ? 'WEBSOCKET' : 'REST_HTTP',
      title: hasWebSocket ? 'WebSocket Event & Channel Stream' : 'REST HTTP Router',
      endpoints,
      grpc_services: [],
      jsonrpc_methods: [],
      graphql_types: [],
      span,
      confidence: 0.92,
      detection_evidence: [
        hasWebSocket ? 'WebSocket lifecycle event listeners detected' : '',
        hasRest ? `HTTP route handlers: ${endpoints.map(e => `${e.method} ${e.path}`).join(', ')}` : '',
      ].filter(Boolean),
    };
  }
}
