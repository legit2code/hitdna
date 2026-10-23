/**
 * Sandbox Network Layer Enforcement & Forced Egress Proxy
 * 
 * Enforces network isolation BEFORE untrusted code executes:
 * 1. E2B SDK Provisioning Configuration: Sets allowInternetAccess and network.denyOut/allowOut
 *    at Sandbox.create() time to enforce kernel/firewall boundaries.
 * 2. Forced Egress Proxy & Socket Interceptor: Starts an in-sandbox/local egress proxy on 127.0.0.1,
 *    configures HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, and preloads a socket-layer network fence
 *    via NODE_OPTIONS to terminate any unauthorized connection before packets can leave.
 * 3. Synthetic Target Routing: Strictly whitelists synthetic targets (e.g. synthetic-target.local),
 *    terminating all disallowed outbound traffic with ECONNREFUSED or HTTP 403 Forbidden.
 */

import http from 'http';
import net from 'net';
import { URL } from 'url';
import { NetworkPolicy, RuntimeEvent } from '../types.ts';
import { NetworkPolicyEngine } from './network-policy.ts';
import { SyntheticTargetService } from './synthetic-target.ts';

export interface EgressProxyOptions {
  policy: NetworkPolicy;
  port?: number;
  scenarioId?: string;
  scenarioVersion?: string;
  onEvent?: (event: RuntimeEvent) => void;
}

export class SandboxEgressProxy {
  private server: http.Server;
  private port: number = 0;
  private policy: NetworkPolicy;
  private options: EgressProxyOptions;
  private capturedEvents: RuntimeEvent[] = [];
  private activeSockets = new Set<net.Socket>();

  constructor(options: EgressProxyOptions) {
    this.options = options;
    this.policy = options.policy;
    this.server = this.createServer();
  }

  public static async start(options: EgressProxyOptions): Promise<SandboxEgressProxy> {
    const proxy = new SandboxEgressProxy(options);
    await proxy.listen(options.port || 0);
    return proxy;
  }

  public getPort(): number {
    return this.port;
  }

  public getUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  public getCapturedEvents(): RuntimeEvent[] {
    return [...this.capturedEvents];
  }

  public updatePolicy(policy: NetworkPolicy): void {
    this.policy = policy;
  }

  private listen(targetPort: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.listen(targetPort, '127.0.0.1', () => {
        const addr = this.server.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        resolve();
      });
      this.server.on('error', reject);
    });
  }

  private recordEvent(event: RuntimeEvent): void {
    this.capturedEvents.push(event);
    if (this.options.onEvent) {
      try {
        this.options.onEvent(event);
      } catch {}
    }
  }

  private createServer(): http.Server {
    const server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    server.on('connection', (socket) => {
      this.activeSockets.add(socket);
      socket.on('close', () => this.activeSockets.delete(socket));
    });

    // Handle HTTPS CONNECT tunnel requests
    server.on('connect', (req, clientSocket, head) => {
      this.handleHttpsConnect(req, clientSocket as any, head);
    });

    return server;
  }

  /**
   * Evaluates and handles HTTPS CONNECT tunnel requests at the TCP/TLS handshake level.
   */
  private handleHttpsConnect(req: http.IncomingMessage, clientSocket: any, head: Buffer): void {
    const [destinationHost, rawPort] = (req.url || '').split(':');
    const port = rawPort ? parseInt(rawPort, 10) : 443;
    const cleanHost = (destinationHost || '').toLowerCase().trim();

    const evalResult = NetworkPolicyEngine.evaluateConnection(
      this.policy,
      cleanHost,
      port,
      'HTTPS',
      this.options.scenarioId || 'SCN-PROXY',
      this.options.scenarioVersion || '1.0.0'
    );

    this.recordEvent(evalResult.event);

    if (!evalResult.allowed) {
      // Reject connection at network layer: send HTTP 403 Forbidden and close TCP socket
      const response = 
        'HTTP/1.1 403 Forbidden\r\n' +
        'Content-Type: text/plain\r\n' +
        'X-Sandbox-Denied-By: SandboxNetworkPolicy\r\n' +
        'Connection: close\r\n\r\n' +
        `Blocked by Sandbox NetworkPolicy at network layer: outbound connection to ${cleanHost}:${port} forbidden.\r\n`;
      clientSocket.write(response);
      clientSocket.destroy();
      return;
    }

    // If target is synthetic target, terminate tunnel locally to synthetic service
    const isSynthetic = SyntheticTargetService.SYNTHETIC_DOMAINS.some(
      d => cleanHost === d || cleanHost.endsWith('.' + d)
    ) || cleanHost.endsWith('.internal') || cleanHost.endsWith('.local') || cleanHost.includes('synthetic');

    if (isSynthetic) {
      // Connect to internal mock responder socket
      const mockServer = net.createServer((mockSocket) => {
        mockSocket.on('data', () => {
          const body = JSON.stringify({
            status: 'SYNTHETIC_OK',
            target: cleanHost,
            synthetic_environment: true,
          });
          mockSocket.write(
            'HTTP/1.1 200 OK\r\n' +
            'Content-Type: application/json\r\n' +
            `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` +
            body
          );
          mockSocket.end();
        });
      });

      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address() as net.AddressInfo;
        const srvSocket = net.connect(addr.port, '127.0.0.1', () => {
          clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          srvSocket.write(head);
          srvSocket.pipe(clientSocket);
          clientSocket.pipe(srvSocket);
        });

        srvSocket.on('close', () => mockServer.close());
        clientSocket.on('close', () => mockServer.close());
      });
      return;
    }

    // Allowed external destination: forward TCP tunnel
    const targetSocket = net.connect(port, cleanHost, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) targetSocket.write(head);
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });

    targetSocket.on('error', (err) => {
      clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      targetSocket.destroy();
    });
  }

  /**
   * Handles plain HTTP requests through the egress proxy.
   */
  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    let host = 'localhost';
    let port = 80;

    if (req.url && req.url.startsWith('http://')) {
      try {
        const parsed = new URL(req.url);
        host = parsed.hostname;
        port = parsed.port ? parseInt(parsed.port, 10) : 80;
      } catch {}
    } else if (req.headers.host) {
      const parts = req.headers.host.split(':');
      host = parts[0];
      if (parts[1]) port = parseInt(parts[1], 10);
    }

    const cleanHost = host.toLowerCase().trim();

    const evalResult = NetworkPolicyEngine.evaluateConnection(
      this.policy,
      cleanHost,
      port,
      'HTTP',
      this.options.scenarioId || 'SCN-PROXY',
      this.options.scenarioVersion || '1.0.0'
    );

    this.recordEvent(evalResult.event);

    if (!evalResult.allowed) {
      res.writeHead(403, {
        'Content-Type': 'application/json',
        'X-Sandbox-Denied-By': 'SandboxNetworkPolicy',
        'Connection': 'close',
      });
      res.end(JSON.stringify({
        error: 'EGRESS_BLOCKED',
        reason: evalResult.reason,
        target: `${cleanHost}:${port}`,
        mechanism: 'FORCED_EGRESS_PROXY',
      }));
      return;
    }

    // If synthetic target, return synthetic mock payload
    const isSynthetic = SyntheticTargetService.SYNTHETIC_DOMAINS.some(
      d => cleanHost === d || cleanHost.endsWith('.' + d)
    ) || cleanHost.endsWith('.internal') || cleanHost.endsWith('.local') || cleanHost.includes('synthetic');

    if (isSynthetic) {
      const synthResponse = SyntheticTargetService.handleSyntheticRequest({
        path: req.url || '/',
        method: (req.method || 'GET') as any,
        headers: req.headers as Record<string, string>,
      });
      res.writeHead(synthResponse.status, {
        ...synthResponse.headers,
        'Content-Type': 'application/json',
      });
      res.end(JSON.stringify(synthResponse.data));
      return;
    }

    // Forward allowed HTTP request
    const connector = http.request({
      host: cleanHost,
      port,
      method: req.method,
      path: req.url,
      headers: req.headers,
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    });

    connector.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'UPSTREAM_ERROR', message: err.message }));
    });

    req.pipe(connector);
  }

  public async stop(): Promise<void> {
    for (const socket of this.activeSockets) {
      try {
        socket.destroy();
      } catch {}
    }
    this.activeSockets.clear();

    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }
}

/**
 * Generates the pre-execution CommonJS bootstrap that hooks the Node.js socket layer
 * BEFORE any untrusted application code or modules can execute.
 */
export function generateNetworkEnforcerBootstrap(policy: NetworkPolicy, proxyPort?: number): string {
  const allowedList = JSON.stringify(policy.allowedDomains || []);
  const policyType = JSON.stringify(policy.type);
  const allowedPorts = JSON.stringify(policy.allowedPorts || [80, 443]);
  const proxyUrl = proxyPort ? `http://127.0.0.1:${proxyPort}` : '';

  return `/**
 * Pre-execution Network Enforcer Bootstrap (In-Sandbox Socket Layer Fence)
 * Runs BEFORE user scripts via NODE_OPTIONS="--require ..."
 */
'use strict';

const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const dns = require('dns');

const POLICY_TYPE = ${policyType};
const ALLOWED_DOMAINS = ${allowedList};
const ALLOWED_PORTS = ${allowedPorts};
const PROXY_URL = ${JSON.stringify(proxyUrl)};

// 1. Force Proxy Environment Variables for sub-shells, curl, wget, and child processes
if (PROXY_URL) {
  process.env.HTTP_PROXY = PROXY_URL;
  process.env.HTTPS_PROXY = PROXY_URL;
  process.env.ALL_PROXY = PROXY_URL;
  process.env.http_proxy = PROXY_URL;
  process.env.https_proxy = PROXY_URL;
  process.env.all_proxy = PROXY_URL;
}

// Helper to evaluate destination against NetworkPolicy
function isHostAllowed(host, port) {
  if (!host) return false;
  const clean = host.toLowerCase().trim().split(':')[0];
  
  // Loopback / local sandbox communication
  if (clean === 'localhost' || clean === '127.0.0.1' || clean === '::1') {
    return true;
  }

  // Allowed ports check
  if (ALLOWED_PORTS.length > 0 && port && !ALLOWED_PORTS.includes(port)) {
    return false;
  }

  if (POLICY_TYPE === 'DEFAULT_DENY') {
    if (!ALLOWED_DOMAINS || ALLOWED_DOMAINS.length === 0) {
      return false;
    }
    return ALLOWED_DOMAINS.some(d => clean === d.toLowerCase() || clean.endsWith('.' + d.toLowerCase()));
  }

  if (POLICY_TYPE === 'WHITELIST_ONLY') {
    return ALLOWED_DOMAINS.some(d => clean === d.toLowerCase() || clean.endsWith('.' + d.toLowerCase()));
  }

  return true; // MONITORED_OPEN
}

function isSyntheticTarget(host) {
  const clean = (host || '').toLowerCase().trim().split(':')[0];
  return clean === 'synthetic-target.local' || clean.endsWith('.synthetic-sandbox.internal') || clean === 'sandbox.caim.internal';
}

// 2. Intercept net.Socket.prototype.connect (the fundamental network socket primitive in Node.js)
const originalSocketConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  let host = '127.0.0.1';
  let port = 80;

  if (args[0] && typeof args[0] === 'object') {
    host = args[0].host || args[0].hostname || 'localhost';
    port = args[0].port || 80;
  } else if (typeof args[0] === 'number') {
    port = args[0];
    if (typeof args[1] === 'string') {
      host = args[1];
    }
  }

  // Evaluate connection attempt
  if (!isHostAllowed(host, port)) {
    const errMsg = 'connect ECONNREFUSED ' + host + ':' + port + ' - Blocked at network layer by Sandbox NetworkPolicy (' + POLICY_TYPE + ')';
    const err = new Error(errMsg);
    err.code = 'ECONNREFUSED';
    err.errno = -111;
    err.syscall = 'connect';
    err.address = host;
    err.port = port;

    process.nextTick(() => {
      this.emit('error', err);
      this.destroy(err);
    });
    return this;
  }

  return originalSocketConnect.apply(this, args);
};

// 3. Intercept globalThis.fetch
if (typeof globalThis.fetch === 'function') {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async function(input, init) {
    const urlStr = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
    let host = 'localhost';
    let port = 80;

    try {
      const url = new URL(urlStr);
      host = url.hostname;
      port = url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80);
    } catch {
      const m = urlStr.match(/^https?:\\/\\/([^/:'"\\s]+)(?::(\\d+))?/i);
      if (m) {
        host = m[1];
        if (m[2]) port = parseInt(m[2], 10);
      }
    }

    if (!isHostAllowed(host, port)) {
      const cause = new Error('connect ECONNREFUSED ' + host + ':' + port + ' - Blocked at network layer by Sandbox NetworkPolicy (' + POLICY_TYPE + ')');
      cause.code = 'ECONNREFUSED';
      cause.errno = -111;
      const fetchErr = new TypeError('fetch failed: connect ECONNREFUSED ' + host + ':' + port + ' - Blocked at network layer by Sandbox NetworkPolicy');
      fetchErr.cause = cause;
      fetchErr.code = 'ECONNREFUSED';
      throw fetchErr;
    }

    if (isSyntheticTarget(host)) {
      // Synthetic target response in-sandbox
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          status: 'SYNTHETIC_OK',
          target: host,
          synthetic_environment: true,
          data: { synthetic_entropy: 0.942, records_processed: 42 },
        }),
        text: async () => JSON.stringify({ status: 'SYNTHETIC_OK', target: host }),
      };
    }

    return originalFetch.apply(this, arguments);
  };
}

// 4. Intercept dns.lookup to prevent DNS exfiltration
const originalDnsLookup = dns.lookup;
dns.lookup = function(hostname, options, callback) {
  const cb = typeof options === 'function' ? options : callback;
  if (typeof hostname === 'string' && !isHostAllowed(hostname, 53)) {
    const err = new Error('getaddrinfo ENOTFOUND ' + hostname + ' - Blocked at network layer by Sandbox NetworkPolicy');
    err.code = 'ENOTFOUND';
    err.syscall = 'getaddrinfo';
    err.hostname = hostname;
    if (cb) process.nextTick(() => cb(err));
    return;
  }
  return originalDnsLookup.apply(this, arguments);
};

// Ready confirmation logged only if debug enabled
if (process.env.SANDBOX_NETWORK_DEBUG === 'true') {
  console.log('[NETWORK_ENFORCER] Pre-execution network fence loaded. Policy: ' + POLICY_TYPE);
}
`;
}

/**
 * Prepares the sandbox session's environment and files with pre-execution network layer enforcement.
 */
export function installSandboxNetworkEnforcer(
  policy: NetworkPolicy,
  proxyPort?: number,
  existingEnv: Record<string, string> = {},
  existingFiles: Record<string, string> = {}
): {
  envVars: Record<string, string>;
  files: Record<string, string>;
  bootstrapPath: string;
} {
  const bootstrapContent = generateNetworkEnforcerBootstrap(policy, proxyPort);
  const bootstrapPath = '.sandbox/network-enforcer.cjs';
  const bootstrapAbsPath = '/home/user/.sandbox/network-enforcer.cjs';

  const files = {
    ...existingFiles,
    [bootstrapPath]: bootstrapContent,
    [bootstrapAbsPath]: bootstrapContent,
  };

  const proxyUrl = proxyPort ? `http://127.0.0.1:${proxyPort}` : '';

  const envVars: Record<string, string> = {
    ...existingEnv,
    NODE_OPTIONS: existingEnv.NODE_OPTIONS 
      ? `${existingEnv.NODE_OPTIONS} --require ./${bootstrapPath}`
      : `--require ./${bootstrapPath}`,
  };

  if (proxyUrl) {
    envVars.HTTP_PROXY = proxyUrl;
    envVars.HTTPS_PROXY = proxyUrl;
    envVars.ALL_PROXY = proxyUrl;
    envVars.http_proxy = proxyUrl;
    envVars.https_proxy = proxyUrl;
    envVars.all_proxy = proxyUrl;
  }

  return { envVars, files, bootstrapPath };
}

/**
 * Builds the E2B SDK options for Sandbox.create() enforcing NetworkPolicy at microVM creation time.
 */
export function buildE2BProvisioningNetworkConfig(
  policy: NetworkPolicy,
  proxyPort?: number
): {
  allowInternetAccess: boolean;
  network?: {
    denyOut?: string[];
    allowOut?: string[];
  };
  envs: Record<string, string>;
} {
  const allowOutList: string[] = [];
  if (policy.type === 'DEFAULT_DENY' || policy.type === 'WHITELIST_ONLY') {
    if (policy.allowedDomains && policy.allowedDomains.length > 0) {
      allowOutList.push(...policy.allowedDomains);
    }
    const cidrs = (policy as any).allowedCidrs;
    if (cidrs && Array.isArray(cidrs) && cidrs.length > 0) {
      allowOutList.push(...cidrs);
    }
  }

  const allowOut = allowOutList.length > 0 ? allowOutList : undefined;
  const isDefaultDeny = policy.type === 'DEFAULT_DENY' && (!allowOut || allowOut.length === 0);

  const effectiveProxyPort = proxyPort || 8080;
  const proxyUrl = `http://127.0.0.1:${effectiveProxyPort}`;
  const envs: Record<string, string> = {
    NODE_OPTIONS: '--require /home/user/.sandbox/network-enforcer.cjs',
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    ALL_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    all_proxy: proxyUrl,
  };

  return {
    allowInternetAccess: !isDefaultDeny,
    network: {
      denyOut: ['0.0.0.0/0'],
      allowOut,
    },
    envs,
  };
}
