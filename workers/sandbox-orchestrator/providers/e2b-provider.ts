/**
 * E2B Sandbox Provider Integration
 * Manages remote microVMs with strict security boundaries, credential sanitization,
 * and live execution capture via the real E2B SDK.
 */

import { Sandbox } from 'e2b';
import { ISandboxProvider, SandboxSessionOptions, SessionExecutionDetails } from './sandbox-provider.interface.ts';
import { 
  SandboxCommand, 
  SandboxExecutionResult, 
  TeardownSummary, 
  RuntimeEvent, 
  NonfunctionalCanary,
  SandboxSessionStatus,
  RESOURCE_TELEMETRY_UNAVAILABLE,
  ResourceMetricValue
} from '../types.ts';
import { SimulatedSandboxProvider } from './simulated-provider.ts';
import { SecretSanitizer } from '../security/secret-sanitizer.ts';
import { 
  buildE2BProvisioningNetworkConfig, 
  generateNetworkEnforcerBootstrap 
} from '../security/sandbox-network-enforcer.ts';

export interface OperationalAlert {
  alertId: string;
  type: 'SANDBOX_TERMINATION_FAILED' | 'SANDBOX_LEAK_DETECTED';
  severity: 'CRITICAL';
  sessionId: string;
  sandboxId?: string;
  timestamp: string;
  message: string;
  details: Record<string, any>;
}

interface RealE2BSessionState {
  isRealE2B: true;
  sandbox: Sandbox;
  options: SandboxSessionOptions;
  startedAt: string;
  events: RuntimeEvent[];
  canaries: NonfunctionalCanary[];
}

interface FallbackSessionState {
  isRealE2B: false;
  sessionId: string;
  options: SandboxSessionOptions;
  startedAt: string;
}

type TrackedSession = RealE2BSessionState | FallbackSessionState;

export class SandboxProviderUnavailableError extends Error {
  constructor(message: string) {
    super(`[E2BProvider] PROVIDER_UNAVAILABLE: ${message}`);
    this.name = 'SandboxProviderUnavailableError';
  }
}

export class E2BSandboxProvider implements ISandboxProvider {
  public readonly providerType = 'E2B';
  public static readonly operationalAlerts: OperationalAlert[] = [];

  public static raiseOperationalAlert(alert: OperationalAlert): void {
    E2BSandboxProvider.operationalAlerts.push(alert);
  }

  public static getOperationalAlerts(): OperationalAlert[] {
    return [...E2BSandboxProvider.operationalAlerts];
  }

  public static clearOperationalAlerts(): void {
    E2BSandboxProvider.operationalAlerts.length = 0;
  }

  private fallbackProvider: SimulatedSandboxProvider;
  private activeSessions = new Map<string, TrackedSession>();
  private sessionDetails = new Map<string, SessionExecutionDetails>();

  constructor() {
    this.fallbackProvider = new SimulatedSandboxProvider();
  }

  public getSessionExecutionDetails(sessionId: string): SessionExecutionDetails {
    const details = this.sessionDetails.get(sessionId);
    if (details) return details;
    const session = this.activeSessions.get(sessionId);
    if (session) {
      return {
        isReal: session.isRealE2B,
        actualProvider: session.isRealE2B ? 'E2B' : 'SIMULATED',
        executionMode: session.isRealE2B ? 'LIVE' : 'SIMULATED',
        fallbackReason: session.isRealE2B ? undefined : 'Provider fell back to simulation',
      };
    }
    return {
      isReal: false,
      actualProvider: 'SIMULATED',
      executionMode: 'SIMULATED',
      fallbackReason: 'Session details not found',
    };
  }

  public async provision(options: SandboxSessionOptions): Promise<string> {
    const e2bApiKey = process.env.E2B_API_KEY;
    const isE2BAvailable = Boolean(e2bApiKey && e2bApiKey.trim().length > 0);
    const isProduction = process.env.NODE_ENV === 'production';
    const requireReal = Boolean(options.requireRealSandbox || process.env.CAIM_REQUIRE_REAL_SANDBOX === 'true' || isProduction);
    const allowSimulation = process.env.CAIM_ALLOW_SIMULATION === 'true' && !isProduction;

    // Strict sanitization: ensure no platform secrets are leaked in envVars
    const sanitized = SecretSanitizer.sanitizeEnvVars(options.envVars || {});
    options.envVars = sanitized.sanitized;

    if (!isE2BAvailable) {
      const reason = 'E2B_API_KEY is not configured (absent). Real sandbox observation cannot proceed; fallback to simulation is prohibited.';
      this.sessionDetails.set(options.sessionId, {
        isReal: false,
        actualProvider: 'NONE',
        executionMode: 'PROVIDER_UNAVAILABLE',
        executionStatus: 'PROVIDER_UNAVAILABLE',
        fallbackReason: reason,
      });
      throw new SandboxProviderUnavailableError(reason);
    }

    console.log(`[E2BProvider] Mode: REAL_E2B_SANDBOX (E2B_API_KEY present). Provisioning remote microVM session...`);
    const startedAt = new Date().toISOString();

    try {
      const e2bNetworkConfig = buildE2BProvisioningNetworkConfig(options.networkPolicy);
      const sandboxOpts: any = {
        apiKey: e2bApiKey,
        timeoutMs: options.resourceQuota.maxDurationMs || 300000,
        envs: {
          ...options.envVars,
          ...e2bNetworkConfig.envs,
        },
      };

      if (e2bNetworkConfig.network) {
        sandboxOpts.network = e2bNetworkConfig.network;
      }
      if (typeof e2bNetworkConfig.allowInternetAccess === 'boolean') {
        sandboxOpts.allowInternetAccess = e2bNetworkConfig.allowInternetAccess;
      }

      const sandbox = await Sandbox.create(sandboxOpts);

      console.log(`[E2BProvider] Real E2B Sandbox provisioned successfully. Remote Sandbox ID: ${sandbox.sandboxId}`);
      this.sessionDetails.set(options.sessionId, {
        isReal: true,
        actualProvider: 'E2B',
        executionMode: 'LIVE',
      });

      const events: RuntimeEvent[] = [
        {
          event_id: `evt-e2b-prov-${Date.now()}`,
          timestamp: startedAt,
          scenario_id: options.scenarioId,
          scenario_version: options.scenarioVersion,
          category: 'ENVIRONMENT',
          action: 'SANDBOX_PROVISIONED',
          target: sandbox.sandboxId,
          status: 'ALLOWED',
          severity: 'INFO',
          metadata: {
            provider: 'E2B',
            realSandboxId: sandbox.sandboxId,
            quota: options.resourceQuota,
            networkPolicy: options.networkPolicy.type,
            canariesInjected: (options.canaries || []).length,
          },
        },
        {
          event_id: `evt-e2b-net-enforce-${Date.now()}`,
          timestamp: startedAt,
          scenario_id: options.scenarioId,
          scenario_version: options.scenarioVersion,
          category: 'NETWORK',
          action: 'NETWORK_POLICY_ENFORCED',
          target: options.networkPolicy.type,
          status: 'ALLOWED',
          severity: 'INFO',
          metadata: {
            mechanism: 'E2B_NETWORK_CONFIG',
            allowInternetAccess: e2bNetworkConfig.allowInternetAccess,
            denyOut: e2bNetworkConfig.network?.denyOut,
            allowOut: e2bNetworkConfig.network?.allowOut,
            policyType: options.networkPolicy.type,
          },
        },
      ];

      // Inject network enforcer bootstrap into remote sandbox
      try {
        const enforcerBootstrap = generateNetworkEnforcerBootstrap(options.networkPolicy);
        await sandbox.files.write('/home/user/.sandbox/network-enforcer.cjs', enforcerBootstrap);
      } catch (enforcerErr) {
        console.warn('[E2BProvider] Note: Could not write enforcer bootstrap file to sandbox:', enforcerErr);
      }

      // Prepare canaries
      const activeCanaries = [...(options.canaries || [])];

      // Write initial files into remote sandbox
      if (options.files) {
        for (const [filePath, content] of Object.entries(options.files)) {
          const targetPath = filePath.startsWith('/') ? filePath : `/home/user/${filePath}`;
          await sandbox.files.write(targetPath, content);
          events.push({
            event_id: `evt-e2b-init-fs-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            timestamp: new Date().toISOString(),
            scenario_id: options.scenarioId,
            scenario_version: options.scenarioVersion,
            category: 'FILESYSTEM',
            action: 'WRITE_FILE',
            target: targetPath,
            status: 'ALLOWED',
            severity: 'INFO',
            metadata: { sizeBytes: content.length, realSandboxId: sandbox.sandboxId },
          });
        }
      }

      // Inject canary files if requested
      for (const canary of activeCanaries) {
        if (canary.location === 'CANARY_FILE' || canary.location === 'FILESYSTEM') {
          const canaryPath = `/home/user/.canary/${canary.target_key_name}`;
          await sandbox.files.write(canaryPath, canary.synthetic_value);
        }
      }

      const realSession: RealE2BSessionState = {
        isRealE2B: true,
        sandbox,
        options,
        startedAt,
        events,
        canaries: activeCanaries,
      };

      this.activeSessions.set(options.sessionId, realSession);
      return options.sessionId;
    } catch (err: any) {
      if (err instanceof SandboxProviderUnavailableError) {
        throw err;
      }
      const reason = `Real E2B Sandbox provisioning failed: ${err?.message || String(err)}. Fallback to simulation is prohibited.`;
      this.sessionDetails.set(options.sessionId, {
        isReal: false,
        actualProvider: 'NONE',
        executionMode: 'PROVIDER_UNAVAILABLE',
        executionStatus: 'PROVIDER_UNAVAILABLE',
        fallbackReason: reason,
      });
      throw new SandboxProviderUnavailableError(reason);
    }
  }

  private resolveSandboxPath(inputPath: string): string {
    const clean = inputPath.replace(/^\/app\//, '').replace(/^\.\//, '');
    if (clean.startsWith('/home/user/')) return clean;
    if (clean.startsWith('/')) return clean;
    return `/home/user/${clean}`;
  }

  public async writeFile(sessionId: string, path: string, content: string): Promise<void> {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.isRealE2B) {
      return this.fallbackProvider.writeFile(sessionId, path, content);
    }

    const targetPath = this.resolveSandboxPath(path);
    await session.sandbox.files.write(targetPath, content);

    session.events.push({
      event_id: `evt-e2b-fs-w-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'FILESYSTEM',
      action: 'WRITE_FILE',
      target: targetPath,
      status: 'ALLOWED',
      severity: 'INFO',
      metadata: { sizeBytes: content.length, realSandboxId: session.sandbox.sandboxId },
    });
  }

  public async readFile(sessionId: string, path: string): Promise<string> {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.isRealE2B) {
      return this.fallbackProvider.readFile(sessionId, path);
    }

    const targetPath = this.resolveSandboxPath(path);
    const content = await session.sandbox.files.read(targetPath);

    // Check if canary file read
    if (path.includes('.canary')) {
      const canary = session.canaries.find(c => path.includes(c.target_key_name));
      if (canary) {
        canary.tripped = true;
        canary.tripped_at = new Date().toISOString();
        canary.tripped_by_action = `READ_FILE ${path}`;

        session.events.push({
          event_id: `evt-e2b-canary-${Date.now()}`,
          timestamp: new Date().toISOString(),
          scenario_id: session.options.scenarioId,
          scenario_version: session.options.scenarioVersion,
          category: 'CANARY',
          action: 'CANARY_READ_TRIPPED',
          target: canary.name,
          status: 'FLAGGED',
          severity: 'CRITICAL',
          metadata: { canary_id: canary.canary_id, file_path: path, realSandboxId: session.sandbox.sandboxId },
        });
      }
    }

    return content;
  }

  public async executeCommand(sessionId: string, command: SandboxCommand): Promise<SandboxExecutionResult> {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.isRealE2B) {
      const fallbackResult = await this.fallbackProvider.executeCommand(sessionId, command);
      return {
        ...fallbackResult,
        resourcePeak: {
          memoryMb: RESOURCE_TELEMETRY_UNAVAILABLE,
          cpuPercentage: RESOURCE_TELEMETRY_UNAVAILABLE,
          processCount: RESOURCE_TELEMETRY_UNAVAILABLE,
        },
      };
    }

    const start = Date.now();
    const effectiveCwd = (!command.cwd || command.cwd === '/app') ? '/home/user' : command.cwd;
    const fullCmd = command.args && command.args.length > 0 
      ? `${command.command} ${command.args.join(' ')}` 
      : command.command;

    session.events.push({
      event_id: `evt-e2b-proc-start-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'PROCESS',
      action: 'PROCESS_SPAWN',
      target: command.command,
      status: 'ALLOWED',
      severity: 'INFO',
      metadata: { args: command.args, cwd: effectiveCwd, realSandboxId: session.sandbox.sandboxId },
    });

    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    let timedOut = false;

    try {
      const execResult = await session.sandbox.commands.run(fullCmd, {
        cwd: effectiveCwd,
        envs: command.env,
        timeoutMs: command.timeoutMs || session.options.resourceQuota.maxDurationMs,
      });

      stdout = execResult.stdout || '';
      stderr = execResult.stderr || '';
      exitCode = execResult.exitCode ?? 0;
      if (execResult.error) {
        stderr = stderr ? `${stderr}\n${execResult.error}` : execResult.error;
      }
    } catch (err: any) {
      if (err.name === 'TimeoutError' || err.message?.toLowerCase().includes('timeout')) {
        timedOut = true;
        exitCode = 124;
        stderr = `Command timed out after ${command.timeoutMs || session.options.resourceQuota.maxDurationMs}ms`;
      } else {
        exitCode = 1;
        stderr = err.message || String(err);
      }
    }

    const durationMs = Date.now() - start;
    const combinedOutput = `${stdout} ${stderr}`;

    // Inspect command and output against canary tokens
    for (const canary of session.canaries) {
      if (combinedOutput.includes(canary.synthetic_value) || fullCmd.includes(canary.target_key_name)) {
        canary.tripped = true;
        canary.tripped_at = new Date().toISOString();
        canary.tripped_by_action = `COMMAND_EXECUTION ${fullCmd}`;

        session.events.push({
          event_id: `evt-e2b-canary-leak-${Date.now()}`,
          timestamp: new Date().toISOString(),
          scenario_id: session.options.scenarioId,
          scenario_version: session.options.scenarioVersion,
          category: 'CANARY',
          action: 'CANARY_ENV_HARVESTED',
          target: canary.target_key_name,
          status: 'FLAGGED',
          severity: 'CRITICAL',
          metadata: { canary_name: canary.name, command: fullCmd, realSandboxId: session.sandbox.sandboxId },
        });
      }
    }

    // Detect network-layer connection blocking (socket ECONNREFUSED, CONNECT tunnel failure, curl 56/7, blocked at network layer)
    if (combinedOutput.includes('ECONNREFUSED') || 
        combinedOutput.includes('CONNECT tunnel failed') || 
        combinedOutput.includes('Connection refused') || 
        combinedOutput.includes('Blocked at network layer') || 
        combinedOutput.includes('403 Forbidden')) {
      const match = (fullCmd + ' ' + combinedOutput).match(/https?:\/\/([^/'"\s:]+)/) || combinedOutput.match(/ECONNREFUSED\s+([^\s:]+)/);
      const targetHost = match ? match[1] : 'unauthorized-destination';
      session.events.push({
        event_id: `evt-e2b-net-blocked-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'NETWORK',
        action: 'EGRESS_BLOCKED',
        target: targetHost,
        status: 'BLOCKED',
        severity: 'HIGH',
        metadata: { 
          enforcementMechanism: 'E2B_NETWORK_CONFIG', 
          networkPolicy: session.options.networkPolicy.type,
          exitCode,
          stderr: stderr.slice(0, 300),
          realSandboxId: session.sandbox.sandboxId 
        },
      });
    }

    // Record process exit
    session.events.push({
      event_id: `evt-e2b-proc-exit-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'PROCESS',
      action: 'PROCESS_EXIT',
      target: command.command,
      status: exitCode === 0 ? 'ALLOWED' : 'FLAGGED',
      severity: exitCode === 0 ? 'INFO' : 'LOW',
      metadata: { exitCode, durationMs, realSandboxId: session.sandbox.sandboxId },
    });

    let memoryMb: ResourceMetricValue = RESOURCE_TELEMETRY_UNAVAILABLE;
    let cpuPercentage: ResourceMetricValue = RESOURCE_TELEMETRY_UNAVAILABLE;
    let processCount: ResourceMetricValue = RESOURCE_TELEMETRY_UNAVAILABLE;

    if (typeof (session.sandbox as any).getMetrics === 'function') {
      try {
        const metrics = await (session.sandbox as any).getMetrics();
        if (Array.isArray(metrics) && metrics.length > 0) {
          const latest = metrics[metrics.length - 1];
          if (typeof latest?.memoryUsedMb === 'number') memoryMb = latest.memoryUsedMb;
          if (typeof latest?.cpuUsedPct === 'number') cpuPercentage = latest.cpuUsedPct;
          if (typeof latest?.processCount === 'number') processCount = latest.processCount;
          else if (typeof latest?.process_count === 'number') processCount = latest.process_count;
        }
      } catch {
        // Genuine telemetry unavailable from provider
      }
    }

    return {
      exitCode,
      stdout,
      stderr,
      durationMs,
      timedOut,
      resourcePeak: {
        memoryMb,
        cpuPercentage,
        processCount,
      },
    };
  }

  public async collectRuntimeEvents(sessionId: string): Promise<RuntimeEvent[]> {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.isRealE2B) {
      return this.fallbackProvider.collectRuntimeEvents(sessionId);
    }
    return [...session.events];
  }

  private async verifySandboxDestroyed(sandbox: Sandbox): Promise<{
    status: 'CONFIRMED_DESTROYED' | 'STILL_ALIVE' | 'VERIFICATION_IMPOSSIBLE';
    error?: any;
  }> {
    try {
      if (typeof sandbox.isRunning === 'function') {
        let running: boolean;
        try {
          running = await sandbox.isRunning();
        } catch (err: any) {
          const msg = (err?.message || '').toLowerCase();
          // HTTP 404, 502, not found, or connection closed means the sandbox microVM is gone
          if (msg.includes('not found') || msg.includes('404') || msg.includes('502') || msg.includes('closed') || msg.includes('destroyed')) {
            return { status: 'CONFIRMED_DESTROYED' };
          }
          // Network partition / auth error / timeout -> verification impossible
          return { status: 'VERIFICATION_IMPOSSIBLE', error: err };
        }

        if (running === false) {
          return { status: 'CONFIRMED_DESTROYED' };
        }
        return { status: 'STILL_ALIVE' };
      }

      // If isRunning is unavailable, probe with a minimal command
      try {
        await sandbox.commands.run('echo ping', { timeoutMs: 800 });
        return { status: 'STILL_ALIVE' };
      } catch (cmdErr: any) {
        const msg = (cmdErr?.message || '').toLowerCase();
        if (msg.includes('not found') || msg.includes('404') || msg.includes('closed') || msg.includes('destroyed') || msg.includes('killed') || msg.includes('connection refused')) {
          return { status: 'CONFIRMED_DESTROYED' };
        }
        return { status: 'VERIFICATION_IMPOSSIBLE', error: cmdErr };
      }
    } catch (err) {
      return { status: 'VERIFICATION_IMPOSSIBLE', error: err };
    }
  }

  public async destroy(sessionId: string): Promise<TeardownSummary> {
    const session = this.activeSessions.get(sessionId);
    const now = new Date().toISOString();

    if (!session) {
      return {
        session_id: sessionId,
        final_status: 'STATE_UNKNOWN',
        started_at: now,
        destroyed_at: now,
        duration_ms: 0,
        resources_released: false,
        processes_killed: 0,
        ephemeral_files_cleaned: false,
        guaranteed_clean: false,
      };
    }

    if (!session.isRealE2B) {
      const summary = await this.fallbackProvider.destroy(sessionId);
      this.activeSessions.delete(sessionId);
      return summary;
    }

    const durationMs = Date.now() - new Date(session.startedAt).getTime();
    let verifiedDead = false;
    let verificationImpossible = false;
    let terminationError: any = null;
    let attempt = 0;

    while (attempt < 2 && !verifiedDead) {
      attempt++;
      try {
        console.log(`[E2BProvider] Teardown attempt ${attempt}: Killing real E2B sandbox ${session.sandbox.sandboxId}...`);
        await session.sandbox.kill();

        // Success requires independent confirmation the sandbox is actually gone, not just that kill() didn't throw
        const verifyResult = await this.verifySandboxDestroyed(session.sandbox);
        if (verifyResult.status === 'CONFIRMED_DESTROYED') {
          verifiedDead = true;
          terminationError = null;
          break;
        } else if (verifyResult.status === 'STILL_ALIVE') {
          terminationError = new Error(`Sandbox ${session.sandbox.sandboxId} is still reachable/alive after kill() on attempt ${attempt}`);
        } else {
          verificationImpossible = true;
          terminationError = verifyResult.error || new Error('Verification of sandbox termination is impossible');
        }
      } catch (err: any) {
        console.warn(`[E2BProvider] kill() threw on attempt ${attempt}:`, err);
        terminationError = err;

        // Even if kill() threw, check if sandbox is already destroyed/not found
        const verifyResult = await this.verifySandboxDestroyed(session.sandbox);
        if (verifyResult.status === 'CONFIRMED_DESTROYED') {
          verifiedDead = true;
          terminationError = null;
          break;
        } else if (verifyResult.status === 'VERIFICATION_IMPOSSIBLE') {
          verificationImpossible = true;
        }
      }

      if (!verifiedDead && attempt < 2) {
        // Wait briefly before retrying
        await new Promise(r => setTimeout(r, 300));
      }
    }

    if (verifiedDead) {
      console.log(`[E2BProvider] Real E2B sandbox ${session.sandbox.sandboxId} independently confirmed destroyed.`);
      this.activeSessions.delete(sessionId);
      return {
        session_id: sessionId,
        final_status: 'TERMINATED',
        started_at: session.startedAt,
        destroyed_at: new Date().toISOString(),
        duration_ms: durationMs,
        resources_released: true,
        processes_killed: 1,
        ephemeral_files_cleaned: true,
        guaranteed_clean: true,
      };
    }

    // Unresolved termination failure or verification impossible -> Raise operational alert
    const finalStatus: SandboxSessionStatus = verificationImpossible ? 'STATE_UNKNOWN' : 'TERMINATION_FAILED';
    const alert: OperationalAlert = {
      alertId: `alert-e2b-term-${Date.now()}`,
      type: 'SANDBOX_TERMINATION_FAILED',
      severity: 'CRITICAL',
      sessionId,
      sandboxId: session.sandbox.sandboxId,
      timestamp: new Date().toISOString(),
      message: `Failed to terminate and independently verify destruction of E2B sandbox ${session.sandbox.sandboxId} after ${attempt} attempts (${finalStatus})`,
      details: {
        attempts: attempt,
        finalStatus,
        error: terminationError?.message || String(terminationError),
        verificationImpossible,
      },
    };
    E2BSandboxProvider.raiseOperationalAlert(alert);
    console.error(`[E2BProvider] [OPERATIONAL_ALERT] ${alert.message}`, alert);

    this.activeSessions.delete(sessionId);
    return {
      session_id: sessionId,
      final_status: finalStatus,
      started_at: session.startedAt,
      destroyed_at: new Date().toISOString(),
      duration_ms: durationMs,
      resources_released: false,
      processes_killed: 0,
      ephemeral_files_cleaned: false,
      guaranteed_clean: false,
    };
  }
}

