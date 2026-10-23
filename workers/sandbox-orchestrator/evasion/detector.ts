/**
 * Evasion & Anti-Analysis Detection Engine
 * Identifies attempts to detect the sandbox, delay execution, tamper with telemetry, or obfuscate behavior.
 */

import { EvasionIndicator, RuntimeEvent } from '../types.ts';

export interface EvasionAnalysisResult {
  indicators: EvasionIndicator[];
  evasionRiskScore: number; // 0.0 - 1.0
  antiAnalysisDetected: boolean;
  summary: string;
}

export class EvasionDetector {
  /**
   * Analyzes an array of collected RuntimeEvents and command traces for evasion patterns.
   */
  public static analyze(events: RuntimeEvent[], rawTraces: string[]): EvasionAnalysisResult {
    const indicators: EvasionIndicator[] = [
      this.detectDelayedActivation(events, rawTraces),
      this.detectEnvironmentFingerprinting(events, rawTraces),
      this.detectCodeObfuscation(events, rawTraces),
      this.detectConditionalActivation(events, rawTraces),
      this.detectAntiAnalysisTampering(events, rawTraces),
    ];

    const detectedCount = indicators.filter(i => i.detected).length;
    const maxConfidence = Math.max(0, ...indicators.filter(i => i.detected).map(i => i.confidence));
    
    // Calculate normalized risk score
    const evasionRiskScore = detectedCount === 0 ? 0.0 : Math.min(1.0, (detectedCount * 0.25) + (maxConfidence * 0.5));
    const antiAnalysisDetected = indicators.some(i => i.detected && (i.type === 'ANTI_ANALYSIS_TAMPERING' || i.type === 'ENVIRONMENT_FINGERPRINTING'));

    let summary = 'No evasion or anti-analysis behavior detected.';
    if (detectedCount > 0) {
      const activeTypes = indicators.filter(i => i.detected).map(i => i.name).join(', ');
      summary = `Detected ${detectedCount} evasion indicator(s): ${activeTypes}. (Risk score: ${evasionRiskScore.toFixed(2)})`;
    }

    return {
      indicators,
      evasionRiskScore: Number(evasionRiskScore.toFixed(2)),
      antiAnalysisDetected,
      summary,
    };
  }

  private static detectDelayedActivation(events: RuntimeEvent[], traces: string[]): EvasionIndicator {
    const evidence: Array<{ event_id?: string; timestamp: string; detail: string }> = [];

    for (const evt of events) {
      if (evt.action === 'EVASION_DELAY_DETECTED') {
        evidence.push({
          event_id: evt.event_id,
          timestamp: evt.timestamp,
          detail: `Explicit delay probe or sleep loop triggered: ${JSON.stringify(evt.metadata)}`,
        });
      }
    }

    for (const trace of traces) {
      if (/sleep\s+([5-9]|\d{2,})/i.test(trace) || /delayed_activation/i.test(trace) || /setTimeout\(\s*.*,\s*[5-9]\d{3,}\)/i.test(trace)) {
        evidence.push({
          timestamp: new Date().toISOString(),
          detail: `Command trace contains prolonged sleep or delay heuristic: ${trace.slice(0, 100)}`,
        });
      }
    }

    const detected = evidence.length > 0;
    return {
      indicator_id: 'EV-001-DELAYED-ACT',
      type: 'DELAYED_ACTIVATION',
      name: 'Delayed / Stalled Activation Heuristic',
      detected,
      confidence: detected ? 0.95 : 0.0,
      description: 'Execution deliberately stalled or delayed via sleep loops to exhaust sandbox runtime watchdog windows.',
      evidence,
    };
  }

  private static detectEnvironmentFingerprinting(events: RuntimeEvent[], traces: string[]): EvasionIndicator {
    const evidence: Array<{ event_id?: string; timestamp: string; detail: string }> = [];

    for (const evt of events) {
      if (evt.action === 'FINGERPRINT_PROBE' || evt.target === '/proc/cpuinfo' || evt.target === '/.dockerenv') {
        evidence.push({
          event_id: evt.event_id,
          timestamp: evt.timestamp,
          detail: `Probed virtual environment artifacts or hypervisor strings: ${evt.target}`,
        });
      }
    }

    for (const trace of traces) {
      if (/cpuinfo|hypervisor|sandbox_check|is_vm|systemd-detect-virt|dockerenv/i.test(trace)) {
        evidence.push({
          timestamp: new Date().toISOString(),
          detail: `Trace contains environment inspection and hypervisor queries: ${trace.slice(0, 100)}`,
        });
      }
    }

    const detected = evidence.length > 0;
    return {
      indicator_id: 'EV-002-ENV-FINGERPRINT',
      type: 'ENVIRONMENT_FINGERPRINTING',
      name: 'Environment & Hypervisor Fingerprinting',
      detected,
      confidence: detected ? 0.90 : 0.0,
      description: 'Inspected hardware markers, MAC OUIs, /proc/cpuinfo, or container flags to determine if running inside a sandbox.',
      evidence,
    };
  }

  private static detectCodeObfuscation(events: RuntimeEvent[], traces: string[]): EvasionIndicator {
    const evidence: Array<{ event_id?: string; timestamp: string; detail: string }> = [];

    for (const trace of traces) {
      if (/eval\s*\(\s*Buffer\.from/i.test(trace) || /Function\s*\(\s*['"]return\s+this['"]\s*\)/i.test(trace) || /\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i.test(trace)) {
        evidence.push({
          timestamp: new Date().toISOString(),
          detail: `Dynamic code evaluation or packed hex/base64 payload detected in trace: ${trace.slice(0, 100)}`,
        });
      }
    }

    const detected = evidence.length > 0;
    return {
      indicator_id: 'EV-003-CODE-OBFUSCATION',
      type: 'CODE_OBFUSCATION',
      name: 'Dynamic Payload & Code Obfuscation',
      detected,
      confidence: detected ? 0.85 : 0.0,
      description: 'Used runtime memory eval, base64 payload decoding, or hex encoding to conceal operational intentions.',
      evidence,
    };
  }

  private static detectConditionalActivation(events: RuntimeEvent[], traces: string[]): EvasionIndicator {
    const evidence: Array<{ event_id?: string; timestamp: string; detail: string }> = [];

    for (const trace of traces) {
      if (/if\s*\(.*(hostname|NODE_ENV|USER|ci|test).*\)/i.test(trace) && /process\.exit/i.test(trace)) {
        evidence.push({
          timestamp: new Date().toISOString(),
          detail: `Target conditions execution based on hostname or test environment presence: ${trace.slice(0, 100)}`,
        });
      }
    }

    const detected = evidence.length > 0;
    return {
      indicator_id: 'EV-004-COND-ACTIVATION',
      type: 'CONDITIONAL_ACTIVATION',
      name: 'Conditional Trigger & Logic Bomb Heuristic',
      detected,
      confidence: detected ? 0.80 : 0.0,
      description: 'Selectively alters execution paths or terminates cleanly when test/sandbox markers are observed.',
      evidence,
    };
  }

  private static detectAntiAnalysisTampering(events: RuntimeEvent[], traces: string[]): EvasionIndicator {
    const evidence: Array<{ event_id?: string; timestamp: string; detail: string }> = [];

    for (const evt of events) {
      if (evt.action === 'TAMPER_TRACER' || evt.category === 'SECURITY' && evt.action.includes('UNHOOK')) {
        evidence.push({
          event_id: evt.event_id,
          timestamp: evt.timestamp,
          detail: `Attempted to disable or unhook runtime telemetry monitor: ${evt.action}`,
        });
      }
    }

    for (const trace of traces) {
      if (/pkill\s+-9\s+.*telemetry|rm\s+-rf\s+\/var\/log|unlink\s+.*tracer/i.test(trace)) {
        evidence.push({
          timestamp: new Date().toISOString(),
          detail: `Trace contains attempts to destroy audit logs or kill tracer processes: ${trace.slice(0, 100)}`,
        });
      }
    }

    const detected = evidence.length > 0;
    return {
      indicator_id: 'EV-005-ANTI-ANALYSIS',
      type: 'ANTI_ANALYSIS_TAMPERING',
      name: 'Anti-Analysis & Telemetry Tampering',
      detected,
      confidence: detected ? 0.95 : 0.0,
      description: 'Attempted to unhook syscall trackers, delete audit logs, or kill supervisory monitoring daemons.',
      evidence,
    };
  }
}
