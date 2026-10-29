/**
 * Health & Readiness Service
 * Canonical Engines: PF-02 (Tooling Foundation) & PF-03 (Typed Config & Secrets)
 */

import { SystemHealth, ReadinessState, DiagnosticInfo } from '../contracts/system.ts';
import { getServerConfig, getPublicClientConfig, getProviderStatuses } from '../config/environment.ts';
import {
  PF02_ENGINE_DEFINITION,
  PF03_ENGINE_DEFINITION,
  PF04_ENGINE_DEFINITION,
  PF09_ENGINE_DEFINITION,
  RI06_ENGINE_DEFINITION,
} from '../domain/foundation.ts';

export class HealthService {
  private startTime: number = Date.now();

  getHealth(): SystemHealth {
    const config = getServerConfig();
    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);

    return {
      status: 'healthy',
      uptimeSeconds,
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      architectureVersion: '5.0.0',
      environment: config.nodeEnv,
      checks: {
        server: true,
        config: true,
        storage: true,
      },
    };
  }

  getReadiness(): ReadinessState {
    const clientConfig = getPublicClientConfig();

    return {
      ready: true,
      phase: clientConfig.currentPhase,
      engineId: PF04_ENGINE_DEFINITION.engineId,
      missingRequirements: [],
      timestamp: new Date().toISOString(),
    };
  }

  getDiagnostics(): DiagnosticInfo & { activeEngines: string[]; totalModules: number; providers: ReturnType<typeof getProviderStatuses> } {
    const config = getServerConfig();
    const allActiveEngines = [
      PF02_ENGINE_DEFINITION,
      PF03_ENGINE_DEFINITION,
      PF04_ENGINE_DEFINITION,
      PF09_ENGINE_DEFINITION,
      RI06_ENGINE_DEFINITION,
    ];
    const totalModules = allActiveEngines.reduce((acc, eng) => acc + eng.modules.length, 0);

    return {
      engineId: PF04_ENGINE_DEFINITION.engineId,
      moduleCoverageCount: totalModules,
      runtimeNodeVersion: process.version,
      activePort: config.port,
      platform: process.platform,
      memoryUsage: process.memoryUsage(),
      activeEngines: allActiveEngines.map(e => e.engineId),
      totalModules,
      providers: getProviderStatuses(),
    };
  }
}

export const healthService = new HealthService();
