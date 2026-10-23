import {
  AgentVersionSnapshot,
  DiffAnalysisResult,
  ImpactAssessment,
  ImpactItem,
  ImpactSeverity,
  ReanalysisTrigger,
} from '../types.ts';

export class ImpactAnalysisEngine {
  /**
   * Evaluates the blast radius and downstream security impact of changes.
   */
  public static evaluate(
    diff: DiffAnalysisResult,
    baseline: AgentVersionSnapshot
  ): ImpactAssessment {
    const impactAssessmentId = `impact-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const impactItems: ImpactItem[] = [];

    let affectsEntryPoints = false;
    let affectsDependencies = false;
    let affectsPermissions = false;
    let capabilityRegressionRisk = false;

    // 1. Evaluate file & AST impact
    for (const fileDiff of diff.fileDiffs) {
      if (fileDiff.changeType === 'UNCHANGED') continue;

      const isEntryPoint =
        fileDiff.path.includes('index.') ||
        fileDiff.path.includes('main.') ||
        fileDiff.path.includes('server.') ||
        fileDiff.path.includes('app.');

      if (isEntryPoint) {
        affectsEntryPoints = true;
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: fileDiff.path,
          impactType: 'API_SURFACE_SHIFT',
          severity: 'HIGH',
          requiredAction: 'REANALYZE',
          description: `Entry point file '${fileDiff.path}' was ${fileDiff.changeType.toLowerCase()}; requires full pipeline re-evaluation.`,
        });
      }
    }

    for (const astDiff of diff.astDiffs) {
      if (astDiff.structuralImpact === 'BREAKING') {
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: `${astDiff.filePath}::${astDiff.name}`,
          impactType: 'DEPENDENCY_BREAKAGE',
          severity: 'CRITICAL',
          requiredAction: 'REGRESSION_TEST',
          description: `Breaking AST signature modification in '${astDiff.name}' may disrupt caller modules.`,
        });
      }
    }

    // 2. Evaluate dependency impact
    for (const depDiff of diff.dependencyDiffs) {
      if (depDiff.changeType === 'UNCHANGED') continue;
      affectsDependencies = true;

      if (depDiff.vulnerabilityDelta.introduced.length > 0) {
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: `package:${depDiff.name}`,
          impactType: 'RISK_ESCALATION',
          severity: 'CRITICAL',
          requiredAction: 'BLOCK',
          description: `Dependency '${depDiff.name}' introduces CVEs: ${depDiff.vulnerabilityDelta.introduced.join(', ')}`,
        });
      } else if (depDiff.vulnerabilityDelta.fixed.length > 0) {
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: `package:${depDiff.name}`,
          impactType: 'SECURITY_HARDENING',
          severity: 'LOW',
          requiredAction: 'ACCEPT',
          description: `Dependency '${depDiff.name}' resolves CVEs: ${depDiff.vulnerabilityDelta.fixed.join(', ')}`,
        });
      }
    }

    // 3. Evaluate capability impact & preservation
    for (const capDiff of diff.capabilityDiffs) {
      if (capDiff.changeType === 'LOST' && capDiff.isEssential) {
        capabilityRegressionRisk = true;
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: `capability:${capDiff.name}`,
          impactType: 'CAPABILITY_REGRESSION',
          severity: 'CRITICAL',
          requiredAction: 'MANUAL_REVIEW',
          description: `Essential capability '${capDiff.name}' was LOST in modified candidate version!`,
        });
      }
    }

    // 4. Evaluate permission impact
    for (const permDiff of diff.permissionDiffs) {
      if (permDiff.riskShift === 'ESCALATED') {
        affectsPermissions = true;
        impactItems.push({
          impactItemId: `item-${impactItems.length + 1}`,
          targetEntity: `permission:${permDiff.resource}`,
          impactType: 'RISK_ESCALATION',
          severity: 'HIGH',
          requiredAction: 'MANUAL_REVIEW',
          description: `Permission scope on resource '${permDiff.resource}' escalated to higher privilege.`,
        });
      }
    }

    // Determine highest severity
    let highestSeverity: ImpactSeverity = 'NONE';
    if (impactItems.some((i) => i.severity === 'CRITICAL')) highestSeverity = 'CRITICAL';
    else if (impactItems.some((i) => i.severity === 'HIGH')) highestSeverity = 'HIGH';
    else if (impactItems.some((i) => i.severity === 'MEDIUM')) highestSeverity = 'MEDIUM';
    else if (impactItems.some((i) => i.severity === 'LOW')) highestSeverity = 'LOW';

    // Determine suggested reanalysis trigger
    let suggestedReanalysisTrigger: ReanalysisTrigger = 'NO_REANALYSIS_NEEDED';
    if (affectsEntryPoints || affectsDependencies || affectsPermissions || capabilityRegressionRisk || highestSeverity === 'CRITICAL') {
      suggestedReanalysisTrigger = 'FULL_REANALYSIS';
    } else if (diff.fileDiffs.some((f) => f.changeType !== 'UNCHANGED')) {
      suggestedReanalysisTrigger = 'INCREMENTAL_REANALYSIS';
    }

    return {
      impactAssessmentId,
      workspaceId: `ws-${baseline.agentVersionId}`,
      highestSeverity,
      affectsEntryPoints,
      affectsDependencies,
      affectsPermissions,
      capabilityRegressionRisk,
      impactItems,
      suggestedReanalysisTrigger,
      createdAt: new Date().toISOString(),
    };
  }
}
