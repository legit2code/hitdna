import {
  AgentVersionSnapshot,
  DiffAnalysisResult,
  FileDiffItem,
  AstDiffItem,
  DependencyDiffItem,
  CapabilityDiffItem,
  PermissionDiffItem,
  BehaviorDiffItem,
  SourceVsAnalyzerAttribution,
  FindingAttributionItem,
  AttributionType,
} from '../types.ts';

export class DifferentialAnalysisEngine {
  /**
   * Performs complete multi-layer differential analysis between baseline and candidate version snapshots.
   */
  public static compare(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): DiffAnalysisResult {
    const versionDiffId = `diff-${baseline.agentVersionId}-${modified.agentVersionId}`;

    const fileDiffs = this.computeFileDiffs(baseline, modified);
    const astDiffs = this.computeAstDiffs(baseline, modified);
    const dependencyDiffs = this.computeDependencyDiffs(baseline, modified);
    const capabilityDiffs = this.computeCapabilityDiffs(baseline, modified);
    const permissionDiffs = this.computePermissionDiffs(baseline, modified);
    const behaviorDiffs = this.computeBehaviorDiffs(baseline, modified);

    const sourceCodeChanged =
      fileDiffs.some((f) => f.changeType !== 'UNCHANGED') ||
      dependencyDiffs.some((d) => d.changeType !== 'UNCHANGED');

    const analyzerRulesChanged =
      baseline.analyzerConfig.engineVersion !== modified.analyzerConfig.engineVersion ||
      baseline.analyzerConfig.rulesetVersion !== modified.analyzerConfig.rulesetVersion ||
      baseline.analyzerConfig.weightMatrixVersion !== modified.analyzerConfig.weightMatrixVersion ||
      baseline.analyzerConfig.probesCount !== modified.analyzerConfig.probesCount;

    const attribution = this.computeAttribution(
      sourceCodeChanged,
      analyzerRulesChanged,
      baseline,
      modified
    );

    const riskScoreDiff = {
      beforeScore: baseline.riskScore,
      afterScore: modified.riskScore,
      riskIndexDelta: modified.riskScore.riskIndex - baseline.riskScore.riskIndex,
      structuralDelta: modified.riskScore.structuralRisk - baseline.riskScore.structuralRisk,
      taintDelta: modified.riskScore.taintVulnerabilityRisk - baseline.riskScore.taintVulnerabilityRisk,
      toolMisuseDelta: modified.riskScore.toolMisuseRisk - baseline.riskScore.toolMisuseRisk,
      evasionDelta: modified.riskScore.sandboxEvasionRisk - baseline.riskScore.sandboxEvasionRisk,
      criticalFindingsDelta: modified.riskScore.criticalFindingsCount - baseline.riskScore.criticalFindingsCount,
    };

    const hasBreakingChanges =
      astDiffs.some((a) => a.structuralImpact === 'BREAKING') ||
      dependencyDiffs.some((d) => d.isBreaking) ||
      capabilityDiffs.some((c) => c.isRegression && c.isEssential) ||
      permissionDiffs.some((p) => p.riskShift === 'ESCALATED');

    return {
      versionDiffId,
      leftVersionId: baseline.agentVersionId,
      rightVersionId: modified.agentVersionId,
      fileDiffs,
      astDiffs,
      dependencyDiffs,
      capabilityDiffs,
      permissionDiffs,
      behaviorDiffs,
      riskScoreDiff,
      attribution,
      hasBreakingChanges,
    };
  }

  private static computeFileDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): FileDiffItem[] {
    const diffs: FileDiffItem[] = [];
    const allPaths = new Set([
      ...Object.keys(baseline.sourceFiles),
      ...Object.keys(modified.sourceFiles),
    ]);

    for (const path of allPaths) {
      const baseFile = baseline.sourceFiles[path];
      const modFile = modified.sourceFiles[path];

      if (!baseFile && modFile) {
        diffs.push({
          path,
          changeType: 'ADDED',
          afterHash: modFile.hash,
          linesAdded: modFile.content.split('\n').length,
          linesRemoved: 0,
          unifiedDiff: `+ ${path} (new file, ${modFile.sizeBytes} bytes)`,
        });
      } else if (baseFile && !modFile) {
        diffs.push({
          path,
          changeType: 'REMOVED',
          beforeHash: baseFile.hash,
          linesAdded: 0,
          linesRemoved: baseFile.content.split('\n').length,
          unifiedDiff: `- ${path} (deleted file)`,
        });
      } else if (baseFile && modFile) {
        if (baseFile.hash !== modFile.hash) {
          const baseLines = baseFile.content.split('\n');
          const modLines = modFile.content.split('\n');
          diffs.push({
            path,
            changeType: 'MODIFIED',
            beforeHash: baseFile.hash,
            afterHash: modFile.hash,
            linesAdded: Math.max(0, modLines.length - baseLines.length),
            linesRemoved: Math.max(0, baseLines.length - modLines.length),
            unifiedDiff: `@@ -1,${baseLines.length} +1,${modLines.length} @@\n- ${baseFile.content.slice(0, 100)}...\n+ ${modFile.content.slice(0, 100)}...`,
          });
        } else {
          diffs.push({
            path,
            changeType: 'UNCHANGED',
            beforeHash: baseFile.hash,
            afterHash: modFile.hash,
            linesAdded: 0,
            linesRemoved: 0,
          });
        }
      }
    }

    return diffs;
  }

  private static computeAstDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): AstDiffItem[] {
    const diffs: AstDiffItem[] = [];
    const baseMap = new Map(baseline.astNodes.map((n) => [`${n.filePath}::${n.name}`, n]));
    const modMap = new Map(modified.astNodes.map((n) => [`${n.filePath}::${n.name}`, n]));

    const allKeys = new Set([...baseMap.keys(), ...modMap.keys()]);

    for (const key of allKeys) {
      const baseNode = baseMap.get(key);
      const modNode = modMap.get(key);

      if (!baseNode && modNode) {
        diffs.push({
          nodeId: modNode.id,
          name: modNode.name,
          kind: modNode.kind,
          filePath: modNode.filePath,
          changeType: 'ADDED',
          afterSignature: modNode.signature,
          structuralImpact: modNode.kind === 'EXPORT' ? 'MAJOR' : 'MINOR',
        });
      } else if (baseNode && !modNode) {
        diffs.push({
          nodeId: baseNode.id,
          name: baseNode.name,
          kind: baseNode.kind,
          filePath: baseNode.filePath,
          changeType: 'REMOVED',
          beforeSignature: baseNode.signature,
          structuralImpact: baseNode.kind === 'EXPORT' ? 'BREAKING' : 'MAJOR',
        });
      } else if (baseNode && modNode) {
        if (baseNode.bodyHash !== modNode.bodyHash || baseNode.signature !== modNode.signature) {
          const sigChanged = baseNode.signature !== modNode.signature;
          diffs.push({
            nodeId: modNode.id,
            name: modNode.name,
            kind: modNode.kind,
            filePath: modNode.filePath,
            changeType: 'MODIFIED',
            beforeSignature: baseNode.signature,
            afterSignature: modNode.signature,
            structuralImpact: sigChanged ? 'BREAKING' : 'MINOR',
          });
        } else {
          diffs.push({
            nodeId: modNode.id,
            name: modNode.name,
            kind: modNode.kind,
            filePath: modNode.filePath,
            changeType: 'UNCHANGED',
            beforeSignature: baseNode.signature,
            afterSignature: modNode.signature,
            structuralImpact: 'INFORMATIONAL',
          });
        }
      }
    }

    return diffs;
  }

  private static computeDependencyDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): DependencyDiffItem[] {
    const diffs: DependencyDiffItem[] = [];
    const allDeps = new Set([
      ...Object.keys(baseline.dependencies),
      ...Object.keys(modified.dependencies),
    ]);

    for (const name of allDeps) {
      const baseDep = baseline.dependencies[name];
      const modDep = modified.dependencies[name];

      if (!baseDep && modDep) {
        const introduced = (modDep.vulnerabilities || []).map((v) => v.cveId);
        diffs.push({
          name,
          changeType: 'ADDED',
          afterVersion: modDep.version,
          vulnerabilityDelta: { fixed: [], introduced },
          isBreaking: false,
        });
      } else if (baseDep && !modDep) {
        const fixed = (baseDep.vulnerabilities || []).map((v) => v.cveId);
        diffs.push({
          name,
          changeType: 'REMOVED',
          beforeVersion: baseDep.version,
          vulnerabilityDelta: { fixed, introduced: [] },
          isBreaking: true,
        });
      } else if (baseDep && modDep) {
        if (baseDep.version !== modDep.version) {
          const baseCves = new Set((baseDep.vulnerabilities || []).map((v) => v.cveId));
          const modCves = new Set((modDep.vulnerabilities || []).map((v) => v.cveId));

          const fixed = [...baseCves].filter((c) => !modCves.has(c));
          const introduced = [...modCves].filter((c) => !baseCves.has(c));

          diffs.push({
            name,
            changeType: 'MODIFIED',
            beforeVersion: baseDep.version,
            afterVersion: modDep.version,
            vulnerabilityDelta: { fixed, introduced },
            isBreaking: false,
          });
        } else {
          diffs.push({
            name,
            changeType: 'UNCHANGED',
            beforeVersion: baseDep.version,
            afterVersion: modDep.version,
            vulnerabilityDelta: { fixed: [], introduced: [] },
            isBreaking: false,
          });
        }
      }
    }

    return diffs;
  }

  private static computeCapabilityDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): CapabilityDiffItem[] {
    const diffs: CapabilityDiffItem[] = [];
    const baseCapMap = new Map(baseline.capabilities.map((c) => [c.id, c]));
    const modCapMap = new Map(modified.capabilities.map((c) => [c.id, c]));

    const allCapIds = new Set([...baseCapMap.keys(), ...modCapMap.keys()]);

    for (const capId of allCapIds) {
      const baseCap = baseCapMap.get(capId);
      const modCap = modCapMap.get(capId);

      if (!baseCap && modCap) {
        diffs.push({
          capabilityId: capId,
          name: modCap.name,
          category: modCap.category,
          changeType: 'GAINED',
          isEssential: modCap.isEssential,
          isRegression: false,
        });
      } else if (baseCap && !modCap) {
        diffs.push({
          capabilityId: capId,
          name: baseCap.name,
          category: baseCap.category,
          changeType: 'LOST',
          isEssential: baseCap.isEssential,
          isRegression: baseCap.isEssential, // Essential lost capability is a strict regression
        });
      } else if (baseCap && modCap) {
        diffs.push({
          capabilityId: capId,
          name: modCap.name,
          category: modCap.category,
          changeType: 'RETAINED',
          isEssential: modCap.isEssential,
          isRegression: false,
        });
      }
    }

    return diffs;
  }

  private static computePermissionDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): PermissionDiffItem[] {
    const diffs: PermissionDiffItem[] = [];
    const basePermMap = new Map(baseline.permissions.map((p) => [`${p.scope}::${p.resource}`, p]));
    const modPermMap = new Map(modified.permissions.map((p) => [`${p.scope}::${p.resource}`, p]));

    const allPermKeys = new Set([...basePermMap.keys(), ...modPermMap.keys()]);

    for (const key of allPermKeys) {
      const baseP = basePermMap.get(key);
      const modP = modPermMap.get(key);

      if (!baseP && modP) {
        diffs.push({
          resource: modP.resource,
          changeType: 'ADDED',
          afterActions: modP.actions,
          riskShift: modP.riskLevel === 'HIGH' || modP.riskLevel === 'CRITICAL' ? 'ESCALATED' : 'NEUTRAL',
        });
      } else if (baseP && !modP) {
        diffs.push({
          resource: baseP.resource,
          changeType: 'REMOVED',
          beforeActions: baseP.actions,
          riskShift: 'REDUCED',
        });
      } else if (baseP && modP) {
        const addedActions = modP.actions.filter((a) => !baseP.actions.includes(a));
        const removedActions = baseP.actions.filter((a) => !modP.actions.includes(a));

        if (addedActions.length > 0) {
          diffs.push({
            resource: modP.resource,
            changeType: 'EXPANDED',
            beforeActions: baseP.actions,
            afterActions: modP.actions,
            riskShift: 'ESCALATED',
          });
        } else if (removedActions.length > 0) {
          diffs.push({
            resource: modP.resource,
            changeType: 'REDUCED',
            beforeActions: baseP.actions,
            afterActions: modP.actions,
            riskShift: 'REDUCED',
          });
        } else {
          diffs.push({
            resource: modP.resource,
            changeType: 'UNCHANGED',
            beforeActions: baseP.actions,
            afterActions: modP.actions,
            riskShift: 'NEUTRAL',
          });
        }
      }
    }

    return diffs;
  }

  private static computeBehaviorDiffs(
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): BehaviorDiffItem[] {
    const diffs: BehaviorDiffItem[] = [];
    const baseMap = new Map(baseline.behaviors.map((b) => [b.scenarioId, b]));
    const modMap = new Map(modified.behaviors.map((b) => [b.scenarioId, b]));

    const allScenarios = new Set([...baseMap.keys(), ...modMap.keys()]);

    for (const id of allScenarios) {
      const baseB = baseMap.get(id);
      const modB = modMap.get(id);

      const beforePassed = baseB ? baseB.passed : false;
      const afterPassed = modB ? modB.passed : false;

      let changeType: 'IMPROVED' | 'REGRESSED' | 'UNCHANGED' = 'UNCHANGED';
      if (!beforePassed && afterPassed) changeType = 'IMPROVED';
      else if (beforePassed && !afterPassed) changeType = 'REGRESSED';

      diffs.push({
        scenarioId: id,
        name: modB?.name || baseB?.name || id,
        changeType,
        beforePassed,
        afterPassed,
        details:
          changeType === 'IMPROVED'
            ? 'Scenario passed in candidate version'
            : changeType === 'REGRESSED'
            ? 'Scenario failed in candidate version'
            : 'Behavior consistent across versions',
      });
    }

    return diffs;
  }

  private static computeAttribution(
    sourceCodeChanged: boolean,
    analyzerRulesChanged: boolean,
    baseline: AgentVersionSnapshot,
    modified: AgentVersionSnapshot
  ): SourceVsAnalyzerAttribution {
    let overallAttribution: AttributionType = 'NO_CHANGE';
    if (sourceCodeChanged && analyzerRulesChanged) overallAttribution = 'BOTH';
    else if (sourceCodeChanged) overallAttribution = 'SOURCE_CHANGE';
    else if (analyzerRulesChanged) overallAttribution = 'ANALYZER_CHANGE';

    const findingsAttribution: FindingAttributionItem[] = [];

    // Synthesize finding attribution records
    const findingDelta = modified.riskScore.criticalFindingsCount - baseline.riskScore.criticalFindingsCount;

    if (findingDelta < 0) {
      // Findings disappeared
      if (sourceCodeChanged && !analyzerRulesChanged) {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'Remediated security issues',
          severity: 'HIGH',
          attribution: 'REMEDIED_VULNERABILITY',
          explanation: 'Vulnerabilities resolved by code modifications while analyzer rules remained fixed.',
        });
      } else if (!sourceCodeChanged && analyzerRulesChanged) {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'Rule relaxation or suppression',
          severity: 'HIGH',
          attribution: 'RULE_RELAXATION',
          explanation: 'Findings cleared due to analyzer ruleset update on identical source code.',
        });
      } else {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'Combined remediation & analyzer change',
          severity: 'HIGH',
          attribution: 'COMBINED_EFFECT',
          explanation: 'Both source modifications and analyzer ruleset version changes occurred simultaneously.',
        });
      }
    } else if (findingDelta > 0) {
      // New findings appeared
      if (sourceCodeChanged && !analyzerRulesChanged) {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'New vulnerability introduced',
          severity: 'CRITICAL',
          attribution: 'NEW_SOURCE_VULNERABILITY',
          explanation: 'Source code edit introduced new security finding under identical analyzer rules.',
        });
      } else if (!sourceCodeChanged && analyzerRulesChanged) {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'New detection probe active',
          severity: 'HIGH',
          attribution: 'NEW_DETECTION_RULE',
          explanation: 'New analyzer rule flagged existing pattern on unmodified source code.',
        });
      } else {
        findingsAttribution.push({
          findingId: 'finding-delta',
          title: 'Combined detection & source shift',
          severity: 'HIGH',
          attribution: 'COMBINED_EFFECT',
          explanation: 'New findings detected with both source edits and analyzer ruleset upgrades.',
        });
      }
    }

    const rationale =
      overallAttribution === 'SOURCE_CHANGE'
        ? 'Differences are purely attributed to source code and dependency modifications.'
        : overallAttribution === 'ANALYZER_CHANGE'
        ? 'Source code is identical; differences are purely attributed to analyzer engine or ruleset changes.'
        : overallAttribution === 'BOTH'
        ? 'Differences involve both source code updates and analyzer engine/ruleset shifts.'
        : 'No source or analyzer differences detected.';

    return {
      overallAttribution,
      sourceCodeChanged,
      analyzerRulesChanged,
      findingsAttribution,
      rationale,
    };
  }
}
