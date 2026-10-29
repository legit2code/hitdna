/**
 * Server Routes: Platform Foundation & Taxonomy (PF-02.M02 / PF-03.M01 / PF-04 / RI-06 / PF-09)
 */

import { Router } from 'express';
import { healthService } from '../services/healthService.ts';
import { SuccessEnvelope } from '../contracts/system.ts';
import { getPublicClientConfig, getFeatureFlags, getProviderStatuses, maskObjectSecrets } from '../config/environment.ts';
import { getMusicRepository } from '../repositories/musicRepository.ts';
import { LANGUAGE_SOURCE_REGISTRY, PATTERN_EXTRACTOR_REGISTRY, METHODOLOGY_VERSION_CATALOG } from '../domain/registries.ts';
import { requireAuth, requireRole, requirePermission } from './authMiddleware.ts';
import { defaultAuthGuard } from '../domain/authorizationGuard.ts';
import { ROLE_PERMISSIONS_MATRIX, AuthorizationError } from '../contracts/auth.ts';

export const apiRouter = Router();

apiRouter.get('/health', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const health = healthService.getHealth();
  const response: SuccessEnvelope = {
    success: true,
    data: health,
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/ready', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const readiness = healthService.getReadiness();
  const response: SuccessEnvelope = {
    success: true,
    data: readiness,
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/diag', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const diagnostics = healthService.getDiagnostics();
  const response: SuccessEnvelope = {
    success: true,
    data: maskObjectSecrets(diagnostics),
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/config', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const publicConfig = getPublicClientConfig();
  const featureFlags = getFeatureFlags();
  const response: SuccessEnvelope = {
    success: true,
    data: {
      client: publicConfig,
      features: featureFlags,
    },
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/providers', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const providers = getProviderStatuses();
  const response: SuccessEnvelope = {
    success: true,
    data: maskObjectSecrets(providers),
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

// RI-06 & PF-04: Genre Graph & Taxonomy Endpoints
apiRouter.get('/taxonomy/genres', async (_req, res) => {
  const repo = getMusicRepository();
  const nodes = await repo.listGenreNodes();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: nodes,
    meta: {
      phase: currentPhase,
      count: nodes.length,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/taxonomy/graph', async (_req, res) => {
  const repo = getMusicRepository();
  const nodes = await repo.listGenreNodes();
  const edges = await repo.listGenreEdges();
  const activeTaxonomy = await repo.getActiveTaxonomyVersion();
  const currentPhase = getPublicClientConfig().currentPhase;

  const response: SuccessEnvelope = {
    success: true,
    data: {
      taxonomyVersion: activeTaxonomy?.version || '5.0.0',
      nodeCount: nodes.length,
      edgeCount: edges.length,
      rootFamilies: nodes.filter(n => n.nodeType === 'ROOT_FAMILY').map(n => ({ id: n.genreId, name: n.name })),
      subgenresCount: nodes.filter(n => n.nodeType === 'SUBGENRE').length,
      hybridLabelsCount: nodes.filter(n => n.nodeType === 'HYBRID_LABEL').length,
    },
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/taxonomy/blends', async (_req, res) => {
  const repo = getMusicRepository();
  const blends = await repo.listGenreBlends();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: blends,
    meta: {
      phase: currentPhase,
      count: blends.length,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

// PF-09: Registries Endpoints
apiRouter.get('/registries/language-sources', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: LANGUAGE_SOURCE_REGISTRY,
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/registries/pattern-extractors', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: PATTERN_EXTRACTOR_REGISTRY,
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

apiRouter.get('/registries/methodologies', (_req, res) => {
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: METHODOLOGY_VERSION_CATALOG,
    meta: {
      phase: currentPhase,
      timestamp: new Date().toISOString(),
    },
  };
  res.status(200).json(response);
});

// P04: Research, Patterns & Epistemic Lineage Endpoints
apiRouter.get('/research/cohorts', async (_req, res) => {
  const repo = getMusicRepository();
  const cohorts = await repo.listCohorts();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: cohorts,
    meta: { phase: currentPhase, count: cohorts.length, timestamp: new Date().toISOString() },
  };
  res.status(200).json(response);
});

apiRouter.get('/research/analysis-runs', async (_req, res) => {
  const repo = getMusicRepository();
  const runs = await repo.listAnalysisRuns();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: runs,
    meta: { phase: currentPhase, count: runs.length, timestamp: new Date().toISOString() },
  };
  res.status(200).json(response);
});

apiRouter.get('/research/vernacular-terms', async (_req, res) => {
  const repo = getMusicRepository();
  const terms = await repo.listVernacularTerms();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: terms,
    meta: { phase: currentPhase, count: terms.length, timestamp: new Date().toISOString() },
  };
  res.status(200).json(response);
});

apiRouter.get('/research/musical-patterns', async (_req, res) => {
  const repo = getMusicRepository();
  const chords = await repo.listChordProgressionPatterns();
  const grooves = await repo.listGroovePatterns();
  const arrangements = await repo.listArrangementPatterns();
  const examples = await repo.listPatternReferenceExamples();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: {
      chordPatterns: chords,
      groovePatterns: grooves,
      arrangementPatterns: arrangements,
      referenceExamples: examples,
    },
    meta: { phase: currentPhase, timestamp: new Date().toISOString() },
  };
  res.status(200).json(response);
});

apiRouter.get('/research/source-policies', async (_req, res) => {
  const repo = getMusicRepository();
  const policies = await repo.listSourcePolicies();
  const currentPhase = getPublicClientConfig().currentPhase;
  const response: SuccessEnvelope = {
    success: true,
    data: policies,
    meta: { phase: currentPhase, count: policies.length, timestamp: new Date().toISOString() },
  };
  res.status(200).json(response);
});

apiRouter.get('/research/lineage/metric/:id', async (req, res) => {
  const repo = getMusicRepository();
  try {
    const lineage = await repo.resolveMetricLineage(req.params.id);
    const response: SuccessEnvelope = {
      success: true,
      data: lineage,
      meta: { phase: getPublicClientConfig().currentPhase, timestamp: new Date().toISOString() },
    };
    res.status(200).json(response);
  } catch (err: any) {
    res.status(404).json({ success: false, error: err.message });
  }
});

apiRouter.get('/research/lineage/language-signal/:id', async (req, res) => {
  const repo = getMusicRepository();
  try {
    const lineage = await repo.resolveLanguageSignalLineage(req.params.id);
    const response: SuccessEnvelope = {
      success: true,
      data: lineage,
      meta: { phase: getPublicClientConfig().currentPhase, timestamp: new Date().toISOString() },
    };
    res.status(200).json(response);
  } catch (err: any) {
    res.status(404).json({ success: false, error: err.message });
  }
});

apiRouter.get('/research/lineage/pattern-reference/:id', async (req, res) => {
  const repo = getMusicRepository();
  try {
    const lineage = await repo.resolvePatternReferenceLineage(req.params.id);
    const response: SuccessEnvelope = {
      success: true,
      data: lineage,
      meta: { phase: getPublicClientConfig().currentPhase, timestamp: new Date().toISOString() },
    };
    res.status(200).json(response);
  } catch (err: any) {
    res.status(404).json({ success: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// PF-05: Authentication, Roles & Protected Boundaries (Phase P06)
// ---------------------------------------------------------------------------

apiRouter.get('/auth/me', requireAuth, (req, res) => {
  const user = req.user!;
  const permissions = ROLE_PERMISSIONS_MATRIX[user.role] || [];
  res.status(200).json({
    success: true,
    data: {
      user,
      permissions,
    },
    meta: {
      phase: getPublicClientConfig().currentPhase,
      timestamp: new Date().toISOString(),
    },
  });
});

apiRouter.get('/auth/privileged-audits', requireAuth, requireRole('ADMIN'), (req, res) => {
  const audits = defaultAuthGuard.getPrivilegedAudits(req.user!);
  res.status(200).json({
    success: true,
    data: audits,
    meta: {
      count: audits.length,
      timestamp: new Date().toISOString(),
    },
  });
});

apiRouter.post(
  '/research/source-record',
  requireAuth,
  requirePermission('MUTATE_SOURCE_RECORDS'),
  (req, res) => {
    try {
      defaultAuthGuard.assertResourceMutation(req.user, {
        resourceCollection: 'sourceRecords',
        action: 'CREATE',
        context: 'Create empirical source record',
      });
      res.status(201).json({
        success: true,
        data: {
          id: `src_rec_${Date.now()}`,
          status: 'COMMITTED',
          actor: req.user!.uid,
          role: req.user!.role,
        },
        meta: { timestamp: new Date().toISOString() },
      });
    } catch (err: any) {
      res.status(403).json({ success: false, error: err.message, code: err.code || 'FORBIDDEN' });
    }
  }
);

apiRouter.post(
  '/research/methodology',
  requireAuth,
  requirePermission('MUTATE_METHODOLOGIES'),
  (req, res) => {
    try {
      defaultAuthGuard.assertResourceMutation(req.user, {
        resourceCollection: 'methodologies',
        action: 'UPDATE',
        context: 'Update research methodology',
      });
      res.status(200).json({
        success: true,
        data: {
          id: req.body.id || `meth_${Date.now()}`,
          status: 'VERSION_BUMPED',
          actor: req.user!.uid,
        },
        meta: { timestamp: new Date().toISOString() },
      });
    } catch (err: any) {
      res.status(403).json({ success: false, error: err.message, code: err.code || 'FORBIDDEN' });
    }
  }
);

apiRouter.get('/research/raw-provider-payload/:providerId', requireAuth, (req, res) => {
  try {
    defaultAuthGuard.assertRawContentAccess(req.user, req.params.providerId);
    res.status(200).json({
      success: true,
      data: {
        providerId: req.params.providerId,
        restrictedContent: `[AUTHORIZED RAW PAYLOAD DUMP FOR ${req.params.providerId}]`,
      },
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err: any) {
    if (err instanceof AuthorizationError) {
      res.status(403).json({
        success: false,
        error: err.message,
        code: err.code,
      });
      return;
    }
    res.status(403).json({ success: false, error: 'Forbidden' });
  }
});

apiRouter.post('/admin/override-governance', requireAuth, requireRole('ADMIN'), (req, res) => {
  const { resourceCollection, resourceId, reason, beforeState, afterState } = req.body;
  try {
    const audit = defaultAuthGuard.recordPrivilegedAudit(
      req.user!,
      'GOVERNANCE_OVERRIDE',
      resourceCollection || 'system',
      resourceId || 'sys_override',
      reason || 'Emergency administrative action',
      beforeState,
      afterState,
      req.ip
    );
    res.status(200).json({
      success: true,
      data: audit,
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err: any) {
    res.status(403).json({ success: false, error: err.message });
  }
});



