/**
 * E2E Test Capability (PF-02.M08)
 * Verifies application shell integration and client/server contract consistency.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { getPublicClientConfig } from '../../config/environment.ts';
import {
  PF02_ENGINE_DEFINITION,
  PF03_ENGINE_DEFINITION,
  PF04_ENGINE_DEFINITION,
  PF09_ENGINE_DEFINITION,
  RI06_ENGINE_DEFINITION,
} from '../../domain/foundation.ts';

describe('App Shell E2E Contract & Integration Tests', () => {
  test('Application shell configuration aligns with active phase P01/P02/P03', () => {
    const publicConfig = getPublicClientConfig();
    assert.ok(['P01', 'P02', 'P03'].includes(publicConfig.currentPhase));
    assert.equal(publicConfig.architectureVersion, '5.0.0');
    assert.equal(publicConfig.appName, 'Hit DNA Music Intelligence');
  });

  test('All PF-02 engine modules are marked IMPLEMENTED', () => {
    for (const mod of PF02_ENGINE_DEFINITION.modules) {
      assert.equal(mod.status, 'IMPLEMENTED', `Module ${mod.moduleId} must be IMPLEMENTED`);
    }
  });

  test('All PF-03 engine modules are marked IMPLEMENTED', () => {
    for (const mod of PF03_ENGINE_DEFINITION.modules) {
      assert.equal(mod.status, 'IMPLEMENTED', `Module ${mod.moduleId} must be IMPLEMENTED`);
    }
  });

  test('All PF-04 persistence engine modules are marked IMPLEMENTED', () => {
    assert.equal(PF04_ENGINE_DEFINITION.modules.length, 8);
    for (const mod of PF04_ENGINE_DEFINITION.modules) {
      assert.equal(mod.status, 'IMPLEMENTED', `Module ${mod.moduleId} must be IMPLEMENTED`);
    }
  });

  test('All PF-09 governance engine modules are marked IMPLEMENTED', () => {
    assert.equal(PF09_ENGINE_DEFINITION.modules.length, 10);
    for (const mod of PF09_ENGINE_DEFINITION.modules) {
      assert.equal(mod.status, 'IMPLEMENTED', `Module ${mod.moduleId} must be IMPLEMENTED`);
    }
  });

  test('All RI-06 genre taxonomy engine modules are marked IMPLEMENTED', () => {
    assert.equal(RI06_ENGINE_DEFINITION.modules.length, 10);
    for (const mod of RI06_ENGINE_DEFINITION.modules) {
      assert.equal(mod.status, 'IMPLEMENTED', `Module ${mod.moduleId} must be IMPLEMENTED`);
    }
  });
});
