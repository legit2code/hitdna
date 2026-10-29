/**
 * Unit & Integration Tests: Authentication, Roles & Security Boundaries (PF-05)
 * Phase: P06
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthUser,
  UserRole,
  ROLE_PERMISSIONS_MATRIX,
  AuthorizationError,
} from '../../contracts/auth.js';
import { AuthorizationGuard } from '../../domain/authorizationGuard.js';
import { createExpressApp } from '../../server/app.js';
import * as fs from 'fs';
import * as path from 'path';

describe('PF-05: Authentication, Roles & Firestore Security Boundaries', () => {
  let guard: AuthorizationGuard;

  const normalUser: AuthUser = {
    uid: 'usr_normal_001',
    email: 'creator@example.com',
    displayName: 'Song Creator',
    photoURL: null,
    role: 'USER',
    createdAt: new Date().toISOString(),
  };

  const otherUser: AuthUser = {
    uid: 'usr_other_002',
    email: 'other@example.com',
    displayName: 'Other Creator',
    photoURL: null,
    role: 'USER',
    createdAt: new Date().toISOString(),
  };

  const researcherUser: AuthUser = {
    uid: 'usr_researcher_001',
    email: 'researcher@hitdna.internal',
    displayName: 'Musicologist Lead',
    photoURL: null,
    role: 'RESEARCHER',
    createdAt: new Date().toISOString(),
  };

  const adminUser: AuthUser = {
    uid: 'usr_admin_001',
    email: 'admin@hitdna.internal',
    displayName: 'Platform Admin',
    photoURL: null,
    role: 'ADMIN',
    createdAt: new Date().toISOString(),
  };

  beforeEach(() => {
    guard = new AuthorizationGuard();
  });

  describe('1. Role & Permission Matrix (Positive & Negative)', () => {
    it('normal USER has read access for published DNA and own generations', () => {
      assert.equal(guard.hasPermission(normalUser, 'READ_PUBLISHED_DNA'), true);
      assert.equal(guard.hasPermission(normalUser, 'READ_APPROVED_ARTISTS'), true);
      assert.equal(guard.hasPermission(normalUser, 'MANAGE_OWN_GENERATIONS'), true);
      assert.equal(guard.hasPermission(normalUser, 'MANAGE_OWN_FEEDBACK'), true);
    });

    it('normal USER is forbidden from mutating source records, evidence, and methodologies', () => {
      assert.equal(guard.hasPermission(normalUser, 'MUTATE_SOURCE_RECORDS'), false);
      assert.equal(guard.hasPermission(normalUser, 'MUTATE_EVIDENCE'), false);
      assert.equal(guard.hasPermission(normalUser, 'MUTATE_METHODOLOGIES'), false);
      assert.equal(guard.hasPermission(normalUser, 'MUTATE_PUBLICATION_STATE'), false);
      assert.equal(guard.hasPermission(normalUser, 'OVERRIDE_GOVERNANCE'), false);

      assert.throws(() => {
        guard.assertPermission(normalUser, 'MUTATE_SOURCE_RECORDS');
      }, AuthorizationError);

      assert.throws(() => {
        guard.assertPermission(normalUser, 'MUTATE_METHODOLOGIES');
      }, AuthorizationError);
    });

    it('RESEARCHER can mutate empirical source records and evidence, but NOT methodologies or publication state', () => {
      assert.equal(guard.hasPermission(researcherUser, 'MUTATE_SOURCE_RECORDS'), true);
      assert.equal(guard.hasPermission(researcherUser, 'MUTATE_EVIDENCE'), true);
      assert.equal(guard.hasPermission(researcherUser, 'MUTATE_DATASETS'), true);
      assert.equal(guard.hasPermission(researcherUser, 'READ_RESTRICTED_RAW_CONTENT'), true);

      // Forbidden
      assert.equal(guard.hasPermission(researcherUser, 'MUTATE_METHODOLOGIES'), false);
      assert.equal(guard.hasPermission(researcherUser, 'MUTATE_PUBLICATION_STATE'), false);
      assert.equal(guard.hasPermission(researcherUser, 'OVERRIDE_GOVERNANCE'), false);
    });

    it('ADMIN has all capabilities including publication, governance override, and audit inspection', () => {
      const allPermissions = ROLE_PERMISSIONS_MATRIX.ADMIN;
      for (const perm of allPermissions) {
        assert.equal(guard.hasPermission(adminUser, perm), true);
      }
    });
  });

  describe('2. Resource Ownership & Mutation Scoping', () => {
    it('allows a user to mutate their own generation artifacts', () => {
      assert.doesNotThrow(() => {
        guard.assertResourceMutation(normalUser, {
          resourceCollection: 'generationRequests',
          action: 'CREATE',
          resourceOwnerId: normalUser.uid,
        });
      });

      assert.doesNotThrow(() => {
        guard.assertResourceMutation(normalUser, {
          resourceCollection: 'generationFeedback',
          action: 'CREATE',
          resourceOwnerId: normalUser.uid,
        });
      });
    });

    it('prevents a user from mutating or accessing another user generation records', () => {
      assert.throws(() => {
        guard.assertResourceMutation(normalUser, {
          resourceCollection: 'generationRequests',
          action: 'UPDATE',
          resourceOwnerId: otherUser.uid,
        });
      }, AuthorizationError);

      try {
        guard.assertResourceOwnership(normalUser, otherUser.uid, 'songSpecifications');
        assert.fail('Should have thrown');
      } catch (err: any) {
        assert.equal(err.code, 'RESOURCE_OWNERSHIP_VIOLATION');
      }
    });

    it('blocks normal users from mutating publishedHitDnaSnapshots or methodologies', () => {
      assert.throws(() => {
        guard.assertResourceMutation(normalUser, {
          resourceCollection: 'publishedHitDnaSnapshots',
          action: 'UPDATE',
        });
      }, AuthorizationError);

      assert.throws(() => {
        guard.assertResourceMutation(normalUser, {
          resourceCollection: 'methodologies',
          action: 'UPDATE',
        });
      }, AuthorizationError);
    });

    it('allows RESEARCHER to mutate source records but blocks them from publication changes', () => {
      assert.doesNotThrow(() => {
        guard.assertResourceMutation(researcherUser, {
          resourceCollection: 'sourceRecords',
          action: 'CREATE',
        });
      });

      assert.throws(() => {
        guard.assertResourceMutation(researcherUser, {
          resourceCollection: 'publishedHitDnaSnapshots',
          action: 'CREATE',
        });
      }, AuthorizationError);
    });

    it('allows ADMIN to mutate publication state and records privileged audit', () => {
      assert.doesNotThrow(() => {
        guard.assertResourceMutation(adminUser, {
          resourceCollection: 'publishedHitDnaSnapshots',
          action: 'CREATE',
        });
      });
    });
  });

  describe('3. Restricted Raw Provider Content Boundaries', () => {
    it('blocks normal user from viewing raw third-party payloads', () => {
      assert.throws(() => {
        guard.assertRawContentAccess(normalUser, 'spotify');
      }, AuthorizationError);

      try {
        guard.assertRawContentAccess(normalUser, 'spotify');
        assert.fail('Should have thrown');
      } catch (err: any) {
        assert.equal(err.code, 'RESTRICTED_CONTENT_VIOLATION');
      }
    });

    it('permits RESEARCHER and ADMIN to inspect raw provider payloads for data verification', () => {
      assert.doesNotThrow(() => {
        guard.assertRawContentAccess(researcherUser, 'spotify');
      });

      assert.doesNotThrow(() => {
        guard.assertRawContentAccess(adminUser, 'billboard');
      });
    });
  });

  describe('4. Privileged Override & Audit Trail', () => {
    it('records and returns privileged audit trails for ADMIN actions', () => {
      const audit = guard.recordPrivilegedAudit(
        adminUser,
        'MANUAL_DNA_FREEZE',
        'publishedHitDnaSnapshots',
        'snap_2026_q1',
        'Quarterly governance baseline freeze'
      );

      assert.equal(audit.actorId, adminUser.uid);
      assert.equal(audit.actorRole, 'ADMIN');
      assert.equal(audit.action, 'MANUAL_DNA_FREEZE');

      const logs = guard.getPrivilegedAudits(adminUser);
      assert.equal(logs.length, 1);
      assert.equal(logs[0].id, audit.id);
    });

    it('rejects non-admin attempt to record privileged audit overrides', () => {
      assert.throws(() => {
        guard.recordPrivilegedAudit(
          researcherUser as any,
          'MANUAL_DNA_FREEZE',
          'publishedHitDnaSnapshots',
          'snap_2026_q1',
          'Unauthorized override attempt'
        );
      }, AuthorizationError);
    });
  });

  describe('5. Client Bundle & Secret Isolation (P00/P06 Hard Boundary)', () => {
    it('verifies that no server or admin secrets leak to client-accessible files', () => {
      const clientFiles = [
        path.join(process.cwd(), 'src/client/auth/authService.ts'),
        path.join(process.cwd(), 'src/client/auth/AuthContext.tsx'),
        path.join(process.cwd(), 'src/App.tsx'),
      ];

      for (const filePath of clientFiles) {
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          assert.equal(content.includes('process.env.GEMINI_API_KEY'), false);
          assert.equal(content.includes('serviceAccountKey'), false);
          assert.equal(content.includes('private_key_id'), false);
          assert.equal(content.includes('FIREBASE_ADMIN'), false);
        }
      }
    });

    it('verifies firestore.rules exists and contains default-deny and role enforcement', () => {
      const rulesPath = path.join(process.cwd(), 'firestore.rules');
      assert.equal(fs.existsSync(rulesPath), true);
      const rulesContent = fs.readFileSync(rulesPath, 'utf8');

      assert.equal(rulesContent.includes('function isAdmin()'), true);
      assert.equal(rulesContent.includes('function isResearcher()'), true);
      assert.equal(rulesContent.includes('function isOwner(userId)'), true);
      assert.equal(rulesContent.includes('allow read, write: if false;'), true);
      assert.equal(rulesContent.includes('match /publishedHitDnaSnapshots/{snapshotId}'), true);
    });
  });

  describe('6. HTTP Server Authorization Guards Integration', () => {
    const _app = createExpressApp();

    it('blocks unauthenticated requests to protected endpoints', async () => {
      const req: any = {
        headers: {},
        path: '/api/auth/me',
      };
      let status = 0;
      let body: any = null;
      const res: any = {
        status: (s: number) => {
          status = s;
          return res;
        },
        json: (b: any) => {
          body = b;
          return res;
        },
      };

      const { requireAuth } = await import('../../server/authMiddleware.js');
      requireAuth(req, res, () => {});
      assert.equal(status, 401);
      assert.equal(body.error, 'UNAUTHENTICATED');
    });

    it('rejects normal user from research source mutation endpoint', async () => {
      const req: any = {
        headers: {},
        user: normalUser,
        path: '/api/research/source-record',
      };
      let status = 0;
      let body: any = null;
      const res: any = {
        status: (s: number) => {
          status = s;
          return res;
        },
        json: (b: any) => {
          body = b;
          return res;
        },
      };

      const { requirePermission } = await import('../../server/authMiddleware.js');
      const middleware = requirePermission('MUTATE_SOURCE_RECORDS');
      middleware(req, res, () => {});

      assert.equal(status, 403);
      assert.equal(body.error, 'PERMISSION_DENIED');
    });

    it('allows RESEARCHER on research source mutation endpoint', async () => {
      const req: any = {
        headers: {},
        user: researcherUser,
        path: '/api/research/source-record',
      };
      let nextCalled = false;
      const res: any = {
        status: () => res,
        json: () => res,
      };

      const { requirePermission } = await import('../../server/authMiddleware.js');
      const middleware = requirePermission('MUTATE_SOURCE_RECORDS');
      middleware(req, res, () => {
        nextCalled = true;
      });

      assert.equal(nextCalled, true);
    });
  });
});
