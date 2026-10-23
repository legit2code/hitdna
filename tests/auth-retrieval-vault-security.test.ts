import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express, { Request, Response, NextFunction } from 'express';
import { Server } from 'http';
import { 
  AuthService, 
  createServerAuthHelper, 
  SecurityClassificationRank 
} from '@caim/auth';
import { initializeKnowledgeAndRetrieval } from '../workers/knowledge/index.ts';
import { RagSynthesisPipeline } from '../workers/knowledge/synthesis/pipeline.ts';
import { HybridRetrievalService } from '../workers/knowledge/retrieval/service.ts';
import { KnowledgeCorpusManager } from '../workers/knowledge/reindex/scheduler.ts';
import { createTestDb } from '@caim/db/migrator.ts';

describe('Security Invariant: Verified Principal & Anti-Tamper Retrieval/RAG Gates', () => {
  let app: express.Application;
  let server: Server;
  let baseUrl: string;
  let authService: AuthService;
  let retrieval: HybridRetrievalService;
  let corpus: KnowledgeCorpusManager;
  let pipeline: RagSynthesisPipeline;

  let lowPrivUserToken: string;
  let adminUserToken: string;

  beforeAll(async () => {
    // 1. Initialize Auth and seed accounts
    AuthService.clearInMemoryPrincipals();
    AuthService.seedDevelopmentPrincipals();
    authService = new AuthService();
    const authHelper = createServerAuthHelper();

    // Log in as low-privilege user ('user' role, max clearance: INTERNAL, has_vault_access: false)
    const userLogin = await authService.loginWithPassword({
      email: 'user@caim.internal',
      password: 'User123!Secure',
    });
    lowPrivUserToken = userLogin.access_token;

    // Log in as admin user ('admin' role, max clearance: VAULT_RESTRICTED, has_vault_access: true)
    const adminLogin = await authService.loginWithPassword({
      email: 'admin@caim.internal',
      password: 'Admin#2026$RotatedRootKey!8472',
    });
    adminUserToken = adminLogin.access_token;

    // 2. Initialize Knowledge & Retrieval system
    const init = await initializeKnowledgeAndRetrieval();
    corpus = init.corpus;
    retrieval = init.retrieval;
    pipeline = new RagSynthesisPipeline(corpus, retrieval);

    // 3. Set up Express application matching apps/server/index.ts
    app = express();
    app.use(express.json());

    // Authentication middleware
    app.use(async (req: Request, _res: Response, next: NextFunction) => {
      try {
        (req as any).principal = await authHelper.authenticateRequest(req.headers as any);
      } catch {
        (req as any).principal = {
          principal_id: 'anonymous',
          is_authenticated: false,
          is_service: false,
          roles: ['anonymous'],
          tenant_id: null,
          accessible_scope_ids: ['00000000-0000-0000-0000-000000000001'],
          max_classification_rank: SecurityClassificationRank.PUBLIC_METADATA,
          grants: [],
        };
      }
      next();
    });

    // Real authentication guard requiring a verified, non-anonymous principal
    const requireAuthenticatedPrincipal = (req: Request, res: Response, next: NextFunction) => {
      const p = (req as any).principal;
      if (!p || !p.is_authenticated || p.roles?.includes('anonymous')) {
        return res.status(401).json({
          error: "Unauthorized: Verified authentication required.",
          authenticated: false,
        });
      }
      next();
    };

    // POST /api/dev/retrieval/execute with real auth and server-side entitlement derivation
    app.post("/api/dev/retrieval/execute", requireAuthenticatedPrincipal, async (req: Request, res: Response) => {
      try {
        const { query, scoped_agent_id, scoped_agent_version_id, budget_max_records } = req.body || {};
        if (!query) {
          return res.status(400).json({ error: "Missing required query string" });
        }

        const principal = (req as any).principal;
        // Server-side entitlement resolution from authoritative store
        const entitlements = await authService.resolvePrincipalEntitlements(principal.principal_id, principal);
        const rank = entitlements.max_classification_rank;
        const vaultAccess = entitlements.has_vault_access;

        const result = await retrieval.retrieveContext(query, {
          caller_user_id: principal.principal_id,
          caller_security_rank: rank,
          caller_has_vault_access: vaultAccess,
          scoped_agent_id,
          scoped_agent_version_id,
          budget_max_records: budget_max_records ? Number(budget_max_records) : 20,
        });

        res.json(result);
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    });

    // POST /api/dev/rag/synthesize with real auth and server-side entitlement derivation
    app.post("/api/dev/rag/synthesize", requireAuthenticatedPrincipal, async (req: Request, res: Response) => {
      try {
        const { query, scoped_agent_id, scoped_agent_version_id, injected_draft_for_testing } = req.body || {};
        if (!query) {
          return res.status(400).json({ error: "Missing required query string" });
        }

        const principal = (req as any).principal;
        const entitlements = await authService.resolvePrincipalEntitlements(principal.principal_id, principal);
        const rank = entitlements.max_classification_rank;
        const vaultAccess = entitlements.has_vault_access;

        const output = await pipeline.answerQuery(query, {
          caller_user_id: principal.principal_id,
          caller_security_rank: rank,
          caller_has_vault_access: vaultAccess,
          scoped_agent_id,
          scoped_agent_version_id,
          injected_draft_for_testing,
        });

        res.json(output);
      } catch (err: any) {
        res.status(500).json({ error: err.message });
      }
    });

    // Start server on ephemeral port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const port = (server.address() as any).port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  }, 30000);

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  describe('1. Authentication Middleware Enforcement', () => {
    it('rejects anonymous requests to POST /api/dev/retrieval/execute with 401 Unauthorized', async () => {
      const res = await fetch(`${baseUrl}/api/dev/retrieval/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'Tell me about system architecture' }),
      });

      expect(res.status).toBe(401);
      const data = await res.json();
      expect(data.authenticated).toBe(false);
      expect(data.error).toContain('Unauthorized');
    });

    it('rejects anonymous requests to POST /api/dev/rag/synthesize with 401 Unauthorized', async () => {
      const res = await fetch(`${baseUrl}/api/dev/rag/synthesize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'Explain security posture' }),
      });

      expect(res.status).toBe(401);
      const data = await res.json();
      expect(data.authenticated).toBe(false);
      expect(data.error).toContain('Unauthorized');
    });
  });

  describe('2. Anti-Tamper Vault Clearance & Security Rank Invariants', () => {
    it('PROVES low-privilege user claiming caller_has_vault_access: true in request body is completely ignored and receives ZERO vault documents', async () => {
      // The user attempts an privilege escalation attack:
      // Sending caller_has_vault_access: true and caller_security_rank: 4 (VAULT_RESTRICTED) in the body
      const attackPayload = {
        query: 'Tell me about the Quantum Enclave Encryption Master Key Blueprint in the vault',
        caller_has_vault_access: true,
        caller_security_rank: 4,
        caller_classification_code: 'VAULT_RESTRICTED',
      };

      const res = await fetch(`${baseUrl}/api/dev/retrieval/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${lowPrivUserToken}`,
        },
        body: JSON.stringify(attackPayload),
      });

      expect(res.status).toBe(200);
      const data = await res.json();

      // Verify the retrieval execution succeeded
      expect(data.documents).toBeDefined();
      expect(Array.isArray(data.documents)).toBe(true);

      // Verify that caller_security_rank in the retrieval audit matches the USER's real clearance (rank 1 / INTERNAL), NOT the claimed rank 4
      expect(data.audit.caller_security_rank).toBe(SecurityClassificationRank.INTERNAL);
      expect(data.audit.caller_has_vault_access).toBe(false);

      // INVARIANT: ABSOLUTELY ZERO vault-restricted documents are returned
      const leakedVaultDocs = data.documents.filter(
        (doc: any) => doc.vault_restricted === true || 
                     doc.security_classification === 'VAULT_RESTRICTED' ||
                     doc.entity_ref_id === 'vault-classified-payload-007'
      );
      expect(leakedVaultDocs.length).toBe(0);

      // Verify that retrieval plan disallowed vault records
      expect(data.audit.plan.allow_vault_restricted).toBe(false);
      expect(data.audit.filtered_out_unauthorized_count).toBeGreaterThanOrEqual(0);
    });

    it('PROVES low-privilege user claiming caller_has_vault_access: true in RAG synthesis is ignored and leaks ZERO vault citations', async () => {
      const attackPayload = {
        query: 'What is the Quantum Enclave Encryption Master Key Blueprint in the vault?',
        caller_has_vault_access: true,
        caller_security_rank: 4,
      };

      const res = await fetch(`${baseUrl}/api/dev/rag/synthesize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${lowPrivUserToken}`,
        },
        body: JSON.stringify(attackPayload),
      });

      expect(res.status).toBe(200);
      const data = await res.json();

      // INVARIANT: Citations must contain ZERO vault references
      const leakedVaultCitations = (data.resolved_citations || []).filter(
        (c: any) => c.vault_restricted === true || c.target_id === 'vault-classified-payload-007'
      );
      expect(leakedVaultCitations.length).toBe(0);

      // The answer must not disclose the quantum master key
      expect(data.answer.toLowerCase()).not.toContain('master-key-0x9948');
    });

    it('PROVES verified admin user with real server-side entitlements DOES receive the vault-restricted content', async () => {
      const res = await fetch(`${baseUrl}/api/dev/retrieval/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminUserToken}`,
        },
        body: JSON.stringify({
          query: 'Tell me about the Quantum Enclave Encryption Master Key Blueprint in the vault',
        }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();

      // Admin has genuine VAULT_RESTRICTED clearance
      expect(data.audit.caller_security_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
      expect(data.audit.caller_has_vault_access).toBe(true);

      // The vault document is legitimately retrieved
      const vaultDoc = data.documents.find(
        (doc: any) => doc.vault_restricted === true || doc.entity_ref_id === 'vault-classified-payload-007'
      );
      expect(vaultDoc).toBeDefined();
    });

    it('PROVES resolvePrincipalEntitlements authoritatively reads roles and grants from PostgreSQL security.principals table', async () => {
      const db = createTestDb({ applyMigrations: true, applySeed: false });
      const { Pool } = db.adapters.createPg();
      const pgClient = new Pool();
      const dbAuthService = new AuthService(pgClient as any);

      // Insert a standard user directly into security.principals
      const standardUserId = '00000000-0000-0000-0000-000000000099';
      await pgClient.query(
        `INSERT INTO security.principals (principal_id, email, hashed_password, roles) 
         VALUES ($1, 'dbuser@caim.internal', 'dummy_hash', ARRAY['user']);`,
        [standardUserId]
      );

      // Resolve entitlements from PostgreSQL
      const standardEntitlements = await dbAuthService.resolvePrincipalEntitlements(standardUserId);
      expect(standardEntitlements.roles).toEqual(['user']);
      expect(standardEntitlements.max_classification_rank).toBe(SecurityClassificationRank.INTERNAL);
      expect(standardEntitlements.has_vault_access).toBe(false);

      // Insert an admin user directly into security.principals
      const adminUserId = '00000000-0000-0000-0000-000000000088';
      await pgClient.query(
        `INSERT INTO security.principals (principal_id, email, hashed_password, roles) 
         VALUES ($1, 'dbadmin@caim.internal', 'dummy_hash', ARRAY['admin']);`,
        [adminUserId]
      );

      const adminEntitlements = await dbAuthService.resolvePrincipalEntitlements(adminUserId);
      expect(adminEntitlements.roles).toContain('admin');
      expect(adminEntitlements.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
      expect(adminEntitlements.has_vault_access).toBe(true);
    });
  });
});
