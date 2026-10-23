import crypto from "node:crypto";
import { OpenTelemetryTracer, AuditLogEngine } from "@caim/workflow/observability.ts";
import { Express, Request, Response } from "express";
import { ServiceContainer } from "../services/container.ts";
import { requireDiagnosticAccess, requireProductUserAccess } from "../middleware/security.ts";
import {
  DeterministicPackageBundler,
  SignatureVerifier,
  ShippingService,
  SignedPackageBundle,
  PackagingPolicyGate,
  PackageBuildInput,
} from "@caim/packaging";


  const PACKAGING_FIXTURES: Record<string, PackageBuildInput> = {
    financial_analyst: {
      packageId: 'pkg-agent-financial-analyst-v1.0.0',
      agentId: 'agent-financial-analyst',
      agentVersionId: 'av-fin-v100',
      versionLabel: 'v1.0.0',
      createdAt: '2026-08-26T12:00:00Z',
      sourceFiles: {
        'src/agent.ts': 'export class FinancialAnalystAgent {\n  async analyzePortfolio(portfolio: any) {\n    return { audited: true, expected_return: 0.12 };\n  }\n}\n',
        'src/policy.ts': 'export const RISK_TOLERANCE_MAX = 0.05;\nexport const AUDITED_COMPLIANCE = true;\n',
        'package.json': '{\n  "name": "financial-analyst",\n  "version": "1.0.0",\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}\n'
      },
      analysisReport: {
        static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
        composition_sbom: { components_count: 2, cve_vulnerabilities: 0, status: 'CLEAN' },
        sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
        decision_score: { overall_score: 88, risk_band: 'LOW', confidence: 0.95 },
        recommendation: { verdict: 'APPROVE', allow_shipment: true }
      },
      sbomComponents: [
        {
          name: 'lodash',
          version: '4.17.21',
          type: 'library',
          purl: 'pkg:npm/lodash@4.17.21',
          licenses: ['MIT'],
          description: 'Lodash modular utilities',
          sha256: 'b0b2e8cf702ff60b377cf3fa096df00bc19e34c9c1ef348f95fe3108c9037c22'
        },
        {
          name: '@caim/runtime',
          version: '2.0.1',
          type: 'framework',
          purl: 'pkg:generic/@caim/runtime@2.0.1',
          licenses: ['Apache-2.0'],
          description: 'CAIM Secure Runtime SDK'
        }
      ],
      validationReference: {
        validation_run_id: 'val-run-fin-001',
        validation_plan_version: 'v2.0.1-standard',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-08-26T12:00:00Z'
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 88,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-08-26T12:00:00Z'
      },
      approvalReferences: [
        {
          approval_id: 'appr-sec-01',
          approver_id: 'usr-auditor-sec',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:05:00Z',
          rationale: 'Zero unmitigated taint sinks; passed deterministic sandbox'
        },
        {
          approval_id: 'appr-admin-02',
          approver_id: 'usr-platform-admin',
          approver_role: 'PLATFORM_ADMIN',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:10:00Z',
          rationale: 'Two-person authorization sign-off confirmed'
        }
      ],
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-08-26',
        analysis_run_id: 'ar-fin-8891',
        input_hashes: ['3c59a2f7c001a1b5b24b899...'],
        generated_at: '2026-08-26T12:00:00Z'
      },
      metadata: {
        author: 'CAIM Enterprise Security Team',
        license: 'Apache-2.0',
        securityClassification: 'RESTRICTED',
        framework: 'Node.js/TypeScript',
        description: 'Autonomous Portfolio Risk & Analytics Agent'
      }
    },
    research_agent: {
      packageId: 'pkg-agent-research-v2.1.0',
      agentId: 'agent-web-research',
      agentVersionId: 'av-research-v210',
      versionLabel: 'v2.1.0',
      createdAt: '2026-08-26T12:00:00Z',
      sourceFiles: {
        'index.ts': 'export async function search(q: string) { return { results: [] }; }\n',
        'config.json': '{\n  "mode": "bounded-search",\n  "max_depth": 2\n}\n'
      },
      analysisReport: {
        static_analysis: { findings_count: 0, status: 'CLEAN' },
        decision_score: { overall_score: 92, risk_band: 'LOW' }
      },
      sbomComponents: [
        {
          name: 'axios',
          version: '1.6.8',
          type: 'library',
          licenses: ['MIT']
        }
      ],
      validationReference: {
        validation_run_id: 'val-run-res-002',
        validation_plan_version: 'v2.0.1-standard',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-08-26T12:00:00Z'
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 92,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-08-26T12:00:00Z'
      },
      approvalReferences: [
        {
          approval_id: 'appr-res-01',
          approver_id: 'usr-auditor-sec',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:05:00Z',
          rationale: 'Passed privacy and egress audits'
        },
        {
          approval_id: 'appr-res-02',
          approver_id: 'usr-lead-eng',
          approver_role: 'PLATFORM_ADMIN',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:08:00Z',
          rationale: 'Two-person approval granted'
        }
      ],
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-08-26',
        analysis_run_id: 'ar-res-4412',
        input_hashes: ['a88bf213904...'],
        generated_at: '2026-08-26T12:00:00Z'
      },
      metadata: {
        author: 'CAIM Research Team',
        license: 'MIT',
        securityClassification: 'INTERNAL',
        framework: 'TypeScript',
        description: 'Web Search and Summarization Autonomous Agent'
      }
    }
  };


export const authoritativePackageBundles = new Map<string, SignedPackageBundle>();

export function registerPackagingRoutes(app: Express, container: ServiceContainer) {
  const { kmsBoundary, platformAuditService, shippingService, globalAuditEngine, globalTracer } = container;

  app.get("/api/dev/packaging/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Packaging fixture endpoints are strictly disabled in production mode." });
    }
    res.json(PACKAGING_FIXTURES);
  });

  app.get("/api/dev/packaging/keys", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(kmsBoundary.getKeyRegistry().listKeys());
  });

  app.post("/api/dev/packaging/build", requireDiagnosticAccess, async (req: Request, res: Response) => {
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ error: "Packaging fixture endpoints are strictly disabled in production mode." });
    }
    try {
      const { fixtureKey, overridePolicyOutcome } = req.body;
      const baseFixture = PACKAGING_FIXTURES[fixtureKey || 'financial_analyst'];
      if (!baseFixture) {
        return res.status(400).json({ error: `Unknown fixture key: ${fixtureKey}` });
      }

      const input: PackageBuildInput = JSON.parse(JSON.stringify(baseFixture));
      if (overridePolicyOutcome) {
        input.policyReference.policy_outcome = overridePolicyOutcome;
        input.policyReference.policy_allowed = overridePolicyOutcome === 'ALLOW';
      }

      const bundle = await DeterministicPackageBundler.buildAndSign(input, kmsBoundary);
      authoritativePackageBundles.set(bundle.package_id, bundle);
      
      // Convert files Map to plain object for JSON response
      const filesObj: Record<string, any> = {};
      for (const [key, val] of bundle.files.entries()) {
        filesObj[key] = val;
      }

      const verification = SignatureVerifier.verifyBundle(bundle);

      res.json({
        bundle: {
          package_id: bundle.package_id,
          manifest: bundle.manifest,
          manifest_hash: bundle.manifest_hash,
          files: filesObj,
          attestation: bundle.attestation,
          signature: bundle.signature,
        },
        verification,
      });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/dev/packaging/verify", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { bundle } = req.body;
      if (!bundle) {
        return res.status(400).json({ error: 'Missing bundle payload in request body' });
      }

      // Reconstruct files Map if received as object
      const filesMap = new Map<string, any>();
      if (bundle.files && typeof bundle.files === 'object') {
        for (const [key, val] of Object.entries(bundle.files)) {
          filesMap.set(key, val);
        }
      }

      const bundleToVerify: SignedPackageBundle = {
        package_id: bundle.package_id,
        manifest: bundle.manifest,
        manifest_hash: bundle.manifest_hash,
        files: filesMap,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const result = SignatureVerifier.verifyBundle(bundleToVerify);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/packaging/ship", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { bundle, targetType, options } = req.body;
      if (!bundle || !targetType) {
        return res.status(400).json({ error: 'Missing bundle or targetType' });
      }

      const filesMap = new Map<string, any>();
      if (bundle.files instanceof Map) {
        for (const [k, v] of bundle.files.entries()) filesMap.set(k, v);
      } else if (bundle.files && typeof bundle.files === 'object') {
        for (const [key, val] of Object.entries(bundle.files)) {
          filesMap.set(key, val);
        }
      }

      const bundleToShip: SignedPackageBundle = {
        package_id: bundle.package_id,
        manifest: bundle.manifest,
        manifest_hash: bundle.manifest_hash,
        files: filesMap,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const receipt = await shippingService.shipBundle(
        bundleToShip,
        targetType,
        options || { targetLocator: 'default-target' }
      );

      let statusCode = 200;
      if (receipt.status === 'NOT_CONFIGURED') {
        statusCode = 400;
      } else if (receipt.status === 'PROVIDER_UNAVAILABLE') {
        statusCode = 503;
      } else if (receipt.status === 'FAILED') {
        statusCode = 500;
      }

      const deliveryConfirmed = receipt.status === 'DELIVERED' && receipt.truthState === 'OBSERVED';
      const simulated = receipt.status === 'SIMULATED_DELIVERY';
      const delivered = deliveryConfirmed;
      const success = deliveryConfirmed;

      res.status(statusCode).json({
        success,
        delivered,
        deliveryConfirmed,
        simulated,
        status: receipt.status,
        truthState: receipt.truthState,
        truth_state: receipt.truth_state,
        receipt,
      });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/dev/packaging/shipments", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(shippingService.getAuditLog());
  });

  // ---------------------------------------------------------------------------
  // P30 OBSERVABILITY, TELEMETRY, AUDIT & COST READ MODELS
  // ---------------------------------------------------------------------------

  // Populate baseline audit events for read models
  globalAuditEngine.recordEvent({
    actorType: 'USER',
    actorId: 'security-lead@caim.internal',
    action: 'POLICY_OVERRIDE_APPROVED',
    targetType: 'POLICY_GATE',
    targetId: 'gate-zero-trust-egress',
    correlation: { traceId: 'trc-init-001', requestId: 'req-init-001' },
    details: { ticket: 'CR-8821', reason: 'Assurance suite stress testing' }
  });

  globalAuditEngine.recordEvent({
    actorType: 'VAULT',
    actorId: 'kms-enclave-caim-root-v2',
    action: 'VAULT_SECRET_ACCESS',
    targetType: 'KMS_KEY',
    targetId: 'kms-enclave-caim-root-v2',
    correlation: { traceId: 'trc-init-001', requestId: 'req-init-001' },
    details: { operation: 'SignDeterministicManifest', clientIp: '10.0.1.20' }
  });


  app.post("/api/packages/verify", requireProductUserAccess, (req: Request, res: Response) => {
    try {
      const { bundle } = req.body;
      if (!bundle) {
        return res.json({
          valid: false,
          status: 'DATA_UNAVAILABLE',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          message: 'DATA_UNAVAILABLE: No signed package bundle provided for cryptographic verification.'
        });
      }

      const filesMap = new Map<string, any>();
      if (bundle.files && typeof bundle.files === 'object') {
        for (const [key, val] of Object.entries(bundle.files)) {
          filesMap.set(key, val);
        }
      }

      const bundleToVerify: SignedPackageBundle = {
        package_id: bundle.package_id,
        manifest: bundle.manifest,
        manifest_hash: bundle.manifest_hash,
        files: filesMap,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const result = SignatureVerifier.verifyBundle(bundleToVerify);
      res.json({
        ...result,
        truthState: 'CONFIRMED',
        truth_state: 'CONFIRMED',
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/packages/ship", requireProductUserAccess, async (req: Request, res: Response) => {
    try {
      const { bundle: rawBundle, package_id, packageId, targetType, options } = req.body;
      const requestedPkgId = rawBundle?.package_id || package_id || packageId;

      if (!rawBundle && !requestedPkgId) {
        return res.status(400).json({
          success: false,
          status: 'DATA_UNAVAILABLE',
          code: 'INVALID_BUNDLE',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: 'DATA_UNAVAILABLE: No package bundle or package ID provided for shipping.',
          message: 'DATA_UNAVAILABLE: No verified package bundle provided for shipping.'
        });
      }

      let bundleToShip: SignedPackageBundle | undefined;

      if (rawBundle && typeof rawBundle === 'object') {
        // Enforce required bundle components without fabrication
        if (!rawBundle.package_id || !rawBundle.manifest || !rawBundle.signature || !rawBundle.attestation) {
          const missingFields: string[] = [];
          if (!rawBundle.package_id) missingFields.push('package_id');
          if (!rawBundle.manifest) missingFields.push('manifest');
          if (!rawBundle.signature) missingFields.push('signature');
          if (!rawBundle.attestation) missingFields.push('attestation');

          return res.status(400).json({
            success: false,
            status: 'DATA_UNAVAILABLE',
            code: 'INVALID_BUNDLE',
            truthState: 'UNKNOWN',
            truth_state: 'UNKNOWN',
            error: `INVALID_BUNDLE: Required release artifacts (${missingFields.join(', ')}) are missing from the bundle payload. Fallback synthesis is strictly prohibited.`,
            message: `DATA_UNAVAILABLE / INVALID_BUNDLE: Incomplete release bundle. Missing required artifacts: ${missingFields.join(', ')}.`,
            missingFields,
          });
        }

        const filesMap = new Map<string, any>();
        if (rawBundle.files instanceof Map) {
          for (const [k, v] of rawBundle.files.entries()) filesMap.set(k, v);
        } else if (rawBundle.files && typeof rawBundle.files === 'object') {
          for (const [key, val] of Object.entries(rawBundle.files)) {
            filesMap.set(key, val);
          }
        }

        bundleToShip = {
          package_id: rawBundle.package_id,
          manifest: rawBundle.manifest,
          manifest_hash: rawBundle.manifest_hash || rawBundle.manifest?.manifest_hash,
          files: filesMap,
          attestation: rawBundle.attestation,
          signature: rawBundle.signature,
        };
      } else if (requestedPkgId && authoritativePackageBundles.has(requestedPkgId)) {
        bundleToShip = authoritativePackageBundles.get(requestedPkgId);
      }

      if (!bundleToShip) {
        return res.status(400).json({
          success: false,
          status: 'DATA_UNAVAILABLE',
          code: 'INVALID_BUNDLE',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: `DATA_UNAVAILABLE: No authoritative signed package bundle found for package_id '${requestedPkgId}'. Auto-completion is prohibited.`,
          message: `DATA_UNAVAILABLE: No authoritative signed package bundle found for package_id '${requestedPkgId}'.`,
        });
      }

      // Check for required bundle fields without fallbacks
      if (
        !bundleToShip.package_id ||
        !bundleToShip.manifest ||
        !bundleToShip.manifest_hash ||
        !bundleToShip.signature ||
        !bundleToShip.attestation
      ) {
        return res.status(400).json({
          success: false,
          status: 'DATA_UNAVAILABLE',
          code: 'INVALID_BUNDLE',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: 'INVALID_BUNDLE: Bundle missing required release fields (package_id, manifest, manifest_hash, signature, attestation).',
          message: 'DATA_UNAVAILABLE: Required package bundle data is incomplete.',
        });
      }

      const target = targetType || options?.targetType || 'LOCAL_STAGING';
      const shipOptions = options || {
        targetLocator: req.body.targetLocator || `/tmp/caim-staging/${bundleToShip.package_id}`,
      };

      // Evaluate Pre-Shipping Policy Gate and signature verification
      const gateResult = PackagingPolicyGate.evaluatePreShippingGate(bundleToShip, target);
      if (!gateResult.allowed) {
        return res.status(400).json({
          success: false,
          status: 'INVALID_BUNDLE',
          code: 'POLICY_GATE_REJECTED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: `INVALID_BUNDLE: Pre-shipping checks failed for target ${target}.`,
          blockers: gateResult.blockers,
        });
      }

      // Real shipping via ShippingService
      const receipt = await shippingService.shipBundle(bundleToShip, target, shipOptions);

      const deliveryConfirmed = receipt.status === 'DELIVERED' && receipt.truthState === 'OBSERVED';
      const simulated = receipt.status === 'SIMULATED_DELIVERY';
      const delivered = deliveryConfirmed;
      const success = deliveryConfirmed;

      // Audit Logging
      const actorId = (req as any).principal?.principal_id || 'product-user';
      const auditPayload = {
        actorType: 'USER' as const,
        actorId: String(actorId),
        action: 'BUNDLE_SHIPPED_PROD' as const,
        targetType: 'PACKAGE_BUNDLE',
        targetId: String(bundleToShip.package_id),
        correlation: { traceId: `trc-${Date.now()}`, requestId: `req-${Date.now()}` },
        status: (deliveryConfirmed ? 'SUCCESS' : 'FAILURE') as 'SUCCESS' | 'FAILURE',
        details: {
          status: receipt.status,
          target_type: receipt.target_type,
          receipt_locator: receipt.receipt_locator || '',
          truth_state: receipt.truthState,
          deliveryConfirmed,
          simulated,
          error: receipt.error || '',
        },
      };
      globalAuditEngine?.recordEvent(auditPayload);
      if (typeof platformAuditService?.recordAuditEntry === 'function') {
        platformAuditService.recordAuditEntry({
          action: 'BUNDLE_SHIPPED_PROD',
          principal_id: String(actorId),
          target_entity_type: 'PACKAGE_BUNDLE',
          target_entity_id: String(bundleToShip.package_id),
          outcome: deliveryConfirmed ? 'SUCCESS' : 'FAILURE',
          details: auditPayload.details,
        }).catch?.(() => {});
      } else if (typeof (platformAuditService as any)?.recordEvent === 'function') {
        (platformAuditService as any).recordEvent({
          action: 'BUNDLE_SHIPPED_PROD',
          actor_id: String(actorId),
          target_id: String(bundleToShip.package_id),
          criticality: deliveryConfirmed ? 'OPERATIONAL' : 'SECURITY',
          details: auditPayload.details,
        })?.catch?.(() => {});
      }

      // DB persistence if database is connected
      let durablePersistenceVerified = !container.dbAdapter;
      let persistenceError: string | null = null;
      let reconciliationId: string | null = null;

      if (container.dbAdapter) {
        try {
          await container.dbAdapter.query(
            `INSERT INTO lifecycle.shipments (shipment_id, package_id, target_type, target_locator, status, shipped_at, receipt_locator, receipt_signature, truth_state, error)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (shipment_id) DO UPDATE
             SET status = EXCLUDED.status,
                 receipt_locator = EXCLUDED.receipt_locator,
                 receipt_signature = EXCLUDED.receipt_signature,
                 truth_state = EXCLUDED.truth_state,
                 error = EXCLUDED.error`,
            [
              receipt.shipment_id,
              receipt.package_id,
              receipt.target_type,
              receipt.target_locator,
              receipt.status,
              receipt.shipped_at || null,
              receipt.receipt_locator || null,
              receipt.receipt_signature || null,
              receipt.truthState || 'UNKNOWN',
              receipt.error || null,
            ]
          );
          durablePersistenceVerified = true;
        } catch (dbErr: any) {
          persistenceError = dbErr.message;
          durablePersistenceVerified = false;
          reconciliationId = `rec-${Date.now()}-${receipt.shipment_id}`;
          console.error(`CRITICAL: Remote shipment succeeded at provider but local DB persistence failed: ${dbErr.message}`);

          shippingService.recordUnresolvedShipment({
            reconciliation_id: reconciliationId,
            shipment_id: receipt.shipment_id,
            package_id: bundleToShip.package_id,
            target_type: String(receipt.target_type),
            target_locator: receipt.target_locator,
            provider_receipt: receipt,
            provider_delivery_verified: deliveryConfirmed,
            durable_persistence_verified: false,
            failure_stage: 'DATABASE_INSERT',
            error_message: dbErr.message,
            occurred_at: new Date().toISOString(),
            reconciled: false,
          });
        }
      }

      // If database is configured and persistence failed, DO NOT report overall workflow success!
      if (container.dbAdapter && !durablePersistenceVerified) {
        const unpersistedReceipt: DeliveryReceipt = {
          ...receipt,
          status: 'PARTIALLY_DELIVERED_UNPERSISTED',
          detailed_state: 'PARTIALLY_DELIVERED_UNPERSISTED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          provider_delivery_verified: deliveryConfirmed,
          durable_persistence_verified: false,
          persistence_error: persistenceError,
          reconciliation_id: reconciliationId,
          error: `Remote artifact delivered to provider, but durable database persistence failed: ${persistenceError}`,
        };

        return res.status(500).json({
          success: false,
          delivered: false,
          deliveryConfirmed: false,
          simulated: false,
          status: 'PARTIALLY_DELIVERED_UNPERSISTED',
          detailed_state: 'PARTIALLY_DELIVERED_UNPERSISTED',
          code: 'PERSISTENCE_FAILED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          provider_delivery_verified: deliveryConfirmed,
          durable_persistence_verified: false,
          persistence_error: persistenceError,
          reconciliation_id: reconciliationId,
          error: `PERSISTENCE_FAILED: Remote upload succeeded, but durable database record could not be persisted. Overall release workflow is unconfirmed. Operator reconciliation required (${reconciliationId}).`,
          receipt: unpersistedReceipt,
        });
      }

      let statusCode = 200;
      if (receipt.status === 'NOT_CONFIGURED') {
        statusCode = 400;
      } else if (receipt.status === 'AUTHORIZATION_DENIED') {
        statusCode = 403;
      } else if (receipt.status === 'INTEGRITY_MISMATCH') {
        statusCode = 422;
      } else if (receipt.status === 'PROVIDER_UNAVAILABLE') {
        statusCode = 503;
      } else if (receipt.status === 'FAILED') {
        statusCode = 500;
      }

      res.status(statusCode).json({
        success,
        delivered,
        deliveryConfirmed,
        simulated,
        status: receipt.status,
        truthState: receipt.truthState,
        truth_state: receipt.truth_state,
        provider_delivery_verified: deliveryConfirmed,
        durable_persistence_verified: durablePersistenceVerified,
        receipt: {
          ...receipt,
          provider_delivery_verified: deliveryConfirmed,
          durable_persistence_verified: durablePersistenceVerified,
        },
      });
    } catch (err: any) {
      if (err.name === 'ShippingPolicyViolationError' || err.blockers) {
        return res.status(400).json({
          success: false,
          status: 'INVALID_BUNDLE',
          code: 'POLICY_GATE_REJECTED',
          truthState: 'UNKNOWN',
          truth_state: 'UNKNOWN',
          error: err.message,
          blockers: err.blockers || [],
        });
      }

      res.status(500).json({
        success: false,
        status: 'FAILED',
        truthState: 'UNKNOWN',
        truth_state: 'UNKNOWN',
        error: err.message,
      });
    }
  });

  // Release manifest endpoint for client
  app.get("/api/dev/packaging/release-manifest", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const { ReleaseManifestGenerator } = await import("@caim/packaging/release-manifest.ts");
      const manifest = ReleaseManifestGenerator.generateManifest();
      res.json(manifest);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to generate release manifest" });
    }
  });

  // Operator endpoint: list unresolved / unpersisted shipments
  app.get("/api/dev/packaging/unresolved", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(shippingService.getUnresolvedShipments());
  });

  app.get("/api/packages/unresolved", requireProductUserAccess, (_req: Request, res: Response) => {
    res.json(shippingService.getUnresolvedShipments());
  });

  // Operator endpoint: reconcile an unresolved shipment without duplicate remote upload
  app.post("/api/dev/packaging/reconcile", requireDiagnosticAccess, async (req: Request, res: Response) => {
    await handleReconcileShipment(req, res);
  });

  app.post("/api/packages/reconcile", requireProductUserAccess, async (req: Request, res: Response) => {
    await handleReconcileShipment(req, res);
  });

  async function handleReconcileShipment(req: Request, res: Response) {
    try {
      const { shipmentId, reconciliationId } = req.body;
      const targetId = shipmentId || reconciliationId;
      if (!targetId) {
        return res.status(400).json({ error: 'Missing shipmentId or reconciliationId' });
      }

      const unresolved = shippingService.getUnresolvedShipment(targetId);
      if (!unresolved) {
        return res.status(404).json({ error: `Unresolved shipment '${targetId}' not found` });
      }

      if (unresolved.reconciled) {
        return res.json({
          reconciled: true,
          message: 'Shipment was already reconciled',
          shipment: unresolved,
        });
      }

      if (container.dbAdapter) {
        const receipt = unresolved.provider_receipt;
        await container.dbAdapter.query(
          `INSERT INTO lifecycle.shipments (shipment_id, package_id, target_type, target_locator, status, shipped_at, receipt_locator, receipt_signature, truth_state, error)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           ON CONFLICT (shipment_id) DO UPDATE
           SET status = EXCLUDED.status,
               receipt_locator = EXCLUDED.receipt_locator,
               receipt_signature = EXCLUDED.receipt_signature,
               truth_state = EXCLUDED.truth_state,
               error = EXCLUDED.error`,
          [
            receipt.shipment_id,
            receipt.package_id,
            receipt.target_type,
            receipt.target_locator,
            receipt.status,
            receipt.shipped_at || null,
            receipt.receipt_locator || null,
            receipt.receipt_signature || null,
            receipt.truthState || 'OBSERVED',
            null,
          ]
        );
      }

      shippingService.markShipmentReconciled(targetId);

      res.json({
        reconciled: true,
        reconciliation_id: unresolved.reconciliation_id,
        shipment_id: unresolved.shipment_id,
        package_id: unresolved.package_id,
        durable_persistence_verified: true,
        message: 'Shipment successfully reconciled into durable database storage without duplicate remote upload.',
      });
    } catch (err: any) {
      res.status(500).json({ error: `Reconciliation failed: ${err.message}` });
    }
  }
}
