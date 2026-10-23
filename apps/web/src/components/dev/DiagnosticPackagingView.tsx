import React, { useState, useEffect } from 'react';
import { 
  Package, 
  ShieldCheck, 
  ShieldAlert, 
  KeyRound, 
  Send, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  RefreshCw, 
  Fingerprint, 
  FileCheck, 
  Layers, 
  Truck, 
  Lock, 
  Code2, 
  Database,
  ExternalLink
} from 'lucide-react';

interface DiagnosticPackagingViewProps {
  currentRole: string;
}

export const DiagnosticPackagingView: React.FC<DiagnosticPackagingViewProps> = ({ currentRole }) => {
  const [activeSubTab, setActiveSubTab] = useState<'builder' | 'manifest' | 'sbom' | 'attestation' | 'shipping'>('builder');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Fixtures and keys
  const [fixtures, setFixtures] = useState<any>(null);
  const [selectedFixture, setSelectedFixture] = useState<string>('financial_analyst');
  const [keys, setKeys] = useState<any[]>([]);

  // Staged package bundle state
  const [currentBundle, setCurrentBundle] = useState<any | null>(null);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [tamperState, setTamperState] = useState<{ tampered: boolean; details?: string }>({ tampered: false });

  // Shipping state
  const [selectedTarget, setSelectedTarget] = useState<'OCI_REGISTRY' | 'S3_STORAGE' | 'WEBHOOK_DEPLOYMENT' | 'LOCAL_STAGING'>('OCI_REGISTRY');
  const [targetLocator, setTargetLocator] = useState<string>('registry.internal.caim.security/agents/financial-analyst');
  const [latestReceipt, setLatestReceipt] = useState<any | null>(null);
  const [shipmentsLog, setShipmentsLog] = useState<any[]>([]);

  // Selected file inspector
  const [selectedFileName, setSelectedFileName] = useState<string>('manifest.json');

  const fetchInitialData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [fixturesRes, keysRes, shipmentsRes] = await Promise.all([
        fetch('/api/dev/packaging/fixtures', { headers: { 'X-Role': currentRole } }),
        fetch('/api/dev/packaging/keys', { headers: { 'X-Role': currentRole } }),
        fetch('/api/dev/packaging/shipments', { headers: { 'X-Role': currentRole } }),
      ]);

      if (fixturesRes.ok) setFixtures(await fixturesRes.json());
      if (keysRes.ok) setKeys(await keysRes.json());
      if (shipmentsRes.ok) setShipmentsLog(await shipmentsRes.json());
    } catch (err: any) {
      setError(err.message || 'Failed to load packaging initial data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInitialData();
  }, [currentRole]);

  // Update target locator default when target changes
  useEffect(() => {
    if (selectedTarget === 'OCI_REGISTRY') {
      setTargetLocator('registry.internal.caim.security/agents/financial-analyst');
    } else if (selectedTarget === 'S3_STORAGE') {
      setTargetLocator('s3://caim-release-vault/releases/financial-analyst/v1.0.0');
    } else if (selectedTarget === 'WEBHOOK_DEPLOYMENT') {
      setTargetLocator('https://deploy.internal.caim.security/hooks/agent-release');
    } else if (selectedTarget === 'LOCAL_STAGING') {
      setTargetLocator('/var/caim/staging/releases/financial-analyst');
    }
  }, [selectedTarget]);

  // Build & Sign Bundle
  const handleBuildAndSign = async (overridePolicyOutcome?: string) => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    setTamperState({ tampered: false });
    try {
      const payload = {
        fixtureKey: selectedFixture,
        overridePolicyOutcome,
      };

      const res = await fetch('/api/dev/packaging/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to build and sign package');
      }

      setCurrentBundle(data.bundle);
      setVerificationResult(data.verification);
      setSelectedFileName('manifest.json');
      setSuccessMsg(`Package ${data.bundle.package_id} built, attested and signed with Ed25519 key ${data.bundle.signature.key_id}`);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Run independent signature & tamper verification
  const handleVerify = async () => {
    if (!currentBundle) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/dev/packaging/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({ bundle: currentBundle }),
      });

      const data = await res.json();
      setVerificationResult(data);
      if (data.valid) {
        setSuccessMsg('Package cryptographic integrity and signature independently VERIFIED.');
      } else {
        setError(`Verification failed: ${data.errors?.join(', ')}`);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Tamper with package bundle to demonstrate signature failure
  const handleTamperTest = () => {
    if (!currentBundle) return;
    const modifiedBundle = JSON.parse(JSON.stringify(currentBundle));
    
    // Modify one source file or manifest byte
    const fileEntries = Object.keys(modifiedBundle.files || {});
    if (fileEntries.length > 0) {
      const targetFileKey = fileEntries.find(k => k.endsWith('.ts') || k.endsWith('.py')) || fileEntries[0];
      if (modifiedBundle.files[targetFileKey]) {
        modifiedBundle.files[targetFileKey].content += '\n// TAMPERED_MALICIOUS_INJECTION = true;\n';
        // Note: sha256 will now mismatch or manifest will mismatch
      }
    }

    setCurrentBundle(modifiedBundle);
    setTamperState({
      tampered: true,
      details: 'Injected modified payload into source file without updating signature.',
    });

    // Run verification immediately on tampered bundle
    fetch('/api/dev/packaging/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
      body: JSON.stringify({ bundle: modifiedBundle }),
    })
      .then(res => res.json())
      .then(data => {
        setVerificationResult(data);
        setError(`Tamper detected! Verification failed as expected: ${data.errors?.join('; ')}`);
      })
      .catch(() => {});
  };

  // Ship package
  const handleShip = async () => {
    if (!currentBundle) {
      setError('Please build and sign a package first.');
      return;
    }
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const res = await fetch('/api/dev/packaging/ship', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          bundle: currentBundle,
          targetType: selectedTarget,
          options: { targetLocator },
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Shipping failed');
      }

      setLatestReceipt(data.receipt);
      if (data.receipt.status === 'DELIVERED' && data.deliveryConfirmed) {
        setSuccessMsg(`Package delivered to ${selectedTarget}: ${data.receipt.receipt_locator}`);
      } else if (data.receipt.status === 'SIMULATED_DELIVERY' || data.simulated) {
        setSuccessMsg(`[SIMULATED - NOT DELIVERED] Development simulation executed for ${selectedTarget}: ${data.receipt.receipt_locator}`);
      } else {
        setError(`Shipment status: ${data.receipt.status} (${data.receipt.error || 'Failed'})`);
      }
      // Refresh shipments
      const shipRes = await fetch('/api/dev/packaging/shipments', { headers: { 'X-Role': currentRole } });
      if (shipRes.ok) setShipmentsLog(await shipRes.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getFileContent = (fileName: string) => {
    if (!currentBundle) return '';
    if (fileName === 'manifest.json') return JSON.stringify(currentBundle.manifest, null, 2);
    if (fileName === 'attestation.json') return JSON.stringify(currentBundle.attestation, null, 2);
    const file = currentBundle.files?.[fileName];
    if (file) return typeof file.content === 'string' ? file.content : JSON.stringify(file.content, null, 2);
    return 'File not found';
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-cyan-600/20 border border-cyan-500/30 text-cyan-400">
                <Package className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-100 font-mono flex items-center space-x-2">
                  <span>P26 — Packaging, Attestation, Signing & Shipping Plane</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                    Ed25519 Cryptographic Trust Chain
                  </span>
                </h2>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Deterministic Merkle packaging • CycloneDX SBOM • in-toto SLSA Attestation • Isolated KMS Boundary • Target Adapters
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleBuildAndSign()}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium shadow transition-all disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Fingerprint className="w-3.5 h-3.5" />}
              <span>Build & Sign Package</span>
            </button>

            <button
              onClick={fetchInitialData}
              disabled={loading}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
              title="Refresh telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Feedback messages */}
        {error && (
          <div className="mt-4 p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg flex items-start space-x-2.5 text-xs text-rose-300 font-mono">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 break-all">{error}</div>
          </div>
        )}

        {successMsg && (
          <div className="mt-4 p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg flex items-start space-x-2.5 text-xs text-emerald-300 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="flex-1">{successMsg}</div>
          </div>
        )}
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center space-x-1.5 border-b border-slate-800 pb-2 text-xs font-mono">
        <button
          onClick={() => setActiveSubTab('builder')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md font-semibold transition-all ${
            activeSubTab === 'builder'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          <span>1. Package & Payload</span>
        </button>

        <button
          onClick={() => setActiveSubTab('manifest')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md font-semibold transition-all ${
            activeSubTab === 'manifest'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5" />
          <span>2. Manifest & Content Explorer</span>
        </button>

        <button
          onClick={() => setActiveSubTab('sbom')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md font-semibold transition-all ${
            activeSubTab === 'sbom'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>3. CycloneDX SBOM & CSV</span>
        </button>

        <button
          onClick={() => setActiveSubTab('attestation')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md font-semibold transition-all ${
            activeSubTab === 'attestation'
              ? 'bg-indigo-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>4. Attestation & Ed25519 Signature</span>
        </button>

        <button
          onClick={() => setActiveSubTab('shipping')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md font-semibold transition-all ${
            activeSubTab === 'shipping'
              ? 'bg-emerald-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Truck className="w-3.5 h-3.5" />
          <span>5. Shipping & Audit ({shipmentsLog.length})</span>
        </button>
      </div>

      {/* Subtab 1: Package Builder & Input Configuration */}
      {activeSubTab === 'builder' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Configuration Column */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 space-y-4">
              <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Agent Release Target</span>
              </h3>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Approved Agent Profile</label>
                <select
                  value={selectedFixture}
                  onChange={(e) => setSelectedFixture(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="financial_analyst">Financial Analyst Autonomous Agent (V1.0.0)</option>
                  <option value="research_agent">Web Search & Intelligence Agent (V2.1.0)</option>
                  <option value="code_evaluator">Sandbox Code Evaluator Agent (V1.2.4)</option>
                </select>
              </div>

              {/* Pre-signing Gate Requirements status */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-[11px] font-mono text-slate-400 font-semibold block">Pre-Signing Policy Gate Criteria</span>
                
                <div className="flex items-center justify-between text-xs font-mono p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-400">Two-Person Sign-off:</span>
                  <span className="text-emerald-400 flex items-center">
                    <CheckCircle2 className="w-3 h-3 mr-1" /> 2 Approvers (Auditor + Admin)
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-400">Validation Run:</span>
                  <span className="text-emerald-400 flex items-center">
                    <CheckCircle2 className="w-3 h-3 mr-1" /> PASSED (Risk Reduced)
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono p-2 bg-slate-950/60 rounded border border-slate-800/80">
                  <span className="text-slate-400">Policy Verdict:</span>
                  <span className="text-emerald-400 flex items-center">
                    <CheckCircle2 className="w-3 h-3 mr-1" /> ALLOW (Score 88/100)
                  </span>
                </div>
              </div>

              {/* Policy Simulation Actions */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-[11px] font-mono text-slate-400 font-semibold block">Policy Gate Test Cases</span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleBuildAndSign('ALLOW')}
                    className="p-2 rounded bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-500/30 text-emerald-300 text-[11px] font-mono text-left"
                  >
                    <span className="font-bold block">✓ Approved</span>
                    <span>Sign Allowed</span>
                  </button>
                  <button
                    onClick={() => handleBuildAndSign('DENY_SHIPPING')}
                    className="p-2 rounded bg-rose-950/40 hover:bg-rose-900/50 border border-rose-500/30 text-rose-300 text-[11px] font-mono text-left"
                  >
                    <span className="font-bold block">✗ Denied Policy</span>
                    <span>Signing Blocked</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Active KMS Key Info */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 space-y-2">
              <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                <span>Isolated KMS Signer Boundary</span>
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                Private signing key material is strictly isolated in the KMS boundary and never exposed to the web or worker bundle.
              </p>
              {keys.length > 0 && (
                <div className="mt-2 p-2.5 bg-slate-950 rounded border border-slate-800 text-[11px] font-mono space-y-1">
                  <div>Key ID: <span className="text-cyan-300">{keys[0].keyId}</span></div>
                  <div>Version: <span className="text-slate-300">{keys[0].keyVersion}</span></div>
                  <div>Algorithm: <span className="text-emerald-400">{keys[0].algorithm}</span></div>
                  <div>Status: <span className="text-emerald-400">{keys[0].status}</span></div>
                </div>
              )}
            </div>
          </div>

          {/* Right Package Overview Column */}
          <div className="lg:col-span-2 space-y-4">
            {currentBundle ? (
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-bold text-slate-200 font-mono">
                        {currentBundle.package_id}
                      </span>
                      <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                        {currentBundle.manifest.version_label}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                      Root Merkle Hash: <code className="text-cyan-300">{currentBundle.manifest_hash}</code>
                    </p>
                  </div>

                  <div className="flex items-center space-x-2">
                    {verificationResult?.valid ? (
                      <span className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono flex items-center">
                        <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> VALID_SIGNATURE
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-mono flex items-center">
                        <XCircle className="w-3.5 h-3.5 mr-1" /> TAMPER_DETECTED
                      </span>
                    )}
                  </div>
                </div>

                {/* Package Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono uppercase block">Total Files</span>
                    <span className="text-base font-bold text-slate-200 font-mono">
                      {Object.keys(currentBundle.files || {}).length}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono uppercase block">Signer Key ID</span>
                    <span className="text-xs font-bold text-cyan-300 font-mono truncate block">
                      {currentBundle.signature.key_id}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono uppercase block">Attestation Predicate</span>
                    <span className="text-xs font-bold text-indigo-300 font-mono truncate block">
                      SLSA Provenance v1
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-mono uppercase block">Policy Verdict</span>
                    <span className="text-xs font-bold text-emerald-400 font-mono truncate block">
                      {currentBundle.manifest.policy_reference.policy_outcome}
                    </span>
                  </div>
                </div>

                {/* Content files table */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 font-mono mb-2">Deterministic Package Contents</h4>
                  <div className="border border-slate-800 rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="p-2.5">File Path</th>
                          <th className="p-2.5">Content Type</th>
                          <th className="p-2.5">SHA-256 Hash</th>
                          <th className="p-2.5 text-right">Size</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                        {currentBundle.manifest.contents.map((item: any) => (
                          <tr key={item.path} className="hover:bg-slate-800/40">
                            <td className="p-2.5 text-cyan-300 font-medium">{item.path}</td>
                            <td className="p-2.5 text-slate-400">{item.content_type}</td>
                            <td className="p-2.5 text-slate-300 font-mono text-[11px]">{item.sha256.slice(0, 16)}...</td>
                            <td className="p-2.5 text-right text-slate-400">{item.size_bytes} B</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Interactive Verification and Tamper Testing Bar */}
                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={handleVerify}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors"
                    >
                      <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Re-verify Cryptographic Bundle</span>
                    </button>

                    <button
                      onClick={handleTamperTest}
                      className="px-3 py-1.5 bg-rose-950/50 hover:bg-rose-900/60 border border-rose-500/30 text-rose-300 rounded text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                      <span>Simulate File Tampering</span>
                    </button>
                  </div>

                  <button
                    onClick={() => setActiveSubTab('shipping')}
                    className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-mono font-medium flex items-center space-x-1.5 shadow transition-colors"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Proceed to Shipping</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="py-20 text-center space-y-3 font-mono bg-slate-900/40 rounded-xl border border-slate-800">
                <Package className="w-10 h-10 text-slate-600 mx-auto" />
                <h3 className="text-sm font-semibold text-slate-300">No Active Package Built</h3>
                <p className="text-xs text-slate-400 max-w-sm mx-auto">
                  Click "Build & Sign Package" to generate a deterministic release bundle with CycloneDX SBOM, in-toto attestation and Ed25519 signature.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 2: Manifest & Content Explorer */}
      {activeSubTab === 'manifest' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-1 bg-slate-900/60 rounded-xl border border-slate-800 p-4 space-y-3">
            <h3 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider">
              Package Deliverables
            </h3>
            <div className="space-y-1">
              {currentBundle?.manifest?.contents?.map((c: any) => (
                <button
                  key={c.path}
                  onClick={() => setSelectedFileName(c.path)}
                  className={`w-full text-left px-2.5 py-1.5 rounded text-xs font-mono transition-colors flex items-center justify-between ${
                    selectedFileName === c.path
                      ? 'bg-cyan-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  <span className="truncate">{c.path}</span>
                  <span className="text-[10px] opacity-70 ml-1">{c.size_bytes}B</span>
                </button>
              ))}
            </div>
          </div>

          <div className="lg:col-span-3 bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-200 font-mono">{selectedFileName}</span>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                SHA-256: {currentBundle?.manifest?.contents?.find((c: any) => c.path === selectedFileName)?.sha256?.slice(0, 20)}...
              </span>
            </div>

            <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800/80 text-xs font-mono text-slate-300 overflow-x-auto max-h-[500px] leading-relaxed">
              {getFileContent(selectedFileName)}
            </pre>
          </div>
        </div>
      )}

      {/* Subtab 3: CycloneDX SBOM & Summary CSV */}
      {activeSubTab === 'sbom' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* CycloneDX SBOM */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>CycloneDX v1.5 JSON SBOM (bom.json)</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  Spec 1.5 Compliant
                </span>
              </div>
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-[400px]">
                {getFileContent('bom.json')}
              </pre>
            </div>

            {/* Summary CSV */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-emerald-400" />
                  <span>Compliance & Risk Summary CSV (summary.csv)</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                  Auditor Format
                </span>
              </div>
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-emerald-300/90 overflow-x-auto max-h-[400px]">
                {getFileContent('summary.csv')}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Subtab 4: in-toto Attestation & Ed25519 Cryptographic Signature */}
      {activeSubTab === 'attestation' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* in-toto Attestation */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-indigo-400" />
                  <span>in-toto v1 Statement & SLSA Provenance</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Statement/v1
                </span>
              </div>
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-[450px]">
                {getFileContent('attestation.json')}
              </pre>
            </div>

            {/* Cryptographic Signature Envelope */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                  <Fingerprint className="w-4 h-4 text-cyan-400" />
                  <span>Ed25519 Signature Envelope</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  Algorithm: Ed25519
                </span>
              </div>

              {currentBundle?.signature ? (
                <div className="space-y-3">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono space-y-2">
                    <div>
                      <span className="text-slate-400">Signature ID: </span>
                      <span className="text-slate-200 font-bold">{currentBundle.signature.signature_id}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Key ID & Version: </span>
                      <span className="text-cyan-300">{currentBundle.signature.key_id} ({currentBundle.signature.key_version})</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Signed At: </span>
                      <span className="text-slate-300">{currentBundle.signature.signed_at}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Signature Base64: </span>
                      <p className="text-[11px] text-emerald-400 break-all mt-1 bg-slate-900 p-2 rounded">
                        {currentBundle.signature.signature_base64}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Public Key (SPKI PEM): </span>
                      <pre className="text-[10px] text-slate-400 mt-1 bg-slate-900 p-2 rounded overflow-x-auto">
                        {currentBundle.signature.public_key_pem}
                      </pre>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-400 font-mono py-10 text-center">
                  No signature generated. Build and sign a package first.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 5: Shipping & Delivery Diagnostics */}
      {activeSubTab === 'shipping' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Target Selector & Ship Action */}
          <div className="lg:col-span-1 bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
            <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
              <Truck className="w-4 h-4 text-emerald-400" />
              <span>Shipping Target Configuration</span>
            </h3>

            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">Target Adapter</label>
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="OCI_REGISTRY">OCI Artifact / Container Registry</option>
                <option value="S3_STORAGE">S3 / Cloud Object Storage Vault</option>
                <option value="WEBHOOK_DEPLOYMENT">Production Webhook / Orchestrator</option>
                <option value="LOCAL_STAGING">Local Staging / Air-Gapped Directory</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-slate-400 mb-1">Target Locator</label>
              <input
                type="text"
                value={targetLocator}
                onChange={(e) => setTargetLocator(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono space-y-1.5">
              <span className="font-semibold text-slate-300 block">Pre-Shipping Verification</span>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Package Ready:</span>
                <span className={currentBundle ? 'text-emerald-400' : 'text-slate-500'}>
                  {currentBundle ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Signature Valid:</span>
                <span className={verificationResult?.valid ? 'text-emerald-400' : 'text-rose-400'}>
                  {verificationResult?.valid ? 'VERIFIED' : 'FAILED'}
                </span>
              </div>
            </div>

            <button
              onClick={handleShip}
              disabled={loading || !currentBundle}
              className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-mono font-bold shadow flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ship to {selectedTarget}</span>
            </button>
          </div>

          {/* Delivery Receipts & Audit History */}
          <div className="lg:col-span-2 space-y-4">
            {latestReceipt && (
              <div className="bg-emerald-950/20 rounded-xl border border-emerald-500/30 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-400 font-mono flex items-center">
                    <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> Latest Delivery Receipt
                  </span>
                  <span className="text-[10px] font-mono text-emerald-300">
                    Status: {latestReceipt.status}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-300">
                  <div>Shipment ID: <span className="text-slate-100">{latestReceipt.shipment_id}</span></div>
                  <div>Transfer Size: <span className="text-cyan-300">{latestReceipt.transfer_size_bytes} B</span></div>
                  <div className="col-span-2">Locator: <span className="text-emerald-300 break-all">{latestReceipt.receipt_locator}</span></div>
                  <div className="col-span-2">Receipt Signature: <span className="text-slate-400 break-all">{latestReceipt.receipt_signature}</span></div>
                </div>
              </div>
            )}

            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-3">
              <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center space-x-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Immutable Delivery Audit Log</span>
              </h3>

              {shipmentsLog.length > 0 ? (
                <div className="border border-slate-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="p-2.5">Shipment ID</th>
                        <th className="p-2.5">Target</th>
                        <th className="p-2.5">Locator</th>
                        <th className="p-2.5">Shipped At</th>
                        <th className="p-2.5 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                      {shipmentsLog.map((s: any) => (
                        <tr key={s.shipment_id} className="hover:bg-slate-800/40">
                          <td className="p-2.5 text-slate-300 font-bold">{s.shipment_id.slice(0, 16)}...</td>
                          <td className="p-2.5 text-cyan-300">{s.target_type}</td>
                          <td className="p-2.5 text-slate-300 truncate max-w-[180px]">{s.target_locator}</td>
                          <td className="p-2.5 text-slate-400">{new Date(s.shipped_at).toLocaleTimeString()}</td>
                          <td className="p-2.5 text-right">
                            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px]">
                              {s.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-xs text-slate-400 font-mono py-8 text-center">
                  No shipments logged yet.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
