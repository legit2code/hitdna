import React, { useState, useMemo } from 'react';
import { 
  Network, 
  GitMerge, 
  ShieldAlert, 
  ShieldCheck, 
  FileCode2, 
  Sparkles, 
  Layers, 
  CheckCircle2, 
  ArrowRight, 
  Terminal, 
  Compass, 
  ExternalLink,
  Code2,
  Lock,
  Cpu,
  Key
} from 'lucide-react';
import { DiagnosticMetricsCard } from './DiagnosticMetricsCard.tsx';
import { 
  CaneCanonicalizer, 
  CaneMappingRegistry, 
  SecurityInferenceGuard,
  CANE_SPEC_VERSION,
  CANE_MAPPING_REGISTRY_VERSION
} from '../../../../../packages/ontology/src/index.ts';
import PRECOMPUTED_CANONICAL_RESULTS from './cane-preset-results.json';

const SAMPLE_PRESETS: Record<string, { label: string; language: string; files: Array<{ path: string; content: string }> }> = {
  multilang_process: {
    label: 'Cross-Language Process Execution (JS + Python + Go)',
    language: 'Polyglot',
    files: [
      {
        path: 'agent_executor.ts',
        content: `import { exec, spawn } from 'child_process';
import axios from 'axios';

export async function runTask(cmd: string, url: string) {
  const res = await axios.get(url);
  exec(cmd);
}`
      },
      {
        path: 'worker_service.py',
        content: `import subprocess
import os

def process_job(cmd: str):
    subprocess.Popen(cmd, shell=True)
    os.system("echo completed")`
      },
      {
        path: 'runner.go',
        content: `package main

import "os/exec"

func ExecuteCommand(cmd string) {
    exec.Command("sh", "-c", cmd).Run()
}`
      }
    ]
  },
  mcp_agent: {
    label: 'Model Context Protocol (MCP) Server Agent',
    language: 'TypeScript',
    files: [
      {
        path: 'mcp_server.ts',
        content: `import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'fs';

const server = new McpServer({ name: 'file-analyst', version: '1.0.0' });

server.tool(
  'read_secure_file',
  { path: z.string() },
  async ({ path }) => {
    const data = fs.readFileSync(path, 'utf8');
    return { content: [{ type: 'text', text: data }] };
  }
);`
      },
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'mcp-file-analyst',
          version: '1.0.0',
          dependencies: {
            '@modelcontextprotocol/sdk': '^1.0.1',
            'zod': '^3.23.0'
          },
          x_mcp_capabilities: {
            prompts: true,
            resources: true,
            tools: true
          }
        }, null, 2)
      }
    ]
  },
  compound_risk: {
    label: 'Compound Risk (Egress + Dynamic Eval + FS Write)',
    language: 'TypeScript / Node',
    files: [
      {
        path: 'eval_agent.ts',
        content: `import * as fs from 'fs';
import fetch from 'node-fetch';

export async function fetchAndExecute(endpoint: string, code: string) {
  const res = await fetch(endpoint);
  eval(code);
  fs.writeFileSync('/tmp/audit.log', 'done');
}`
      }
    ]
  }
};

export const DiagnosticCaneView: React.FC = () => {
  const [selectedPresetKey, setSelectedPresetKey] = useState<string>('multilang_process');
  const [activeSubtab, setActiveSubtab] = useState<'manifest' | 'triples' | 'rules' | 'inferences' | 'lineage' | 'extensions'>('manifest');

  const preset = SAMPLE_PRESETS[selectedPresetKey];

  // Retrieve live CANE Canonicalization result for active preset
  const canonicalResult = useMemo(() => {
    return (PRECOMPUTED_CANONICAL_RESULTS as Record<string, any>)[selectedPresetKey] || null;
  }, [selectedPresetKey]);

  return (
    <div className="space-y-6">
      {/* Header banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-semibold text-white">CANE Canonicalization & Ontology Mapping</h2>
                <span className="px-2 py-0.5 text-xs font-mono rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60">
                  CANE v{CANE_SPEC_VERSION}
                </span>
                <span className="px-2 py-0.5 text-xs font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Registry v{CANE_MAPPING_REGISTRY_VERSION}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Translates normalized source facts across JS, Python, Go into unified CAIM entities and ontology semantics with deterministic provenance.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-slate-950 p-1.5 rounded-lg border border-slate-800">
            <span className="text-xs text-slate-400 px-2 font-medium">Preset:</span>
            {Object.entries(SAMPLE_PRESETS).map(([key, p]) => (
              <button
                key={key}
                onClick={() => setSelectedPresetKey(key)}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  selectedPresetKey === key
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                {p.language}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      {canonicalResult && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <DiagnosticMetricsCard
            title="Source Facts"
            value={canonicalResult.diagnostics.total_source_facts}
            subtitle="Extracted AST facts"
            icon={<FileCode2 className="w-4 h-4 text-sky-400" />}
          />
          <DiagnosticMetricsCard
            title="Mapped Capabilities"
            value={canonicalResult.diagnostics.total_capabilities}
            subtitle="Unified CAIM concepts"
            icon={<Layers className="w-4 h-4 text-indigo-400" />}
          />
          <DiagnosticMetricsCard
            title="Ontology Triples"
            value={canonicalResult.ontology_relationships.length}
            subtitle="Semantic relationships"
            icon={<GitMerge className="w-4 h-4 text-cyan-400" />}
          />
          <DiagnosticMetricsCard
            title="Compound Inferences"
            value={canonicalResult.diagnostics.total_inferences}
            subtitle="Taxonomic derivations"
            icon={<Sparkles className="w-4 h-4 text-amber-400" />}
          />
          <DiagnosticMetricsCard
            title="Avg Confidence"
            value={`${Math.round(canonicalResult.diagnostics.average_mapping_confidence * 100)}%`}
            subtitle="Weighted rule score"
            icon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />}
          />
          <DiagnosticMetricsCard
            title="Security Guard"
            value={canonicalResult.diagnostics.security_guard_status}
            subtitle="Strict non-escalation"
            icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
          />
        </div>
      )}

      {/* Main Subtabs Navigation */}
      <div className="flex border-b border-slate-800 gap-1">
        {[
          { id: 'manifest', label: 'CAIM Entities Manifest', count: canonicalResult?.caim_manifest.capabilities.length },
          { id: 'triples', label: 'Ontology Triples Graph', count: canonicalResult?.ontology_relationships.length },
          { id: 'inferences', label: 'Taxonomic Inferences', count: canonicalResult?.inferences.length },
          { id: 'rules', label: 'Source→Canonical Mapping Rules', count: CaneMappingRegistry.rules.length },
          { id: 'lineage', label: 'Source Provenance Lineage', count: canonicalResult?.mapping_matches.length },
          { id: 'extensions', label: 'Preserved Extensions', count: Object.keys(canonicalResult?.unmapped_extensions || {}).length },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveSubtab(tab.id as any)}
            className={`px-4 py-2.5 text-xs font-medium border-b-2 flex items-center gap-2 transition-all ${
              activeSubtab === tab.id
                ? 'border-indigo-500 text-indigo-300 bg-indigo-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-800 text-slate-300 font-mono">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Subtab Content */}
      {canonicalResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          {/* Subtab 1: CAIM Manifest */}
          {activeSubtab === 'manifest' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-semibold text-white mb-2">Canonical Agent Specification (CAIM)</h3>
                <p className="text-xs text-slate-400">
                  Source-independent semantic entities synthesized from polyglot source facts.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Capabilities */}
                <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/50 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Capabilities ({canonicalResult.caim_manifest.capabilities.length})</span>
                    <span className="text-[10px] font-mono text-indigo-400">caim:capability</span>
                  </div>
                  <div className="space-y-2">
                    {canonicalResult.caim_manifest.capabilities.map((cap, idx) => (
                      <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
                        <div>
                          <div className="font-mono text-xs text-indigo-300 font-medium">{cap.canonical_key}</div>
                          <div className="text-[10px] text-slate-500 mt-0.5">ID: {cap.capability_id.slice(0, 18)}...</div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300">
                            {cap.declaration_state}
                          </span>
                          <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                            {Math.round(cap.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Tools */}
                <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/50 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Tools & Invocation Interfaces ({canonicalResult.caim_manifest.tools.length})</span>
                    <span className="text-[10px] font-mono text-sky-400">caim:tool</span>
                  </div>
                  <div className="space-y-2">
                    {canonicalResult.caim_manifest.tools.length === 0 ? (
                      <div className="text-xs text-slate-500 italic p-3">No tools explicitly registered in this sample.</div>
                    ) : (
                      canonicalResult.caim_manifest.tools.map((t, idx) => (
                        <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
                          <div>
                            <div className="font-mono text-xs text-sky-300 font-medium">{t.canonical_name}</div>
                            <div className="text-[10px] text-slate-400 mt-0.5">{t.description || 'No description provided'}</div>
                          </div>
                          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-sky-950 text-sky-300 border border-sky-800">
                            {t.tool_type}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Components & Dependencies */}
              <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/50 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Components & Dependency Graph ({canonicalResult.caim_manifest.components.length})</span>
                  <span className="text-[10px] font-mono text-purple-400">caim:component</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  {canonicalResult.caim_manifest.components.map((comp, idx) => (
                    <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="font-mono text-xs text-purple-300 font-medium">{comp.canonical_name}</div>
                        <div className="text-[10px] text-slate-500">{comp.ecosystem} ({comp.version || 'direct'})</div>
                      </div>
                      <span className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-slate-800 text-slate-400">
                        {comp.component_type}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Subtab 2: Ontology Triples */}
          {activeSubtab === 'triples' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Ontology Semantic Graph Triples</h3>
                  <p className="text-xs text-slate-400">
                    Formal RDF-style subject-predicate-object assertions linking canonical concepts.
                  </p>
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-3">Subject Concept / Entity</th>
                      <th className="p-3">Predicate</th>
                      <th className="p-3">Object Concept / Entity</th>
                      <th className="p-3">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                    {canonicalResult.ontology_relationships.map((rel, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-3 text-indigo-300">{rel.subject_concept_id}</td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-amber-300 border border-slate-700">
                            {rel.predicate}
                          </span>
                        </td>
                        <td className="p-3 text-cyan-300">{rel.object_concept_id}</td>
                        <td className="p-3 text-emerald-400">{Math.round(rel.confidence * 100)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Subtab 3: Inferences */}
          {activeSubtab === 'inferences' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">Taxonomic & Structural Inferences</h3>
                <p className="text-xs text-slate-400">
                  Higher-order risks and compound capabilities derived with deterministic inference rules and epistemic state guards.
                </p>
              </div>

              {canonicalResult.inferences.length === 0 ? (
                <div className="text-xs text-slate-500 italic p-4 bg-slate-950/40 rounded border border-slate-800">
                  No compound inference rules matched this artifact. Select &quot;Compound Risk&quot; preset to view compound derivations.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3">
                  {canonicalResult.inferences.map((inf, idx) => (
                    <div key={idx} className="p-4 bg-slate-950 rounded-lg border border-amber-500/20 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-amber-400" />
                          <span className="font-mono text-xs font-bold text-amber-300">{inf.canonical_key}</span>
                          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300">
                            {inf.epistemic_state}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-slate-500">{inf.inference_rule_id}</span>
                          <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-amber-950 text-amber-400 border border-amber-800">
                            {Math.round(inf.confidence * 100)}%
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">{inf.rationale}</p>

                      <div className="pt-2 border-t border-slate-800/80 flex items-center gap-2 text-[10px] font-mono text-slate-400">
                        <span className="text-slate-500">Antecedents:</span>
                        {inf.antecedent_concept_ids.map((ant, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-indigo-300">
                            {ant}
                          </span>
                        ))}
                        <span className="text-slate-500 ml-auto">Engine: {inf.provenance.engine_key}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Subtab 4: Mapping Rules Registry */}
          {activeSubtab === 'rules' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">Source → Canonical Mapping Catalog</h3>
                <p className="text-xs text-slate-400">
                  Active mapping rules catalog matching polyglot AST patterns to canonical ontology keys.
                </p>
              </div>

              <div className="space-y-2">
                {CaneMappingRegistry.rules.map((rule, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-white">{rule.rule_name}</span>
                        <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300">
                          {rule.rule_id}
                        </span>
                        {rule.security_sensitive && (
                          <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-rose-950 text-rose-400 border border-rose-800">
                            SECURITY SENSITIVE
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[11px] text-slate-400 mt-1">
                        Pattern: <code className="text-indigo-300 bg-slate-900 px-1 py-0.5 rounded">{rule.source_pattern}</code>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right font-mono text-[11px]">
                        <span className="text-slate-500">Target: </span>
                        <span className="text-emerald-300 font-bold">{rule.target_canonical_key}</span>
                      </div>
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300">
                        {rule.source_ecosystems.join(', ')}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Subtab 5: Lineage */}
          {activeSubtab === 'lineage' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">Source Provenance & Lineage Resolutions</h3>
                <p className="text-xs text-slate-400">
                  Exact AST source spans and rules executed for each mapped canonical fact.
                </p>
              </div>

              <div className="space-y-2">
                {canonicalResult.mapping_matches.map((m, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-indigo-300">{m.target_canonical_key}</span>
                        <span className="text-slate-500 font-mono">from</span>
                        <span className="font-mono text-amber-300">{m.matched_construct}</span>
                      </div>
                      <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-slate-800 text-slate-300">
                        Rule: {m.rule_id}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
                      <span>File: <code className="text-slate-200">{m.file_path}</code></span>
                      {m.span && (
                        <span>Lines: <code className="text-slate-200">{m.span.start_line}:{m.span.start_col} - {m.span.end_line}:{m.span.end_col}</code></span>
                      )}
                      <span>Ecosystem: <code className="text-slate-200">{m.source_ecosystem}</code></span>
                      <span className="text-emerald-400 ml-auto">Confidence: {Math.round(m.confidence * 100)}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Subtab 6: Extensions */}
          {activeSubtab === 'extensions' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">Preserved Unmapped Extensions</h3>
                <p className="text-xs text-slate-400">
                  Vendor-specific fields and unrecognized config attributes preserved verbatim without data loss.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs">
                <pre className="text-slate-300 overflow-x-auto">
                  {JSON.stringify(canonicalResult.unmapped_extensions, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
