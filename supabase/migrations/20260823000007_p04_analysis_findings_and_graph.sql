-- Migration: 20260823000007_p04_analysis_findings_and_graph.sql
-- Purpose: Create Static Findings, CallGraph, Control/Dataflow Results, SBOM, and Runtime Events for Analysis
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21

-- 1. Static Findings Table
CREATE TABLE IF NOT EXISTS analysis.static_findings (
  finding_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  source_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  rule_id text NOT NULL,
  finding_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  message text NOT NULL,
  location_hint text NULL,
  raw_payload jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_static_findings_run ON analysis.static_findings(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_static_findings_stage ON analysis.static_findings(stage_run_id);
CREATE INDEX IF NOT EXISTS idx_static_findings_span ON analysis.static_findings(source_span_id);
CREATE INDEX IF NOT EXISTS idx_static_findings_severity ON analysis.static_findings(severity);

-- 2. CallGraph Nodes Table
CREATE TABLE IF NOT EXISTS analysis.callgraph_nodes (
  node_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  source_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  symbol_name text NOT NULL,
  node_type text NOT NULL,
  qualified_name text NOT NULL,
  properties jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_callgraph_nodes_run ON analysis.callgraph_nodes(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_callgraph_nodes_symbol ON analysis.callgraph_nodes(symbol_name);

-- 3. CallGraph Edges Table
CREATE TABLE IF NOT EXISTS analysis.callgraph_edges (
  edge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  caller_node_id uuid NOT NULL REFERENCES analysis.callgraph_nodes(node_id) ON DELETE CASCADE,
  callee_node_id uuid NOT NULL REFERENCES analysis.callgraph_nodes(node_id) ON DELETE CASCADE,
  call_type text NOT NULL DEFAULT 'DIRECT' CHECK (call_type IN ('DIRECT', 'DYNAMIC', 'DISPATCH', 'ASYNC')),
  call_site_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_callgraph_edges_caller ON analysis.callgraph_edges(caller_node_id);
CREATE INDEX IF NOT EXISTS idx_callgraph_edges_callee ON analysis.callgraph_edges(callee_node_id);
CREATE INDEX IF NOT EXISTS idx_callgraph_edges_run ON analysis.callgraph_edges(analysis_run_id);

-- 4. Taint Flows Table (Dataflow Analysis)
CREATE TABLE IF NOT EXISTS analysis.taint_flows (
  taint_flow_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  source_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  sink_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  source_type text NOT NULL,
  sink_type text NOT NULL,
  sanitizer_type text NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  path_summary text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_taint_flows_run ON analysis.taint_flows(analysis_run_id);

-- 5. SBOM Components Table (Software Bill of Materials)
CREATE TABLE IF NOT EXISTS analysis.sbom_components (
  sbom_component_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  purl text NULL,
  name text NOT NULL,
  version text NOT NULL,
  ecosystem text NOT NULL,
  license_expression text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sbom_components_run ON analysis.sbom_components(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_sbom_components_purl ON analysis.sbom_components(purl);

-- 6. SBOM Dependencies Table
CREATE TABLE IF NOT EXISTS analysis.sbom_dependencies (
  sbom_dependency_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  parent_component_id uuid NOT NULL REFERENCES analysis.sbom_components(sbom_component_id) ON DELETE CASCADE,
  child_component_id uuid NOT NULL REFERENCES analysis.sbom_components(sbom_component_id) ON DELETE CASCADE,
  dependency_scope text NOT NULL DEFAULT 'RUNTIME' CHECK (dependency_scope IN ('RUNTIME', 'DEV', 'OPTIONAL', 'PEER', 'TRANSITIVE')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sbom_dependencies_parent ON analysis.sbom_dependencies(parent_component_id);
CREATE INDEX IF NOT EXISTS idx_sbom_dependencies_child ON analysis.sbom_dependencies(child_component_id);

-- 7. Runtime Events Table (Dynamic / Sandbox execution)
CREATE TABLE IF NOT EXISTS analysis.runtime_events (
  runtime_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  event_type text NOT NULL,
  event_timestamp timestamptz NOT NULL DEFAULT now(),
  duration_ms integer NULL,
  source_locator text NULL,
  payload jsonb NULL,
  status text NOT NULL DEFAULT 'RECORDED' CHECK (status IN ('RECORDED', 'ANOMALY', 'VIOLATION')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_runtime_events_run ON analysis.runtime_events(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_runtime_events_type ON analysis.runtime_events(event_type);
