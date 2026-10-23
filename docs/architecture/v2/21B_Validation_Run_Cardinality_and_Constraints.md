# ValidationRun Cardinality & Referential Integrity

**Document:** 21B  
**Version:** 2.0.1  
**Status:** LOCKED — migration requirement for P03/P05

## 1. Problem Corrected

The V2.0 dictionary previously represented `validation_runs` with one ambiguous optional `analysis_run_id`. That is insufficient because validation must identify:

1. the exact baseline analytical snapshot;
2. the exact modified/candidate analytical snapshot; and
3. the exact AnalysisRun that executes/records the validation comparison.

## 2. Locked Shape

`lifecycle.validation_runs` includes:

```text
validation_run_id uuid PK
validation_type text NOT NULL
baseline_agent_version_id uuid NOT NULL
modified_agent_version_id uuid NOT NULL
baseline_analysis_run_id uuid NOT NULL
modified_analysis_run_id uuid NOT NULL
validation_analysis_run_id uuid NOT NULL
scenario_pack_id uuid null
validation_plan_version text NOT NULL
policy_ruleset_version text null
scope_id uuid NOT NULL
status text NOT NULL
started_at timestamptz NOT NULL
completed_at timestamptz null
created_at timestamptz NOT NULL
```

Locked `validation_type` values at baseline:

```text
SOURCE_MODIFICATION
ANALYTICAL_REEVALUATION
POLICY_REEVALUATION
SCENARIO_REEVALUATION
```

## 3. AnalysisRun Constraint Added in P03

`analysis.analysis_runs` must include:

```text
UNIQUE (analysis_run_id, agent_version_id)
UNIQUE (analysis_run_id, scope_id)
```

The first unique key exists specifically so validation can enforce version/run ownership at the database layer.
The second supports inherited-scope enforcement for derived records.

## 4. Composite Foreign Keys

```text
(baseline_analysis_run_id, baseline_agent_version_id)
  → analysis_runs(analysis_run_id, agent_version_id)

(modified_analysis_run_id, modified_agent_version_id)
  → analysis_runs(analysis_run_id, agent_version_id)

validation_analysis_run_id
  → analysis_runs(analysis_run_id)
```

This prevents a baseline or modified run from silently referencing an AnalysisRun that belongs to a different AgentVersion.

## 5. Validation Type Invariants

### SOURCE_MODIFICATION
`baseline_agent_version_id != modified_agent_version_id`.

### ANALYTICAL_REEVALUATION
The two AgentVersion IDs may be equal; AnalysisRun IDs must identify the different analytical executions/configurations being compared.

### POLICY_REEVALUATION / SCENARIO_REEVALUATION
AgentVersion IDs may be equal when only policy/scenario configuration changed. The exact compared AnalysisRun IDs and versioned policy/scenario inputs remain mandatory.

## 6. Scope

Validation is `DERIVED_INHERITED_SCOPE`.
Its scope is resolved from baseline, modified and validation AnalysisRuns plus scenario/policy inputs. More than one distinct organization tenant in those inputs is rejected.

## 7. Migration Ownership

- **P03** creates `analysis_runs` with both composite unique constraints.
- **P05** creates the redesigned `validation_runs` with the composite FKs and validation-type constraints.
- **P25** implements validation behavior against this already-existing schema; it must not redesign the table.
