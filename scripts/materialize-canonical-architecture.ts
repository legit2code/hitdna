import fs from 'node:fs';
import path from 'node:path';

// Canonical manifest data with all 66 engines across the 7 domains
export const CANONICAL_DOMAINS = [
  {
    domainId: "D01",
    domainCode: "PF",
    name: "Platform Foundation & Governance",
    requirementFamilies: ["ARCHITECTURE_GOVERNANCE", "SECURITY", "REPRODUCIBILITY", "VERSIONING"],
    engines: [
      { id: "PF-01", name: "Architecture & Build Constitution Engine", purpose: "Lock the controlled product architecture, truth invariants, phase boundaries and change-governance process.", moduleCount: 8 },
      { id: "PF-02", name: "Repository & Tooling Foundation", purpose: "Provide strict TypeScript full-stack project boundaries, build tooling, tests and baseline CI.", moduleCount: 9 },
      { id: "PF-03", name: "Typed Configuration & Secrets Engine", purpose: "Centralize public/server/worker configuration, provider credentials, feature flags and redaction.", moduleCount: 8 },
      { id: "PF-04", name: "Canonical Music Data Model & Repository Engine", purpose: "Own typed persistence contracts and repository boundaries for the entire music intelligence model.", moduleCount: 8 },
      { id: "PF-05", name: "Authentication, Roles & Authorization Engine", purpose: "Enforce identity, role-aware access and privileged admin/research boundaries before data reaches UI or tools.", moduleCount: 8 },
      { id: "PF-06", name: "Shared Contracts & Validation Engine", purpose: "Provide source-independent TypeScript/Zod contracts used by client, server, jobs and analytics.", moduleCount: 9 },
      { id: "PF-07", name: "Lifecycle State Engine", purpose: "Control legal states for research, analysis, publication, artist review and generation records.", moduleCount: 9 },
      { id: "PF-08", name: "Workflow, Queue, Job & Outbox Control Plane", purpose: "Run durable asynchronous research, enrichment, analytics, clustering, publication and generation work.", moduleCount: 12 },
      { id: "PF-09", name: "Version, Prompt & Methodology Governance", purpose: "Version every taxonomy, methodology, prompt, model, extractor, clustering rule and publication policy that can change conclusions.", moduleCount: 10 }
    ]
  },
  {
    domainId: "D02",
    domainCode: "RI",
    name: "Research, Sources & Continuous Ingestion",
    requirementFamilies: ["CONTINUOUS_RESEARCH", "PROVENANCE", "RIGHTS_AND_SOURCE_POLICY", "ALL_GENRE_HYBRID"],
    engines: [
      { id: "RI-01", name: "Source Adapter Framework", purpose: "Isolate chart, metadata, audio, lyric, slang, lexicon and research-provider mechanics behind one source contract.", moduleCount: 10 },
      { id: "RI-02", name: "Continuous Research Scheduler", purpose: "Keep current-hit, feature, slang and enrichment research refreshed according to provider-permitted cadences.", moduleCount: 9 },
      { id: "RI-03", name: "Research Acquisition & Raw Preservation", purpose: "Accept real authorized source bytes/records, validate them and preserve immutable raw provenance.", moduleCount: 10 },
      { id: "RI-04", name: "Song & Artist Identity Resolution", purpose: "Resolve duplicate provider observations into canonical song/artist identities while preserving ambiguity, versions and aliases.", moduleCount: 10 },
      { id: "RI-05", name: "Chart Observation & Hit Qualification", purpose: "Normalize chart evidence and determine reproducible membership eligibility using versioned hit policies.", moduleCount: 9 },
      { id: "RI-06", name: "Genre, Subgenre, Scene & Hybrid Taxonomy", purpose: "Model all genres and researched hybrids as a versioned graph rather than a single genre string.", moduleCount: 10 },
      { id: "RI-07", name: "Source Reconciliation & Canonical Mapping", purpose: "Reconcile conflicting observations by feature family without destroying losing evidence.", moduleCount: 9 },
      { id: "RI-08", name: "Coverage, Freshness & Data Quality Engine", purpose: "Measure source, cohort and feature completeness so every published claim discloses what was actually observed.", moduleCount: 9 },
      { id: "RI-09", name: "Rights, Licensing & Source Policy Engine", purpose: "Enforce what source material may be collected, stored, analyzed, excerpted or exposed.", moduleCount: 8 }
    ]
  },
  {
    domainId: "D03",
    domainCode: "MI",
    name: "Music Understanding & Pattern Intelligence",
    requirementFamilies: ["MEASURED_MUSIC_FEATURES", "MODERN_LANGUAGE", "CHORD_GROOVE_ARRANGEMENT", "NO_FABRICATION"],
    engines: [
      { id: "MI-01", name: "Feature Observation & Normalization Framework", purpose: "Convert accepted evidence into typed music observations without making Hit DNA conclusions yet.", moduleCount: 8 },
      { id: "MI-02", name: "Audio Feature Intelligence", purpose: "Measure or ingest reproducible audio properties used by Hit DNA.", moduleCount: 10 },
      { id: "MI-03", name: "Song Structure & Section Intelligence", purpose: "Represent arrangement sections and derive reproducible structure/timing patterns.", moduleCount: 10 },
      { id: "MI-04", name: "Hook Intelligence", purpose: "Measure hook placement, recurrence, title use and repetition while separating subjective catchiness claims.", moduleCount: 9 },
      { id: "MI-05", name: "Rhythm, Cadence & Groove Intelligence", purpose: "Measure rhythmic pocket, vocal density and generalized groove patterns where evidence supports them.", moduleCount: 11 },
      { id: "MI-06", name: "Production, Dynamics, 808 & Arrangement Intelligence", purpose: "Measure production and arrangement movement including dynamics, drops, bass/808 behavior and instrument entrances/exits.", moduleCount: 11 },
      { id: "MI-07", name: "Lyrical, Theme & Language Feature Intelligence", purpose: "Measure authorized lyrical features and AI-assisted themes with explicit provenance/review states.", moduleCount: 10 },
      { id: "MI-08", name: "Modern Language, Slang & Vernacular Intelligence", purpose: "Continuously research modern words, phrases, meanings, context, recency and trajectory for authentic current lyric writing.", moduleCount: 12 },
      { id: "MI-09", name: "Melodic, Harmonic & Chord Intelligence", purpose: "Extract/ingest chords, progressions, harmonic rhythm and melodic features when validated evidence exists.", moduleCount: 11 },
      { id: "MI-10", name: "Musical Pattern Abstraction Engine", purpose: "Convert measured chord, groove and arrangement patterns into safe aggregate/transposable references for generation.", moduleCount: 9 }
    ]
  },
  {
    domainId: "D04",
    domainCode: "HD",
    name: "Hit DNA Analytics, Archetypes & Trends",
    requirementFamilies: ["STATISTICAL_TRUTH", "MULTI_ARCHETYPE", "TEMPORAL_TRENDS", "TOP_HIT_DNA", "HYBRID_DNA"],
    engines: [
      { id: "HD-01", name: "Hit Cohort & Denominator Engine", purpose: "Define exact immutable qualifying populations before any percentage is allowed to exist.", moduleCount: 11 },
      { id: "HD-02", name: "Evidence, Assertion, Claim & Confidence Engine", purpose: "Turn observations and analysis outputs into auditable claims while preserving uncertainty and contradiction.", moduleCount: 10 },
      { id: "HD-03", name: "Deterministic Statistical Analytics", purpose: "Calculate real frequencies, distributions and percentages from persisted cohort/feature records.", moduleCount: 11 },
      { id: "HD-04", name: "Multi-Archetype Clustering Engine", purpose: "Discover distinct modes of successful songs rather than collapsing a genre into one average profile.", moduleCount: 11 },
      { id: "HD-05", name: "Temporal Evolution & Trend Intelligence", purpose: "Compare immutable DNA snapshots over time and distinguish rising, stable, declining and emerging archetypes.", moduleCount: 10 },
      { id: "HD-06", name: "DNA Snapshot & Publication Registry", purpose: "Freeze every published DNA result with exact dataset, methodology and evidence references.", moduleCount: 9 },
      { id: "HD-07", name: "Top Hit DNA Ranking & Recommendation", purpose: "Convert complex analytics into up to five simple factual creator choices.", moduleCount: 10 },
      { id: "HD-08", name: "Hybrid Genre DNA Intelligence", purpose: "Analyze researched hybrid cohorts separately from arbitrary creative blends and preserve component lineage.", moduleCount: 7 },
      { id: "HD-09", name: "Novelty, Saturation & Pattern-Break Intelligence", purpose: "Quantify pattern prevalence/saturation and define controlled departures without rewriting research truth.", moduleCount: 8 }
    ]
  },
  {
    domainId: "D05",
    domainCode: "AR",
    name: "Artist Research & Style Intelligence",
    requirementFamilies: ["REAL_ARTIST_RESEARCH", "ABSTRACT_STYLE_EXPORT", "NO_ARTIST_NAME_LEAKAGE"],
    engines: [
      { id: "AR-01", name: "Real Artist Research Intake", purpose: "Create real artist identities and attach authorized evidence before any style profile becomes selectable.", moduleCount: 7 },
      { id: "AR-02", name: "Artist Style Profile & Review", purpose: "Curate vocal, cadence, delivery, lyrical, production, energy and ad-lib traits with explicit review states.", moduleCount: 10 },
      { id: "AR-03", name: "Artist Profile Versioning & Eligibility", purpose: "Preserve historical profile versions and decide which profiles may be used for generation.", moduleCount: 7 },
      { id: "AR-04", name: "Artist Style Resolver", purpose: "Convert an approved internal artist profile into exportable abstract performance traits.", moduleCount: 8 },
      { id: "AR-05", name: "Artist Identity Leakage & Similarity Guard", purpose: "Prevent external prompts from receiving real artist names, aliases, IDs or copying uniquely identifying material.", moduleCount: 8 },
      { id: "AR-06", name: "Artist Style Fusion Intelligence", purpose: "Blend two approved abstract profiles dimension-by-dimension while keeping provenance and deterministic ratios.", moduleCount: 10 }
    ]
  },
  {
    domainId: "D06",
    domainCode: "CG",
    name: "Creative Generation & Song Construction",
    requirementFamilies: ["KEYWORD_BRIEF", "ERA_AUTHENTIC_LANGUAGE", "EVIDENCE_CONSTRAINED_GENERATION", "PERFORMANCE_LYRICS", "SUNO_PROMPT", "GENERATION_LINEAGE"],
    engines: [
      { id: "CG-01", name: "Creator Keyword, Theme & Language Brief", purpose: "Turn user ideas plus optional evidence-backed suggestions into a structured creative brief before song generation.", moduleCount: 13 },
      { id: "CG-02", name: "Language Freshness & Era Authenticity Resolver", purpose: "Choose current, 90-day, 12-month, era-authentic or neutral language guidance and prevent anachronistic slang.", moduleCount: 9 },
      { id: "CG-03", name: "Song Specification & Blueprint Engine", purpose: "Assemble exact DNA, musical patterns, artist traits, keyword brief and generation strategy into a validated song blueprint.", moduleCount: 14 },
      { id: "CG-04", name: "Hook Strategy Engine", purpose: "Translate measured hook DNA and creator concept into an original hook plan.", moduleCount: 10 },
      { id: "CG-05", name: "Modern Lyric Engineering Engine", purpose: "Generate original lyrics using blueprint constraints, modern language intelligence, keyword directives and performance markup.", moduleCount: 12 },
      { id: "CG-06", name: "Musical Pattern Reference Injection", purpose: "Translate safe chord/groove/arrangement pattern references into generation-facing instructions without copying hit melodies.", moduleCount: 8 },
      { id: "CG-07", name: "Suno-Style Sound Prompt Engine", purpose: "Create a concise production/performance prompt from validated DNA, pattern references and safe artist traits.", moduleCount: 11 },
      { id: "CG-08", name: "Generation Strategy & Pattern-Break Engine", purpose: "Apply user-selected fidelity and creative strategies without mutating the factual DNA snapshot.", moduleCount: 11 },
      { id: "CG-09", name: "Generation Orchestrator", purpose: "Coordinate the complete authenticated generation pipeline and preserve stage lineage.", moduleCount: 14 },
      { id: "CG-10", name: "Generation Validation & Truth Guard", purpose: "Validate DNA compliance, language rules, formatting, pattern breaks, artist leakage and evidence completeness before success.", moduleCount: 11 },
      { id: "CG-11", name: "Generation History, Feedback & Reproducibility", purpose: "Store user-owned generation lineage and feedback without contaminating research truth.", moduleCount: 10 }
    ]
  },
  {
    domainId: "D07",
    domainCode: "PA",
    name: "Product Experience, Operations & Assurance",
    requirementFamilies: ["CREATOR_SIMPLICITY", "EVIDENCE_DRILLDOWN", "ADMIN_GOVERNANCE", "OBSERVABILITY", "EVALUATION", "CI_CD", "DEFINITION_OF_DONE"],
    engines: [
      { id: "PA-01", name: "Public/Internal API & Contract Engine", purpose: "Expose implemented domains through stable typed APIs while keeping business logic out of HTTP/UI layers.", moduleCount: 11 },
      { id: "PA-02", name: "Creator Experience UI", purpose: "Provide the simple genre -> period -> Top Hit DNA -> artist/keywords -> generate workflow.", moduleCount: 13 },
      { id: "PA-03", name: "DNA Explorer & Music Pattern UI", purpose: "Expose deep distributions, chord/groove/arrangement, trends, cohort comparisons and evidence drill-down.", moduleCount: 12 },
      { id: "PA-04", name: "Research Console & Data Source Operations", purpose: "Give researchers visibility into providers, ingestion, raw->normalized lineage, cohorts, clustering and unresolved data issues.", moduleCount: 12 },
      { id: "PA-05", name: "Artist Styles & Review UI", purpose: "Expose approved artist profiles to creators and evidence/review/version workflows to authorized staff.", moduleCount: 9 },
      { id: "PA-06", name: "Admin, Methodology & Publication Governance UI", purpose: "Manage taxonomy, methodologies, prompts, versions, publication controls and audit without unsafe direct writes.", moduleCount: 11 },
      { id: "PA-07", name: "Observability, Freshness, Cost & Audit Engine", purpose: "Make research and generation diagnosable with correlation, freshness and measured operational cost.", moduleCount: 14 },
      { id: "PA-08", name: "Golden Corpus & Regression Evaluation", purpose: "Continuously test statistical truth, cohort accuracy, clustering stability, generation constraints and no-fabrication behavior.", moduleCount: 14 },
      { id: "PA-09", name: "CI/CD, Recovery & Continuous Operations", purpose: "Run mandatory build/security/evaluation gates and recover ongoing research without corrupting factual history.", moduleCount: 18 },
      { id: "PA-10", name: "Engine Parity & Implementation Coverage Audit", purpose: "Prove every approved engine is accounted for exactly once with code, tests, telemetry, security and known gaps.", moduleCount: 8 },
      { id: "PA-11", name: "Requirements & Definition-of-Done Traceability", purpose: "Map every authoritative requirement to implementation, data, APIs/jobs, tests and evaluation evidence.", moduleCount: 10 },
      { id: "PA-12", name: "Production Hardening & Final Release Audit", purpose: "Verify security, truth lineage, continuous research, user workflows and clean-checkout reproducibility before COMPLETE.", moduleCount: 12 }
    ]
  }
];

// Ensure directories
fs.mkdirSync(path.join(process.cwd(), 'docs/architecture'), { recursive: true });
fs.mkdirSync(path.join(process.cwd(), 'docs/implementation'), { recursive: true });

// 1. Generate ENGINE_RESPONSIBILITY_MATRIX.csv
let matrixCsv = 'engine_id,engine_name,domain_id,domain_name,purpose,module_count\n';
let totalEngines = 0;
let totalModules = 0;

for (const d of CANONICAL_DOMAINS) {
  for (const e of d.engines) {
    totalEngines++;
    totalModules += e.moduleCount;
    matrixCsv += `${e.id},"${e.name}",${d.domainId},"${d.name}","${e.purpose.replace(/"/g, '""')}",${e.moduleCount}\n`;
  }
}

fs.writeFileSync(path.join(process.cwd(), 'docs/architecture/ENGINE_RESPONSIBILITY_MATRIX.csv'), matrixCsv, 'utf8');

// 2. Generate ENGINE_COVERAGE.csv
let coverageCsv = 'engine_id,engine_name,domain_id,status,phase_primary,implemented_modules,total_modules\n';
for (const d of CANONICAL_DOMAINS) {
  for (const e of d.engines) {
    let status = 'PLANNED';
    let phase = 'FUTURE';
    let implemented = 0;

    if (e.id === 'PF-01') {
      status = 'BOOTSTRAPPED';
      phase = 'P00';
      implemented = e.moduleCount;
    } else if (e.id === 'PF-02') {
      status = 'VERIFIED';
      phase = 'P01';
      implemented = e.moduleCount;
    } else if (e.id === 'PF-09') {
      status = 'BOOTSTRAPPED';
      phase = 'P00';
      implemented = 2;
    }

    coverageCsv += `${e.id},"${e.name}",${d.domainId},${status},${phase},${implemented},${e.moduleCount}\n`;
  }
}

fs.writeFileSync(path.join(process.cwd(), 'docs/implementation/ENGINE_COVERAGE.csv'), coverageCsv, 'utf8');

// 3. Generate REQUIREMENT_COVERAGE.csv
const requirements = [
  { id: "REQ-001", family: "ARCHITECTURE_GOVERNANCE", name: "Canonical 66-Engine Architecture Materialization", phase: "P00", status: "VERIFIED" },
  { id: "REQ-002", family: "ARCHITECTURE_GOVERNANCE", name: "P00 Master Build Constitution Invariants Enforced", phase: "P00", status: "VERIFIED" },
  { id: "REQ-003", family: "ALL_GENRE_HYBRID", name: "All-Genre & Hybrid Graph Contract Specification", phase: "P00", status: "VERIFIED" },
  { id: "REQ-004", family: "MODERN_LANGUAGE", name: "Modern Language & Vernacular Intelligence Specification", phase: "P00", status: "VERIFIED" },
  { id: "REQ-005", family: "CHORD_GROOVE_ARRANGEMENT", name: "Musical Pattern Intelligence & Abstraction Specification", phase: "P00", status: "VERIFIED" },
  { id: "REQ-006", family: "KEYWORD_BRIEF", name: "Creator Keyword & Theme Brief Specification", phase: "P00", status: "VERIFIED" },
  { id: "REQ-007", family: "STATISTICAL_TRUTH", name: "Deterministic Lineage & Denominator Rule Specification", phase: "P00", status: "VERIFIED" },
  { id: "REQ-008", family: "SECURITY", name: "Server-Side Secrets & Provider Redaction Policy", phase: "P00", status: "VERIFIED" },
  { id: "REQ-009", family: "REPRODUCIBILITY", name: "Versioned Repository & Tooling Foundation (PF-02)", phase: "P01", status: "VERIFIED" }
];

let reqCsv = 'requirement_id,family,name,primary_phase,status\n';
for (const r of requirements) {
  reqCsv += `${r.id},${r.family},"${r.name}",${r.phase},${r.status}\n`;
}
fs.writeFileSync(path.join(process.cwd(), 'docs/implementation/REQUIREMENT_COVERAGE.csv'), reqCsv, 'utf8');

console.log(`Successfully generated canonical architecture tables:`);
console.log(`Total Domains: ${CANONICAL_DOMAINS.length}`);
console.log(`Total Engines: ${totalEngines}`);
console.log(`Total Modules: ${totalModules}`);
