import fs from 'node:fs';
import path from 'node:path';

// Complete mapping of all 52 prompts: P-01, P00, P00A, P01..P48 (with P09A)
const prompts = [
  { id: "P-01", engine: "PF-01", name: "ENVIRONMENT_PREFLIGHT", category: "PREFLIGHT", severity: "BLOCKER", desc: "Validate container environment and basic Node runtime", cmd: "node -v" },
  { id: "P00", engine: "PF-01", name: "ARCHITECTURE_CANONICAL_BASELINE", category: "ARCHITECTURE_DRIFT", severity: "BLOCKER", desc: "Materialize 7 domains, 66 engines, 670 modules baseline", cmd: "npx tsx scripts/verify-p00.ts" },
  { id: "P00A", engine: "PF-01", name: "INTEGRITY_VERIFIER_BOOTSTRAP", category: "BUILD_VERIFICATION", severity: "BLOCKER", desc: "Bootstrap deterministic truth verification harness and self-tests", cmd: "npx tsx tools/integrity/phase-verifier.ts P00A" },
  { id: "P01", engine: "PF-02", name: "REPOSITORY_FOUNDATION_TOOLING", category: "BUILD_VERIFICATION", severity: "BLOCKER", desc: "Strict TypeScript config, module boundaries, unit and integration tests", cmd: "npm test" },
  { id: "P02", engine: "PF-03", name: "TYPED_CONFIG_SECRETS_ENGINE", category: "CONFIG_GOVERNANCE", severity: "BLOCKER", desc: "Typed configuration schemas and secret redaction enforcement", cmd: "npm run test:unit" },
  { id: "P03", engine: "PF-04", name: "CANONICAL_MUSIC_DATA_MODEL", category: "DATA_INTEGRITY", severity: "BLOCKER", desc: "Song, artist, and genre entity schemas and validation", cmd: "npm run test:unit" },
  { id: "P04", engine: "PF-04", name: "HIT_DNA_OBSERVATION_DATA_MODEL", category: "DATA_INTEGRITY", severity: "BLOCKER", desc: "Feature observation and measurement schema entities", cmd: "npm run test:unit" },
  { id: "P05", engine: "PF-04", name: "REPOSITORY_PERSISTENCE_TIER", category: "DATA_INTEGRITY", severity: "BLOCKER", desc: "Repository interfaces and cloud persistence adapters", cmd: "npm run test:integration" },
  { id: "P06", engine: "PF-05", name: "AUTHENTICATION_ROLES_RBAC", category: "SECURITY_AUTHORIZATION", severity: "BLOCKER", desc: "Authentication, roles (Creator/Researcher/Admin), and authorization", cmd: "npm run test:integration" },
  { id: "P07", engine: "PF-06", name: "SHARED_CONTRACTS_VALIDATION", category: "SCHEMA_VALIDATION", severity: "BLOCKER", desc: "Zod schemas, envelopes, and epistemic state validations", cmd: "npm run test:unit" },
  { id: "P08", engine: "PF-07", name: "LIFECYCLE_STATE_ENGINE", category: "STATE_MACHINE", severity: "BLOCKER", desc: "Formal state transitions for songs, runs, and published snapshots", cmd: "npm run test:unit" },
  { id: "P09", engine: "PF-08", name: "WORKFLOW_QUEUE_JOB_ENGINE", category: "WORKFLOW_ORCHESTRATION", severity: "BLOCKER", desc: "Durable asynchronous background job queues and worker runtime", cmd: "npm run test:integration" },
  { id: "P09A", engine: "PF-08", name: "OUTBOX_PATTERN_AND_DISPATCHER", category: "WORKFLOW_ORCHESTRATION", severity: "BLOCKER", desc: "Transactional outbox pattern and reliable dispatch", cmd: "npm run test:unit" },
  { id: "P10", engine: "PF-09", name: "METHODOLOGY_AND_PROMPT_VERSIONING", category: "VERSION_GOVERNANCE", severity: "BLOCKER", desc: "Version governance over prompt templates, extractors, and policies", cmd: "npm run test:unit" },
  { id: "P11", engine: "RI-01", name: "SOURCE_ADAPTER_FRAMEWORK", category: "SOURCE_INTEGRATION", severity: "BLOCKER", desc: "Source connector contracts and adapter isolation", cmd: "npm run test:unit" },
  { id: "P12", engine: "RI-02", name: "CONTINUOUS_RESEARCH_SCHEDULER", category: "CONTINUOUS_RESEARCH", severity: "BLOCKER", desc: "Cadence-controlled ingestion scheduler", cmd: "npm run test:unit" },
  { id: "P13", engine: "RI-03", name: "RAW_PRESERVATION_AND_INGESTION", category: "RAW_PRESERVATION", severity: "BLOCKER", desc: "Immutable raw payload preservation with SHA-256 hashes", cmd: "npm run test:integration" },
  { id: "P14", engine: "RI-04", name: "IDENTITY_RESOLUTION_DEDUPLICATION", category: "IDENTITY_RESOLUTION", severity: "BLOCKER", desc: "Deterministic song and artist deduplication and alias resolution", cmd: "npm run test:unit" },
  { id: "P15", engine: "RI-05", name: "CHART_OBSERVATION_HIT_QUALIFICATION", category: "HIT_QUALIFICATION", severity: "BLOCKER", desc: "Chart qualification and hit cohort membership policy", cmd: "npm run test:unit" },
  { id: "P16", engine: "RI-06", name: "GENRE_HYBRID_GRAPH_TAXONOMY", category: "GENRE_GRAPH", severity: "BLOCKER", desc: "Directed graph genre, subgenre, and researched hybrid taxonomy", cmd: "npm run test:unit" },
  { id: "P17", engine: "RI-07", name: "SOURCE_RECONCILIATION_MAPPING", category: "DATA_RECONCILIATION", severity: "BLOCKER", desc: "Precedence-based field resolution and conflict preservation", cmd: "npm run test:unit" },
  { id: "P18", engine: "RI-08", name: "COVERAGE_FRESHNESS_QUALITY", category: "DATA_QUALITY", severity: "BLOCKER", desc: "Cohort and feature family observation completeness metrics", cmd: "npm run test:unit" },
  { id: "P19", engine: "RI-09", name: "RIGHTS_LICENSING_SOURCE_POLICY", category: "RIGHTS_POLICY", severity: "BLOCKER", desc: "Licensing limits, snippet boundaries, and copyright guards", cmd: "npm run test:unit" },
  { id: "P20", engine: "MI-01", name: "FEATURE_OBSERVATION_NORMALIZATION", category: "FEATURE_EXTRACTION", severity: "BLOCKER", desc: "Raw signal normalization without premature DNA claims", cmd: "npm run test:unit" },
  { id: "P21", engine: "MI-02", name: "AUDIO_FEATURE_INTELLIGENCE", category: "AUDIO_INTELLIGENCE", severity: "BLOCKER", desc: "Acoustic and waveform feature measurement engine", cmd: "npm run test:unit" },
  { id: "P22", engine: "MI-03", name: "SONG_STRUCTURE_SECTION_INTELLIGENCE", category: "STRUCTURE_INTELLIGENCE", severity: "BLOCKER", desc: "Section boundary and arrangement architecture detection", cmd: "npm run test:unit" },
  { id: "P23", engine: "MI-04", name: "HOOK_PLACEMENT_AND_RECURRENCE", category: "HOOK_INTELLIGENCE", severity: "BLOCKER", desc: "Hook timing, placement, title match, and recurrence tracking", cmd: "npm run test:unit" },
  { id: "P24", engine: "MI-05", name: "RHYTHM_CADENCE_GROOVE_INTELLIGENCE", category: "RHYTHM_INTELLIGENCE", severity: "BLOCKER", desc: "Pocket, swing, syncopation, and vocal density measurement", cmd: "npm run test:unit" },
  { id: "P25", engine: "MI-06", name: "PRODUCTION_DYNAMICS_ARRANGEMENT", category: "PRODUCTION_INTELLIGENCE", severity: "BLOCKER", desc: "Dynamic range, drop placement, 808 behavior, and instrument movement", cmd: "npm run test:unit" },
  { id: "P26", engine: "MI-07", name: "LYRICAL_THEME_LANGUAGE_FEATURES", category: "LYRIC_INTELLIGENCE", severity: "BLOCKER", desc: "Lyrical themes, emotion, and sentiment feature measurement", cmd: "npm run test:unit" },
  { id: "P27", engine: "MI-08", name: "MODERN_LANGUAGE_SLANG_INTELLIGENCE", category: "SLANG_INTELLIGENCE", severity: "BLOCKER", desc: "Vernacular language, slang lexicon, recency, and regional trajectory", cmd: "npm run test:unit" },
  { id: "P28", engine: "MI-09", name: "HARMONIC_CHORD_INTELLIGENCE", category: "CHORD_INTELLIGENCE", severity: "BLOCKER", desc: "Key, Roman numeral chord progressions, and harmonic rhythm", cmd: "npm run test:unit" },
  { id: "P29", engine: "MI-10", name: "MUSICAL_PATTERN_ABSTRACTION", category: "PATTERN_ABSTRACTION", severity: "BLOCKER", desc: "Safe transposable pattern references and no-copy guard", cmd: "npm run test:unit" },
  { id: "P30", engine: "HD-01", name: "FROZEN_COHORT_DENOMINATOR_ENGINE", category: "STATISTICAL_TRUTH", severity: "BLOCKER", desc: "Immutable qualifying cohort denominators before percentage calculations", cmd: "npm run test:unit" },
  { id: "P31", engine: "HD-02", name: "EVIDENCE_ASSERTION_CLAIM_SYSTEM", category: "EVIDENCE_LINEAGE", severity: "BLOCKER", desc: "Auditable claims with evidence links and contradiction handling", cmd: "npm run test:unit" },
  { id: "P32", engine: "HD-03", name: "DETERMINISTIC_STATISTICAL_ANALYTICS", category: "STATISTICAL_TRUTH", severity: "BLOCKER", desc: "Deterministic calculation of frequencies, medians, and archetype shares", cmd: "npm run test:unit" },
  { id: "P33", engine: "HD-04", name: "MULTI_ARCHETYPE_CLUSTERING", category: "CLUSTERING", severity: "BLOCKER", desc: "Reproducible mathematical clustering of distinct song archetypes", cmd: "npm run test:unit" },
  { id: "P34", engine: "HD-05", name: "TEMPORAL_TREND_INTELLIGENCE", category: "TREND_INTELLIGENCE", severity: "BLOCKER", desc: "Rolling 90-day/12-month cohort evolution and trajectory analysis", cmd: "npm run test:unit" },
  { id: "P35", engine: "HD-06", name: "DNA_SNAPSHOT_REGISTRY", category: "SNAPSHOT_REGISTRY", severity: "BLOCKER", desc: "Immutable frozen published snapshots with methodology lineage", cmd: "npm run test:unit" },
  { id: "P36", engine: "HD-07", name: "TOP_HIT_DNA_RECOMMENDATIONS", category: "RECOMMENDATION", severity: "BLOCKER", desc: "Evidence-backed top 5 factual choices for creators", cmd: "npm run test:unit" },
  { id: "P37", engine: "HD-08", name: "HYBRID_GENRE_DNA_INTELLIGENCE", category: "HYBRID_DNA", severity: "BLOCKER", desc: "Researched hybrid cohort analysis vs. creative blends", cmd: "npm run test:unit" },
  { id: "P38", engine: "HD-09", name: "NOVELTY_SATURATION_INTELLIGENCE", category: "NOVELTY_INTELLIGENCE", severity: "BLOCKER", desc: "Pattern saturation measurement and controlled pattern-breaks", cmd: "npm run test:unit" },
  { id: "P39", engine: "AR-01", name: "REAL_ARTIST_RESEARCH_INTAKE", category: "ARTIST_RESEARCH", severity: "BLOCKER", desc: "Authorized artist identity and empirical discography intake", cmd: "npm run test:unit" },
  { id: "P40", engine: "AR-02", name: "ARTIST_STYLE_PROFILE_CURATION", category: "ARTIST_RESEARCH", severity: "BLOCKER", desc: "Curated performance traits across vocal, delivery, and production", cmd: "npm run test:unit" },
  { id: "P41", engine: "AR-04", name: "ABSTRACT_ARTIST_STYLE_RESOLVER", category: "ARTIST_SAFETY", severity: "BLOCKER", desc: "Transformation of artist profile into abstract, copyright-safe style", cmd: "npm run test:unit" },
  { id: "P42", engine: "AR-05", name: "ARTIST_IDENTITY_LEAKAGE_GUARD", category: "ARTIST_SAFETY", severity: "BLOCKER", desc: "Strict prevention of artist name or alias leakage into generation prompts", cmd: "npm run test:unit" },
  { id: "P43", engine: "CG-01", name: "CREATOR_KEYWORD_THEME_BRIEF", category: "GENERATION_BRIEF", severity: "BLOCKER", desc: "Must-use/avoid keyword brief with provenance tracking", cmd: "npm run test:unit" },
  { id: "P44", engine: "CG-03", name: "SONG_BLUEPRINT_ASSEMBLY", category: "SONG_CONSTRUCTION", severity: "BLOCKER", desc: "Assembly of DNA, patterns, brief, and abstract style into song blueprint", cmd: "npm run test:unit" },
  { id: "P45", engine: "CG-05", name: "MODERN_LYRIC_ENGINEERING", category: "LYRIC_GENERATION", severity: "BLOCKER", desc: "Evidence-constrained lyric generation with performance tags", cmd: "npm run test:unit" },
  { id: "P46", engine: "CG-07", name: "SUNO_SOUND_PROMPT_ENGINE", category: "SOUND_PROMPT", severity: "BLOCKER", desc: "Suno-optimized production prompt generation under 1000 chars", cmd: "npm run test:unit" },
  { id: "P47", engine: "CG-10", name: "GENERATION_TRUTH_GUARD", category: "TRUTH_GUARD", severity: "BLOCKER", desc: "Post-generation verification against blueprint and safety invariants", cmd: "npm run test:unit" },
  { id: "P48", engine: "PA-12", name: "PRODUCTION_RELEASE_AUDIT", category: "RELEASE_GATE", severity: "BLOCKER", desc: "Final full-spectrum integrity, security, and verification audit", cmd: "npm run integrity:all" }
];

let csv = 'check_id,phase,engine_id,rule_name,category,severity,description,verification_command\n';
for (const p of prompts) {
  const checkId = `CHK-${p.id}-01`;
  csv += `${checkId},${p.id},${p.engine},${p.name},${p.category},${p.severity},"${p.desc.replace(/"/g, '""')}","${p.cmd}"\n`;
}

fs.writeFileSync(path.join(process.cwd(), 'docs/implementation/INTEGRITY_CHECK_MATRIX.csv'), csv, 'utf8');
console.log(`Generated INTEGRITY_CHECK_MATRIX.csv with ${prompts.length} prompt checks.`);
