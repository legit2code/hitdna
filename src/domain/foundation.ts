/**
 * Domain: Platform Foundation & Governance
 * Canonical Engine: PF-02 (Repository & Tooling Foundation)
 * Architecture Version: 5.0.0
 */

export interface CanonicalModule {
  moduleId: string;
  name: string;
  parentEngineId: string;
  primaryBuildPhases: string[];
  status: 'PLANNED' | 'IN_PROGRESS' | 'IMPLEMENTED' | 'VERIFIED';
}

export interface CanonicalEngineDefinition {
  engineId: string;
  name: string;
  purpose: string;
  domainId: string;
  primaryBuildPhases: string[];
  modules: CanonicalModule[];
}

export const PF02_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'PF-02',
  name: 'Repository & Tooling Foundation',
  purpose: 'Provide strict TypeScript full-stack project boundaries, build tooling, tests and baseline CI.',
  domainId: 'D01',
  primaryBuildPhases: ['P01'],
  modules: [
    { moduleId: 'PF-02.M01', name: 'React App Shell', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M02', name: 'Node Server Shell', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M03', name: 'Workspace Boundary Manager', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M04', name: 'TypeScript Strict Config', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M05', name: 'Lint/Format Tooling', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M06', name: 'Unit Test Harness', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M07', name: 'Integration Test Harness', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M08', name: 'E2E Harness', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-02.M09', name: 'CI Baseline', parentEngineId: 'PF-02', primaryBuildPhases: ['P01'], status: 'IMPLEMENTED' },
  ],
};

export const PF03_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'PF-03',
  name: 'Typed Configuration & Secrets Engine',
  purpose: 'Centralize public/server/worker configuration, provider credentials, feature flags and redaction.',
  domainId: 'D01',
  primaryBuildPhases: ['P02'],
  modules: [
    { moduleId: 'PF-03.M01', name: 'Public Client Configuration', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M02', name: 'Server Runtime Configuration', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M03', name: 'Worker & Job Configuration', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M04', name: 'Provider Credentials & Secrets Vault', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M05', name: 'Secret Redaction & Log Masking', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M06', name: 'Feature Flags & Runtime Switches', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M07', name: 'Environment Validation & Typing', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-03.M08', name: 'Provider Health & Credential State Resolver', parentEngineId: 'PF-03', primaryBuildPhases: ['P02'], status: 'IMPLEMENTED' },
  ],
};

export const PF04_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'PF-04',
  name: 'Canonical Music Data Model & Repository Engine',
  purpose: 'Own typed persistence contracts and repository boundaries for the entire music intelligence model.',
  domainId: 'D01',
  primaryBuildPhases: ['P03'],
  modules: [
    { moduleId: 'PF-04.M01', name: 'Core Music Entity Data Models', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M02', name: 'Source Observation & Ingestion Schema', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M03', name: 'Song & Artist Identity Schemas', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M04', name: 'Genre Graph & Multi-Assignment Schema', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M05', name: 'Hybrid Genre & Blend Schema', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M06', name: 'Repository Contract & Query Abstractions', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M07', name: 'Object Storage Metadata & Durable References', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-04.M08', name: 'Audit Log & Registry Schemas', parentEngineId: 'PF-04', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
  ],
};

export const PF05_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'PF-05',
  name: 'Authentication, Roles & Authorization Engine',
  purpose: 'Enforce identity, role-aware access and privileged admin/research boundaries before data reaches UI or tools.',
  domainId: 'D01',
  primaryBuildPhases: ['P06'],
  modules: [
    { moduleId: 'PF-05.M01', name: 'Identity & Authentication Provider Adapter', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M02', name: 'Role Definition & Capability Matrix', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M03', name: 'Server-Side Authorization & Endpoint Guards', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M04', name: 'Firestore Security Rules Specification', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M05', name: 'User Ownership & Resource Scoping Guard', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M06', name: 'Privileged Mutation & Override Audit Logger', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M07', name: 'Raw & Restricted Content Access Controller', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-05.M08', name: 'Client Auth State & Token Lifecycle Manager', parentEngineId: 'PF-05', primaryBuildPhases: ['P06'], status: 'IMPLEMENTED' },
  ],
};

export const PF09_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'PF-09',
  name: 'Version, Prompt & Methodology Governance',
  purpose: 'Version every taxonomy, methodology, prompt, model, extractor, clustering rule and publication policy that can change conclusions.',
  domainId: 'D01',
  primaryBuildPhases: ['P00', 'P03'],
  modules: [
    { moduleId: 'PF-09.M01', name: 'Methodology Versioning & Registry', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M02', name: 'Prompt Template Versioning & Catalog', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M03', name: 'Genre Taxonomy Versioning', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M04', name: 'Musical Pattern Extractor Versioning', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M05', name: 'Modern Language Source Governance', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M06', name: 'Clustering Rule & Policy Versioning', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M07', name: 'Publication Policy & Freeze Registry', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M08', name: 'Evaluation & Benchmark Versioning', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M09', name: 'Model Version Registry & Mapping', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'PF-09.M10', name: 'Governance Audit Trail & Lineage', parentEngineId: 'PF-09', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
  ],
};

export const RI06_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'RI-06',
  name: 'Genre, Subgenre, Scene & Hybrid Taxonomy',
  purpose: 'Model all genres and researched hybrids as a versioned graph rather than a single genre string.',
  domainId: 'D02',
  primaryBuildPhases: ['P03'],
  modules: [
    { moduleId: 'RI-06.M01', name: 'Genre Directed Graph Data Structure', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M02', name: 'Node Types & Hierarchical Classification', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M03', name: 'Edge Relationships & Influence Topology', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M04', name: 'Researched Hybrid Taxonomy', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M05', name: 'Creative Blend Distinction & Rules', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M06', name: 'Multi-Genre Song Assignment Model', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M07', name: 'External Genre Mapping & Aliases', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M08', name: 'Graph Traversal & Lineage Navigation', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M09', name: 'Taxonomy Versioning & Migration Engine', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-06.M10', name: 'Dynamic Taxonomy Extensibility', parentEngineId: 'RI-06', primaryBuildPhases: ['P03'], status: 'IMPLEMENTED' },
  ],
};

export const RI09_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'RI-09',
  name: 'Rights, Licensing & Source Policy Engine',
  purpose: 'Enforce what source material may be collected, stored, analyzed, excerpted or exposed.',
  domainId: 'D02',
  primaryBuildPhases: ['P04'],
  modules: [
    { moduleId: 'RI-09.M01', name: 'Source Policy Catalog & Governance', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M02', name: 'Storage Tier & Boundary Controller', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M03', name: 'Fair Use & Snippet Length Limiter', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M04', name: 'Unauthorized Scraping Prohibition Guard', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M05', name: 'Clean Room Melody & Copyright Guard', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M06', name: 'Provider Attribution & Citation Manager', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M07', name: 'Licensing Compliance & Audit Trail', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
    { moduleId: 'RI-09.M08', name: 'Data Exfiltration & Payload Restriction', parentEngineId: 'RI-09', primaryBuildPhases: ['P04'], status: 'IMPLEMENTED' },
  ],
};

export const CG11_ENGINE_DEFINITION: CanonicalEngineDefinition = {
  engineId: 'CG-11',
  name: 'Generation History, Feedback & Reproducibility',
  purpose: 'Store user-owned generation lineage and feedback without contaminating research truth.',
  domainId: 'D06',
  primaryBuildPhases: ['P05'],
  modules: [
    { moduleId: 'CG-11.M01', name: 'Generation Request & Specification Store', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M02', name: 'Creative Output Isolation & Storage Engine', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M03', name: 'Generation Lineage & Manifest Assembler', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M04', name: 'Snapshot & Prompt Version Lock Manager', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M05', name: 'Pattern Break Decision Tracker', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M06', name: 'Zero Artist Leakage Verification Store', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M07', name: 'User Feedback & Sentiment Store (Non-Promotable)', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M08', name: 'Large Artifact Storage Reference Resolver', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M09', name: 'Lifecycle Outbox & Event Publisher', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
    { moduleId: 'CG-11.M10', name: 'Immutable Generation Audit & Retention Manager', parentEngineId: 'CG-11', primaryBuildPhases: ['P05'], status: 'IMPLEMENTED' },
  ],
};

export interface WorkspaceBoundaries {
  client: string;
  server: string;
  domain: string;
  repositories: string;
  services: string;
  workers: string;
  contracts: string;
  config: string;
  testing: string;
  docs: string;
}

export const WORKSPACE_BOUNDARIES: WorkspaceBoundaries = {
  client: 'src/client',
  server: 'src/server',
  domain: 'src/domain',
  repositories: 'src/repositories',
  services: 'src/services',
  workers: 'src/workers',
  contracts: 'src/contracts',
  config: 'src/config',
  testing: 'src/testing',
  docs: 'docs',
};
