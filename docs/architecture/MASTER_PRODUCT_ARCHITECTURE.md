# Master Product Architecture — Hit DNA Music Intelligence

**Architecture Version:** 5.0.0  
**Pack Version:** 6.0.0  
**Status:** LOCKED_TARGET_BASELINE  
**Canonical Manifest Hash:** `1ccc957a962db4c93b5b2a872fb7cddbd4025d938ecdc5de86ca88c17bf5454b`  
**Expected Companion Hash:** `091dbc8629246eadd10581acbd41285c9b72ee1712bb1cddd0de783ec125d80b`

---

## 1. System Vision & The Master Build Constitution

Hit DNA Music Intelligence is an evidence-backed intelligence engine and constrained song construction platform. It bridges empirical music research, high-resolution audio and lyrical feature extraction, statistical trend tracking, and generative songwriting under strict truth governance.

### Core Constitution Invariants
1. **Measured Intelligence, Not Generated Intelligence:** Hit DNA is derived from empirical chart records, musical evidence, and deterministic calculations. Generative AI (Gemini) reasons over supplied evidence; it never invents empirical truth.
2. **Deterministic Percentages:** No published percentage or frequency may exist without numerator, denominator, qualifying cohort, versioned calculation, coverage, and source lineage.
3. **Graph-Based Genre & Hybrid Identity:** Genres, subgenres, scenes, and researched hybrids are nodes and edges in a versioned graph, never flattened single-string primitives.
4. **Modern Language & Vernacular Integrity:** Slang, colloquialisms, and regional idioms are continuously ingested from reviewed sources with recency, trajectory, and scene context.
5. **No-Copy Safe Pattern Abstraction:** Musical patterns (chords, groove grids, arrangement templates) are expressed as transposable harmonic functions and rhythmic subdivisions; copyright-infringing melodies, lyrics, or stems are strictly forbidden.
6. **Zero Production Fixture Contamination:** Test fixtures are confined to isolated testing suites under explicit tags (`TEST_FIXTURE`) and never committed to production datastores or runtime views.

---

## 2. Seven Canonical Architecture Domains

The system is partitioned into exactly 7 coexistent domains:

| Domain ID | Domain Code | Name | Engines | Module Count |
| :--- | :--- | :--- | :--- | :--- |
| **D01** | `PF` | Platform Foundation & Governance | `PF-01` to `PF-09` | 81 |
| **D02** | `RI` | Research, Sources & Continuous Ingestion | `RI-01` to `RI-09` | 84 |
| **D03** | `MI` | Music Understanding & Pattern Intelligence | `MI-01` to `MI-10` | 101 |
| **D04** | `HD` | Hit DNA Analytics, Archetypes & Trends | `HD-01` to `HD-09` | 87 |
| **D05** | `AR` | Artist Research & Style Intelligence | `AR-01` to `AR-06` | 50 |
| **D06** | `CG` | Creative Generation & Song Construction | `CG-01` to `CG-11` | 123 |
| **D07** | `PA` | Product Experience, Operations & Assurance | `PA-01` to `PA-12` | 144 |
| **TOTAL** | | **7 Domains** | **66 Engines** | **670 Modules** |

---

## 3. Data Lineage Pipeline

```
Raw Source Records (RI-03)
       ↓
Identity Resolution & Qualification (RI-04, RI-05)
       ↓
Feature Observation & Normalization (MI-01 — MI-09)
       ↓
Cohort Definition & Denominator Freeze (HD-01)
       ↓
Deterministic Statistical Analytics (HD-03)
       ↓
Multi-Archetype Clustering (HD-04)
       ↓
Temporal Trend Tracking (HD-05)
       ↓
DNA Snapshot Publication (HD-06)
       ↓
Top Hit DNA Recommendations (HD-07)
       ↓
Creator Song Blueprint Assembly (CG-03)
       ↓
Constrained Generation: Lyrics & Sound Prompt (CG-05, CG-07)
       ↓
Post-Generation Verification Guard (CG-10)
```
