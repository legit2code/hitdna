# HIT DNA MUSIC INTELLIGENCE — PROJECT REQUIREMENTS SOURCE OF TRUTH

## Product purpose
Build an evidence-driven music intelligence and creation platform that continuously ingests authorized/current music evidence, measures real hit-pattern statistics, discovers multiple Hit DNA archetypes across any genre or researched hybrid genre, tracks modern language, and lets creators build original songs from measured musical patterns.

## Genre scope — ALL GENRES
The product must support **all genres, subgenres, regional styles, scenes and hybrid/crossover genres** through an extensible versioned taxonomy/graph. Do not require a code release to add a genre label.

The initial controlled vocabulary may include broad families such as Pop, Rock, Hip-Hop/Rap, R&B/Soul, Country, Electronic/Dance, Latin, Jazz, Blues, Folk/Americana, Classical, Gospel/Christian, Reggae/Dancehall, Metal, Punk, Alternative/Indie, Afrobeats/African Pop, K-Pop/J-Pop and other regional/scene families, but this is **not an exhaustive closed list**.

Hybrid examples that must be representable as first-class labels/relationships include:
- Hip-Hop/R&B
- Country/Pop
- Rap/Rock
- Country-Rap / Hick-Hop
- Latin Trap
- Pop-Punk
- R&B/Pop
- Rock/Pop
- Country/Rock
- Electronic/Pop
- future multi-genre combinations

A **researched hybrid genre/cohort** is different from a user-created **CREATIVE_BLEND**. Only researched cohorts may display empirical percentages. A creative blend may combine published DNA snapshots/traits but must not claim historical hybrid prevalence unless a real hybrid cohort supports it.

## Mandatory core genre/hybrid schema
The architecture/database must include typed concepts equivalent to:

`GenreNode`
- id
- canonicalName
- slug
- nodeType: ROOT_FAMILY | GENRE | SUBGENRE | REGIONAL_STYLE | SCENE | HYBRID_LABEL | ERA_STYLE
- aliases/sourceLabels
- active/reviewStatus
- regionTags/cultureContext where evidence supports it
- effectiveFrom/effectiveTo where relevant
- taxonomyVersion

`GenreEdge`
- fromGenreId
- toGenreId
- relation: IS_A | DERIVED_FROM | FUSED_WITH | INFLUENCED_BY | REGIONAL_VARIANT | ERA_VARIANT | RELATED_TO
- source/evidence references where the relationship is research-derived
- status/version

`GenreBlendDefinition`
- id/displayName
- component genre IDs
- optional component weights ONLY when measured or explicitly user-selected as creative settings
- blendType: RESEARCHED_HYBRID | CREATIVE_BLEND
- evidence/status/version

`SongGenreAssignment`
- songId
- genreNodeId or researched hybrid ID
- source/method/evidence
- confidence/review status
- taxonomy version

No app logic may assume `song.genre` is a single string.

## Creator north-star workflow
1. User chooses/searches any available genre, subgenre, regional style or researched hybrid.
2. Optional Hybrid Builder allows two or more genres. If a researched hybrid exists, use it; otherwise clearly label the combination `CREATIVE_BLEND`.
3. User chooses Current, Rolling 90 Days, Rolling 12 Months, a named year, historical period or other supported cohort.
4. System presents up to five statistically publishable Hit DNA archetypes with factual share/trend/freshness. User can choose Most Common, Fastest Rising or Choose Myself.
5. User can inspect **Harmony/Chords**, **Groove/Rhythm**, **Arrangement**, **Hook**, **Structure**, **Production**, **Lyrics/Language** and other evidence tabs for that archetype when coverage is sufficient.
6. User may choose one or two researched real-world artist influences; real names are display/internal only and external prompts receive approved abstract traits.
7. User can enter their own keywords/phrases and receive optional **evidence-backed keyword/slang/theme suggestions**.
8. User controls explicit/clean mode, language/vernacular freshness, regional language context, DNA Fidelity, Pattern Break, Current Trend Weight and Hook Priority.
9. System builds a saved evidence-backed Song Specification, Hook Strategy, Keyword/Language Plan, then original performance-marked lyrics and a <1000-character Suno sound prompt.
10. Result tabs include Lyrics, Sound Prompt, DNA Evidence, Song Blueprint, Validation and Music Pattern References.

## Creator keyword requirements
Users must be able to provide:
- required keywords or exact phrases (`MUST_USE`)
- optional keywords (`PREFER`)
- inspiration-only concepts (`INSPIRE_ONLY`)
- words/phrases to avoid (`AVOID`)
- title phrase/title seed
- story elements, locations, characters, objects and imagery
- emotion/tone
- point of view
- hook words/rhyme anchors
- language/region/scene preference

The application may suggest keyword banks from measured themes, modern-language intelligence, the selected Hit DNA archetype and approved artist traits. Every suggestion must be labeled as `SOURCE_BACKED`, `AI_CREATIVE`, or `USER_SUPPLIED`; never present AI creative wording as a measured trend.

## Modern Language / Slang Intelligence — ongoing
The platform must maintain a versioned modern-language corpus for lyric generation and analysis.

Potential source classes include:
- Urban Dictionary or similar community slang dictionaries **only through permitted/configured access or reviewed imports**;
- Wiktionary/dictionary/lexicon sources when permitted;
- authorized public/community discussion sources;
- licensed/authorized lyric text or annotations;
- reviewed editorial music/culture sources;
- administrator-curated evidence.

Do not assume any named source exposes an official API. No unauthorized scraping.

Each `VernacularTerm`/`ModernLanguageSignal` should support:
- canonical term/phrase and variants
- definition/meaning by context
- genre/scene/region/community context
- firstObservedAt/lastObservedAt in this corpus
- frequency and recency/trajectory only when actually measured
- current/stale/emerging status
- explicitness/offensiveness/context-sensitivity flags
- source references and authority/source-type
- review status
- usage notes and generation eligibility
- methodology/version

Community-dictionary definitions are **observations**, not automatic VERIFIED truth. The engine should triangulate sources or require review according to policy before high-confidence generation guidance.

Creator controls should include `Language Freshness`: CURRENT | LAST_90_DAYS | LAST_12_MONTHS | ERA_AUTHENTIC | NEUTRAL, plus optional region/scene filters. The lyric engine must avoid anachronistic slang when Era Authentic is selected.

## Chord / harmony / rhythm / arrangement DNA — core requirement
Where authorized audio/music evidence and validated extractors support it, the application must capture:

`ChordEvent`
- song/section/time span
- root, quality, inversion/bass where measurable
- duration/beats
- key-relative Roman numeral representation
- source/extractor/version/confidence

`ChordProgressionPattern`
- normalized/transposable scale-degree sequence
- chord qualities
- harmonic rhythm/durations
- section role
- occurrence count/share in defined cohort
- evidence/coverage/version

`GroovePattern`
- meter/time signature
- tempo/perceived tempo
- subdivision grid
- kick/snare/clap/hat or percussion onset descriptors where measurable
- swing/syncopation/pocket descriptors only when a validated method exists
- section role and evidence/version

`ArrangementPattern`
- ordered sections
- bar/time lengths where supported
- energy/density contour
- instrument-family entrances/exits
- drops/breakdowns/beat switches/transitions
- chord/harmonic changes by section where measured
- evidence/version

`PatternReferenceExample`
- an **abstract, transposable, non-melodic reference template** generated from aggregate measured patterns
- examples: `i–VI–III–VII, two beats each in 4/4`; a generalized kick/snare/hat grid; a section/bar/energy arrangement template
- references underlying aggregate metrics/archetypes
- never copies lyrics, melody, stems or a uniquely identifying passage from a specific hit

The generation engine may receive these safe pattern references to understand the measured chord/groove/arrangement language of the selected archetype.

## Factual percentage rule
Any percentage/share must be calculated by deterministic code from persisted qualifying records and preserve numerator, denominator, raw value, rounding, cohort, coverage, exclusions, snapshot, methodology, time and source lineage. Archetype share is prevalence in the defined observed cohort — never a probability that a new song will become a hit.

## Continuous research requirement
Research ingestion is ongoing. New chart/current-hit, modern-language and music-feature observations refresh according to configured/provider-permitted schedules. Rolling/current views can change as accepted evidence arrives; published historical snapshots remain immutable.

## Hit DNA model
Never reduce a genre/cohort to one average. Use multi-modal archetype clustering when evidence supports it. Never force five creator choices: display up to five publishable archetypes. Hybrid cohorts use the same statistical truth gates as single-genre cohorts.

## Artist intelligence
Real-artist profiles must be researched/curated from evidence, not fabricated from Gemini memory. Internal/display identity remains separate from exportable abstract traits. Missing profile => `NO_ARTIST_PROFILE_AVAILABLE`.

## Lyric performance format
Structural tags on their own line, followed by a delivery directive line. Ad-libs use parentheses. Punctuation may intentionally influence performance: `...` trailing/spacey; commas phrasing breaths; repeated commas stutter/stumble; `-` sharp syllable break; `--` hard cut/beat pause; CAPS emphasis.

## Non-negotiable truth policy
No fake/seed/simulated production data. No fabricated provider results, evidence, percentages, slang trends, genre relationships, chord patterns, artist research, tests or citations. Test fixtures remain isolated. Missing data is a valid production state.

---

## Canonical Schemas & Data Contracts

### 1. Phase Evidence Receipt Contract
```json
{
  "promptId": "<PROMPT_ID>",
  "packVersion": "6.0.0",
  "architectureVersion": "5.0.0",
  "architectureIdentitySha256": "091dbc8629246eadd10581acbd41285c9b72ee1712bb1cddd0de783ec125d80b",
  "status": "BLOCKED",
  "gitCommit": null,
  "dirty": null,
  "changedFiles": [],
  "commands": [],
  "checks": {},
  "providers": [],
  "knownGaps": [],
  "generatedAt": "<ISO8601>"
}
```

### 2. Checkpoint Verification Matrix Row
`PromptId,ReceiptPath,ReceiptSha256,ArchitectureVersion,ManifestSha256,Status,VerifiedAt,GitCommit,Notes`

### 3. Requirement Coverage Tracking Row
`RequirementID,ImplementationStatus,CodeRefs,DataObjects,APIEventJobRefs,TestRefs,EvaluationRefs,LatestResult,ReleaseBlocking,Notes`

### 4. Published Metric Lineage Contract
```json
{
  "metricId": "",
  "displayClaim": "",
  "numerator": null,
  "denominator": null,
  "rawShare": null,
  "displayValue": null,
  "cohortId": "",
  "featureCoveredCount": null,
  "coverageRate": null,
  "analysisRunId": "",
  "methodologyVersion": "",
  "datasetSnapshotId": "",
  "calculatedAt": null,
  "sourceEvidenceIds": [],
  "publishability": "NOT_PUBLISHABLE"
}
```

### 5. Musical Pattern Abstraction Contract
```json
{
  "patternType": "CHORD_PROGRESSION|GROOVE|ARRANGEMENT",
  "canonicalSignature": "",
  "safeReferenceText": "",
  "occurrenceMetricId": null,
  "archetypeId": null,
  "cohortId": null,
  "abstractionVersion": "",
  "sourceOccurrenceIds": [],
  "publishability": "NOT_PUBLISHABLE"
}
```

### 6. Modern Language Signal / Vernacular Term Contract
```json
{
  "term": "",
  "variants": [],
  "meanings": [],
  "sourceRefs": [],
  "sourceType": "",
  "genreContextIds": [],
  "regionTags": [],
  "firstObservedAt": null,
  "lastObservedAt": null,
  "frequency": null,
  "trajectory": "INSUFFICIENT_EVIDENCE",
  "reviewStatus": "UNVERIFIED",
  "generationEligible": false
}
```

### 7. Core Genre & Researched Hybrid Definition Contract
```json
{
  "genreTaxonomyVersion": "TEMPLATE",
  "genreNodes": [
    {
      "id": "genre_example",
      "canonicalName": "Example",
      "nodeType": "GENRE",
      "aliases": [],
      "reviewStatus": "REFERENCE_ONLY"
    }
  ],
  "genreEdges": [],
  "genreBlendDefinitions": [],
  "note": "Reference schema only. Do not treat example data as production research."
}
```

### 8. Engine Coverage Matrix Row
`Domain,Engine,ImplementationStatus,PrimaryPackage,PrimaryCodeRefs,Contracts,PersistenceDataObjects,JobsEvents,Tests,Telemetry,SecurityReviewed,KnownGaps,Notes`

### 9. Build State Contract
```json
{
  "architectureVersion": "4.0",
  "currentPrompt": "P-01",
  "completedPrompts": [],
  "lastGreenCommit": null,
  "databaseMigrationHead": null,
  "implementedDomains": [],
  "implementedEngines": [],
  "knownBlockers": [],
  "testStatus": {
    "typecheck": "not-run",
    "unit": "not-run",
    "integration": "not-run",
    "e2e": "not-run",
    "golden": "not-run"
  },
  "dataIntegrity": {
    "fabricatedProductionDataDetected": false,
    "lastAudit": null
  },
  "updatedAt": null
}
```
