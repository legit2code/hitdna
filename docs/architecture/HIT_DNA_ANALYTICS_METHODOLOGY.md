# Hit DNA Analytics Methodology & Statistical Truth

**Domain:** `D04 — Hit DNA Analytics, Archetypes & Trends`  
**Architecture Version:** 5.0.0  

---

## 1. The Denominator Before Percentage Mandate

No percentage, frequency, or distribution metric may be published without an immutable frozen cohort denominator (`HD-01`).

$$\text{Published Metric} = \frac{\text{Numerator (Observed Count)}}{\text{Denominator (Frozen Cohort Size)}} \pm \text{Coverage Error}$$

### Invariant Rules
- Every metric requires:
  - Explicit numerator and denominator count.
  - Coverage percentage of features observed within the cohort.
  - Versioned calculation algorithm ID (`HD-03`).
  - Immutable link back to the specific `AnalysisRun` and `DnaSnapshot`.
- If an empirical cohort has fewer than the minimum support threshold ($N < 15$), frequencies must not be published as percentages; the system must return `INSUFFICIENT_EVIDENCE`.

---

## 2. Multi-Archetype Clustering (`HD-04`)

Hit music within a genre does not conform to a single average song profile. Multi-Archetype Clustering discovers distinct, reproducible clusters (archetypes) using deterministic K-means or Gaussian Mixture models on standardized acoustic and structural feature matrices:
- Example: High-tempo energetic dance-pop vs. mid-tempo acoustic ballad in the same pop cohort.
- Archetypes receive human-readable descriptive labels only after numerical clustering is finalized.
- Each archetype maintains its own measured share and feature distributions.
