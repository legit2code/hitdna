# Security, Secrets & Access Control Architecture

**Engines:** `PF-03` / `PF-05` / `PA-07`  
**Architecture Version:** 5.0.0  

---

## 1. Secrets Isolation Invariant

- **Zero Secret Exposure to Client:** No private API key (`GEMINI_API_KEY`, database credentials, provider auth tokens) may ever be bundled in client assets or emitted in HTTP diagnostic responses.
- **Server-Side API Proxying:** All AI inference and external research provider communication occurs strictly within the Node server environment.
- **Redaction Policy:** All logs, telemetry traces, and diagnostic payloads redact credentials using `redactSecret()`.

## 2. Role-Based Access Control (RBAC) (`PF-05`)

| Role | Permissions |
| :--- | :--- |
| **Creator** | View published DNA snapshots, assemble song briefs, generate lyrics and sound prompts, save personal history. |
| **Researcher** | Access research acquisition queues, review taxonomy edges, inspect raw observation lineage, run clustering diagnostics. |
| **Admin** | Manage version governance, activate prompt/model methodologies, audit security logs, approve release candidates. |

## 3. Epistemic Error Handling
When a provider or credential is absent, the system never crashes or hallucinates fallback research. It emits typed states:
- `NOT_CONFIGURED`
- `DATA_UNAVAILABLE`
- `INSUFFICIENT_EVIDENCE`
- `SOURCE_ERROR`
