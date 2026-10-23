# Audit Log Durability & Integrity Policy

**Document Reference:** Architecture V2.0.1 / F-12 Audit Remediation  
**Status:** Approved & Enforced  
**Classification:** Confidential — Engineering & Security Architecture  

---

## 1. Objective & Threat Model

The platform audit trail is designed to be tamper-evident across processes and restarts, append-only in the database, verified on an automated schedule, and anchored outside the database via cryptographic checkpoints.

### Key Threat Guarantees:
1. **Tamper-Evidence:** Any unauthorized modification (`UPDATE`), excision (`DELETE`), or reordering of audit records breaks the cryptographic SHA-256 hash chain and is immediately flagged by the verifier.
2. **Append-Only Enforcement:** Database-level privileges (`REVOKE UPDATE, DELETE, TRUNCATE`) combined with a fail-closed trigger (`trg_prevent_audit_log_mutation`) prevent mutations, even from superusers.
3. **No Process-Static State:** The chain head is persisted in `security.audit_chain_head(stream_id, seq, hash)`. Concurrent writers serialize using transactional row locks (`FOR UPDATE`), ensuring strictly increasing sequence numbers without forks.
4. **Deterministic Canonicalization:** Payloads are serialized using RFC 8785 JSON Canonicalization Scheme (JCS) before hashing.
5. **Fail-Closed Durability:** Security-critical actions are blocked (`AuditPersistenceError`) if audit persistence fails.

---

## 2. Audited Event Catalog

The platform strictly logs the following mandatory security and governance event classes:

| Event Class | Action Identifiers | Criticality | Required Context Fields |
|:---|:---|:---|:---|
| **Authentication** | `AUTHENTICATION_LOGIN`, `AUTHENTICATION_LOGOUT`, `AUTHENTICATION_FAILED`, `AUTHENTICATION_MFA` | `SECURITY` | `principal_id`, `client_ip`, `user_agent`, `auth_method` |
| **Authorization Denials** | `AUTHORIZATION_DENIED`, `SCOPE_BOUNDARY_VIOLATION`, `UNAUTHORIZED_ACCESS` | `SECURITY` | `principal_id`, `attempted_action`, `target_entity_type`, `target_entity_id`, `denial_reason` |
| **System Transactions** | `SYSTEM_TX_EXECUTED`, `SYSTEM_TX` | `SECURITY_CRITICAL` | `actor` (mandatory), `reason` (mandatory), `target_entity_type='DATABASE'` |
| **Admin & Role Changes** | `ROLE_ASSIGNED`, `ROLE_REVOKED`, `ROLE_CHANGED`, `PRINCIPAL_CREATED`, `PRINCIPAL_DELETED`, `TENANT_ADMIN_ACTION` | `SECURITY_CRITICAL` | `actor`, `target_principal_id`, `role_name`, `tenant_id` |
| **Exports & Disclosures** | `DATA_EXPORTED`, `PACKAGE_EXPORTED`, `SBOM_EXPORTED`, `AUDIT_EXPORTED` | `SECURITY_CRITICAL` | `exporter_id`, `target_artifact_id`, `destination_type`, `sha256_digest` |
| **Key & Secret Management** | `KEY_ROTATED`, `KEY_REVOKED`, `ATTESTATION_SIGNED`, `MANIFEST_SIGNED` | `SECURITY_CRITICAL` | `key_id`, `key_alias`, `key_version`, `revocation_reason` |
| **Policy & Scoring Overrides** | `POLICY_OVERRIDDEN`, `SCORING_OVERRIDDEN`, `RELEASE_GATE_OVERRIDE` | `SECURITY_CRITICAL` | `approver_id`, `override_reason`, `target_run_id`, `risk_score_delta` |

---

## 3. Data Minimization & Privacy Protection

To prevent sensitive data leakage while preserving non-repudiation:
- **No Secrets or Credentials:** Passwords, API keys, JWTs, bearer tokens, cookies, database credentials, and KMS private keys are NEVER logged. All `details` payloads pass through `SecretRedactor.redactObject` before canonical hashing.
- **No Full Request/Response Bodies:** Raw HTTP request bodies, source code blobs, or untrusted user input files are omitted. Only references (hashes, entity IDs, version labels) are recorded.
- **Minimization of PII:** User identifiers are limited to opaque principal UUIDs and organization emails. IP addresses are truncated or anonymized where applicable by policy.

---

## 4. Hash Chaining & RFC 8785 Serialization

Each audit stream maintains a hash chain:
$$H_0 = \text{GENESIS\_}0^{64}$$
$$H_i = \text{SHA-256}(\text{JCS}(\text{Payload}_i))$$

Where $\text{JCS}$ is the RFC 8785 JSON Canonicalization Scheme applied to the canonical object containing:
- `action`
- `algorithm` (`sha256-rfc8785-v1`)
- `audit_id`
- `classification`
- `correlation_id`
- `criticality`
- `details` (redacted, keys sorted)
- `outcome`
- `previous_hash` ($H_{i-1}$)
- `principal_id`
- `sequence_number` ($i$)
- `stream_id` (`tenant:<uuid>` or `global`)
- `target_entity_id`
- `target_entity_type`
- `tenant_id`
- `timestamp` (ISO 8601 UTC)

---

## 5. External Anchoring & Checkpoints

1. **Scheduled Verifier:** A scheduled worker walks all audit streams from `security.audit_chain_head`, verifies sequence continuity and hash chaining from genesis to head, and alerts on any breach.
2. **Ed25519 Signed Checkpoints:** Upon verification, an immutable checkpoint object is generated:
   - Signed using Ed25519 via `KmsSignerBoundary`.
   - Written to write-once object storage (`WORM` bucket / Cloud Storage Object Lock).

---

## 6. Retention Policy

- **Operational Database Storage (`security.platform_audit_log`):**
  - Minimum retention: **365 days** (1 year) in primary PostgreSQL storage.
  - Deletion or truncation is strictly prohibited by database triggers and privilege revocation.
- **Archival / External Checkpoint Storage (Object Storage):**
  - Minimum retention: **7 years** for signed checkpoint envelopes and exported compliance archives.
  - Configured with Write-Once-Read-Many (WORM) retention lock.
