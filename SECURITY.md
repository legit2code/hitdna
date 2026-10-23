# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

## Reporting a Vulnerability

The CAIM engineering and security team takes security vulnerabilities seriously.

To report a vulnerability or security concern, please send an encrypted or direct report to:
- **Security Contact**: `security@caim.internal`
- **GitHub Advisory**: GitHub Private Vulnerability Reporting (`https://github.com/caim-security/caim-platform/security/advisories/new`)
- **Subject**: `[SECURITY VULNERABILITY REPORT] CAIM Platform`

Please include:
1. Detailed description of the vulnerability and attack vector.
2. Step-by-step reproduction steps or proof-of-concept.
3. Affected components, endpoints, or worker pipelines.
4. Any potential mitigations or workarounds identified.

We will acknowledge receipt within 24 hours and provide coordinated disclosure updates.
Please do NOT file public GitHub issues for undisclosed security vulnerabilities.

## Supply Chain & Dependency Build Policy

- **Package Manager**: Strictly `pnpm 9.15.9`.
- **`pnpm.onlyBuiltDependencies`**: Pinned explicitly to packages requiring platform-specific binary compilation (`argon2`, `esbuild`). Packages such as `@google/genai` and `protobufjs` are strictly excluded from postinstall compilation permissions to prevent supply-chain compromise.
- **Source Artifact Safety**: No compiled native binaries (ELF/Mach-O/PE32) or zip archives may be committed to the repository. Binaries must be built deterministically and verified with SHA-256 digests.
  - **Explicit Narrow Exception (Evaluation Fixture)**: `artifacts/corpus-held-out.tar.gz` (SHA-256: `9807a12237b9c4157f942bd9f1e2ee788ed668942e837feba0cdefd2785701ed`) is an explicit, narrow exception to repository archive restrictions. It is a sealed test corpus fixture containing held-out evaluation samples (plain-text source and labels) required for offline regression gate execution in CI environments. It contains zero binary executables and must strictly match its registered cryptographic checksum.
