# Software Bill of Materials (SBOM) — cryptoflex v0.2.0

## Direct Dependencies

| Package | Version Constraint | Role | Security Relevance |
|---------|-------------------|------|-------------------|
| `cryptography` | `>=42.0.0,<45.0.0` | Provides X25519 ECDH, HKDF-SHA384, AES-256-GCM | **Critical** — all classical crypto and AEAD operations |
| `liboqs-python` | `>=0.10.0,<1.0.0` (optional) | Python wrapper for liboqs C library | **Critical** — provides ML-KEM-768/1024 post-quantum KEM |
| `pytest` | `>=8.0.0` (dev only) | Test framework | Not shipped |

## Transitive Dependencies (Security-Relevant)

| Package | Pulled By | Role |
|---------|-----------|------|
| `cffi` | `cryptography` | C Foreign Function Interface for OpenSSL binding |
| `liboqs` (native C) | `liboqs-python` | NIST PQC reference implementations (ML-KEM) |
| `OpenSSL` / `BoringSSL` | `cryptography` | Underlying crypto engine |

## Native Library Requirements

### liboqs (Post-Quantum)
- **Required version**: liboqs 0.10.x+ (matching liboqs-python release)
- **Architecture**: Must match Python interpreter architecture (x86_64 / arm64)
- **Build**: Pre-built binaries preferred over import-time compilation
- **Supply chain**: Pin to a specific release tag; verify against OQS project GPG signatures

### OpenSSL / BoringSSL (Classical)
- **Required version**: OpenSSL 3.0+ (via `cryptography` package)
- **Managed by**: The `cryptography` Python package bundles its own OpenSSL

## Packaging Guidance (Discussion #2534)

> "Compiling opportunistically during import makes installation
> non-reproducible and expands the supply-chain surface. Prefer signed,
> version-pinned application artifacts produced in CI for every supported
> OS/architecture."

Recommended CI pipeline:
1. Build `liboqs` from a pinned release tag in CI
2. Run `pip install liboqs-python==<pinned>` against the CI-built native lib
3. Run the full cryptoflex test suite
4. Produce platform-specific wheels or containers
5. Sign artifacts and publish SBOM alongside the release

## Cryptographic Primitives Used

| Primitive | Standard | Used For |
|-----------|----------|----------|
| X25519 | RFC 7748 | Classical key exchange (modeled as KEM) |
| ML-KEM-768 | NIST FIPS 203 | Post-quantum key encapsulation |
| ML-KEM-1024 | NIST FIPS 203 | Post-quantum key encapsulation (high assurance) |
| HKDF-SHA384 | RFC 5869 | Hybrid KEM combiner key derivation |
| AES-256-GCM | NIST SP 800-38D | Authenticated encryption with associated data |
