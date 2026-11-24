# Changelog

All notable changes to the shared GitLab CI/CD implementation are documented here.

## Unreleased

### Changed
- Use unique per-pipeline candidate tags to prevent concurrent build races.
- Derive stable image tags from inventory versions: `version-dev`, `version-rc`, and `version`.
- Build protected images with Buildx registry cache, provenance, SBOM attestations, and metadata output.
- Forward GitLab CI/CD proxy variables to the DinD service without storing proxy URLs in source.
- Preserve immutable digests through scan, runtime verification, signing, and Harbor promotion.

### Documentation
- Added a professional Vietnamese README with Mermaid architecture, parent/child pipeline, FAST/FULL/RELEASE DAGs, file responsibilities, variables, tag policy, security boundaries and local test instructions.

### Tests
- Added regression coverage for tag policy, DinD proxy forwarding, BuildKit cache/attestations, and metadata-derived digests.
