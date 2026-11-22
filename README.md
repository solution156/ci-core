# CI Core

Repository chứa template, script, và logic cốt lõi cho pipeline GitLab.

## Cấu trúc repo

- `scripts/` — utilities (pipeline.py, catalog.py, plan.py, harbor.py, release.py, job.py)
- `templates/` — GitLab CI templates (workspace-parent.yaml, workspace-child.yaml, common.yaml)
- `tests/` — unit/contract/local integration tests
- `docs/` — pipeline runbook docs

## Giới thiệu template

### workspace-parent.yaml
- Parent validates source
- Creates dynamic child pipeline
- Stages: validate, plan, build, scan, sign, promote, cleanup

### workspace-child.yaml
- Per-image templates
- Stages: prepare, build, scan, patch, verify, sbom, evidence, sign, devguard, promote, release, cleanup

## Trạm chạy (Runner) yêu cầu

- Python 3.12+
- Docker
- git
- Trivy, Cosign (có thể cài qua image build)

## Liên kết pipeline

Project `workspace-images` sẽ `include` file từ project `https://gitlab.com/hermes156/ci-core`,
file chính: `/templates/workspace-parent.yaml`
- `CI_CORE_PROJECT` = `hermes156/ci-core`
- `CI_CORE_REF`   = `v2.1.0`

## CI Pipeline (from workspace-images)

### validate
- Python compile + unit tests
- Bash syntax check
- Trivy secret/misconfig scan

### plan
- Generate child pipeline YAML
- Create plan artifacts

### build
- Docker build for each image in images.json
- Push to Harbor registry

### scan
- Trivy vulnerability scan
- Report artifacts

### patch
- Harbor snapshot
- Verify patch results

### verify
- Runtime checks
- Trivy gate (HIGH,CRITICAL)

### sbom
- CycloneDX SBOM generation

### evidence
- Release evidence bundle

### sign
- Cosign signing of image tags
- Generation of attestation and provenance

### promote
- Promote image to production tag in Harbor

### release
- Publish final image and manifest

### cleanup
- Clean up job-local files (not registry)

## Build & Trigger

Các image sẽ được build và push lên Harbor registry theo `images.json`.
Pipeline cần các biến môi trường sau (đặt ở GitLab CI/CD settings):
- `HARBOR_REGISTRY`: registry host (vd: `rd-harbor-secops.servicemicro.net`)
- `HARBOR_PROJECT`: project trong Harbor (vd: `kubeworkspace`)
- `HARBOR_USER`, `HARBOR_PASSWORD`: credential cho Harbor
- `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`: bằng chứng digital signing
