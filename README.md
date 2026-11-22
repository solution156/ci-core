# KubeWorkspace — CI Core (candidate v2.1.0)

Thư viện GitLab templates và scripts cho repo Workspace Images. CI Core không tự build application image khi push core.

**Runbook chính:** [docs/PIPELINE_GUIDE_VI.md](docs/PIPELINE_GUIDE_VI.md).

## Files

- `templates/common.yaml`: tool defaults, clone đúng core ref bằng CI_JOB_TOKEN.
- `templates/workspace-parent.yaml`: validation → planner → native dynamic-child trigger.
- `templates/workspace-child.yaml`: build/scan/patch/verify/SBOM/evidence/sign/promote/release/cleanup templates.
- Hai file `workspace-*.gitlab-ci.yml` cũ chỉ là wrapper compatibility.
- `scripts/catalog.py`: metadata và event/selection policy.
- `scripts/plan.py`: sinh child YAML (JSON subset), không cần YAML library trong job runtime.
- `scripts/pipeline.py`, `harbor.py`, `release.py`, `job.py`: runtime và job-scoped credentials.
- `tests/`: regression tests, artifact/DAG/security contracts và opt-in real local integration.

## Flow

- Development/MR FAST: diff-selective build + runtime smoke, không push/sign/promote.
- Protected main FULL: mặc định **tất cả enabled images**; manual web selection có kiểm soát.
- Protected `release/<image>/vX.Y.Z` branch: một image, `rc-X.Y.Z`.
- Protected `<image>/vX.Y.Z` hoặc `release/<image>/vX.Y.Z` Git tag: một image, immutable `X.Y.Z` và GitLab Release.
- VS Code có CI bootstrap resolve lockfile thật; không bắt cài extension trên host, không bịa version. Normal builds vẫn require valid lock.

## Test local

```bash
cd /root/kubeworkspace/ci-core
/usr/bin/python3 -m unittest discover -s tests -v
/usr/bin/python3 -m compileall -q scripts tests
/usr/bin/python3 tests/local_integration.py          # plan only
/usr/bin/python3 tests/local_integration.py --run    # real Docker fixture, local registry, Trivy, Cosign
```

Python cần PyYAML cho tests. Trên CI dùng `tests/requirements.txt`; môi trường hạn chế mạng nên mirror dependency hoặc dùng test image đã có sẵn. Runtime planner chỉ dùng standard library.

Integration fixture không chứng minh GitLab/Harbor production. Kết quả thực ở `reports/local-integration/result.json`; report/evidence không commit.

## Rollout

1. Review/publish core và tạo **tag mới `v2.1.0`**; không force đổi `v2.0.0`.
2. Consumer include `/templates/workspace-parent.yaml` và clone `CI_CORE_REF` cùng tag.
3. Job-token allowlist, protected refs, pull-only vs push credentials, CA/proxy/DinD isolation phải cấu hình trên hạ tầng thật.
4. GitLab >=18.2 dùng `strategy: mirror`; bản cũ cần kiểm tra và đổi `depend`.
5. CI Lint thật + FAST trước FULL/RELEASE. Không cấp production signing/push secrets cho untrusted branch/MR.

Không cần cài GitLab server để chạy tests local. Không mở daemon DinD không TLS ra host/public network. Không prune shared daemon.
