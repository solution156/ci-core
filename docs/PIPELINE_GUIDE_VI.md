# Hướng dẫn vận hành pipeline image (bản refactor)

## Phạm vi và trạng thái

- Hai source tree: `ci-core/` (templates, planner, runtime scripts, tests) và `workspace-images/` (catalog, Dockerfiles, runtime hooks).
- Đây là mã **local**, không đồng nghĩa đã publish lên GitLab/Harbor. Xem báo cáo kiểm thử để biết bước nào thực sự chạy.
- Không cần cài GitLab server/Runner để chạy unit tests và integration fixture local. Cần GitLab thật để kiểm chứng CI Lint, quyền job token, protected refs, bridge và artifacts qua các job.
- Không sửa credential/provider của Hermes. Không push, promote, tạo release production từ môi trường local này.

## 1. Các thay đổi thiết kế

Parent: validate → plan → native trigger → cleanup.

- `templates/common.yaml`: defaults và bootstrap scripts chung, dùng cùng một ref.
- `templates/workspace-parent.yaml`: catalog/shell/source validation, sinh dynamic child artifact.
- `templates/workspace-child.yaml`: hidden templates cho từng loại công việc.
- `scripts/plan.py`: sinh JSON hợp lệ dưới dạng YAML; runtime chỉ dùng Python standard library.
- Tên `.gitlab-ci.yml` template cũ là wrapper, tránh hai implementation lệch nhau.
- Trigger job là GitLab bridge, **không có** image/script/services. `strategy: mirror` yêu cầu GitLab >=18.2; bản cũ dùng `depend` sau khi kiểm tra tương thích.
- Child có `CI_PIPELINE_SOURCE=parent_pipeline`. Planner ghi lại parent source/ref để phục vụ điều phối và trace; không dùng biến tự khai báo thay thế protected-ref controls trên server.

DAG FULL/RELEASE cho mỗi image:

```text
build -> scan -> patch -> verify:trivy + verify:runtime
      -> gen-sbom -> evidence -> sign -> [devguard] -> promote -> [release] -> cleanup
```

- Build ghi `build.json` và `built.txt` chứa digest sau push.
- Scan ban đầu đọc **built digest**, dùng làm đầu vào chọn OS patches.
- Patch dùng FROM digest ban đầu, không dùng mutable tag làm base; sau push ghi digest mới trong `patch.json`.
- Harbor snapshot đọc lại registry và từ chối nếu candidate không còn khớp digest do patch ghi nhận.
- Trivy gate, runtime, SBOM, evidence/sign đều dùng post-patch `verified.txt`.
- Artifact của mỗi image nằm ở `out/<image-id>/`; `needs:artifacts` cấp trực tiếp. Chỉ evidence/sign/promote giữ bundle tổng hợp có chủ đích.
- Gate severity là lỗi thực qua `--exit-code 1`. Scan ban đầu chỉ lập báo cáo để có thể patch trước gate cuối.
- Promote chỉ đổi tag trên artifact đã kiểm thử, không rebuild; release tag khác digest đã tồn tại bị từ chối.
- Release API đọc lại tag/commit sau POST; retry với release khớp đã tồn tại là idempotent.
- Những thao tác mutable main/RC dùng resource_group; vẫn cần chính sách Harbor immutability cho release tags trên server.

## 2. Luồng Git

- MR hoặc push/web `feature/*`, `bugfix/*`, `hotfix/*`: FAST, chỉ image liên quan diff. Build + runtime smoke trong cùng job, **không push/sign/promote**.
- Có MR mở: không chạy thêm development push pipeline trùng MR.
- Push/web protected `main`: FULL mặc định **tất cả enabled images**, kể cả commit đầu hoặc chỉ thay CI.
- Protected branch `release/<image>/vX.Y.Z`: FULL cho đúng image, tag Harbor `rc-X.Y.Z`.
- Protected Git tag `<image>/vX.Y.Z` **hoặc** `release/<image>/vX.Y.Z`: RELEASE cho đúng image, tag Harbor `X.Y.Z`, GitLab Release.
- Tag/branch version phải bằng `images.json` của image đó.
- Run pipeline trên main/development branch: `IMAGE_SELECTION=chrome` hoặc `chrome,firefox` hoặc `all`. Để `auto` trên push/MR; không đặt override cố định ở Project Variables.
- FAST không có base đáng tin: tạo `images:no-changes`, không đoán all. Khi cần kiểm thử thật, Run pipeline + lựa chọn image rõ ràng.
- MR diff dùng `CI_MERGE_REQUEST_DIFF_BASE_SHA`; push dùng `CI_COMMIT_BEFORE_SHA`; fallback hiện tại `HEAD^`. Với nhánh mới nhiều commit trước lần push đầu, nên dùng MR để có base đầy đủ hoặc manual selection.
- Shared dependency trong catalog chỉ làm rebuild các image khai báo liên quan; thay `.dockerignore` có thể ảnh hưởng mọi image. Main FULL all là yêu cầu riêng, không phải thiếu selective-build support.

## 3. VS Code: bootstrap không cần cài trên host

Lỗi gốc là lockfile chỉ chứa comment, trong khi Dockerfile mặc định `EXTENSION_MODE=locked`. Không thể tự tạo version giả hoặc tắt validation để gọi là đã sửa.

Catalog giờ có `extension_lock` metadata (`manifest`, `lock`, `generated`) và `runtime_check` hook. Không cần hardcode tên `vscode` trong planner/runtime.

Quy trình GitLab:

1. Giữ `enabled:false` trong lần bootstrap đầu. Hoặc nếu đã bật, bootstrap chỉ bỏ qua kiểm tra lock của đúng image được yêu cầu.
2. Run pipeline trên development branch hoặc protected main, đặt **duy nhất** `EXTENSION_BOOTSTRAP=vscode`; giữ `IMAGE_SELECTION=auto`.
3. Parent kiểm tra manifest, child có `lock:vscode` (không sign/promote).
4. Job build Docker với `EXTENSION_MODE=resolve`, cài extensions thật, dùng CLI của image kiểm tra phiên bản đã cài, xuất `out/vscode/extensions.lock` artifact.
5. Tải artifact, review rồi commit nội dung vào `images/vscode/configs/extensions.lock`. Sau đó đổi `enabled:true` và chạy FAST/review MR.
6. FULL/RELEASE vẫn bắt buộc lock khớp toàn bộ manifest. Lock sai format/trùng/thiếu/thừa ID đều fail trước build.

Bootstrap local với Docker, không cần VS Code trên host:

```bash
cd /root/kubeworkspace/workspace-images
IMAGE_ID=vscode WORKSPACE_REF_KIND=bootstrap PARENT_PIPELINE_SOURCE=web \
ROOT_PIPELINE_ID=20261122 /usr/bin/python3 ../ci-core/scripts/pipeline.py lock
```

Lệnh này pull base và tải extension qua mạng, có thể tốn nhiều GB. Không tự commit/enable image. Đối với extension private/proxy/CA, cần cấu hình riêng; không đưa token vào build args hoặc layer.

## 4. Variables và quyền truy cập

Có defaults trong YAML, không cần khai báo lại tất cả:

- `CI_CORE_PROJECT`, `CI_CORE_REF`: cùng project/tag với include. Include pin và clone pin bắt buộc khớp.
- `HARBOR_REGISTRY`, `HARBOR_PROJECT`: đích registry.
- `PYTHON_IMAGE`: default image nội bộ `build/ci-tools:v1` cần Python3 + git.
- `DOCKER_CLI_IMAGE`, `DIND_IMAGE`: default Docker27.5.1 CLI/DinD.
- `SHELL_IMAGE`, `TRIVY_IMAGE`, `COSIGN_IMAGE`, `DEVGUARD_SCANNER_IMAGE`: có thể mirror/override nội bộ.
- `HEAVY_RESOURCE_GROUP=workspace-heavy`: serialize Docker build/patch/runtime trong cùng GitLab project.
- `TRIVY_SCAN_SEVERITY`, `TRIVY_GATE_SEVERITY`, `TRIVY_PATCH_SEVERITY`, `AUTO_PATCH_OS`, `PATCH_PACKAGE_EXCLUDE`.
- `DEVGUARD_ENABLED=false` mặc định; khi bật cần asset/API/token riêng.

Secrets, phải cấu hình GitLab theo least privilege:

- `HARBOR_USER`, `HARBOR_PASSWORD`: robot push và Harbor API cho protected main/release. Chọn **Protected**, mask/hide nếu GitLab hỗ trợ; quyền đúng project.
- `COSIGN_PRIVATE_KEY`: GitLab File variable hoặc encrypted key text; **Protected**. `COSIGN_PASSWORD`: **Protected + Masked**. Không gửi key/password vào chat.
- `DOCKER_AUTH_CONFIG`: cần khi Runner pull private job images. **Toàn giá trị là JSON**, chỉ trường `auth` chứa base64(username:password). Không base64 cả document.
- Nếu development cần pull private base/job image: dùng **robot pull-only**, không cấp credential push/sign cho MR. Có thể dùng DOCKER_AUTH_CONFIG pull-only cho job image và `HARBOR_PULL_USER`/`HARBOR_PULL_PASSWORD` cho Docker client trong FAST/bootstrap.
- Cấu hình private job image phải khả dụng *trước* before_script. `docker login` trong job không chữa được lỗi pull chính job image.
- Credentials còn phụ thuộc project/group Variable precedence và GitLab protected-resource policies. Không forward toàn bộ pipeline variables sang child một cách vô điều kiện.
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` và aliases có thể cần cho job/APK/build. Docker daemon/BuildKit và job container là các context khác nhau; biến trong job không sửa được daemon pull image. Không có quyền Runner thì nhờ quản trị hoặc dùng registry đã reachable.
- Không tự đặt/ghi đè các biến predefined như `CI_SERVER_URL`, `CI_API_V4_URL`, `CI_JOB_TOKEN`, `CI_COMMIT_SHA` trên GitLab.
- CI core phải cho phép `CI_JOB_TOKEN` của consumer đọc repo theo GitLab allowlist/membership. Include cũng cần người khởi tạo có quyền đọc template.

Docker CLI job hiện dùng `apk add python3 bash git` nếu thiếu. Nếu air-gapped, build/mirror combined CLI image có đủ tools rồi override `DOCKER_CLI_IMAGE`. Trivy cần vulnerability DB mirror/cache cập nhật; Cosign image cần shell/base64 cùng binary cho script hiện tại. Test core cần PyYAML trong image test hoặc pip mirror cho `tests/requirements.txt`.

## 5. Test local

Unit/contract tests (không Docker/GitLab/Harbor):

```bash
cd /root/kubeworkspace/ci-core
/usr/bin/python3 -m unittest discover -s tests -v
/usr/bin/python3 -m compileall -q scripts tests
```

Trong máy này `/usr/bin/python3` có PyYAML; Python mặc định của Hermes có thể khác. Không dùng `pip --break-system-packages`; nếu thiếu hãy dùng venv hoặc package đã được quản trị duyệt.

Tests dùng Git repo tạm thật để kiểm diff. Command recording/mock chỉ kiểm contract của Docker/Harbor/Release, không chứng minh API production chạy.

Opt-in integration **thật** nhưng dùng fixture nhỏ, không phải Chrome/VSCode production:

```bash
/usr/bin/python3 tests/local_integration.py             # chỉ in plan
/usr/bin/python3 tests/local_integration.py --run       # thực thi local Docker
```

Harness dựng registry tạm chỉ bind `127.0.0.1`, tạo fixture Git/image, gọi runtime build/push/patch/runtime/evidence, scan/gate/SBOM bằng Trivy thật, ký/verify bằng key tạm Cosign. Registry bị xóa đúng tên khi kết thúc; không prune daemon hay tác động Harbor production. Checkpoint Harbor snapshot được thay bằng read-back từ **OCI local**, ghi rõ đây không phải test Harbor API. Kết quả ở `ci-core/reports/local-integration/result.json`; log mỗi bước và evidence ở cùng cây. Private signing key test bị xóa sau run. Image/cache được giữ để retry nhanh, không tự xóa image khác.

Runtime CLI `pipeline.py`, `harbor.py`, `release.py` hỗ trợ `--dry-run` để in intent không gọi network/Docker. Đây không thay thế kiểm tra prerequisites/build thật.

## 6. Rollout an toàn

1. Review source/diff local. Backup ban đầu: `/root/.hermes/cache/scratch/kubeworkspace-before-20261122T092639Z`.
2. Publish core templates/scripts/tests vào repo core qua nhánh review. Run core tests.
3. Sau review, tạo **tag mới `v2.1.0`**. Không force-retag `v2.0.0` đang được consumer khác dùng.
4. Consumer đã chuẩn bị include và `CI_CORE_REF=v2.1.0`. Chỉ push consumer sau khi tag chứa file mới tồn tại. Nếu dùng version khác, đổi cả hai vị trí cùng lúc.
5. Dùng CI Lint/Pipeline Editor trên **GitLab thật** để resolve cross-project includes và validate config. YAML parse local không tương đương GitLab semantic validation.
6. Run pipeline `feature/chrome` với `IMAGE_SELECTION=chrome`: parent xanh và child build/runtime xanh; không có sign/promote.
7. Bootstrap VSCode, commit verified lock rồi enable, chạy FAST.
8. Test FULL trên protected main với các credential/CA/proxy chuẩn. Kiểm đủ scan/patch/verify/SBOM/evidence/sign/promote chứ không dừng ở build xanh.
9. Test protected release tag cho một image; so sánh digest trong registry với report/evidence. Retry không được đổi immutable release sang digest khác.

Không cài hay yêu cầu full GitLab server trên máy 4CPU/15GiB để thực hiện bước 5–9; dùng GitLab hiện có khi có quyền.

## 7. Giới hạn và chẩn đoán

- Source cũ đã có `GIT_DEPTH=0`, images và DinD. Không thể kết luận lỗi sau build là thiếu chúng.
- Chưa có log job sau build trên main nên **nguyên nhân production chưa được xác nhận**. Bản refactor sửa các contract được tái hiện local, không gọi đó là đã sửa mọi lỗi production.
- Host local không resolve được Harbor nội bộ thì không build exact Chrome base/đẩy Harbor được. Cần mạng/VPN/DNS/CA hợp lệ; không tự sửa hosts hay bỏ TLS.
- Không bật DinD `--network host` trên `0.0.0.0:2375`. Local test dùng Docker daemon hiện có; GitLab DinD là service network riêng và cần Runner privileged do quản trị cấu hình.
- Cosign hiện dùng khóa nội bộ và `--tlog-upload=false` cho registry nội bộ. Điều này không cung cấp transparency log; cần xác minh public key tin cậy ở deployment.
- Provenance là predicate tự tạo, **không phải chứng nhận đạt cấp SLSA**. Runtime smoke cơ bản không thay thế UAT browser/GUI, integration application, image functionality.
- AUTO_PATCH_OS chỉ hỗ trợ OS findings Debian/Ubuntu; không tự vá browser/npm/extensions. CRITICAL còn lại khiến gate fail; không tắt gate để lấy trạng thái xanh.
- Platform hiện chỉ `linux/amd64`; thêm platform cần mở rộng schema/build/runtime tests có kiểm soát.
- Resource_group chỉ serialize trong project, không thay Runner concurrency/memory controls toàn hệ thống.

## 8. Tài liệu chính thức đã đối chiếu

- GitLab downstream/dynamic child: https://docs.gitlab.com/ci/pipelines/downstream_pipelines/
- GitLab YAML reference: https://docs.gitlab.com/ci/yaml/
- Private job images / Docker auth: https://docs.gitlab.com/ci/docker/using_docker_images/
- Trivy image/SBOM: https://trivy.dev/latest/docs/target/container_image/
- Cosign: https://docs.sigstore.dev/cosign/signing/signing_with_containers/

Luôn đối chiếu CLI `--help` và version đang cài, không giả định “latest docs” tương thích mọi phiên bản GitLab/tool.
