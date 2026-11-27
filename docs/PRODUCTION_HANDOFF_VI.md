# Nghiệm thu production và bàn giao image

## 1. Trước khi đổi pin consumer

- Publish engine vào GitLab đích bằng ref được bảo vệ không được di chuyển. Giữ pin cũ để rollback. Kiểm tra parent include, script checkout và child include trỏ cùng ref; lưu SHA tại `.ci-tools/engine-commit.txt`. `strategy: mirror` yêu cầu GitLab từ 18.2. Chạy CI Lint trên instance đích.
- Cấu hình `COSIGN_PUBLIC_KEY` dạng GitLab **File** trên protected refs, lấy từ kho trust độc lập. Chữ ký hiện dùng key và không ghi transparency log. Chỉ rollout nếu policy cho phép chế độ này. Không bỏ xác minh chữ ký hoặc TLS để xử lý lỗi cấu hình.
- Image chạy `security:source` (`TRIVY_IMAGE`) cần Trivy và Python 3. Với runner air-gapped, mirror image có sẵn cả hai, CA và nguồn DB/check bundle được duyệt. Alpine mặc định có thể cài Python qua `apk` khi runner truy cập được repository.
- Image gate từ chối report không có inventory OS/package được hỗ trợ; image tối giản không có inventory cần policy và scanner thích hợp riêng. Không coi thiếu kết quả là không có CVE. Bật branch protection, giới hạn quyền override CI variables và thực thi tag immutability tại Harbor. Dùng tài khoản pull-only ở hệ thống nhận.

## 2. Bàn giao đúng một image reference

Chỉ lấy `.reference` trong `out/<image-id>/promotion.json` từ job promote thành công của **protected release tag**. Bàn giao `registry/project/repo@sha256:…`; không dùng `ci-p…`, `-dev` hoặc `-rc` cho production. SBOM, chữ ký và provenance là bằng chứng, không phải image cần chạy.

Trên máy nhận, dùng bản `verify_release.py` đã được duyệt, Docker/Cosign, CA và quyền đọc Harbor. `EXPECTED_*` và `TRUSTED_COSIGN_PUBLIC_KEY` phải đến từ cấu hình hoặc phiếu phê duyệt độc lập, không suy ra từ dữ liệu chưa xác minh của image. Với chế độ không Rekor đã được phê duyệt:

```sh
set -eu
python3 scripts/verify_release.py "$IMAGE_REF" \
  --repository "$EXPECTED_REPOSITORY" --source "$EXPECTED_SOURCE_URL" \
  --commit "$EXPECTED_SOURCE_SHA" --engine-commit "$EXPECTED_ENGINE_SHA" \
  --key "$TRUSTED_COSIGN_PUBLIC_KEY" --allow-no-transparency-log

docker pull "$IMAGE_REF"
```

Chỉ triển khai đúng `IMAGE_REF` sau khi tất cả lệnh trên thành công. Verifier kiểm chữ ký và provenance, không khẳng định SLSA Build L3 hoặc tự chứng minh Harbor đã promote: vẫn phải lấy reference từ kết quả release được duyệt. Nếu máy nhận không tới Harbor, cần quy trình copy riêng sang registry đích giữ digest và kiểm tra chữ ký/bằng chứng ở đích; không giả định `docker save` mang theo attestation trong registry.

## 3. Tiêu chí nghiệm thu trên hạ tầng đích

1. FAST không push/ký/promote; protected `main` chạy đủ image enabled; release branch chỉ tạo `-rc`; protected release tag tạo tag version bất biến và GitLab Release.
2. Source finding ngoài phạm vi exception, secret, report không hợp lệ, CVE bị policy chặn và runtime check lỗi đều không phát hành image. Xác minh nhánh vá thật đổi digest, quét lại digest cuối và chỉ upload một image qua gate.
3. Từ máy nhận thực sự, verify bằng public key đã cấp, pull bằng quyền read-only, chạy smoke workload với entrypoint thật và target platform. Với ngoại lệ root, xác minh biện pháp kiểm soát runtime đã được phê duyệt. Xác nhận khả năng rollback bằng digest cũ, retention image và evidence, và lưu kết quả nghiệm thu.

GitHub push, unit test và registry loopback không thay thế các bước trên.
