# Tổng quan pipeline CI Core

`ci-core` là mẫu GitLab CI/CD dùng chung để kiểm tra, build và phát hành container image. Repo sử dụng mẫu chứa Dockerfile và khai báo danh sách image cùng phiên bản trong `images.json`, rồi nối với `ci-core` qua [mẫu `.gitlab-ci.yml`](docs/consumer.gitlab-ci.yml) trên cùng GitLab.

## Luồng pipeline

1. **Pipeline cha:** kiểm tra `images.json`, quét lỗi cấu hình và thông tin bí mật trong mã nguồn, sau đó chọn image theo nhánh hoặc tag Git.
2. **Pipeline con:** FAST build và chạy kiểm tra cơ bản. FULL/RELEASE build trên runner, quét bằng Trivy, vá gói hệ điều hành nếu áp dụng, rồi quét lại và kiểm tra image cuối theo chính sách.
3. **Phát hành:** chỉ đẩy image đã qua kiểm tra lên Harbor. Pipeline đối chiếu digest, ký và xác minh image cùng bằng chứng build bằng Cosign, sau đó mới gắn tag phát hành cho cùng digest.

## Khi nào chạy

| Chế độ | Điều kiện | Kết quả |
|---|---|---|
| FAST | Merge request hoặc nhánh `feature/*`, `bugfix/*`, `hotfix/*` | Build thử image được chọn; không đẩy lên Harbor. |
| FULL | Nhánh `main` được bảo vệ | Build toàn bộ image đang bật; gắn tag `<version>-dev`. |
| FULL | Nhánh `release/<image>/vX.Y.Z` được bảo vệ | Build một image; gắn tag `<version>-rc`. |
| RELEASE | Tag Git được bảo vệ: `<image>/vX.Y.Z` hoặc `release/<image>/vX.Y.Z` | Phát hành một image với tag `<version>` và tạo GitLab Release. |

## Biến cấu hình chính

| Biến | Mục đích |
|---|---|
| `CI_CORE_PROJECT`, `CI_CORE_REF` | Đặt trong `.gitlab-ci.yml` của repo build image; phải khớp project và ref trong `include`. |
| `HARBOR_REGISTRY`, `HARBOR_PROJECT` | Đích lưu và phát hành image. |
| `HARBOR_USER`, `HARBOR_PASSWORD` | Tài khoản đẩy image và gắn tag; chỉ cấp trên nhánh/tag được bảo vệ. |
| `IMAGE_GATE_TOOLS_IMAGE`, `COSIGN_IMAGE` | Image công cụ build, quét và ký cho FULL/RELEASE. |
| `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`, `COSIGN_PUBLIC_KEY` | Khóa ký, mật khẩu và khóa công khai xác minh. Khóa công khai là biến loại **File**, được cấp riêng. |
| `TRIVY_IMAGE`, `IMAGE_SELECTION` | Có thể đổi image quét mã nguồn; `IMAGE_SELECTION` mặc định `auto`, có thể chọn image khi chạy FAST thủ công. |

Đặt thông tin đăng nhập và khóa ký ở **Settings → CI/CD → Variables** của repo build image; dùng **Protected**, không ghi vào YAML.

## Đầu ra triển khai

Lấy trường `.reference` từ `out/<image>/promotion.json` của bản RELEASE đã duyệt. Hệ thống nhận xác minh chữ ký rồi `docker pull` đúng địa chỉ `registry/project/repo@sha256:…`. Không cần mang theo báo cáo quét hay tệp CI để chạy container.
