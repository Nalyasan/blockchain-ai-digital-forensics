# BÁO CÁO DỌN DẸP AN TOÀN VÀ HƯỚNG DẪN KHÔI PHỤC (`CLEANUP_MANIFEST_AND_RESTORE`)

- **Tài liệu căn cứ**: `AGENT.md` v6.0 & Ủy quyền dọn dẹp an toàn Milestone M6
- **Tệp kê khai máy đọc**: `cleanup_manifest.json` (tại thư mục gốc dự án)
- **Thời điểm thực thi (UTC)**: `2026-11-05T12:02:34Z`
- **Tổng dung lượng rác thu hồi**: `784,755,980` bytes (~748.40 MiB / 784.76 MB) trên `26,999` tệp dư thừa/cache.

---

## 1. Quy trình an toàn trước khi dọn dẹp

1. **Rà soát tham chiếu toàn mã nguồn**: Quét toàn bộ `forensics/`, `scripts/`, `tests/`, `contracts/`, `.bat`, `.ps1`, `.toml` để xác nhận **0 tham chiếu hoạt động** tới các mục bị loại bỏ; gỡ bỏ tham chiếu đường dẫn tạm `scratch/` trong `scripts/fetch_labels.py` và `tests/test_integration_lifecycle.py`.
2. **Bảo toàn kiểm thử đối kháng**: Di chuyển tệp kiểm thử hợp lệ `scratch/test_adversarial_did.py` sang `tests/test_adversarial_did.py` (SHA-256: `D199F88539F5CDB2695030895C01777740748B90C357A35607818558123EC2CC`, 71/71 bài kiểm thử đạt) trước khi dọn `scratch/`.
3. **Kiểm tra Reparse Point / Symlink & Ranh giới thư mục**: Mọi mục tiêu được xác minh `FILE_ATTRIBUTE_REPARSE_POINT == 0` (cả cấp thư mục cha lẫn đệ quy toàn bộ cây con) và thuộc phạm vi nội bộ kho mã nguồn dự án, tuyệt đối không chạm thư mục ngoài.
4. **Sao lưu ngoài repository kèm đối chiếu SHA-256**: Toàn bộ 28 tệp kịch bản/thử nghiệm độc lập trong `scratch/` được sao lưu ra thư mục ngoài repository có gắn dấu thời gian và kiểm tra khớp mã băm SHA-256 100% trước khi xóa khỏi dự án.

---

## 2. Bảng tổng hợp các hạng mục đã dọn dẹp

| Đường dẫn tương đối | Phân loại | Số tệp | Dung lượng (bytes) | Tham chiếu | Sao lưu ngoài repo | Thao tác |
|---|---|---:|---:|:---:|---|---|
| `osint-attack-surface` | Thư mục ngoài phạm vi dự án | 857 | 11,846,381 | 0 | Không (xóa vĩnh viễn theo xác nhận rõ ràng của chủ dự án) | `PERMANENT_DELETE_AUTHORIZED` |
| `scratch` | Không gian nháp & bản sao tạm | 23,050 | 607,352,712 | 0 | Có (28 tệp kịch bản độc lập đã xác minh SHA-256; xem `cleanup_manifest.json`) | `BACKED_UP_AND_REMOVED` |
| `%SystemDrive%` | Thư mục cache phát sinh do thiếu biến môi trường | 4 | 989,184 | 0 | Không (cache hệ điều hành tái tạo được) | `REMOVED_REPRODUCIBLE_CACHE` |
| `out` | Build output Foundry tạo nhầm ở thư mục gốc | 23 | 1,994,701 | 0 | Không (bản chuẩn nằm tại `contracts/out/`) | `REMOVED_REPRODUCIBLE_CACHE` |
| `cache` | Compiler cache Foundry tạo nhầm ở thư mục gốc | 1 | 3,484 | 0 | Không (cache biên dịch tái tạo được) | `REMOVED_REPRODUCIBLE_CACHE` |
| `contracts/cache` | Solidity compiler cache | 31 | 124,037 | 0 | Không (tái tạo tự động qua `forge build --root contracts`) | `REMOVED_REPRODUCIBLE_CACHE` |
| `tmp_pytest` | Thư mục chạy tạm của Pytest | 1 | 204,800 | 0 | Không (thư mục tạm tái tạo được) | `REMOVED_REPRODUCIBLE_CACHE` |
| `tmp_pytest_run` | Thư mục `--basetemp` tạm của Pytest | 2,759 | 155,127,932 | 0 | Không (thư mục tạm tái tạo được) | `REMOVED_REPRODUCIBLE_CACHE` |
| `**/__pycache__` (20 thư mục) | Bytecode cache Python | 273 | 7,112,749 | 0 | Không (tái tạo tự động bởi CPython) | `REMOVED_REPRODUCIBLE_CACHE` |

---

## 3. Chứng nhận bảo toàn tài sản bất biến sau dọn dẹp

Toàn bộ đặc tả, cơ sở dữ liệu canonical, khóa mạch ZKML, mô hình ML, tài liệu vận hành và chứng cứ nghiệm thu lịch sử được giữ nguyên vẹn 100% bitwise:

| Tài sản được bảo vệ | SHA-256 xác minh sau dọn dẹp | Trạng thái |
|---|---|---|
| `AGENT.md` (v6.0) | `DAE75E00D95A5F2F67FD4D78ED9B843DD8AA791A24B8D7AC3831A0556F16FB7E` | **INTACT** |
| `docs/legacy/agent_v5.1.txt` | `A4B883D325FD93A9EEA7A53928FD3698B0FDD2A8144E0E5F5320A3EDEBA1F143` | **INTACT** |
| `data/real_p4.db` | `6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97` | **INTACT** |
| `data/forensics.db` | `3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001` | **INTACT** |
| `data/benchmark_p6.db` | `C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507` | **INTACT** |
| `.env` | `C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C` | **INTACT** |

---

## 4. Hướng dẫn khôi phục (Restoration Procedure)

1. **Khôi phục các tệp kịch bản nháp từ bản sao lưu ngoài repository** (nếu cần đối chiếu lịch sử):
   ```powershell
   $Manifest = Get-Content -Raw -Path .\cleanup_manifest.json | ConvertFrom-Json
   $ScratchEntry = $Manifest.removed_items | Where-Object { $_.path -eq "scratch" }
   New-Item -ItemType Directory -Force -Path .\scratch_restored | Out-Null
   foreach ($f in $ScratchEntry.backed_up_standalone_files) {
       $Dest = Join-Path .\scratch_restored (Split-Path $f.file -Leaf)
       Copy-Item -LiteralPath $f.backup_path -Destination $Dest -Force
       $ActualHash = (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash.ToUpper()
       if ($ActualHash -ne $f.sha256) {
           throw "SHA-256 mismatch restoring $($f.file): got $ActualHash, expected $($f.sha256)"
       }
   }
   Write-Host "Restored and verified $($ScratchEntry.backed_up_standalone_files.Count) standalone files."
   ```
2. **Tái tạo các thư mục build cache khi cần**:
   - Biên dịch lại hợp đồng thông minh Foundry: `.\tools\foundry\forge.exe build --root contracts`
   - Bytecode Python (`__pycache__`) và cache Pytest (`.pytest_cache`) được CPython / Pytest tự động sinh lại khi thực thi.
3. **Lưu ý đối với `osint-attack-surface/`**: Đã xóa vĩnh viễn không lưu bản sao ngoài theo chỉ thị trực tiếp của chủ dự án vì thư mục không thuộc phạm vi đề tài.
