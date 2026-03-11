# Báo cáo ML EaglePro (2026-03-11)

## 1. Mục tiêu
- Xây hệ thống phát hiện brute-force dựa vào rule + ML
- ML bao gồm: binary (attack/benign) và multiclass (benign/credential_stuffing/distributed_attack/rapid_bruteforce)
- So sánh performance giữa rule-based và ML

## 2. Dữ liệu sử dụng
- Source generator: `scripts/run_generator.py`
- File output:
  - `data/all_events.ndjson` (data tổng)
  - `data/train_events.ndjson`, `data/test_events.ndjson`
- Feature build:
  - `python scripts/run_ml.py build`
  - `data/features/train_features.parquet`
  - `data/features/test_features.parquet`

## 3. Phát hiện lỗi ban đầu
1. `train_models` split theo thời gian (70/15/15) khiến test nội bộ có thể thiếu attack type.
   - Kết quả `model_metadata.json` lúc đầu: `credential_stuffing/distributed_attack/rapid_bruteforce` support = 0.
2. `run_ml.py all` mặc định eval `t_high_precision` (thấu ngưỡng 1.0):
   - Precision = 1.0 nhưng Recall ~ 0.004 => gần như không bắt attack.

## 4. Cách fix
1. Trong `ml/core/train_models.py`:
   - Thêm `stratified split` (`_split_stratified_indices`) khi có nhiều class.
   - Fallback về time-series nếu stratify thất bại.
2. Trong `scripts/run_ml.py`:
   - `evaluate` và `all` đổi `--threshold-key` mặc định thành `t_balanced`.
   - Đảm bảo `all` dùng `t_balanced` nếu không nạp threshold từ CLI.

## 5. Kết quả sau sửa
- Lập pipeline: `python scripts/run_ml.py all`
- `models/model_metadata.json`:
  - `binary.t_balanced`: `precision 0.9979`, `recall 0.9979`, `f1 0.9979`
  - `binary.t_high_precision`: `threshold=1.0`, `precision=1.0`, `recall=0.0082` (dành cho use-case ít FP)
  - `multiclass` trên split nội bộ: 
    - `benign support=3089`, `credential_stuffing support=1350`, `distributed_attack support=40`, `rapid_bruteforce support=68`.
    - `precision/recall/f1=1.0` cho nhiều lớp nhỏ do sample đẹp.
- `run_ml.py all` evaluate với `t_balanced`:
  - Rule v ML (binary): prec 0.997 vs 0.999, recall 0.985 vs 0.995, F1 0.991 vs 0.997.
  - Attack rates ML:
    - `credential_stuffing`: 8981/9000 (0.998)
    - `distributed_attack`: 259/270 (0.959)
    - `rapid_bruteforce`: 436/450 (0.969)

## 6. Giải thích khác biệt 2 loại kết quả
- `model_metadata.json` là đánh giá nội bộ trên `train_features.parquet` test split (tập test chia từ train data).
- `run_ml.py all` dùng `data/test_events.ndjson` để so sánh ML vs Rule (dataset độc lập), nên số liệu thực tế hơn.
- Hai loại đều hợp lý; chú ý khi báo cáo phải ghi rõ nguồn dataset.

## 7. Lời khuyên nộp báo cáo
- Ghi kèm: `model_metadata.json`, `reports/ml_vs_rule_*.json`, log execution from `run_ml.py all`.
- Nêu rõ khi nào dùng `t_high_precision` và khi nào dùng `t_balanced`.

## 8. Lệnh tham khảo
```bash
python scripts/run_generator.py              # sinh data
python scripts/run_ml.py all                 # build + train + evaluate
python scripts/run_ml.py evaluate --threshold-key t_balanced --dataset data/test_events.ndjson --models-dir models --output-dir reports
```
