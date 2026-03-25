# Mô-đun Agent

Mô-đun Agent cung cấp khả năng phản hồi được hỗ trợ bởi AI cho hệ thống phát hiện brute-force EaglePro. Nó giám sát sự kiện, phân loại tấn công và triển khai chiến lược phản hồi tự động.

## Kiến trúc

Agent được tổ chức thành nhiều mô-đun con:

- `core/`: Chức năng lõi của agent
  - `agent.py`: Lớp ResponseAgent chính
  - `trạng thái.py`: Quản lý trạng thái phản hồi
  - `strategies.py`: Triển khai chiến lược phản hồi
- `processing/`: Các thành phần xử lý sự kiện
  - `event_loader.py`: Tải và lọc sự kiện
  - `classifier.py`: Phân loại sự kiện dựa trên ML

## Tính năng

- **Giám sát Liên tục**: Giám sát sự kiện thời gian thực với khoảng thời gian có thể cấu hình
- **Phân loại ML**: Sử dụng mô hình ML đã được đào tạo để phát hiện tấn công
- **Phản hồi Tự động**: Triển khai nhiều chiến lược phản hồi:
  - Chặn/gỡ chặn IP
  - Thực thi 2FA
  - Tạo cảnh báo
- **Quản lý Trạng thái**: Duy trì trạng thái phản hồi qua các chu kỳ giám sát
- **Có thể Cấu hình**: Ngưỡng phản hồi và chiến lược có thể tùy chỉnh

## Cách sử dụng

### Dòng lệnh

```bash
# Chạy giám sát liên tục
python scripts/run_agent.py

# Chạy một chu kỳ
python scripts/run_agent.py --once

# Tập dữ liệu và khoảng thời gian tùy chỉnh
python scripts/run_agent.py --tập dữ liệu data/custom_events.ndjson --check-interval 60
```

### Sử dụng theo chương trình

```python
from agent.core.agent import ResponseAgent
from agent.core.trạng thái import ResponseState
from agent.processing.event_loader import EventLoader

# Khởi tạo các thành phần
trạng thái = ResponseState()
agent = ResponseAgent(trạng thái, models_dir="models")

# Chạy một chu kỳ
agent.run_once("data/test_events.ndjson")

# Chạy giám sát liên tục
agent.run_continuous("data/test_events.ndjson", check_interval=300)
```

## Chiến lược Phản hồi

Agent triển khai một số chiến lược phản hồi dựa trên phân loại tấn công:

1. **Chặn IP**: Chặn các IP có độ tin cậy tấn công cao
2. **Thực thi 2FA**: Yêu cầu 2FA cho các tài khoản đáng ngờ
3. **Giới hạn Tốc độ**: Triển khai giới hạn tốc độ tạm thời
4. **Tạo Cảnh báo**: Tạo cảnh báo cho đội ngũ bảo mật

## Cấu hình

Ngưỡng phản hồi và chiến lược có thể được cấu hình thông qua lớp ResponseState:

```python
trạng thái = ResponseState(
    block_threshold=0.8,      # Chặn IP với độ tin cậy > 0.8
    unblock_after=3600,       # Gỡ chặn sau 1 giờ
    max_alerts_per_hour=10    # Giới hạn tốc độ cảnh báo
)
```

## Tích hợp

Agent tích hợp với:
- Mô hình ML để phân loại
- Hệ thống phát hiện dựa trên quy tắc
- Ứng dụng web để giám sát thời gian thực
- Hệ thống thông báo cảnh báo

## Giám sát

Agent cung cấp khả năng giám sát:
- Ghi log hành động phản hồi
- Số liệu hiệu suất
- Duy trì trạng thái
- Xử lý lỗi và khôi phục