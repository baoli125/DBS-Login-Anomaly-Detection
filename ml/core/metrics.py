"""
Tiện ích tập trung cho đánh giá và số liệu ML trong phát hiện bất thường.

Mô-đun này chứa tất cả các hàm tính ngưỡng, số liệu và logic đánh giá
cho cả đào tạo và suy luận. Sử dụng mô-đun này cho tất cả đánh giá và báo cáo ML nhằm đảm bảo rõ ràng
và dễ bảo trì.
"""

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
)


def select_binary_thresholds(y_true: np.ndarray, y_scores: np.ndarray) -> Dict[str, float]:
    """
    Chọn các ngưỡng hữu ích cho phân loại nhị phân:
      - t_high_recall: recall >= 0.95
      - t_high_precision: precision >= 0.95
      - t_balanced: tối đa hóa điểm F1
    Trả về một dict các ngưỡng.
    """
    if np.sum(y_true) == 0:
        return dict(t_high_recall=0.1, t_balanced=0.5, t_high_precision=0.9)
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    p = precision[:-1]
    r = recall[:-1]
    f1 = np.where((p + r) > 0, 2 * p * r / (p + r), 0.0)
    best_f1_idx = int(np.argmax(f1))
    t_balanced = float(thresholds[best_f1_idx])
    high_recall_mask = r >= 0.95
    if np.any(high_recall_mask):
        idxs = np.where(high_recall_mask)[0]
        best_idx = idxs[int(np.argmax(f1[idxs]))]
        t_high_recall = float(thresholds[best_idx])
    else:
        t_high_recall = float(thresholds[np.argmax(r)])
    high_prec_mask = p >= 0.95
    if np.any(high_prec_mask):
        idxs = np.where(high_prec_mask)[0]
        best_idx = int(idxs[-1])
        t_high_precision = float(thresholds[best_idx])
    else:
        t_high_precision = float(thresholds[np.argmax(p)])
    return dict(
        t_high_recall=t_high_recall,
        t_balanced=t_balanced,
        t_high_precision=t_high_precision,
    )


def load_thresholds(config_dir: Optional[str] = None) -> Dict[str, float]:
    """
    Tải các ngưỡng cố định từ file cấu hình JSON.
    
    Tìm kiếm file thresholds.json trong thư mục config:
      1. Nếu config_dir được cung cấp, tìm trong đó
      2. Nếu không, tìm trong <project_root>/ml/config/
      3. Fallback về ngưỡng mặc định nếu file không tìm thấy
    
    Trả về dict với keys: t_high_recall, t_balanced, t_high_precision
    """
    if config_dir is None:
        # Tìm project root từ vị trí hiện tại của file này
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
        config_dir = os.path.join(project_root, "ml/config")
    
    config_file = os.path.join(config_dir, "thresholds.json")
    
    # Fallback về ngưỡng mặc định
    default_thresholds = {
        "t_high_recall": 0.3,
        "t_balanced": 0.5,
        "t_high_precision": 0.7
    }
    
    if not os.path.exists(config_file):
        print(f"[CẢNH BÁO] Không tìm thấy file thresholds.json tại {config_file}. Sử dụng ngưỡng mặc định.")
        return default_thresholds
    
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        thresholds = config.get("binary_thresholds", default_thresholds)
        return thresholds
    except (json.JSONDecodeError, IOError) as e:
        print(f"[LỖI] Không thể đọc file thresholds.json: {e}. Sử dụng ngưỡng mặc định.")
        return default_thresholds


def compute_model_scores(model: Any, scaler: Any, X: np.ndarray) -> np.ndarray:
    """Tính toán điểm mô hình cho ma trận đặc trưng.

    Công thức chi tiết (cho mô hình nhị phân như Logistic Regression):
      1. Chuẩn hóa đặc trưng: X_scaled = scaler.transform(X)
         - scaler là StandardScaler, chuẩn hóa về mean=0, std=1 để tránh bias.

      2. Tính logit (trước sigmoid): logit = w * X_scaled + b
         - w: vector trọng số (weights) học được từ dữ liệu.
         - b: bias (intercept) học được.
         - Đây là kết quả của decision_function().

      3. Áp dụng hàm sigmoid để chuyển logit thành xác suất:
         score = 1 / (1 + exp(-logit)) = predict_proba(X_scaled)[:, 1]
         - predict_proba trả về [P(class=0), P(class=1)], ta lấy P(class=1).
         - Giá trị score ∈ [0, 1]: gần 1 nghĩa là khả năng tấn công cao, gần 0 là thấp.

    Đối với mô hình không có predict_proba (ít phổ biến):
      - decision_function: Trả về logit trực tiếp (không sigmoid), có thể âm/dương.
      - predict: Trả về nhãn dự đoán (0 hoặc 1), không phải score liên tục.

    Trả về một mảng điểm float (cao hơn nghĩa là có khả năng tấn công cao hơn).
    """
    X_scaled = scaler.transform(X)

    if hasattr(model, "predict_proba"):
        return model.predict_proba(X_scaled)[:, 1]
    if hasattr(model, "decision_function"):
        return model.decision_function(X_scaled)
    return model.predict(X_scaled)


def compute_binary_metrics(y_true: np.ndarray, y_scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    """Tính toán các số liệu phân loại nhị phân tiêu chuẩn tại một ngưỡng đã cho.

    Điểm ML được chuyển đổi thành dự đoán nhị phân bằng cách sử dụng:
        y_pred = (y_score >= threshold)

    Các số liệu sau đó được suy ra từ y_true so với y_pred.
    
    === GIẢI THÍCH CÁC CHỈ SỐ TRẢ VỀ ===
    - threshold: Ngưỡng quyết định (0-1). Score >= threshold → dự đoán tấn công
    
    - precision: Độ chính xác dự đoán tấn công
      = Số tấn công dự đoán đúng / Tổng số dự đoán là tấn công
      ≈ "Khi hệ thống báo tấn công, có bao nhiêu % là đúng?"
      * Cao = ít báo động sai | Thấp = nhiều báo động sai
    
    - recall: Tỷ lệ phát hiện tấn công thực tế (cũng gọi sensitivity)
      = Số tấn công dự đoán đúng / Tổng số tấn công thực tế
      ≈ "Trong tấn công thực tế, bao nhiêu % được phát hiện?"
      * Cao = phát hiện nhiều | Thấp = bỏ sót nhiều tấn công
    
    - f1: Điểm cân bằng giữa precision và recall
      = 2 * (precision * recall) / (precision + recall)
      ≈ "Độ báo động tốt như thế nào (cân bằng 2 khía cạnh)?"
      * Cao (gần 1) = cân bằng tốt | Thấp (gần 0) = kém
    
    - roc_auc: Diện tích dưới đường cong ROC (0-1)
      ≈ "Mô hình phân biệt tấn công/benign tốt không (trên toàn bộ threshold)?"
      * 0.5 = ngẫu nhiên | 1.0 = hoàn hảo | 0.7-0.8 = tốt
    
    - pr_auc: Diện tích dưới đường cong Precision-Recall (0-1)
      ≈ "Khả năng cân bằng precision-recall tốt không (trên toàn bộ threshold)?"
      * Cao = mô hình tốt | Thấp = mô hình kém
    """
    y_pred = (y_scores >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    unique_classes = np.unique(y_true)
    if len(unique_classes) == 1:
        roc_auc = 0.5
        pr_auc = 0.0 if unique_classes[0] == 0 else 1.0
    else:
        roc_auc = roc_auc_score(y_true, y_scores)
        pr_auc = average_precision_score(y_true, y_scores)
    return dict(
        threshold=float(threshold),
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        roc_auc=float(roc_auc),
        pr_auc=float(pr_auc),
    )


def compute_multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray, class_labels: List[str]) -> Dict[str, Any]:
    """
    Tính toán số liệu đa lớp, bao gồm ma trận nhầm lẫn và thống kê theo lớp.

    Trả về một từ điển chứa:
      - classification_report: precision/recall/f1 theo lớp
      - confusion_matrix: dưới dạng list-of-lists
      - labels: thứ tự nhãn lớp
    """
    report = classification_report(
        y_true, y_pred, labels=np.arange(len(class_labels)), target_names=class_labels, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_labels)))
    return dict(
        classification_report=report,
        confusion_matrix=cm.tolist(),
        labels=class_labels,
    )


# ---------------------------------------------------------------------------
# Đặc trưng engineering / scoring formulas (used by ML pipeline)
# ---------------------------------------------------------------------------


def hour_fraction(dt: datetime) -> float:
    """Chuyển đổi datetime thành giá trị giờ phân số.

    Công thức:
        hour_fraction = hour + minute/60 + second/3600

    Điều này hữu ích để tạo đặc trưng thời gian tuần hoàn (sin/cos) nắm bắt
    các mẫu hàng ngày mà không có sự gián đoạn tại nửa đêm.
    """
    return dt.hour + dt.minute / 60.0 + dt.second / 3600.0


def is_business_hours(dt: datetime) -> int:
    """Trả về 1 nếu datetime nằm trong giờ làm việc đã định nghĩa, ngược lại 0.

    Chính sách (demo):
      - Ngày trong tuần (Thứ Hai-Chủ Nhật)
      - Giờ 08:00-18:00 (bao gồm bắt đầu, loại trừ kết thúc)

    Điều này cung cấp proxy đơn giản cho hành vi người dùng "thường xuyên" so với ngoài giờ.
    """
    if dt.weekday() >= 5:
        return 0
    return int(8 <= dt.hour < 18)


def cyclic_hour_features(dt: datetime) -> Tuple[float, float]:
    """Trả về mã hóa tuần hoàn (sin, cos) cho thời gian trong ngày.

    Sử dụng công thức:
        angle = 2*pi * (hour_fraction / 24)
        sin = sin(angle)
        cos = cos(angle)

    Các đặc trưng này bảo toàn bản chất tuần hoàn của thời gian đồng hồ.
    """
    frac = hour_fraction(dt)
    angle = 2.0 * np.pi * frac / 24.0
    return float(np.sin(angle)), float(np.cos(angle))


def rate(numerator: float, denominator: float) -> float:
    """Chia an toàn cho tỷ lệ.

    Trả về numerator/denominator nếu denominator > 0, ngược lại 0.0.
    """
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def compute_avg_interarrival_seconds(timestamps: List[datetime]) -> float:
    """Tính toán thời gian đến trung bình (giây) cho danh sách dấu thời gian.

    Công thức:
        avg = sum(delta_i) / (len(delta_i)) trong đó delta_i = t[i] - t[i-1]

    Nếu ít hơn 2 dấu thời gian, trả về 0.0.
    """
    if len(timestamps) < 2:
        return 0.0
    deltas = [
        (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]
    return float(sum(deltas) / len(deltas))


def count_within_window(timestamps: List[datetime], reference: datetime, window_seconds: float) -> int:
    """Đếm dấu thời gian nằm trong [reference - window, reference]."""
    cutoff = reference - timedelta(seconds=window_seconds)
    return sum(1 for t in timestamps if t >= cutoff)


def unique_entities_within_window(
    pairs: List[Tuple[datetime, str]], reference: datetime, window_seconds: float
) -> int:
    """Đếm các phần tử thứ hai duy nhất trong cặp (dấu thời gian, thực thể) trong cửa sổ thời gian."""
    cutoff = reference - timedelta(seconds=window_seconds)
    return len({entity for ts, entity in pairs if ts >= cutoff})
