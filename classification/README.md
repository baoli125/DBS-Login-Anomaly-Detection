# Classification Mô-đun

The Classification mô-đun provides ML-based sự kiện classification capabilities for the EaglePro brute-force phát hiện system. It includes both single sự kiện and tập dữ liệu classification with comprehensive result formatting.

## Architecture

The classification mô-đun is organized into:

- `core/`: Core classification functionality
  - `classifier.py`: EventClassifier for ML classification
  - `formatter.py`: ResultFormatter for output display
- `demo/`: Demonstration modules
  - `single_event.py`: Single sự kiện classification demo
  - `dataset_demo.py`: Tập dữ liệu classification demo

## Đặc trưng

- **Single Sự kiện Classification**: Phân loại individual events with confidence scores
- **Tập dữ liệu Classification**: Batch phân loại multiple events with performance metrics
- **Model Support**: Supports both binary and multiclass classification models
- **Result Formatting**: Multiple output formats (detailed, summary, JSON)
- **Validation**: Input validation and error handling
- **Statistics**: Tập dữ liệu statistics and classification metrics

## Usage

### Command Line

```bash
# Single sự kiện classification
python scripts/run_classification.py single --sự kiện '{"timestamp": "2024-01-01T00:00:00Z", "username": "admin", "src_ip": "192.168.1.100", "success": false}'

# Tập dữ liệu classification demo
python scripts/run_classification.py tập dữ liệu --tập dữ liệu data/test_events.ndjson --limit 20

# Tập dữ liệu statistics
python scripts/run_classification.py stats --tập dữ liệu data/test_events.ndjson
```

### Programmatic Usage

```python
from classification.core.classifier import EventClassifier
from classification.core.formatter import ResultFormatter

# Khởi tạo classifier
classifier = EventClassifier(models_dir="models")
formatter = ResultFormatter()

# Single sự kiện classification
sự kiện = {"timestamp": "2024-01-01T00:00:00Z", "username": "admin", "src_ip": "192.168.1.100", "success": False}
result = classifier.classify_single_event(sự kiện)
print(formatter.format_single_result(result))

# Tập dữ liệu classification
events = load_ndjson("data/test_events.ndjson")
classifications, summary = classifier.classify_dataset(events, limit=100)
print(formatter.format_dataset_results(classifications, summary))
```

## Classification Models

The mô-đun supports multiple model types:

- **Binary Classification**: Tấn công vs Benign phát hiện
- **Multiclass Classification**: Specific tấn công type identification
- **Đặc trưng Engineering**: Automatic đặc trưng extraction from events
- **Model Tải**: Automatic model and scaler tải

## Output Formats

### Single Sự kiện Results
```
 Classification Result
═══════════════════════════
Sự kiện: admin @ 192.168.1.100
Prediction: tấn công (confidence: 0.92)
Tấn công Type: bruteforce
Đặc trưng Used: 15
```

### Tập dữ liệu Results
```
 Tập dữ liệu Classification Summary
═══════════════════════════════════
Total Events: 100
Tấn công Events: 23 (23.0%)
Benign Events: 77 (77.0%)

Tấn công Types:
  bruteforce: 15
  credential_stuffing: 8

Performance:
  Accuracy: 0.94
  Precision: 0.89
  Recall: 0.91
```

## Integration

The classification mô-đun integrates with:
- ML training pipeline for model updates
- Dựa trên quy tắc phát hiện for hybrid approaches
- Web application for real-time classification
- Alert generation systems

## Validation

The mô-đun includes comprehensive validation:
- Sự kiện structure validation
- Model availability checks
- Đặc trưng extraction validation
- Result consistency checks

## Error Handling

Robust error handling for:
- Missing model files
- Invalid sự kiện data
- Classification failures
- File I/O errors