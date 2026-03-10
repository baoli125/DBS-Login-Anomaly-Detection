# Classification Module

The Classification module provides ML-based event classification capabilities for the EaglePro brute-force detection system. It includes both single event and dataset classification with comprehensive result formatting.

## Architecture

The classification module is organized into:

- `core/`: Core classification functionality
  - `classifier.py`: EventClassifier for ML classification
  - `formatter.py`: ResultFormatter for output display
- `demo/`: Demonstration modules
  - `single_event.py`: Single event classification demo
  - `dataset_demo.py`: Dataset classification demo

## Features

- **Single Event Classification**: Classify individual events with confidence scores
- **Dataset Classification**: Batch classify multiple events with performance metrics
- **Model Support**: Supports both binary and multiclass classification models
- **Result Formatting**: Multiple output formats (detailed, summary, JSON)
- **Validation**: Input validation and error handling
- **Statistics**: Dataset statistics and classification metrics

## Usage

### Command Line

```bash
# Single event classification
python scripts/run_classification.py single --event '{"timestamp": "2024-01-01T00:00:00Z", "username": "admin", "src_ip": "192.168.1.100", "success": false}'

# Dataset classification demo
python scripts/run_classification.py dataset --dataset data/test_events.ndjson --limit 20

# Dataset statistics
python scripts/run_classification.py stats --dataset data/test_events.ndjson
```

### Programmatic Usage

```python
from classification.core.classifier import EventClassifier
from classification.core.formatter import ResultFormatter

# Initialize classifier
classifier = EventClassifier(models_dir="models")
formatter = ResultFormatter()

# Single event classification
event = {"timestamp": "2024-01-01T00:00:00Z", "username": "admin", "src_ip": "192.168.1.100", "success": False}
result = classifier.classify_single_event(event)
print(formatter.format_single_result(result))

# Dataset classification
events = load_ndjson("data/test_events.ndjson")
classifications, summary = classifier.classify_dataset(events, limit=100)
print(formatter.format_dataset_results(classifications, summary))
```

## Classification Models

The module supports multiple model types:

- **Binary Classification**: Attack vs Benign detection
- **Multiclass Classification**: Specific attack type identification
- **Feature Engineering**: Automatic feature extraction from events
- **Model Loading**: Automatic model and scaler loading

## Output Formats

### Single Event Results
```
 Classification Result
═══════════════════════════
Event: admin @ 192.168.1.100
Prediction: attack (confidence: 0.92)
Attack Type: bruteforce
Features Used: 15
```

### Dataset Results
```
 Dataset Classification Summary
═══════════════════════════════════
Total Events: 100
Attack Events: 23 (23.0%)
Benign Events: 77 (77.0%)

Attack Types:
  bruteforce: 15
  credential_stuffing: 8

Performance:
  Accuracy: 0.94
  Precision: 0.89
  Recall: 0.91
```

## Integration

The classification module integrates with:
- ML training pipeline for model updates
- Rule-based detection for hybrid approaches
- Web application for real-time classification
- Alert generation systems

## Validation

The module includes comprehensive validation:
- Event structure validation
- Model availability checks
- Feature extraction validation
- Result consistency checks

## Error Handling

Robust error handling for:
- Missing model files
- Invalid event data
- Classification failures
- File I/O errors