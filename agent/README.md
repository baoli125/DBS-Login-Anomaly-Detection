# Agent Module

The Agent module provides AI-powered response capabilities for the EaglePro brute-force detection system. It monitors events, classifies attacks, and implements automated response strategies.

## Architecture

The agent is organized into several sub-modules:

- `core/`: Core agent functionality
  - `agent.py`: Main ResponseAgent class
  - `state.py`: Response state management
  - `strategies.py`: Response strategy implementations
- `processing/`: Event processing components
  - `event_loader.py`: Event loading and filtering
  - `classifier.py`: ML-based event classification

## Features

- **Continuous Monitoring**: Real-time event monitoring with configurable intervals
- **ML Classification**: Uses trained ML models for attack detection
- **Automated Responses**: Implements various response strategies:
  - IP blocking/unblocking
  - 2FA enforcement
  - Alert generation
- **State Management**: Maintains response state across monitoring cycles
- **Configurable**: Customizable response thresholds and strategies

## Usage

### Command Line

```bash
# Run continuous monitoring
python scripts/run_agent.py

# Run single cycle
python scripts/run_agent.py --once

# Custom dataset and interval
python scripts/run_agent.py --dataset data/custom_events.ndjson --check-interval 60
```

### Programmatic Usage

```python
from agent.core.agent import ResponseAgent
from agent.core.state import ResponseState
from agent.processing.event_loader import EventLoader

# Initialize components
state = ResponseState()
agent = ResponseAgent(state, models_dir="models")

# Run single cycle
agent.run_once("data/test_events.ndjson")

# Run continuous monitoring
agent.run_continuous("data/test_events.ndjson", check_interval=300)
```

## Response Strategies

The agent implements several response strategies based on attack classification:

1. **IP Blocking**: Blocks IPs with high attack confidence
2. **2FA Enforcement**: Requires 2FA for suspicious accounts
3. **Rate Limiting**: Implements temporary rate limits
4. **Alert Generation**: Creates alerts for security teams

## Configuration

Response thresholds and strategies can be configured through the ResponseState class:

```python
state = ResponseState(
    block_threshold=0.8,      # Block IPs with confidence > 0.8
    unblock_after=3600,       # Unblock after 1 hour
    max_alerts_per_hour=10    # Rate limit alerts
)
```

## Integration

The agent integrates with:
- ML models for classification
- Rule-based detection system
- Web application for real-time monitoring
- Alert notification systems

## Monitoring

The agent provides monitoring capabilities:
- Response action logging
- Performance metrics
- State persistence
- Error handling and recovery