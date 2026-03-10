#!/usr/bin/env python3
"""
Agent Runner Script

Runs AI response agent for EaglePro.
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.runner import main

if __name__ == "__main__":
    main()