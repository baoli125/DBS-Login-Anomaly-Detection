#!/usr/bin/env python3
"""
Agent Trình chạy Script

Runs AI phản hồi agent for EaglePro.
"""

import sys
import os
from pathlib import Path

# Thêm thư mục gốc dự án vào path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from agent.runner import main

if __name__ == "__main__":
    main()