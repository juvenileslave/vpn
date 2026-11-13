#!/usr/bin/env python3
"""Use the actual lifecycle against an intentionally invalid nginx candidate."""
from pathlib import Path
import sys

sys.path.insert(0, '/usr/local/libexec/cover-site')
import lifecycle

lifecycle.activate(Path(sys.argv[1]))
