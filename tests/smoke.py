#!/usr/bin/env python3
"""Local content-transfer smoke test against the Go agent's real probe function."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
subprocess.run(['go','test','-v','./...'],cwd=ROOT/'agent',check=True)
print('SMOKE OK: full response, short response, interrupted response')
