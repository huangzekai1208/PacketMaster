from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_script_module(relative_path: str, module_name: str):
    """Load a module from the hyphenated speed-analyze scripts directory."""
    scripts_dir = Path(__file__).resolve().parents[1] / "speed-analyze" / "scripts"
    module_path = scripts_dir / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load script module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module
