#!/usr/bin/env python3
import sys
import json
import importlib
from pathlib import Path
MODULE_TO_DIRECTORY = {
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "misp-stix": "misp-stix",
    "maec": "python-maec",
}
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1

results = {
    'success': 1,
    'stix': 0,
    'cybox': 0,
    'mixbox': 0,
    'maec': 0,
    'stix2': 0,
    'misp-stix': 0,
    'pymisp': 0
}

MODULE_TO_DIRECTORY = {
    "stix2": "cti-python-stix2",
    "stix": "python-stix",
    "cybox": "python-cybox",
    "mixbox": "mixbox",
    "misp_stix_converter": "misp-stix",
    "maec": "python-maec",
}
# Load module from system package and if not found use local version
_CURRENT_PATH = Path(__file__).resolve().parent
_CURRENT_PATH_IDX = 0
for module_name, dir_path in MODULE_TO_DIRECTORY.items():
    try:
        importlib.import_module(module_name)
    except ImportError:
        sys.path.insert(_CURRENT_PATH_IDX, str(_CURRENT_PATH / dir_path))
        _CURRENT_PATH_IDX += 1

try:
    import pymisp
    results['pymisp'] = pymisp.__version__
except Exception:
    results['success'] = 0

try:
    import stix
    results['stix'] = stix.__version__
except Exception:
    results['success'] = 0

try:
    import cybox
    results['cybox'] = cybox.__version__
except Exception:
    results['success'] = 0

try:
    import mixbox
    results['mixbox'] = mixbox.__version__
except Exception:
    results['success'] = 0

try:
    import maec
    results['maec'] = maec.__version__
except Exception:
    results['success'] = 0

try:
    import stix2
    results['stix2'] = stix2.__version__
except Exception:
    results['success'] = 0

try:
    import misp_stix_converter
    results['misp-stix'] = misp_stix_converter.__version__
except Exception:
    results['success'] = 0

print(json.dumps(results))
sys.exit(0)
