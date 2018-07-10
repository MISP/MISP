#!/usr/bin/env python3

import json
import sys
results = {
    'success': 1,
    'stix': 0,
    'cybox': 0,
    'mixbox': 0,
    'maec': 0,
    'pymisp': 0
}
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

print(json.dumps({
    'success': results['success'],
    'stix': results['stix'],
    'cybox': results['cybox'],
    'mixbox': results['mixbox'],
    'maec': results['maec'],
    'pymisp': results['pymisp']
}))
sys.exit(1)
