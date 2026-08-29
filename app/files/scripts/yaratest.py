#!/usr/bin/env python3

import json
import sys
results = {
    'success': 1,
    'plyara': 0,
}
try:
    import plyara
    results['plyara'] = 1
except Exception:
    results['plyara'] = 0
    results['success'] = 0

print(json.dumps({
    'success': results['success'],
    'plyara': results['plyara']
}))
sys.exit(0)
