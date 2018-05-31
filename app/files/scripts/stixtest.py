import json, sys
results = {
    'success': 1,
    'stix': 0,
    'cybox': 0,
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
    pass

try:
    import mixbox
    results['mixbox'] = mixbox.__version__
except Exception:
    pass

print(json.dumps({
    'success' : results['success'],
    'stix' : results['stix'],
    'cybox' : results['cybox'],
    'mixbox' : results['mixbox'],
    'pymisp' : results['pymisp']
}))
sys.exit(1)

