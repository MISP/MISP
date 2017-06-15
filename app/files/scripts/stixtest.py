import json, sys
try:
    import stix
    import cybox
except ImportError:

    print(json.dumps({'success' : 0}))
    sys.exit(1)
try:
    import mixbox
    print(json.dumps({'success' : 1, 'stix' : stix.__version__, 'cybox' : cybox.__version__, 'mixbox' : mixbox.__version__}))
except ImportError:
    print(json.dumps({'success' : 1, 'stix' : stix.__version__, 'cybox' : cybox.__version__, 'mixbox' : 0}))
sys.exit(1)
