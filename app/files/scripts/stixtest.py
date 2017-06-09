import json, sys
try:
    import stix
    import cybox
    import mixbox
except ImportError:
    print json.dumps({'success' : 0})
    sys.exit(1)
print json.dumps({'success' : 1, 'stix' : stix.__version__, 'cybox' : cybox.__version__, 'mixbox' : mixbox.__version__})
sys.exit(1)
