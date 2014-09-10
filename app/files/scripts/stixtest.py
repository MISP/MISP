import json, sys
try:
    import stix
    import cybox
except ImportError:
    print json.dumps({'success' : 0})
    sys.exit(1)
print json.dumps({'success' : 1})
sys.exit(1)
