from stix.core import STIXPackage
import sys
import json
import os


def loadPackage(filename):
    try:
        data = STIXPackage.from_xml(filename)
    except:
        print json.dumps(
            {'success': 0,
                'message': 'Could not read sightings file. ' + filename})
        sys.exit(1)
    try:
        data = data.to_dict()
        return data
    except:
        print json.dumps(
            {'success': 0, 'message': 'Could not parse the sightings file.'})
        sys.exit(1)


def saveFile(data, filename):
    try:
        with open(filename, 'w') as f:
            f.write(json.dumps(data))
            f.close()
    except:
        print json.dumps(
            {'success': 0, 'message': 'Could not write response file.'})
        sys.exit(1)
    return True


def getValueFromRelatedObservables(observables):
    values = []
    for observable in observables:
        temp = getValuesFromObservable(observable["observable"])
        if temp:
            values.extend(temp)
    return values


def getValueFromIndicator(indicator):
    return getValuesFromObservable(indicator["observable"])


def getValuesFromObservable(observable):
    returnValue = observable.get("object", {}).get("properties", {})
    returnValue = returnValue.get("value")
    if isinstance(returnValue, basestring):
        return [returnValue]
    elif returnValue is None:
        return []
    else:
        return returnValue["value"]


def main(args):
    filename = sys.path[0] + "/tmp/" + args[1]
    stix_package = loadPackage(filename)
    data = {}
    for indicator in stix_package["indicators"]:
        data["values"] = []
        for sighting in indicator["sightings"]["sightings"]:
            if "timestamp" in sighting:
                data["timestamp"] = sighting["timestamp"]
            if "related_observables" in sighting:
                data["values"] = getValueFromRelatedObservables(
                    sighting["related_observables"]["observables"])
        if not data["values"]:
            data["values"] = getValueFromIndicator(indicator)
    saveFile(data, filename + '.out')
    print json.dumps({'success': 1, 'message': ''})


if __name__ == "__main__":
    main(sys.argv)
