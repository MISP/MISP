import json
from argparse import ArgumentParser
from pymisp import ExpandedPyMISP

def query_misp(args):
    # VERY IMPORTANT FEATURE HERE
    features = ('returnFormat', 'eventid', 'withAttachments', 'type')
    # END OF THE VERY IMPORTANT FEATURE

    body = {feature: getattr(args, feature)[0] if isinstance(getattr(args, feature), list) and len(getattr(args, feature)) == 1 else getattr(args, feature) for feature in features if hasattr(args, feature) and getattr(args, feature)}

    with open(args.setup, 'rt', encoding='utf-8') as f:
        setup = json.loads(f.read())

    misp = ExpandedPyMISP(setup['misp_url'], setup['misp_key'], setup['misp_verifycert'])
    result = misp.direct_call(setup['relative_path'], body)

    to_write = (json.dumps(result[0], indent=4) if isinstance(result, list) else json.dumps(result, indent=4) if isinstance(result, dict) else result)

    with open(args.output, 'wt', encoding='utf-8') as f:
        f.write(to_write)

if __name__ == '__main__':
    parser = ArgumentParser(description='Gather MISP Event collections based on the parameters')
    parser.add_argument('--setup', default='setup.json', help='Path to the file containing the required setup to connect to the MISP server.')
    parser.add_argument('--returnFormat', type=str, required=True, help='Export format type')
    parser.add_argument('--eventid', nargs='+', help='Filter on Event id')
    parser.add_argument('--type', type=str, help='Attribute type')
    parser.add_argument('--withAttachments', type=int, help='Export Attributes with the attachments')
    parser.add_argument('-o', '--output', type=str, required=True, help='Name of the output file to save the result of the query in')
    args = parser.parse_args()
    query_misp(args)
