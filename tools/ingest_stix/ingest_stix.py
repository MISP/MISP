import json
from argparse import ArgumentParser
from pymisp import ExpandedPyMISP
from pymisp.exceptions import PyMISPError

def ingest_to_misp(path, version, url, key, verifycert):
    try:
        misp = ExpandedPyMISP(url, key, verifycert)
    except PyMISPError:
        return f'Unable to connect to MISP ({url}). Please make sure the API key and the URL are correct.'

    errors = []
    for filename in path:
        response = misp.upload_stix(filename, version=version)
        if response.status_code != 200:
            errors.append(filename)

    if errors:
        file = "file: " if len(errors) == 1 else "files:\n- "
        print_errors = '\n- '.join(errors)
        return f'Error with the ingestion of the following {file}{print_errors}'
    return f'Successfully ingested {len(path)} STIX {version} files.'


if __name__ == '__main__':
    parser = ArgumentParser(description='')
    parser.add_argument('--misp_url', help='URL of the MISP instance you want to connect to.')
    parser.add_argument('--misp_key', help='API key of the user you want to use.')
    parser.add_argument('--misp_verifycert', action='store_true', help='To check the validity of the certificate.')
    parser.add_argument('--version', required=True, help='STIX version (1 or 2).')
    parser.add_argument('--path', nargs='+', required=True, help='Path to the STIX files to ingest.')
    args = parser.parse_args()

    if args.version not in ('1', '2'):
        sys.exit('Please specify the STIX version: 1 or 2.')
    with open('setup.json', 'rt', encoding='utf-8') as f:
        default_setup = json.loads(f.read())
    features = ('misp_url', 'misp_key', 'misp_verifycert')
    setup = [getattr(args, feature) if getattr(args, feature) else default_setup[feature] for feature in features]
    print(ingest_to_misp(args.path, args.version, *setup))
