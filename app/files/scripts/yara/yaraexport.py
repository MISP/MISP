from misp2yara import mispevent2yara, mispattrs2yara, MISPRuleTemplate
import sys
import json
import os
from optparse import OptionParser


def rules2json_export(rules, extra_comment=''):
    return json.dumps([rule2json_export(r) for r in rules])

def rule2json_export(rule, extra_comment=''):
    json_dict = {
        'value': str(rule),
        'comment': '',
        'valid': None
    }
    if isinstance(rule, MISPRuleTemplate):
        if rule.loaded_from_source:
            json_dict['comment'] += 'Loaded from source. '
        else:
            json_dict['comment'] += 'Generated. '
        if rule.autofixed:
            json_dict['comment'] += 'May be unreliable due to automatic repairs: '
            json_dict['comment'] += rule.autofixed_comment
        json_dict['valid'] = True
        return json_dict
    else:
        json_dict['comment'] += 'Broken yara attribute. Could not parse or repair.'
        json_dict['valid'] = False
        return json_dict

def file_is_empty(path):
    return os.stat(path).st_size==0

def output_json(output_path, output_rules):
    with open(output_path, 'a+', encoding='utf-8') as f:
        if file_is_empty(output_path):
            pass
        else:
            f.write(',')
        to_write = rules2json_export(output_rules)[1:-1]
        f.write(to_write)

def output_raw(output_path, output_rules):
    with open(output_path, 'a+', encoding='utf-8') as f:
        to_write = '\n\n'.join([str(r) for r in output_rules])
        f.write(to_write)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="in_file",
                      help="input file", metavar="FILE")
    parser.add_option("-g", "--out-generated", dest="out_gen",
                      help="output for generated rules", metavar="FILE")
    parser.add_option("-a", "--out-asis", dest="out_asis",
                      help="output for as-is rules", metavar="FILE")
    parser.add_option("-r", "--raw",
                      action="store_true", dest="raw_output", default=False,
                      help="outputs raw yara rules instead of json-structured rules")
    (options, args) = parser.parse_args()

    in_path = options.in_file
    out_path_gen = options.out_gen
    out_path_asis = options.out_asis
    raw_mode = options.raw_output

    loaded = None
    with open(in_path, 'r', encoding='utf-8') as in_file:
        content = in_file.read()
        if content:
            loaded = json.loads(content)['response']
            # raise Warning("loaded {}".format(content))
            if 'Attribute' in loaded:
                generated, asis_valid, asis_broken = mispattrs2yara(loaded['Attribute'])
            elif isinstance(loaded, list):
                generated = []
                asis_valid = []
                asis_broken = []
                for event_dict in loaded:
                    if 'Event' in event_dict:
                        curr_generated, curr_asis_valid, curr_asis_broken = mispevent2yara(event_dict['Event'])
                        generated += curr_generated
                        asis_valid += curr_asis_valid
                        asis_broken += curr_asis_broken
                    else:
                        raise Exception('Json doesn\'t seem to be an list of attributes or events')
            else:
                raise Exception('Json doesn\'t seem to be an list of attributes or events')
            if raw_mode:
                output_raw(out_path_gen, generated)
                output_raw(out_path_asis, asis_valid + asis_broken)
            else:
                output_json(out_path_gen, generated)
                output_json(out_path_asis, asis_valid + asis_broken)
