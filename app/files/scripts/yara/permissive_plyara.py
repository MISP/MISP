import plyara
from plyara.exceptions import ParseError
from plyara import *
from unittest import mock
import re
import string

PERMISSIVE_MODE = True # set to False to use the regular, strict, plyara parser for debugging


_original_match = re.match
def _multiline_match(pattern, string, flags=0):
    return _original_match(pattern, string, flags=flags | re.DOTALL | re.MULTILINE)


class _MultilinePlyara(plyara.Plyara):

    def parse_string(self, input_string):
        with mock.patch.object(re, 'match', _multiline_match):
            return super(plyara.Plyara, self).parse_string(input_string)


class PermissivePlyara():

    def parse_string(self, input_string):
        try:
            if PERMISSIVE_MODE:
                return self._permissive_parse_string(input_string)
            else:
                return plyara.Plyara().parse_string(input_string)
        except ParseError as e:
            raise
        # some errors are not properly caught by plyara
        # convert everything to ParseError to avoid uncatchable crashes
        except Exception as e:
            raise ParseError('Uncaught plyara exception ({}): {}'.format(type(e).__name__, str(e)), None, None)

    def _permissive_parse_string(self, input_string, fix_notes=None, original_error=None):
        if not fix_notes:
            fix_notes = set()
        # with mock.patch.object(re, 'match', overridden_match):
        try:
            # res = super(Plyara, self).parse_string(input_string) # weird failures, couldn't debug. possibly due to internal state
            # re-instanciating playra to avoid internal state errors
            res = _MultilinePlyara().parse_string(input_string)
            if fix_notes:
                for r in res:
                    r['permissive_plyara_fixed'] = True
                    r['permissive_plyara_comment'] = '. '.join(fix_notes)
            return res
        except ParseError as e:
            if not original_error:
                original_error = e
            str_error = str(e)
            fixed = input_string
            if str_error.startswith('Illegal character') and any(elem in str_error for elem in '”“″'):
                fixed = _fix_quotes(input_string)
                fix_notes.add('Wrong quotes characters')
            elif str_error.startswith('Unknown text Rule'):
                fixed = _fix_capital(input_string)
                fix_notes.add('Rule => rule')
            elif str_error.startswith('Illegal character'):
                fixed = _fix_illegal_chars(input_string)
                fix_notes.add('Illegal characters')
            elif str_error.startswith('Unknown text { for token of type LBRACE') \
                and input_string.lstrip().startswith \
                and input_string.rstrip().endswith('}'):
                fixed = _fix_noname(input_string)
                fix_notes.add('Missing rule name')
            elif re.match(r'Unknown text\s?_\s?for token of type ID', str_error):
                fixed = _fix_spaced_underscores(input_string)
                fix_notes.add("' _ ' => '_'")
            else:
                fixed = _fix_magic(input_string)
                fix_notes.add('Magic fix (highly unreliable)')

            if fixed != input_string:
                return self._permissive_parse_string(fixed, fix_notes, original_error)
            else:
                raise original_error
                # best_error = 'BEST GUESS ERROR: {}\n'.format(str(e))
                # best_guess = 'BEST GUESS: \n{}'.format(input_string)
                # raise ParseError(best_error+best_guess, None, None) from e


def _fix_quotes(yara_src):
    repaired = yara_src
    repaired = repaired.replace('”', '"')
    repaired = repaired.replace('“', '"')
    repaired = repaired.replace('″', '"')
    return repaired

def _fix_capital(yara_src):
    repaired = yara_src.replace('Rule', 'rule')
    return repaired

def _fix_illegal_chars(yara_src):
    repaired = ''.join(filter(lambda x: x in string.printable, yara_src))
    return repaired

def _fix_noname(yara_src):
    repaired = 'rule UnnamedRule ' + yara_src
    return repaired

def _fix_spaced_underscores(yara_src):
    repaired = yara_src.replace(' _ ', '_')
    return repaired

def _fix_magic(yara_src):
    repaired = ''
    for line in yara_src.splitlines():
        if '//' not in line:
            repaired += line
        else:
            repaired += '\n{}\n'.format(line)
    return repaired if repaired else yara_src


# Keeping this code for later as it contains more advanced fixes

# def _try_simple_repairs(yara_src, error):
#     reasons = []
#     # common quotes error
#     repaired = yara_src
#     repaired = repaired.replace('”', '"')
#     repaired = repaired.replace('“', '"')
#     repaired = repaired.replace('″', '"')
#     if repaired != yara_src:
#         reasons.append('wrong quotes characters')
#     # missing rule declaration
#     if repaired.strip().startswith('{'):
#         reasons.append('missing rule name')
#         rulename = 'UnnamedRule'
#         repaired = 'rule {} {}'.format(rulename, repaired)
#     # capital letter rule declaration
#     if repaired.strip().startswith('Rule'):
#         reasons.append('Rule => rule')
#         repaired = repaired.replace('Rule', 'rule')
#     if 'Illegal character' in str(error):
#         repaired = ''.join(filter(lambda x: x in string.printable, repaired))
#         reasons.append('illegal characters')
#     # badly formated declaration:
#     # check if rule matches format : DATA rule DECLARATION { CONTENT } DATA
#     split_source = re.split(r'rule\s(.*?){(.*)}', repaired, flags=re.MULTILINE|re.DOTALL)
#     if len(split_source) == 4:
#         split_source = {'pre': split_source[0],
#                         'declaration': split_source[1].replace(' ', '').rstrip().rstrip(':'),
#                         'content': split_source[2],
#                         'post': split_source[3]}
#         quoted_content = re.split(r'\"(.+?)\"', split_source['content'], re.MULTILINE | re.DOTALL)
#         nolinebreak_content = ''
#         for chunk in quoted_content:  # remove line breaks in strings and meta
#             if chunk.startswith('"') and chunk.endswith('"'):
#                 nolinebreak_content += ''.join(chunk.splitlines())
#         reassembled = 'rule {} {{ {} }}'.format(split_source['declaration'], split_source['content'])
#         repaired = reassembled
#     return repaired, reasons
