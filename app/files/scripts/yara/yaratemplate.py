from permissive_plyara import PermissivePlyara
from permissive_plyara import ParseError
import plyara
from plyara import utils
import warnings
import re
__version__ = '0.1'
__yara_version__ = '8.1'


class YaraTemplateException(Exception):
    def __init__(self, message, source=None):
        super(Exception, self).__init__(message)
        self.source = source


class YaraLexerException(YaraTemplateException):
    pass


class YaraTemplateRuleConflictException(YaraTemplateException):
    pass


class YaraTemplateRuleDependencyException(YaraTemplateException):
    pass


class YaraRuleTemplate:

    class _YaraStringsItem:
        def __init__(self, stringstype, name, value,
                        modifiers, force_escape=True):
            if not name.startswith('$'):
                name = '${}'.format(name)
            if stringstype == 'byte':
                value = '{{ {} }}'.format(value)
            elif stringstype == 'text':
                if force_escape:
                    value = yara_escape_str(value)
                value = '"{}"'.format(value)
            elif stringstype == 'regex':
                if force_escape:
                      # escape all unescaped '/'
                    value = re.sub(r'(?<=[^\\])/', r'\\'+r'/', value)
                # # quick and dirty way to get rid of illegal line carriages in regexes
                # value = ''.join([l.strip() for l in value.splitlines()])
                value = '/{}/'.format(value)
            self.stringstype = stringstype
            self.name = name
            self.value = value
            self.modifiers = modifiers

        def __str__(self):
            name = self.name
            value = self.value
            modifiers = ' '.join(self.modifiers)
            return "{} = {} {}".format(name, value, modifiers)

    def __init__(self, rulename):
        self.rulename = rulename
        self.ruletags = set()
        self.rulescopes = set()  # can be empty, 'global' or 'private'
        self.meta = set()
        self.strings = []  # list instead of name=>value dict because of anonymous strings
        self.condition = ''
        self.file_dependencies = []
        self.rule_dependencies = []
        self.module_dependencies = []
        self.loaded_from_source = False
        self.autofixed = False
        self.autofixed_comment = ''

    @classmethod
    def from_source(cls, yara_source):
        if not isinstance(yara_source, str):
            yara_source = str(yara_source)
        try:
            plyara_parsed = PermissivePlyara().parse_string(yara_source)
        except ParseError as e:
            raise YaraLexerException(str(e), yara_source)
        rules = []
        try:
            for plyara_rule in plyara_parsed:
                rule = cls._from_plyara(plyara_rule)
                rules.append(rule)
            return rules
        except YaraTemplateException as e:
            e.source = yara_source
            raise

    # Creates a YaraRuleTemplate from plyara's array output format
    @classmethod
    def _from_plyara(cls, plyara_out):
        plyara_out = cls._ensure_one_rule(plyara_out)
        rule = cls(plyara_out['rule_name'])
        rule.loaded_from_source = True
        if 'tags' in plyara_out:
            rule.ruletags.update(plyara_out['tags'])
        if 'scopes' in plyara_out:
            rule.rulescopes.update(plyara_out['scopes'])
        if 'metadata' in plyara_out:
            for m in plyara_out['metadata']:
                for k, v in m.items():
                    rule.add_meta(k,v)
        if 'strings' in plyara_out:
            for s in plyara_out['strings']:
                s_modifiers = s['modifiers'] if 'modifiers' in s else []
                if s['type'] == 'byte' or s['type'] == 'regex':
                    value = s['value'][1:-1]
                else:
                    value = s['value']
                rule._strings(s['type'], s['name'], value, s_modifiers)
        if 'raw_condition' in plyara_out:
            _, cond = plyara_out['raw_condition'].split("condition:",1)
            rule.condition = cond
            # parsing conditions is too tricky and prone to errors
            # rule.condition = " ".join(plyara_out['condition_terms'])
        else:
            return rule # stop and return to avoid uncaught plyara exceptions
        if 'includes' in plyara_out:
            rule.file_dependencies = plyara_out['includes']
        rule.rule_dependencies = plyara.utils.detect_dependencies(plyara_out)
        rule.module_dependencies = plyara.utils.detect_imports(plyara_out)
        if 'permissive_plyara_fixed' in plyara_out \
            and plyara_out['permissive_plyara_fixed']:
            rule.autofixed = True
        if 'permissive_plyara_comment' in plyara_out:
            rule.autofixed_comment = plyara_out['permissive_plyara_comment']
        return rule

    def __str__(self):
        includes = set(self.file_dependencies)
        imports = set(self.module_dependencies)
        includes_str = '\n'.join(['include "{}"'.format(i) for i in includes])
        imports_str = '\n'.join(['import "{}"'.format(i) for i in imports])
        scopes = (' '.join(self.rulescopes) + ' ') if self.rulescopes else ''
        tags_str = (' : ' + ' '.join(self.ruletags)) if self.ruletags else ''
        declaration = '{}rule {}{}'.format(scopes, self.rulename, tags_str)
        meta_section = ''
        strings_section = ''
        condition_section = ''
        if self.meta:
            sorted_meta = sorted(self.meta)
            meta_section += '\tmeta:'
            for (m, v) in sorted_meta:
                meta_section += '\n\t\t{} = "{}"'.format(m, v)
            meta_section += '\n'
        if self.strings:
            strings_section += '\tstrings:'
            for s in self.strings:
                strings_section += '\n\t\t{}'.format(s)
            strings_section += '\n'
        if self.condition:
            condition_section += '\tcondition:'
            for cond_line in self.condition.splitlines():
                stripped = cond_line.strip()
                if stripped:
                    condition_section += '\n\t\t{}'.format(stripped)
        result = '{}\n{}\n{}\n{{\n{}{}{}\n}}'.format(includes_str,
                                                    imports_str,
                                                    declaration,
                                                    meta_section,
                                                    strings_section,
                                                    condition_section)
        if not self.condition:
            result = '// this rule will not compile (mandatory "condition" section missing)\n{}'.format(result)
        return result

    def add_meta(self, meta_key, meta_value):
        # remove illegal characters (same filter as "strings" entries)
        meta_value = yara_escape_str(str(meta_value))
        self.meta.add((meta_key, meta_value))
        return self

    def set_name(self, name):
        # replace forbidden characters with '_'
        name = re.sub(r'[^A-Za-z0-9_]', '_', name)
        if name[0].isdigit():
            name = '_{}'.format(name)
        self.rulename = name
        return self

    def add_tag(self, tag):
        # replace forbidden characters with '_'
        tag = re.sub(r'[^A-Za-z0-9_]', '_', tag)
        if tag[0].isdigit():
            tag = '_{}'.format(tag)
        self.ruletags.add(tag)
        return self

    def set_condition(self, condition_expression):
        self.condition = condition_expression
        return self

    def and_condition(self, condition_expression):
        if not self.condition:
            self.condition = '{}'.format(condition_expression)
        else:
            self.condition = '{}\n and {}'.format(self.condition,
                                                condition_expression)
        return self

    def or_condition(self, condition_expression):
        if not self.condition:
            self.condition = '{}'.format(condition_expression)
        else:
            self.condition = '{}\n or {}'.format(self.condition,
                                                condition_expression)
        return self

    # Adds an entry to the 'strings' section
    # str_type can be 'byte', 'text' or 'regex'
    # name could be None for anonymous strings
    def _strings(self, str_type, name, value, modifiers):
        if name == '$' or not name:
            name = '$'
        force_escape = False if self.loaded_from_source else True
        str_entry = self._YaraStringsItem(str_type, name, value, modifiers, force_escape)
        if str_entry.name == '$' or str_entry.name not in (o.name for o in self.strings):
            self.strings.append(str_entry)
        else:
            raise YaraTemplateException(
                'There is already a string named "{}"'.format(str_entry.name))
        return self

    # adds a 'byte' entry ({}) to strings section (default: nocase ascii wide)
    def strings_hex(self, name, value):
        self._strings('byte', name, value, [])
        return self

    # adds a 'text' entry ("") to strings section (default: nocase ascii wide)
    def strings_text(self, name, value, escape_newlines=True, nocase=True,
                        ascii=True, wide=True, xor=False, fullword=False):
        modifiers = []
        # escaping unescaped double quotes
        if nocase:
            modifiers.append('nocase')
        if ascii:
            modifiers.append('ascii')
        if wide:
            modifiers.append('wide')
        if xor:
            modifiers.append('xor')
        if fullword:
            modifiers.append('fullword')
        if escape_newlines and len(value.splitlines()) > 1:
            # only regex supports system-agnostic line breaks
            value = _str2yara_regex(value)
            self._strings('regex', name, value, modifiers)
        elif len(value.splitlines()) > 1:
            for line in value.splitlines():
                self._strings('text', name, line, modifiers)
                # TODO: imporvement: group lines with 'all of $*'
                # instead of (\r|\r\n|\n|\x1E)
        else:
            self._strings('text', name, value, modifiers)
        return self

    # adds a 'regex' entry (//) to strings section (default: nocase ascii wide)
    def strings_regex(self, name, value, nocase=True, ascii=True,
                        wide=True, fullword=False):
        modifiers = []
        if nocase:
            modifiers.append('nocase')
        if ascii:
            modifiers.append('ascii')
        if wide:
            modifiers.append('wide')
        if fullword:
            modifiers.append('fullword')
        self._strings('regex', name, value, modifiers)
        return self

    # adds an 'include' statement
    def add_file_dependency(self, file_name):
        if file_name not in self.file_dependencies:
            self.file_dependencies.append(file_name)
        return self

    # adds an rule dependency, useful to determine the order in a group of rules
    def add_rule_dependency(self, rule_name):
        if rule_name not in self.rule_dependencies:
            self.rule_dependencies.append(rule_name)
        return self

    # adds an 'import' dependency
    def add_module_dependency(self, module_name):
        if module_name not in self.module_dependencies:
            self.module_dependencies.append(module_name)
        return self

    @staticmethod
    def _ensure_one_rule(plyara_output):
        if isinstance(plyara_output, list):
            if len(plyara_output) != 1:
                error_msg = 'Single rule expected, \
                    string contains {} rules'.format(len(plyara_output))
                raise YaraTemplateException(error_msg)
            else:
                return plyara_output[0]
        else:
            return plyara_output


# =============== Tools ===================

# replaces special characters in yara 'text' strings
def yara_escape_str(pattern):
    _special_chars_map = {
        ord(b'\\'): '\\\\',
        ord(b'"'): '\\"',
        ord(b'\n'): '\\n',
        ord(b'\t'): '\\t',
        ord(b'\r'): '\\\\r'
    }
    return pattern.translate(_special_chars_map)


# helps convert a python string to a yara 'regex' string, escapes special chars
# handles newlines by making them system-agnostic and optional
def _str2yara_regex(pattern):
    _special_chars_map = {

        ord(b'/'): '\\/',
        # covers '\' and all escapes not valid in python but valid in yara:
        # \w \W \s \S \d \D \B
        ord(b'\\'): '\\\\',
        ord(b'^'): '\\^',
        ord(b'$'): '\\$',
        ord(b'|'): '\\|',
        ord(b'('): '\\(',
        ord(b')'): '\\)',
        ord(b'['): '\\[',
        ord(b']'): '\\]',

        ord(b'*'): '\\*',
        ord(b'+'): '\\+',
        ord(b'?'): '\\?',
        ord(b'{'): '\\{',
        ord(b'}'): '\\}',

        ord(b'\t'): '\\t',
        ord(b'\f'): '\\f',
        ord(b'\a'): '\\a',
        # covers \n \r\n \r and other exotic line breaks (\x1E)
        ord(b'\n'): '(\\x0D|\\x0A\\x0D|\\x0A|\\x1E)?',

        ord(b'\b'): '\\b'
    }
    pattern = '\n'.join(pattern.splitlines())
    return pattern.translate(_special_chars_map)
