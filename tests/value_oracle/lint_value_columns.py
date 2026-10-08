#!/usr/bin/env python3
"""
Static lint: where does PHP code under app/ use the attribute value columns
(value1, value2, and the virtual Attribute.value) in SQL?

Each reference inside a PHP string literal is classified by what the string
is used for:

    sql        SQL text: raw queries, string subqueries, virtual-field
               expressions, anything concatenated with SQL keywords
    condition  a find/paginate/updateAll/deleteAll condition, as a key
               ('Attribute.value1 LIKE' => $x) or a string condition
    fields     a selected column
    order      an ORDER BY term (including paginator sort keys)
    group      a GROUP BY term
    write      a write-side column list (save fieldList, updateAll SET,
               the *_FIELDS whitelists)
    dynamic    a bare column name used as data that SQL is composed from
               elsewhere (column loops, filter maps); needs a human look

A query term whose column is composed at run time ('Attribute.' . $field)
may name a value column too; it is reported with the column '?', and
'Attribute.value' . $n with the column 'value?'.

PHP-side array access ($row['value1']), data keys and prose are not SQL;
--show-ignored lists them. Comments and text outside PHP tags are never
read. A bare 'value' is reported only inside a query on an attribute model
(it is the virtual field there). Findings matched by the allowlist are
reported apart (--show-allowed).

Usage:
    lint_value_columns.py [--root DIR] [--json PATH] [--show-allowed]
                          [--show-ignored] [--strict] [PATH...]

Report-only by default (exit 0). --strict exits 1 when any finding is
outside the allowlist.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

KINDS = ('sql', 'condition', 'fields', 'order', 'group', 'write', 'dynamic')
EXTENSIONS = ('.php', '.ctp')
SKIP_DIRS = ('app/Vendor', 'app/Lib/cakephp', 'app/tmp', 'app/files')

ALLOW = [
    ('app/Lib/Migration/LegacyMigrationsTrait.php', '*',
     'frozen 2.x upgrade corpus; runs only against the old schema'),
    ('app/Lib/Migration/Migrations/*', '*',
     'migrations convert the text columns'),
    ('app/Lib/Tools/AttributeValueBackfillTool.php', '*',
     'the backfill sets the value ids from the text columns'),
    ('app/Test/BaselineGeneratorTest.php', '*',
     'schema tooling fixtures; no attribute query'),
    ('app/Test/MigrationGrammarTest.php', '*',
     'schema tooling fixtures; no attribute query'),
    ('app/Test/SchemaBuilderTest.php', '*',
     'schema tooling fixtures; no attribute query'),
    ('app/Test/DatasourceCapabilitiesTest.php', '*',
     'quoting fixtures; no attribute query'),
    ('app/Test/QueryPlanSummaryTest.php', '*',
     'plan reducer fixtures; no attribute query'),
    ('app/Controller/Component/RestSearchComponent.php',
     'RestSearchComponent::$paramArray',
     'public filter names, not columns'),
    ('app/Model/MispAttribute.php', 'MispAttribute::set_filter_tags',
     'filter names that rank selectivity, not columns'),
    ('app/Model/AttributeValue.php', '*',
     'the value dictionary: maps the value columns to their ids'),
    ('app/Lib/Tools/ValueConditionRewriter.php', '*',
     'moves conditions on the value columns to the ids'),
    ('app/Lib/Tools/ValueFieldTranslator.php', '*',
     'moves the value field of field lists and orders to the ids'),
    ('app/Test/AttributeValue*Test.php', '*',
     'value table tests: the text columns are their reference or data'),
    ('app/Test/ValueConditionRewriter*.php', '*',
     'rewriter tests: the 2.x conditions are their reference'),
    ('app/Test/ValueFieldTranslatorTest.php', '*',
     'translator tests: the value field is their input'),
]

ATTRIBUTE_ALIASES = {'Attribute', 'ShadowAttribute', 'ReferencedAttribute',
                     'MispAttribute'}
ATTRIBUTE_CLASSES = {'MispAttribute', 'ShadowAttribute'}
FIND_CALLS = {'find', 'paginate', 'field', 'hasany', 'updateall',
              'deleteall'}
ATTRIBUTE_FETCHERS = {'fetchattributes', 'fetchattributessimple',
                      'fetchattributesimple', 'fetchattributesinchunks',
                      'fetchattributesinchunkssingle'}
SQL_CALLS = {'query', 'fetchall', 'execute', 'rawquery', 'prepare', 'exec'}
FORM_CALLS = {'input', 'textarea', 'hidden', 'control', 'radio', 'checkbox'}
CONDITION_KEYS = {'conditions', 'or', 'and', 'not', 'xor'}
KEY_KINDS = {'fields': 'fields', 'order': 'order', 'sort': 'order',
             'group': 'group', 'fieldlist': 'write',
             'data_path': 'data', 'path': 'data'}
CONTROL = {'if', 'elseif', 'while', 'for', 'switch', 'catch', 'match',
           'return', 'echo', 'print', 'and', 'or', 'xor', 'case', 'use',
           'fn', 'function', 'declare', 'exit', 'die', 'include',
           'require', 'include_once', 'require_once', 'yield', 'throw',
           'clone', 'else', 'foreach'}
ARRAY_PREFIX = {'return', 'yield', 'echo', 'print', 'case', 'and', 'or',
                'xor', 'as', 'else', 'throw', 'in', 'clone'}
ASSIGN = {'=', '.=', '+=', '-=', '??=', '|=', '&=', '*='}
CHAIN = {'->', '::', '?->', '\\'}

REF = re.compile(
    r'(?<![\w$])(?:`?(?P<alias>[A-Za-z_]\w*)`?\s*\.\s*)?'
    r'`?(?P<col>value[12]?)`?(?![\w])')
SQL_TEXT = re.compile(
    r'\b(?:SELECT\s|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|'
    r'FROM\s|WHERE\s|JOIN\s|GROUP\s+BY|ORDER\s+BY|HAVING\s|UNION\s|'
    r'(?:USE|FORCE|IGNORE)\s+INDEX|CREATE\s|ALTER\s+TABLE|DROP\s|'
    r'CASE\s+WHEN)|(?i:\b(?:from|join)\s+`?(?:shadow_)?attributes\b)')
COLUMN = r'\.?(?:[A-Za-z_]\w*\.)?value[12]?'
PLAIN = re.compile(r'^\s*' + COLUMN + r'\s*$')
DIRECTION = re.compile(r'^\s*' + COLUMN + r'\s+(?:ASC|DESC)\s*$', re.I)
OPERATOR = re.compile(
    r'^\s*' + COLUMN + r'\s*(?:(?:NOT\s+)?(?:LIKE|IN|BETWEEN|REGEXP|RLIKE)'
    r'\b|IS\b|[=!<>]).*$', re.I | re.S)
WRAPPED = re.compile(r'[A-Za-z_]\w*\([^()]*' + COLUMN + r'\b', re.I)
RELEVANT = re.compile(r'value[12]|Attribute')
ALIAS_DOT = re.compile(r'^(?:%s)\.$' % '|'.join(sorted(ATTRIBUTE_ALIASES)))
COMPARISON = re.compile(
    r'(?:\bLIKE\b|\bIN\b|\bBETWEEN\b|\bIS\b|[=<>!]=?)', re.I)

TOKEN = re.compile(r'''
    (?P<ws>\s+)
  | (?P<close>\?>)
  | (?P<comment>(?://|\#)(?:[^\n?]|\?(?!>))*|/\*.*?(?:\*/|\Z))
  | (?P<heredoc><<<[ \t]*(?P<q>["\']?)(?P<label>[A-Za-z_]\w*)(?P=q)\r?\n)
  | (?P<quote>[\'"`])
  | (?P<var>\$[A-Za-z_\x80-\uffff][\w\x80-\uffff]*)
  | (?P<id>[A-Za-z_\x80-\uffff][\w\x80-\uffff]*)
  | (?P<num>0[xXbB][0-9a-fA-F_]+|\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+)
  | (?P<op>===|!==|<=>|\*\*=|\.\.\.|<<=|>>=|\?\?=|\?->|=>|->|::|==|!=|<>
        |<=|>=|&&|\|\||\?\?|\+\+|--|\+=|-=|\*=|/=|\.=|%=|&=|\|=|\^=|<<|>>
        |\*\*|.)
''', re.X | re.S)


class Tok:
    __slots__ = ('kind', 'text', 'line')

    def __init__(self, kind, text, line):
        self.kind = kind
        self.text = text
        self.line = line

    def __repr__(self):
        return '%s(%r)@%d' % (self.kind, self.text, self.line)


class Node:
    __slots__ = ('kind', 'name', 'line', 'items')

    def __init__(self, kind, line, name=None):
        self.kind = kind
        self.name = name
        self.line = line
        self.items = []


def lex(src):
    """PHP tokens: str (raw literal content), var, id, num, op. Text outside
    PHP tags, comments and whitespace are dropped; '?>' counts as ';'."""
    toks = []
    i, n, line = 0, len(src), 1
    while i < n:
        j = src.find('<?', i)
        if j < 0:
            break
        line += src.count('\n', i, j)
        if src.startswith('<?php', j):
            i = j + 5
        elif src.startswith('<?=', j):
            i = j + 3
            toks.append(Tok('id', 'echo', line))
        else:
            i = j + 2
        i, line = lex_php(src, i, line, toks)
    return toks


def lex_php(src, i, line, toks):
    """Tokenises from i until '?>' or the end; returns (index, line)."""
    n = len(src)
    while i < n:
        m = TOKEN.match(src, i)
        kind = m.lastgroup
        if kind == 'close':
            toks.append(Tok('op', ';', line))
            return m.end(), line
        if kind == 'quote':
            quote = m.group(kind)
            j = string_end(src, i + 1, quote)
            toks.append(Tok('str', src[i + 1:j], line))
            line += src.count('\n', i, j)
            i = j + 1
            continue
        if kind == 'heredoc':
            start = m.end()
            e = re.compile(r'^[ \t]*' + m.group('label') + r'\b',
                           re.M).search(src, start)
            stop = e.start() if e else n
            line += src.count('\n', i, start)
            toks.append(Tok('str', src[start:stop], line))
            line += src.count('\n', start, stop)
            i = e.end() if e else n
            continue
        if kind in ('var', 'id', 'num', 'op'):
            toks.append(Tok(kind, m.group(kind), line))
        else:
            line += src.count('\n', i, m.end())
        i = m.end()
    return i, line


def string_end(src, j, quote):
    """Index of the closing quote; skips escapes and, in double-quoted
    strings, '{$...}' interpolations, which may contain quotes."""
    n = len(src)
    while j < n and src[j] != quote:
        if src[j] == '\\':
            j += 2
        elif quote == '"' and src.startswith('{$', j):
            depth, j = 1, j + 2
            while j < n and depth:
                if src[j] in '\'"':
                    j = string_end(src, j + 1, src[j])
                elif src[j] == '{':
                    depth += 1
                elif src[j] == '}':
                    depth -= 1
                j += 1
        else:
            j += 1
    return j


def is_op(item, *texts):
    return isinstance(item, Tok) and item.kind == 'op' and item.text in texts


def opening_kind(char, prev):
    if char == '{':
        if is_op(prev, '->', '?->', '::') or (
                isinstance(prev, Tok) and prev.kind == 'op'
                and prev.text == '$'):
            return 'paren', None
        return 'block', None
    if char == '[':
        if isinstance(prev, Node) and prev.kind in ('call', 'index',
                                                    'paren'):
            return 'index', None
        if isinstance(prev, Tok) and (
                prev.kind in ('var', 'str')
                or (prev.kind == 'id' and prev.text.lower()
                    not in ARRAY_PREFIX)):
            return 'index', None
        return 'array', None
    if isinstance(prev, Tok) and prev.kind == 'id':
        name = prev.text.lower()
        if name in ('array', 'list'):
            return 'array', None
        if name in CONTROL:
            return 'paren', name
        return 'call', prev.text
    if isinstance(prev, Tok) and prev.kind == 'var':
        return 'call', prev.text
    if isinstance(prev, Node) and prev.kind in ('call', 'index'):
        return 'call', None
    return 'paren', None


def build_tree(toks):
    root = Node('root', 1)
    stack = [root]
    for t in toks:
        cur = stack[-1]
        if t.kind == 'op' and t.text in '([{' and len(t.text) == 1:
            prev = cur.items[-1] if cur.items else None
            kind, name = opening_kind(t.text, prev)
            node = Node(kind, t.line, name)
            cur.items.append(node)
            stack.append(node)
        elif t.kind == 'op' and t.text in ')]}' and len(t.text) == 1:
            if len(stack) > 1:
                stack.pop()
        else:
            cur.items.append(t)
    return root


def split(items, seps):
    parts, cur = [], []
    for item in items:
        if is_op(item, *seps):
            parts.append(cur)
            cur = []
        else:
            cur.append(item)
    parts.append(cur)
    return parts


def statements(items):
    """Split a block body into statements at ';' and after nested blocks,
    keeping a block attached to the statement header before it."""
    out, cur = [], []
    for item in items:
        if is_op(item, ';'):
            out.append(cur)
            cur = []
        elif isinstance(item, Node) and item.kind == 'block':
            cur.append(item)
            out.append(cur)
            cur = []
        else:
            cur.append(item)
    out.append(cur)
    return [s for s in out if s]


def chain_text(items):
    """'$this->Attribute' style text for a var/id chain."""
    return ''.join(i.text for i in items
                   if isinstance(i, Tok) and i.kind in ('var', 'id', 'op'))


def receiver_before(items, index):
    """The member chain in front of items[index] (a call node)."""
    j = index - 1
    if j >= 0 and isinstance(items[j], Tok) and items[j].kind == 'id':
        j -= 1
    chain = []
    while j >= 1 and is_op(items[j], *CHAIN) and isinstance(
            items[j - 1], Tok) and items[j - 1].kind in ('var', 'id'):
        chain[:0] = [items[j - 1], items[j]]
        j -= 2
    return chain_text(chain).rstrip('->:?')


def last_segment(text):
    return re.split(r'->|::|\?->', text)[-1].lstrip('$') if text else ''


def string_key(items):
    """The literal key of an array element or index, if it is one string."""
    strs = [i for i in items if isinstance(i, Tok) and i.kind == 'str']
    if len(items) == 1 and strs:
        return strs[0].text
    return None


class Scanner:
    def __init__(self, path, src):
        self.path = path
        self.lines = src.splitlines()
        self.findings = []
        self.skipped = []

    def scan(self, root):
        self.block(root.items, [])

    def block(self, items, ctx):
        for stmt in statements(items):
            self.statement(stmt, ctx)

    def statement(self, items, ctx):
        if self.declaration(items, ctx):
            return
        for p, item in enumerate(items):
            if is_op(item, *ASSIGN):
                self.assignment(items[:p], items[p + 1:], ctx)
                return
        self.expression(items, ctx, 'expr')

    def declaration(self, items, ctx):
        """function/class bodies: walk the body with the new scope."""
        for p, item in enumerate(items):
            if not (isinstance(item, Tok) and item.kind == 'id'):
                continue
            word = item.text.lower()
            if word in ('class', 'trait', 'interface') and p + 1 < len(
                    items) and isinstance(items[p + 1], Tok):
                body = next((i for i in items[p + 1:] if isinstance(i, Node)
                             and i.kind == 'block'), None)
                if body is not None:
                    name = items[p + 1].text
                    self.block(body.items, ctx + [('class', name)])
                    return True
            if word == 'function':
                rest = [i for i in items[p + 1:] if not is_op(i, '&')]
                nxt = rest[0] if rest else None
                name = nxt.text if isinstance(nxt, Tok) and \
                    nxt.kind == 'id' else None
                body = next((i for i in items[p + 1:] if isinstance(i, Node)
                             and i.kind == 'block'), None)
                if body is None or (name is None and p > 0):
                    # a closure inside an expression is walked with it
                    return False
                scope = ctx if name is None else ctx + [('func', name)]
                self.block(body.items, scope)
                return True
        return False

    def assignment(self, left, right, ctx):
        base_items, keys, lkeys = [], [], []
        for item in left:
            if isinstance(item, Node) and item.kind == 'index':
                lkeys.append((item.items, list(keys)))
                keys.append(string_key(item.items))
            elif not keys and isinstance(item, Tok):
                base_items.append(item)
        names = [i for i in base_items if i.kind in ('var', 'id', 'op')
                 and i.text.lower() not in ('public', 'private', 'protected',
                                            'static', 'const', 'var',
                                            'readonly', 'global')]
        base = chain_text(names)
        for index, before in lkeys:
            self.expression(index, ctx + [('lvalue', base, before)], 'lkey')
        self.statement(right, ctx + [('lvalue', base, keys)])

    def expression(self, items, ctx, position):
        sql_runs = self.sql_runs(items)
        for p, item in enumerate(items):
            if isinstance(item, Tok):
                if item.kind == 'str' and ALIAS_DOT.match(item.text) and \
                        p + 1 < len(items) and is_op(items[p + 1], '.'):
                    self.composed(item, ctx, position)
                elif item.kind == 'str':
                    tail = p + 1 < len(items) and is_op(items[p + 1], '.')
                    self.string(item, ctx, position, p in sql_runs, tail)
                continue
            if item.kind == 'array':
                self.array(item, ctx)
            elif item.kind == 'call':
                receiver = receiver_before(items, p)
                for a, arg in enumerate(split(item.items, (',',))):
                    self.expression(arg, ctx + [
                        ('call', item.name, a, receiver)], 'arg')
            elif item.kind == 'index':
                self.expression(item.items, ctx, 'index')
            elif item.kind == 'paren':
                inner = ctx + [('foreach',)] if item.name == 'foreach' \
                    else ctx
                for part in split(item.items, (',', ';')):
                    self.statement(part, inner)
            elif item.kind == 'block':
                self.block(item.items, ctx)

    def sql_runs(self, items):
        """Positions of strings that share a '.' concatenation with SQL."""
        runs, cur = [], []
        for p, item in enumerate(items):
            if isinstance(item, Tok) and item.kind == 'op' and \
                    item.text not in ('.',) and item.text not in CHAIN:
                runs.append(cur)
                cur = []
            elif isinstance(item, Tok) and item.kind == 'str':
                cur.append(p)
        runs.append(cur)
        hits = set()
        for run in runs:
            if len(run) > 1 and any(SQL_TEXT.search(items[p].text)
                                    for p in run):
                hits.update(run)
        return hits

    def array(self, node, ctx):
        for element in split(node.items, (',',)):
            arrow = next((p for p, i in enumerate(element)
                          if is_op(i, '=>')), None)
            if arrow is None:
                self.expression(element, ctx, 'element')
                continue
            key_items, value = element[:arrow], element[arrow + 1:]
            key = string_key(key_items)
            self.expression(key_items, ctx, 'key')
            self.expression(value, ctx + [('key', key)], 'value')

    def string(self, tok, ctx, position, in_sql=False, tail=False):
        """tail: a '.' concatenation continues the string, so a trailing
        'value' is the start of value1 or value2."""
        text = tok.text
        refs = list(REF.finditer(text))
        if not refs:
            return
        by_line = {}
        for m in refs:
            col = m.group('col')
            alias = m.group('alias')
            if tail and col == 'value' and m.end() == len(text):
                col = 'value?'
            if col == 'value' and alias not in ATTRIBUTE_ALIASES and (
                    alias is not None or not PLAIN.match(text)
                    and not OPERATOR.match(text)
                    and not DIRECTION.match(text)):
                continue
            line = tok.line + text.count('\n', 0, m.start())
            by_line.setdefault(line, []).append((col, alias))
        for line, found in sorted(by_line.items()):
            self.record(tok, line, found, ctx, position, in_sql)

    def composed(self, tok, ctx, position):
        kind, _ = self.kind('qualified', ctx, position)
        if kind in ('condition', 'fields', 'order', 'group'):
            self.add(tok.line, ctx, kind, ['?'], 'composed', position)

    def record(self, tok, line, refs, ctx, position, in_sql):
        text = tok.text
        form = text_form(text)
        if in_sql:
            form = 'sql'
        kind, model = self.kind(form, ctx, position)
        bare_value = all(col == 'value' and alias is None
                         for col, alias in refs)
        if any(col == 'value?' for col, _ in refs):
            form = 'composed'
        if bare_value and (not model or kind not in (
                'condition', 'fields', 'order', 'group')):
            return
        if kind in ('access', 'data', 'text'):
            self.skipped.append({'path': self.path, 'line': line,
                                 'symbol': symbol(ctx), 'reason': kind,
                                 'snippet': self.snippet(line)})
            return
        self.add(line, ctx, kind, [col for col, _ in refs], form, position)

    def add(self, line, ctx, kind, columns, form, position):
        """One finding per symbol, line and kind; columns are merged."""
        sym = symbol(ctx)
        for f in self.findings:
            if (f['line'], f['symbol'], f['kind']) == (line, sym, kind):
                f['columns'] = sorted(set(f['columns']) | set(columns))
                return
        self.findings.append({
            'path': self.path,
            'line': line,
            'symbol': sym,
            'kind': kind,
            'columns': sorted(set(columns)),
            'form': form,
            'position': position,
            'snippet': self.snippet(line),
        })

    def kind(self, form, ctx, position):
        decided, model = decide(ctx)
        if form == 'sql':
            return 'sql', model
        if position == 'index':
            return 'access', model
        if form == 'text':
            return 'text', model
        if decided == 'data':
            return 'data', model
        if decided is not None:
            return decided, model
        if form == 'direction':
            return 'order', model
        if form in ('operator', 'wrapped-operator'):
            return 'condition', model
        if form == 'wrapped':
            return 'sql', model
        if position in ('key', 'lkey'):
            if form == 'qualified':
                return 'condition', model
            if model or ('foreach',) in ctx:
                return 'dynamic', model
            return 'data', model
        return 'dynamic', model

    def snippet(self, line):
        text = self.lines[line - 1].strip() if line <= len(self.lines) \
            else ''
        return text if len(text) <= 120 else text[:117] + '...'


def text_form(text):
    if SQL_TEXT.search(text):
        return 'sql'
    bare = text.replace('`', '').replace('"', '')
    if PLAIN.match(bare):
        return 'qualified' if '.' in bare else 'bare'
    if DIRECTION.match(bare):
        return 'direction'
    if OPERATOR.match(bare):
        return 'operator'
    if WRAPPED.search(bare):
        return 'wrapped-operator' if COMPARISON.search(bare) else 'wrapped'
    return 'text'


def decide(ctx):
    """Walk the context outward; return (kind or None, attribute-model?)."""
    model = False
    decided = None
    if any(f[0] == 'lvalue' and last_segment(f[1]).lower() == 'actsas'
           for f in ctx):
        return 'data', False
    for frame in reversed(ctx):
        tag = frame[0]
        if tag == 'key' and frame[1] is not None:
            found = key_kind(frame[1])
            if frame[1] in ATTRIBUTE_ALIASES:
                model = True
        elif tag == 'lvalue':
            found = lvalue_kind(frame[1], frame[2])
        elif tag == 'call':
            found, attr = call_kind(frame[1], frame[2], frame[3], ctx)
            model = model or attr
        else:
            found = None
        if found is not None and decided is None:
            decided = found
    return decided, model


def key_kind(key):
    low = key.lower()
    if low in CONDITION_KEYS:
        return 'condition'
    return KEY_KINDS.get(low)


def lvalue_kind(base, keys):
    for key in reversed(keys):
        if key is not None:
            found = key_kind(key)
            if found is not None:
                return found
    name = last_segment(base).lower()
    if 'virtualfields' in name:
        return 'sql'
    if 'cond' in name:
        return 'condition'
    if 'fieldlist' in name or re.search(r'editable|capture|_?to_?update|'
                                        r'_?to_?copy', name):
        return 'write'
    if 'field' in name or 'column' in name:
        return 'fields'
    if 'order' in name or 'sort' in name:
        return 'order'
    if 'group' in name:
        return 'group'
    return None


def call_kind(name, arg, receiver, ctx):
    low = (name or '').lower()
    attr = low in ATTRIBUTE_FETCHERS or (
        low in FIND_CALLS and (
            last_segment(receiver) in ATTRIBUTE_ALIASES
            or (receiver == '$this' and any(
                f[0] == 'class' and f[1] in ATTRIBUTE_CLASSES
                for f in ctx))))
    if low in SQL_CALLS:
        return 'sql', attr
    if low in FORM_CALLS:
        return 'data', attr
    if low == 'field' and arg == 0:
        return 'fields', attr
    if low == 'savefield' and arg == 0:
        return 'write', attr
    if low in ('save', 'saveall', 'savemany', 'saveassociated'):
        return ('write' if arg >= 2 else 'data'), attr
    if low == 'updateall':
        return ('write' if arg == 0 else 'condition'), attr
    if low in ('deleteall', 'hasany') and arg == 0:
        return 'condition', attr
    if low == 'generic_add_filter' and arg == 2:
        return 'condition', attr
    return None, attr


def symbol(ctx):
    cls = next((f[1] for f in reversed(ctx) if f[0] == 'class'), None)
    func = next((f[1] for f in reversed(ctx) if f[0] == 'func'), None)
    if func:
        return '%s::%s' % (cls, func) if cls else func
    lvalue = next((f for f in ctx if f[0] == 'lvalue'), None)
    if cls and lvalue:
        return '%s::%s' % (cls, lvalue[1])
    return cls or '-'


def scan_source(path, src):
    scanner = Scanner(path, src)
    if RELEVANT.search(src):
        scanner.scan(build_tree(lex(src)))
    return scanner.findings, scanner.skipped


def source_files(root, paths):
    for top in paths or [os.path.join(root, 'app')]:
        if os.path.isdir(top):
            yield from walk(top, root)
        else:
            yield top


def walk(top, root):
    for dirpath, dirnames, filenames in os.walk(top, onerror=lambda e: None):
        rel = os.path.relpath(dirpath, root)
        dirnames[:] = sorted(
            d for d in dirnames
            if not any(os.path.join(rel, d).startswith(s) for s in SKIP_DIRS)
            and d not in ('Vendor', 'node_modules', '.git'))
        for f in sorted(filenames):
            if f.endswith(EXTENSIONS):
                yield os.path.join(dirpath, f)


def allowed(finding, allow):
    for path, sym, reason in allow:
        if fnmatch.fnmatch(finding['path'], path) and \
                fnmatch.fnmatch(finding['symbol'], sym):
            return reason
    return None


def run(root, paths=None, allow=ALLOW):
    findings, accepted, ignored, files = [], [], [], 0
    for path in source_files(root, paths):
        rel = os.path.relpath(os.path.abspath(path), root)
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                src = f.read()
        except OSError:
            continue
        files += 1
        found, skipped = scan_source(rel, src)
        ignored.extend(skipped)
        for finding in found:
            reason = allowed(finding, allow)
            if reason is None:
                findings.append(finding)
            else:
                accepted.append(dict(finding, allowed=reason))
    return {'files': files, 'findings': findings, 'allowed': accepted,
            'ignored': ignored}


def report(result, show_allowed, show_ignored, out):
    groups = {}
    for f in result['findings']:
        groups.setdefault(f['path'], {}).setdefault(f['symbol'], []).append(f)
    for path in sorted(groups):
        print(path, file=out)
        for sym in sorted(groups[path], key=lambda s: groups[path][s][0][
                'line']):
            print('  ' + sym, file=out)
            for f in groups[path][sym]:
                print('    %5d  %-9s %-14s %s' % (
                    f['line'], f['kind'], '+'.join(f['columns']),
                    f['snippet']), file=out)
    if show_allowed:
        print('\nallowed:', file=out)
        for f in result['allowed']:
            print('  %s:%d %s %s (%s)' % (f['path'], f['line'], f['kind'],
                                          '+'.join(f['columns']),
                                          f['allowed']), file=out)
    if show_ignored:
        print('\nignored (not SQL):', file=out)
        for f in result['ignored']:
            print('  %s:%d %-6s %s' % (f['path'], f['line'], f['reason'],
                                       f['snippet']), file=out)
    kinds = Counter(f['kind'] for f in result['findings'])
    reasons = Counter(f['reason'] for f in result['ignored'])
    composed = sum(1 for f in result['findings'] if f['form'] == 'composed')
    sites = {(f['path'], f['symbol']) for f in result['findings']}
    print('\n%d findings in %d symbols across %d files (%d files scanned)'
          % (len(result['findings']), len(sites), len(groups),
             result['files']), file=out)
    print('  ' + '  '.join('%s=%d' % (k, kinds[k]) for k in KINDS)
          + '  (composed column: %d)' % composed, file=out)
    print('  allowed=%d  ignored: %s' % (
        len(result['allowed']), ' '.join(
            '%s=%d' % kv for kv in sorted(reasons.items()))), file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Report SQL uses of the attribute value columns')
    parser.add_argument('paths', nargs='*',
                        help='files or directories (default: app/)')
    parser.add_argument('--root', default=REPO,
                        help='repository root (paths are reported relative '
                             'to it)')
    parser.add_argument('--json', help='also write the full result here')
    parser.add_argument('--show-allowed', action='store_true')
    parser.add_argument('--show-ignored', action='store_true',
                        help='list the occurrences judged not to be SQL')
    parser.add_argument('--strict', action='store_true',
                        help='exit 1 when anything is outside the allowlist')
    args = parser.parse_args(argv)
    result = run(os.path.abspath(args.root), args.paths)
    report(result, args.show_allowed, args.show_ignored, sys.stdout)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=1, sort_keys=True)
            f.write('\n')
    return 1 if args.strict and result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
