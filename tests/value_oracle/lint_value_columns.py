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
(it is the virtual field there).

A finding is set aside, in this order, when:
    the allowlist names its file or symbol (ALLOW entries without a count);
    a rule makes it legal: a condition key the attribute and proposal
        beforeFind hooks carry to the value ids (rewrite), the value field
        of a primary field list or order (translate), a save field list
        whose value keys beforeSave interns (write);
    a pinned entry names its site: ALLOW entries with a count, and the
        PENDING sites that a later task still has to move. A pinned entry
        must match exactly its count of findings, so a site that grows,
        shrinks or goes away fails --strict until the entry follows.
--show-allowed lists what was set aside, and why.

Usage:
    lint_value_columns.py [--root DIR] [--json PATH] [--show-allowed]
                          [--show-ignored] [--strict] [--final] [PATH...]

Report-only by default (exit 0). --strict exits 1 when a finding is left
or a pinned entry is out of date; --final also fails on the PENDING sites,
which must be gone before the text columns are dropped.
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from collections import Counter, namedtuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

KINDS = ('sql', 'condition', 'fields', 'order', 'group', 'write', 'dynamic')
EXTENSIONS = ('.php', '.ctp')
SKIP_DIRS = ('app/Vendor', 'app/Lib/cakephp', 'app/tmp', 'app/files')

Entry = namedtuple('Entry', 'path symbol reason kinds count',
                   defaults=(None, None))
Pending = namedtuple('Pending', 'path symbol task count')

ALLOW = [Entry(*e) for e in [
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
    # Pinned sites: the rules cannot see why these are safe
    ('app/Test/SqlDialectTest.php', 'SqlDialectTest::testSha256Prefix',
     'the backfill hash expression as SQL text; never run', None, 4),
    ('app/Controller/AttributesController.php',
     'AttributesController::updateAttributeValues',
     'search keys of an attribute find: plain LIKE keys the rewriter '
     'carries', ('condition',), 2),
    ('app/Controller/ShadowAttributesController.php',
     'ShadowAttributesController::__indexOrder',
     'the sort guard: value is translated, the value columns are refused',
     ('order', 'dynamic'), 2),
    ('app/Model/Event.php', 'Event::wildcardAttributeConditions',
     'column names for plain LIKE keys in an attribute subquery, which '
     'the subquery hook rewrites', ('dynamic',), 1),
    ('app/Model/Event.php', 'Event::fetchPaginatedAttributes',
     'the sort comes from $allowedSortFields: value is translated, no '
     'value column is listed', ('order',), 1),
    ('app/Model/Feed.php', 'Feed::getFreetextFeedCorrelations',
     'value keys of hydrated rows, read in PHP', ('dynamic',), 1),
    ('app/Model/MispAttribute.php', 'MispAttribute::relatedAttributesOf',
     'the value keys a related field list asks the hydrator for',
     ('dynamic',), 1),
    ('app/Model/MispAttribute.php', 'MispAttribute::buildFilterConditions',
     'filter names, which reach generic_add_filter as plain keys',
     ('dynamic',), 2),
]]

# Sites still reading the text columns, by the task that moves them. That
# task removes its entry; the column drop needs this list empty (--final).
PENDING = [Pending(*p) for p in [
    ('app/Model/Behavior/DefaultCorrelationBehavior.php',
     'DefaultCorrelationBehavior::CONFIG', 'AV-501: correlation engines', 2),
    ('app/Model/Behavior/NoAclCorrelationBehavior.php',
     'NoAclCorrelationBehavior::CONFIG', 'AV-501: correlation engines', 2),
    ('app/Model/Correlation.php', 'Correlation::ssdeepCorrelation',
     'AV-501: correlation engines', 1),
    ('app/Model/Behavior/OnDemandCorrelationBehavior.php',
     'OnDemandCorrelationBehavior::CONFIG', 'AV-502: OnDemand rewrite', 2),
    ('app/Model/Behavior/OnDemandCorrelationBehavior.php',
     'OnDemandCorrelationBehavior::__collectCorrelations',
     'AV-502: OnDemand rewrite', 14),
    ('app/Model/Correlation.php', 'Correlation::generateTopOnDemand',
     'AV-503: top lists', 1),
    ('app/Test/SqlDialectTest.php',
     'SqlDialectTest::testUpsertAppendsTheEnginesConflictClause',
     'AV-503: top lists (generateTopOnDemand statement)', 2),
    ('app/Model/Correlation.php', 'Correlation::cidrCorrelation',
     'AV-602: CIDR on the facet', 6),
    ('app/Model/Correlation.php', 'Correlation::getCidrListFromDatabase',
     'AV-602: CIDR on the facet', 1),
    ('app/Model/MispAttribute.php', 'MispAttribute::__bro',
     'AV-701: Bro export', 2),
    ('app/Lib/Dashboard/TrendingAttributesWidget.php',
     'TrendingAttributesWidget::handler', 'AV-703: widgets', 6),
    ('app/Lib/Dashboard/TrendingWidget.php',
     'TrendingWidget::countVulnerability', 'AV-703: widgets', 2),
    ('app/Lib/Dashboard/AttributeGeoMapWidget.php',
     'AttributeGeoMapWidget::*', 'AV-703: widgets', 6),
    ('app/Console/Command/SearchPerformanceShell.php',
     'SearchPerformanceShell::__collectStats', 'AV-704: shells', 4),
]]

ATTRIBUTE_ALIASES = {'Attribute', 'ShadowAttribute', 'ReferencedAttribute',
                     'MispAttribute'}
ATTRIBUTE_CLASSES = {'MispAttribute', 'ShadowAttribute'}
# The aliases whose beforeFind rewrites conditions and translates the value
# field, by model class
HOOKED = {'MispAttribute': 'Attribute', 'ShadowAttribute': 'ShadowAttribute'}
# ValueConditionRewriter::OPERATORS
REWRITER_OPERATORS = {'=', 'IN', '!=', '<>', 'NOT IN', 'LIKE', 'NOT LIKE'}
FIND_CALLS = {'find', 'paginate', 'field', 'hasany', 'updateall',
              'deleteall'}
ATTRIBUTE_FETCHERS = {'fetchattributes', 'fetchattributessimple',
                      'fetchattributesimple', 'fetchattributesinchunks',
                      'fetchattributesinchunkssingle'}
QUERY_CALLS = FIND_CALLS | ATTRIBUTE_FETCHERS | {
    'generic_add_filter', 'rewriteconditions', 'findorder',
    'subquerygenerator'}
# No beforeFind runs for these
UNHOOKED_CALLS = {'updateall', 'deleteall'}
ASSOCIATION_KEYS = {'contain', 'joins'}
MODEL_KEY = re.compile(r'^[A-Z]\w*$')
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


def concat_tail(items, p):
    """What follows the column composed at items[p]: '' when one operand
    follows, the literal when a second operand is a string, None otherwise."""
    operands, cur = [], []
    for item in items[p + 1:]:
        if is_op(item, '.'):
            operands.append(cur)
            cur = []
        elif isinstance(item, Tok) and item.kind == 'op' and \
                item.text not in CHAIN:
            break
        else:
            cur.append(item)
    operands.append(cur)
    operands = operands[1:]
    if len(operands) == 1:
        return ''
    last = operands[-1]
    if len(operands) == 2 and len(last) == 1 and isinstance(last[0], Tok) \
            and last[0].kind == 'str':
        return last[0].text
    return None


def option(elements, name):
    """The value items of the literal key name among array elements."""
    for element in elements:
        arrow = next((p for p, i in enumerate(element) if is_op(i, '=>')),
                     None)
        if arrow is not None:
            key = string_key(element[:arrow])
            if key is not None and key.lower() == name:
                return element[arrow + 1:]
    return None


def callbacks_option(items):
    """'true', 'false', 'before' or 'after'; '?' when not a literal."""
    if len(items) == 1 and isinstance(items[0], Tok):
        text = items[0].text.lower()
        if items[0].kind == 'id' and text in ('true', 'false'):
            return text
        if items[0].kind == 'str' and text in ('before', 'after'):
            return text
    return '?'


class Scanner:
    def __init__(self, path, src):
        self.path = path
        self.lines = src.splitlines()
        self.findings = []
        self.skipped = []
        # (symbol, variable) -> callbacks of the find the variable is
        # handed to as its conditions, fields or order
        self.handed = {}

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
                    self.composed(item, ctx, position, concat_tail(items, p))
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
        elements = split(node.items, (',',))
        callbacks = option(elements, 'callbacks')
        if callbacks is not None:
            callbacks = callbacks_option(callbacks)
            ctx = ctx + [('callbacks', callbacks)]
            for name in ('conditions', 'fields', 'order'):
                value = option(elements, name)
                if value and len(value) == 1 and isinstance(value[0], Tok) \
                        and value[0].kind == 'var':
                    self.handed[(symbol(ctx), value[0].text)] = callbacks
        for element in elements:
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

    def composed(self, tok, ctx, position, tail):
        kind, _ = self.kind('qualified', ctx, position)
        if kind in ('condition', 'fields', 'order', 'group'):
            self.add(tok.line, ctx, kind, [('?', tok.text[:-1])], 'composed',
                     position, tok.text, tail)

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
        self.add(line, ctx, kind, refs, form, position, text)

    def add(self, line, ctx, kind, refs, form, position, text, tail=None):
        """One finding per symbol, line and kind; columns are merged, and
        each string behind it is kept as a use, for the rules."""
        sym = symbol(ctx)
        use = dict(self.facts(ctx), text=text, tail=tail, form=form,
                   position=position, refs=refs)
        columns = [col for col, _ in refs]
        for f in self.findings:
            if (f['line'], f['symbol'], f['kind']) == (line, sym, kind):
                f['columns'] = sorted(set(f['columns']) | set(columns))
                f['uses'].append(use)
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
            'uses': [use],
        })

    def facts(self, ctx):
        """What the context shows of the query a reference sits in: the
        query call (name, argument), the alias whose hooks see it ('other'
        for another model, None when unknown), an association or join
        between the two, the find's callbacks option, the variable the
        reference is assigned into, and the frame that decided its kind."""
        call, inner = None, []
        for frame in reversed(ctx):
            if frame[0] == 'call' and (frame[1] or '').lower() in QUERY_CALLS:
                call = frame
                break
            inner.append(frame)
        name = call[1].lower() if call else None
        keys = []
        for frame in reversed(inner):
            if frame[0] == 'key' and frame[1] is not None:
                keys.append(frame[1])
            elif frame[0] == 'lvalue':
                keys.extend(k for k in frame[2] if k is not None)
        model_keys = [k for k in keys if k.lower() in ASSOCIATION_KEYS or (
            MODEL_KEY.match(k) and k.lower() not in CONDITION_KEYS)]
        association = bool(model_keys)
        if name in ATTRIBUTE_FETCHERS:
            model = 'Attribute'
        elif name in FIND_CALLS:
            model = self.receiver_alias(call[3], ctx)
        elif name == 'findorder' and call[2] == 2 and model_keys:
            # the sortable fields of each model, not an association
            model = alias_of(model_keys[0])
            association = len(model_keys) > 1
        else:
            model = None
        callbacks = next((f[1] for f in reversed(ctx)
                          if f[0] == 'callbacks'), None)
        lvalue = next((f[1] for f in ctx if f[0] == 'lvalue'), None)
        origin = decide(ctx)[2]
        return {'call': name, 'arg': call[2] if call else None,
                'model': model, 'association': association,
                'callbacks': callbacks, 'lvalue': lvalue,
                'origin': origin}

    def receiver_alias(self, receiver, ctx):
        if receiver == '$this':
            cls = next((f[1] for f in reversed(ctx) if f[0] == 'class'),
                       None)
            if cls in HOOKED:
                return HOOKED[cls]
            return 'other' if self.path.startswith('app/Model/') else None
        segment = last_segment(receiver)
        if not segment[:1].isupper():
            return None
        return alias_of(segment)

    def kind(self, form, ctx, position):
        decided, model, _ = decide(ctx)
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
    """Walk the context outward; return (kind or None, attribute-model?,
    the frame that decided the kind)."""
    model = False
    decided = origin = None
    if any(f[0] == 'lvalue' and last_segment(f[1]).lower() == 'actsas'
           for f in ctx):
        return 'data', False, None
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
            decided, origin = found, frame
    return decided, model, origin


def alias_of(name):
    """The hooked alias a model or alias name stands for, else 'other'."""
    if name in ('Attribute', 'MispAttribute'):
        return 'Attribute'
    if name == 'ShadowAttribute':
        return 'ShadowAttribute'
    return 'other'


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
    for finding in scanner.findings:
        for use in finding['uses']:
            handed = scanner.handed.get((finding['symbol'], use['lvalue']))
            if use['callbacks'] is None and handed is not None:
                use['callbacks'] = handed
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


def key_form(text):
    """(alias, column, operator) of a condition key, split as
    ValueConditionRewriter::parseKey splits it; None for any other text."""
    parts = text.strip().split(None, 1)
    if not parts:
        return None
    m = re.match(r'^(?:(\w+)\.)?(value[12]?)$',
                 parts[0].replace('`', '').replace('"', ''))
    if not m:
        return None
    operator = ' '.join(parts[1].split()).upper() if len(parts) > 1 else '='
    return m.group(1), m.group(2), operator


def own_alias(use, alias):
    """Whether the hooks of the query see a column of this alias."""
    model = use['model']
    if model == 'other':
        return False
    if alias is None:
        return True
    if alias not in HOOKED.values():
        return False
    return model is None or alias == model


def rewritten(use):
    """A condition key the attribute and proposal hooks carry to the ids:
    beforeFind with callbacks on or 'before', the attribute subquery hook,
    or rewriteConditions() at the call site."""
    if use['call'] in UNHOOKED_CALLS or \
            use['callbacks'] not in (None, 'true', 'before'):
        return False
    if use['association']:
        return False
    if use['form'] == 'composed':
        if use['tail'] is None or use['text'].count('.') != 1:
            return False
        alias = use['text'][:-1]
        operator = ' '.join(use['tail'].split()).upper() or '='
    else:
        parsed = key_form(use['text'])
        if parsed is None:
            return False
        alias, _, operator = parsed
    if operator not in REWRITER_OPERATORS:
        return False
    if use['call'] == 'generic_add_filter' and use['arg'] == 2:
        # the field names it builds its keys from
        if operator != '=':
            return False
    elif use['position'] not in ('key', 'lkey'):
        return False
    return own_alias(use, alias)


def translated(use):
    """The value field in the primary field list or order of an attribute
    or proposal find with callbacks on, which ValueFieldTranslator reads
    from the ids."""
    if use['callbacks'] not in (None, 'true') or use['association']:
        return False
    if use['form'] not in ('qualified', 'bare', 'direction') or \
            use['position'] not in ('element', 'value', 'key'):
        return False
    return all(col == 'value' and own_alias(use, alias)
               for col, alias in use['refs'])


def interned(use):
    """A save field list: beforeSave interns the value keys and adds the
    id columns. updateAll and saveField write past it."""
    origin = use['origin']
    return not (origin and origin[0] == 'call' and
                (origin[1] or '').lower() in ('updateall', 'savefield'))


RULES = {
    'condition': ('rewrite', rewritten),
    'fields': ('translate', translated),
    'order': ('translate', translated),
    'write': ('write', interned),
}


def legal(finding):
    """The rule that makes every use behind the finding legal, if one does."""
    rule = RULES.get(finding['kind'])
    if rule and all(rule[1](use) for use in finding['uses']):
        return rule[0]
    return None


def matches(finding, entry):
    return fnmatch.fnmatch(finding['path'], entry.path) and \
        fnmatch.fnmatch(finding['symbol'], entry.symbol) and \
        (entry.kinds is None or finding['kind'] in entry.kinds)


def allowed(finding, allow):
    for entry in allow:
        if matches(finding, entry):
            return entry.reason
    return None


def run(root, paths=None, allow=None, pending=None, final=False):
    allow = [Entry(*e) for e in (ALLOW if allow is None else allow)]
    pending = PENDING if pending is None else pending
    principled = [e for e in allow if e.count is None]
    pinned = [(e, 'allowed') for e in allow if e.count is not None] + \
        [(Entry(p.path, p.symbol, p.task, None, p.count), 'pending')
         for p in ([] if final else pending)]
    left, accepted, ruled, ignored, scanned = [], [], [], [], []
    for path in source_files(root, paths):
        rel = os.path.relpath(os.path.abspath(path), root)
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                src = f.read()
        except OSError:
            continue
        scanned.append(rel)
        found, skipped = scan_source(rel, src)
        ignored.extend(skipped)
        for finding in found:
            reason = allowed(finding, principled)
            rule = None if reason else legal(finding)
            if reason:
                accepted.append(dict(finding, allowed=reason))
            elif rule:
                ruled.append(dict(finding, rule=rule))
            else:
                left.append(finding)
    findings, deferred, stale = [], [], []
    taken = set()
    for entry, kind in pinned:
        hits = [i for i, f in enumerate(left)
                if i not in taken and matches(f, entry)]
        taken.update(hits)
        for i in hits:
            if kind == 'allowed':
                accepted.append(dict(left[i], allowed=entry.reason))
            else:
                deferred.append(dict(left[i], task=entry.reason))
        if len(hits) != entry.count and any(
                fnmatch.fnmatch(p, entry.path) for p in scanned):
            stale.append({'path': entry.path, 'symbol': entry.symbol,
                          'kinds': entry.kinds, 'expected': entry.count,
                          'found': len(hits), 'entry': kind,
                          'reason': entry.reason})
    findings = [f for i, f in enumerate(left) if i not in taken]
    return {'files': len(scanned), 'findings': findings, 'allowed': accepted,
            'legal': ruled, 'pending': deferred, 'stale': stale,
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
        for title, key in (('allowed', 'allowed'), ('legal by rule', 'rule'),
                           ('pending', 'task')):
            print('\n%s:' % title, file=out)
            for f in result[{'rule': 'legal', 'task': 'pending'}.get(
                    key, key)]:
                print('  %s:%d %s %s (%s)' % (
                    f['path'], f['line'], f['kind'], '+'.join(f['columns']),
                    f[key]), file=out)
    if show_ignored:
        print('\nignored (not SQL):', file=out)
        for f in result['ignored']:
            print('  %s:%d %-6s %s' % (f['path'], f['line'], f['reason'],
                                       f['snippet']), file=out)
    if result['stale']:
        print('\nout of date (%s entries; update them):' % len(
            result['stale']), file=out)
        for e in result['stale']:
            print('  %s %s %s: %d findings, entry says %d (%s)' % (
                e['entry'], e['path'], e['symbol'], e['found'],
                e['expected'], e['reason']), file=out)
    kinds = Counter(f['kind'] for f in result['findings'])
    reasons = Counter(f['reason'] for f in result['ignored'])
    rules = Counter(f['rule'] for f in result['legal'])
    tasks = Counter(f['task'].split(':')[0] for f in result['pending'])
    composed = sum(1 for f in result['findings'] if f['form'] == 'composed')
    sites = {(f['path'], f['symbol']) for f in result['findings']}
    print('\n%d findings in %d symbols across %d files (%d files scanned)'
          % (len(result['findings']), len(sites), len(groups),
             result['files']), file=out)
    print('  ' + '  '.join('%s=%d' % (k, kinds[k]) for k in KINDS)
          + '  (composed column: %d)' % composed, file=out)
    print('  allowed=%d  legal: %s  ignored: %s' % (
        len(result['allowed']),
        ' '.join('%s=%d' % kv for kv in sorted(rules.items())) or '-',
        ' '.join('%s=%d' % kv for kv in sorted(reasons.items()))), file=out)
    print('  pending=%d: %s  out of date=%d' % (
        len(result['pending']),
        ' '.join('%s=%d' % kv for kv in sorted(tasks.items())) or '-',
        len(result['stale'])), file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Report SQL uses of the attribute value columns')
    parser.add_argument('paths', nargs='*',
                        help='files or directories (default: app/)')
    parser.add_argument('--root', default=REPO,
                        help='repository root (paths are reported relative '
                             'to it)')
    parser.add_argument('--json', help='also write the full result here')
    parser.add_argument('--show-allowed', action='store_true',
                        help='list what the allowlist, the rules and the '
                             'pending sites set aside')
    parser.add_argument('--show-ignored', action='store_true',
                        help='list the occurrences judged not to be SQL')
    parser.add_argument('--strict', action='store_true',
                        help='exit 1 on a finding or an out-of-date entry')
    parser.add_argument('--final', action='store_true',
                        help='the pending sites are findings too')
    args = parser.parse_args(argv)
    result = run(os.path.abspath(args.root), args.paths, final=args.final)
    report(result, args.show_allowed, args.show_ignored, sys.stdout)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({k: [{a: b for a, b in v.items() if a != 'uses'}
                           for v in vs] if isinstance(vs, list) else vs
                       for k, vs in result.items()},
                      f, indent=1, sort_keys=True)
            f.write('\n')
    failed = result['findings'] or result['stale']
    return 1 if args.strict and failed else 0


if __name__ == '__main__':
    sys.exit(main())
