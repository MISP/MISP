import io
import json
import os
import tempfile
import unittest
from unittest import mock

import lint_value_columns as lint


def scan(body, path='app/Model/Foo.php'):
    src = '<?php\nclass Foo extends AppModel\n{\n' + body + '\n}\n'
    return lint.scan_source(path, src)


def kinds(body):
    """(line within body, kind, columns) per finding."""
    findings, _ = scan(body)
    return [(f['line'] - 3, f['kind'], '+'.join(f['columns']))
            for f in findings]


class ClassificationTest(unittest.TestCase):
    def test_find_options(self):
        self.assertEqual([(5, 'condition', 'value1'),
                          (6, 'fields', 'value2'),
                          (7, 'order', 'value1'),
                          (8, 'group', 'value1')], kinds('''
    public function a()
    {
        return $this->Attribute->find('all', [
            'conditions' => ['Attribute.value1 LIKE' => $x],
            'fields' => ['Attribute.id', 'Attribute.value2'],
            'order' => 'Attribute.value1 ASC',
            'group' => ['Attribute.value1'],
        ]);
    }'''))

    def test_conditions_built_in_variables(self):
        self.assertEqual([(5, 'condition', 'value1'),
                          (6, 'condition', 'value2'),
                          (7, 'condition', 'value1'),
                          (8, 'condition', 'value1')], kinds('''
    public function a()
    {
        $conditions = [];
        $conditions['Attribute.value1'] = $v;
        $includeConditions['OR'][] = array('Attribute.value2 LIKE' => $i);
        $conditions['INET_ATON(value1) BETWEEN ? AND ?'] = [$a, $b];
        $conditions[] = 'IS_IPV6(value1)';
    }'''))

    def test_function_wrapped_key_is_a_condition(self):
        findings, _ = scan('''
    public function a()
    {
        $x = ['search' => 'UPPER(Attribute.value1) LIKE'];
    }''')
        self.assertEqual(('condition', 'wrapped-operator'),
                         (findings[0]['kind'], findings[0]['form']))

    def test_sql_text_heredoc_and_concatenation(self):
        self.assertEqual([(6, 'sql', 'value2'), (7, 'sql', 'value2'),
                          (10, 'sql', 'value2')], kinds('''
    public function a()
    {
        $this->query(<<<SQL
            SELECT a.id
            FROM attributes a WHERE a.value2 <> ''
            GROUP BY a.value2
            SQL);
        $sql = "SELECT "
            . "SUM(value2 != '') AS x "
            . "FROM attributes";
    }'''))

    def test_virtual_field_definitions_are_sql(self):
        self.assertEqual([(3, 'sql', 'value1+value2'),
                          (6, 'sql', 'value1')], kinds('''
    public $virtualFields = array(
        'value' => "CASE WHEN Attribute.value2 = '' THEN Attribute.value1 END",
    );
    public function a() {
        $this->MispAttribute->virtualFields['m'] = 'MD5(Attribute.value1)';
    }'''))

    def test_php_side_uses_are_ignored(self):
        findings, skipped = scan('''
    public function a($attribute)
    {
        $v = $attribute['Attribute']['value1'];
        $this->data['Attribute']['value2'] = $pieces[1];
        unset($row['value1']);
        $m = __('Composite (value1|value2) format.');
        echo $this->Form->input('Attribute.value');
        // 'Attribute.value1' => $x in a comment
    }''')
        self.assertEqual([], findings)
        self.assertEqual(['access', 'data', 'access', 'text', 'data'],
                         [s['reason'] for s in skipped])

    def test_bare_value_needs_an_attribute_query(self):
        self.assertEqual([(5, 'fields', 'value'), (8, 'fields', 'value')],
                         kinds('''
    public function a()
    {
        $this->Attribute->find('list', [
            'fields' => ['value', 'id']]);
        $this->Tag->find('list', ['fields' => ['value']]);
        $this->Event->find('all', ['contain' => [
            'Attribute' => ['fields' => ['value']]]]);
    }'''))

    def test_qualified_virtual_field(self):
        self.assertEqual([(5, 'condition', 'value')], kinds('''
    public function a()
    {
        $this->Event->find('first', ['conditions' => [
            'Attribute.value' => $v, 'Tag.value' => $v]]);
    }'''))

    def test_value_id_columns_are_not_references(self):
        self.assertEqual([], kinds('''
    public function a()
    {
        $this->find('all', ['conditions' => [
            'Attribute.value1_id' => $id, 'md5_value1' => 1]]);
    }'''))

    def test_write_lists(self):
        self.assertEqual([(2, 'write', 'value1+value2'),
                          (5, 'write', 'value1+value2')], kinds('''
    const EDITABLE_FIELDS = ['value1', 'value2'];
    public function a()
    {
        $this->save($attribute, true, ['value1', 'value2']);
    }'''))

    def test_dynamic_column_names(self):
        self.assertEqual([(4, 'dynamic', 'value1+value2'),
                          (6, 'dynamic', 'value1')], kinds('''
    public function a()
    {
        foreach (array('value1', 'value2') as $field) {
        }
        $this->fetchValues($a, 'value1');
    }'''))

    def test_composed_column(self):
        self.assertEqual([(4, 'order', '?'), (5, 'fields', 'value+value?'),
                          (6, 'condition', '?')],
                         kinds('''
    public function a()
    {
        $p['order'] = ['ShadowAttribute.' . $sort => 'ASC'];
        $q = ['fields' => ['Attribute.value' . $n, 'Attribute.value']];
        $c = $this->generic_add_filter($c, $v, 'Attribute.' . $f);
        echo $this->Form->input('Attribute.' . $k . '.value');
    }'''))

    def test_behaviour_config_is_not_sql(self):
        self.assertEqual([], kinds('''
    public $actsAs = array(
        'Regexp' => array('fields' => array('value', 'value2')));'''))

    def test_symbols(self):
        findings, _ = scan('''
    public $validate = ['x' => 'Attribute.value1 LIKE'];
    private function &b(array $x = [])
    {
        $f = function () {
            return ['conditions' => ['Attribute.value2' => 1]];
        };
    }''')
        self.assertEqual(['Foo::$validate', 'Foo::b'],
                         [f['symbol'] for f in findings])

    def test_template_html_is_skipped(self):
        src = ('<div>Attribute.value1 LIKE</div>\n'
               '<?php echo $this->element("x", [\n'
               "    'sort' => 'Attribute.value',\n"
               ']); ?>\n<span>value2</span>\n')
        findings, _ = lint.scan_source('app/View/X/index.ctp', src)
        self.assertEqual([(3, 'order', '-')],
                         [(f['line'], f['kind'], f['symbol'])
                          for f in findings])

    def test_interpolation_with_quotes_does_not_end_the_string(self):
        self.assertEqual([(4, 'sql', 'value1')], kinds('''
    public function a()
    {
        $q = "SELECT {$row["x"]} FROM attributes WHERE value1 = 1";
    }'''))


def judged(body, path='app/Model/Foo.php', cls='Foo'):
    """(line within body, kind, rule or None) per finding."""
    src = '<?php\nclass ' + cls + ' extends AppModel\n{\n' + body + '\n}\n'
    findings, _ = lint.scan_source(path, src)
    return [(f['line'] - 3, f['kind'], lint.legal(f)) for f in findings]


class RewriteRuleTest(unittest.TestCase):
    def test_condition_keys_the_hooks_carry(self):
        self.assertEqual([(5, 'condition', 'rewrite'),
                          (6, 'condition', 'rewrite'),
                          (7, 'condition', 'rewrite'),
                          (8, 'condition', 'rewrite'),
                          (9, 'condition', 'rewrite'),
                          (11, 'condition', 'rewrite'),
                          (13, 'condition', 'rewrite')], judged('''
    public function a()
    {
        $this->Attribute->find('all', ['conditions' => [
            'Attribute.value1' => $x, 'OR' => ['Attribute.value2 LIKE' => $y],
            'Attribute.value NOT IN' => $z, 'Attribute.type' => 'ip-src']]);
        $conditions['value1 !='] = $v;
        $c = $this->generic_add_filter($c, $v, ['Attribute.value2']);
        $c[] = ['Attribute.' . $field . ' NOT LIKE' => $w];
        $this->ShadowAttribute->find('all', ['conditions' => [
            'ShadowAttribute.value2 <>' => $v], 'callbacks' => 'before']);
        $c = $this->Attribute->loadAttributeValue()->rewriteConditions(
            ['Attribute.value1' => $v], 'Attribute');
    }'''))

    def test_a_proposal_model_rewrites_its_own_alias(self):
        self.assertEqual([(5, 'condition', 'rewrite'),
                          (6, 'condition', None)], judged('''
    public function a()
    {
        $this->find('all', ['conditions' => [
            'ShadowAttribute.value1' => $x,
            'Attribute.value1' => $x]]);
    }''', cls='ShadowAttribute'))

    def test_forms_the_rewriter_refuses_stay_findings(self):
        self.assertEqual([(5, 'condition', None),
                          (6, 'condition', None),
                          (7, 'condition', None),
                          (8, 'condition', None),
                          (9, 'condition', None),
                          (10, 'condition', None),
                          (11, 'condition', None),
                          (12, 'condition', None)], judged('''
    public function a()
    {
        $this->Attribute->find('all', ['conditions' => [
            'LOWER(Attribute.value1) LIKE' => $x]]);
        $conditions[] = 'Attribute.value1 = 1';
        $conditions['INET_ATON(value1) BETWEEN ? AND ?'] = [$a, $b];
        $conditions['Attribute.value1 REGEXP'] = $r;
        $conditions['Attribute.' . $f . ' BETWEEN ? AND ?'] = [$a, $b];
        $conditions['Attribute.' . $f . $operator] = $v;
        $conditions['ReferencedAttribute.value1'] = $v;
        $x = ['search' => 'Attribute.value1 LIKE'];
    }'''))

    def test_finds_that_skip_the_hooks_stay_findings(self):
        self.assertEqual([(5, 'condition', None),
                          (7, 'condition', None),
                          (9, 'condition', None),
                          (11, 'condition', None),
                          (13, 'condition', None),
                          (15, 'condition', None),
                          (16, 'condition', None),
                          (17, 'condition', 'rewrite'),
                          (19, 'condition', None)], judged('''
    public function a()
    {
        $this->Attribute->find('all', ['conditions' => [
            'Attribute.value1' => $x], 'callbacks' => false]);
        $this->Attribute->find('all', ['conditions' => [
            'Attribute.value1' => $x], 'callbacks' => 'after']);
        $this->Attribute->find('all', ['conditions' => [
            'Attribute.value1' => $x], 'callbacks' => $callbacks]);
        $this->Attribute->updateAll(['Attribute.comment' => 1],
            ['Attribute.value1' => $x]);
        $this->Attribute->deleteAll(
            ['Attribute.value1' => $x]);
        $this->Event->find('all', ['conditions' => [
            'Attribute.value2' => $x,
            'value1' => $x]]);
        $kept['value1 LIKE'] = $x;
        $this->Attribute->find('all', ['conditions' => $kept]);
        $skipped['value1 LIKE'] = $x;
        $this->Attribute->find('all', [
            'conditions' => $skipped, 'callbacks' => false]);
    }'''))

    def test_a_join_or_association_condition_is_not_rewritten(self):
        self.assertEqual([(6, 'condition', None),
                          (8, 'condition', None)], judged('''
    public function a()
    {
        $this->Event->Attribute->find('all', [
            'joins' => [['table' => 'attributes', 'alias' => 'Attribute',
                'conditions' => ['Attribute.value1' => $v]]],
            'contain' => ['Attribute' => [
                'conditions' => ['Attribute.value2' => $v]]]]);
    }'''))

    def test_generic_add_filter_takes_field_names(self):
        self.assertEqual([(4, 'condition', 'rewrite'),
                          (5, 'condition', None),
                          (6, 'condition', 'rewrite'),
                          (7, 'condition', 'rewrite')], judged('''
    public function a()
    {
        $c = $this->generic_add_filter($c, $v, 'Attribute.' . $f);
        $c = $this->generic_add_filter($c, $v, 'Attribute.value1 LIKE');
        $c = $this->generic_add_filter($c, $v, 'Attribute.value2');
        $c = $this->generic_add_filter(['value1 LIKE' => $x], $v, 'id');
    }'''))


class TranslateRuleTest(unittest.TestCase):
    def test_primary_field_lists_and_orders_on_the_value(self):
        self.assertEqual([(5, 'fields', 'translate'),
                          (6, 'order', 'translate'),
                          (7, 'fields', 'translate'),
                          (8, 'order', 'translate'),
                          (9, 'fields', 'translate'),
                          (11, 'order', 'translate'),
                          (12, 'order', 'translate'),
                          (13, 'order', 'translate')], judged('''
    public function a()
    {
        $this->Attribute->find('all', [
            'fields' => ['Attribute.id', 'Attribute.value'],
            'order' => 'Attribute.value DESC']);
        $this->ShadowAttribute->find('list', ['fields' => ['value'],
            'order' => ['ShadowAttribute.value' => 'ASC']]);
        $attributeFields = ['Attribute.id', 'Attribute.value'];
        $params['order'] = $this->findOrder($o, 'Attribute', [
            'Attribute' => ['id', 'value'], 'Event' => ['id']]);
        $sort_keys = ['Attribute.value', 'Attribute.id'];
        $x = ['sort' => 'ShadowAttribute.value'];
    }'''))

    def test_what_the_translator_does_not_see_stays_a_finding(self):
        self.assertEqual([(5, 'fields', None),
                          (6, 'order', None),
                          (8, 'fields', None),
                          (10, 'fields', None),
                          (12, 'fields', None),
                          (13, 'order', None),
                          (14, 'order', None),
                          (15, 'group', None)], judged('''
    public function a()
    {
        $this->Attribute->find('all', [
            'fields' => ['Attribute.value1'],
            'order' => 'count(Attribute.value1) desc']);
        $this->Event->find('all', ['contain' => ['Attribute' => [
            'fields' => ['Attribute.value']]]]);
        $this->Attribute->find('all', ['callbacks' => 'before',
            'fields' => ['Attribute.value']]);
        $this->Event->find('all', [
            'fields' => ['Attribute.value'],
            'order' => ['Attribute.' . $sort => 'ASC']]);
        $sort = ['Attribute.value1'];
        $p['group'] = ['Attribute.value'];
    }'''))


class WriteRuleTest(unittest.TestCase):
    def test_save_field_lists_but_not_writes_past_beforesave(self):
        self.assertEqual([(2, 'write', 'write'),
                          (5, 'write', 'write'),
                          (6, 'write', 'write'),
                          (7, 'write', None),
                          (8, 'write', None)], judged('''
    const EDITABLE_FIELDS = ['value1', 'value2'];
    public function a()
    {
        $this->save($attribute, true, ['value1', 'value2']);
        $this->saveAll($a, ['fieldList' => ['Attribute' => ['value1']]]);
        $this->updateAll(['Attribute.value1' => "'x'"], ['id' => 1]);
        $this->saveField('value2', 'x');
    }'''))


class EntryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        model = os.path.join(self.tmp.name, 'app', 'Model')
        os.makedirs(model)
        body = ("<?php\nclass Bar {\n public function a() {\n"
                "  $q = 'SELECT value1 FROM attributes';\n"
                "  $r = 'SELECT value2 FROM attributes';\n }\n"
                " public function b() {\n"
                "  $f = ['fields' => ['Attribute.value1']];\n }\n}\n")
        self.path = os.path.join(model, 'Bar.php')
        with open(self.path, 'w') as f:
            f.write(body)

    def tearDown(self):
        self.tmp.cleanup()

    def run_with(self, allow=(), pending=(), final=False):
        return lint.run(self.tmp.name, allow=list(allow),
                        pending=[lint.Pending(*p) for p in pending],
                        final=final)

    def test_a_pinned_entry_takes_exactly_its_count(self):
        result = self.run_with(
            allow=[('app/Model/Bar.php', 'Bar::a', 'why', ('sql',), 2)],
            pending=[('app/Model/Bar.php', 'Bar::b', 'AV-1: later', 1)])
        self.assertEqual([], result['findings'])
        self.assertEqual([], result['stale'])
        self.assertEqual(['why', 'why'],
                         [f['allowed'] for f in result['allowed']])
        self.assertEqual(['AV-1: later'],
                         [f['task'] for f in result['pending']])

    def test_a_site_that_grows_shrinks_or_goes_is_out_of_date(self):
        for count in (1, 3):
            result = self.run_with(
                allow=[('app/Model/Bar.php', 'Bar::a', 'why', None, count)])
            self.assertEqual([(count, 2)], [(e['expected'], e['found'])
                                           for e in result['stale']])
        result = self.run_with(
            pending=[('app/Model/Bar.php', 'Bar::gone', 'AV-1: x', 1)])
        self.assertEqual([(1, 0)], [(e['expected'], e['found'])
                                    for e in result['stale']])

    def test_entries_for_files_not_scanned_are_not_checked(self):
        result = lint.run(
            self.tmp.name, [self.path],
            pending=[lint.Pending('app/Model/Other.php', 'X::y', 'AV-1', 1)])
        self.assertEqual([], result['stale'])

    def test_a_kind_filter_leaves_other_kinds_as_findings(self):
        result = self.run_with(
            allow=[('app/Model/Bar.php', 'Bar::*', 'why', ('sql',), 2)])
        self.assertEqual(['fields'],
                         [f['kind'] for f in result['findings']])

    def test_final_turns_the_pending_sites_into_findings(self):
        pending = [('app/Model/Bar.php', 'Bar::*', 'AV-1: later', 3)]
        self.assertEqual([], self.run_with(pending=pending)['findings'])
        result = self.run_with(pending=pending, final=True)
        self.assertEqual(3, len(result['findings']))
        self.assertEqual([], result['stale'])

    def test_strict_fails_on_an_out_of_date_entry(self):
        def strict(count, *flags):
            entry = lint.Pending('app/Model/Bar.php', 'Bar::*', 'AV-1', count)
            with mock.patch('sys.stdout', io.StringIO()), \
                    mock.patch.object(lint, 'ALLOW', []), \
                    mock.patch.object(lint, 'PENDING', [entry]):
                return lint.main(['--root', self.tmp.name, '--strict']
                                 + list(flags))
        self.assertEqual(1, strict(4))
        self.assertEqual(0, strict(3))
        self.assertEqual(1, strict(3, '--final'))


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        model = os.path.join(self.tmp.name, 'app', 'Model')
        vendor = os.path.join(self.tmp.name, 'app', 'Vendor')
        os.makedirs(model)
        os.makedirs(vendor)
        body = ("<?php\nclass Bar {\n public function a() {\n"
                "  $q = 'SELECT value1 FROM attributes';\n }\n}\n")
        for path in (os.path.join(model, 'Bar.php'),
                     os.path.join(vendor, 'Lib.php')):
            with open(path, 'w') as f:
                f.write(body)

    def tearDown(self):
        self.tmp.cleanup()

    def test_vendor_is_skipped_and_paths_are_relative(self):
        result = lint.run(self.tmp.name, allow=[])
        self.assertEqual(1, result['files'])
        self.assertEqual('app/Model/Bar.php', result['findings'][0]['path'])

    def test_allowlist_moves_findings_aside(self):
        result = lint.run(self.tmp.name,
                          allow=[('app/Model/*', 'Bar::a', 'because')])
        self.assertEqual([], result['findings'])
        self.assertEqual('because', result['allowed'][0]['allowed'])

    def test_strict_exit_status_and_json(self):
        out = os.path.join(self.tmp.name, 'out.json')
        with mock.patch('sys.stdout', io.StringIO()):
            self.assertEqual(0, lint.main(['--root', self.tmp.name,
                                           '--json', out]))
            self.assertEqual(1, lint.main(['--root', self.tmp.name,
                                           '--strict']))
        with open(out) as f:
            self.assertEqual('sql',
                             json.load(f)['findings'][0]['kind'])


class RepositoryTest(unittest.TestCase):
    """T1 failing: the tree passes --strict, and a text-column read planted
    outside the rules or into a pinned site does not."""

    def test_the_tree_passes_strict(self):
        result = lint.run(lint.REPO)
        self.assertEqual([], [(f['path'], f['line'], f['kind'])
                              for f in result['findings']])
        self.assertEqual([], result['stale'])

    def planted(self, path, before, code):
        """The lint run over a copy of one file with code planted in it."""
        with open(os.path.join(lint.REPO, path), encoding='utf-8') as f:
            src = f.read()
        self.assertEqual(1, src.count(before))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = os.path.join(tmp.name, path)
        os.makedirs(os.path.dirname(target))
        with open(target, 'w', encoding='utf-8') as f:
            f.write(src.replace(before, code + before))
        return lint.run(tmp.name)

    def test_a_planted_read_fails(self):
        plants = [
            "$this->query('SELECT value1 FROM attributes');",
            "$this->Attribute->find('all', ['conditions' => "
            "['UPPER(Attribute.value2)' => 'X']]);",
            "$this->Attribute->find('all', ['conditions' => "
            "['Attribute.value1' => 'x'], 'callbacks' => false]);",
            "$this->Attribute->find('all', ['fields' => "
            "['Attribute.value2']]);",
        ]
        for code in plants:
            result = self.planted(
                'app/Model/Event.php', '    public function fetchEvent(',
                '    public function planted()\n    {\n        ' + code
                + '\n    }\n\n')
            self.assertEqual(['Event::planted'],
                             [f['symbol'] for f in result['findings']], code)
            self.assertEqual([], result['stale'])

    def test_a_read_planted_in_a_pending_site_fails(self):
        result = self.planted(
            'app/Console/Command/SearchPerformanceShell.php',
            "        $stats['approximate'] = $fast;\n",
            "        $this->query('SELECT value2 FROM attributes');\n")
        self.assertEqual([], result['findings'])
        self.assertEqual([('SearchPerformanceShell::__collectStats', 4, 5)],
                         [(e['symbol'], e['expected'], e['found'])
                          for e in result['stale']])


if __name__ == '__main__':
    unittest.main()
