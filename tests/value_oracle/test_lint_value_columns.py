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


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        model = os.path.join(self.tmp.name, 'app', 'Model')
        vendor = os.path.join(self.tmp.name, 'app', 'Vendor')
        os.makedirs(model)
        os.makedirs(vendor)
        body = ("<?php\nclass Bar {\n public function a() {\n"
                "  $c['Attribute.value1'] = 1;\n }\n}\n")
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
            self.assertEqual('condition',
                             json.load(f)['findings'][0]['kind'])


if __name__ == '__main__':
    unittest.main()
