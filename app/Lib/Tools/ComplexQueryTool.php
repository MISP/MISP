<?php

class ComplexQueryException extends Exception
{
    /** @var array */
    public $errors;

    public function __construct(array $errors)
    {
        $this->errors = $errors;
        parent::__construct('Invalid query', 400);
    }
}

/**
 * Turns the boolean `query` tree of a restSearch request into CakePHP
 * conditions: for the attribute scope by default, for another scope through
 * that scope's field registry.
 *
 * validate() checks the whole tree without touching the database and
 * rejects it entirely on the first bad node; only then does compile() build
 * conditions, one self-contained fragment per leaf. Error messages and paths
 * are built from fixed templates and whitelisted names only, never from
 * user input.
 */
class ComplexQueryTool
{
    const NUMERIC_OPS = ['=', '!=', '>', '<', '>=', '<=', 'IN', 'NOT IN'];
    const STRING_OPS = ['=', '!=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'];
    const EXACT_STRING_OPS = ['=', '!=', 'IN', 'NOT IN'];
    const BOOL_OPS = ['=', '!='];
    const NEGATED_OPS = ['!=' => '=', 'NOT IN' => 'IN', 'NOT LIKE' => 'LIKE'];
    const MAX_ERRORS = 10;

    /**
     * kind: int | time | bool | string
     * column: native condition column (int, time, bool, native string), or a
     *     list of columns any of which may match
     * lower: compare the columns in lower case, for case-sensitive ones
     * via: [association, key(, its field)]: the column belongs to the associated model,
     *     matched through a subquery on its id (or that field), e.g. ['Orgc', 'GalaxyCluster.orgc_id']
     * key_column: on a wildcard entry (`meta.*`, any name under `meta.`), the column the
     *     rest of the name must equal; paths and discovery show the name as `meta.<key>`
     * reserved: [names, condition]: a value equal to one of the names in any case
     *     also matches the condition, e.g. the built-in MISP organisation, which has no row
     * handler: legacy set_filter_* method building a string field's fragment
     * nullable: column that negation must also match when it is NULL
     * selective: counts as a selective sibling for the tag plan choice
     * level: what the field is matched against (event, attribute, object)
     */
    const FIELDS = [
        'id' => ['kind' => 'int', 'column' => 'Attribute.id', 'level' => ['attribute']],
        'event_id' => ['kind' => 'int', 'column' => 'Attribute.event_id', 'level' => ['attribute']],
        'object_id' => ['kind' => 'int', 'column' => 'Attribute.object_id', 'level' => ['attribute']],
        'distribution' => ['kind' => 'int', 'column' => 'Attribute.distribution', 'level' => ['attribute']],
        'timestamp' => ['kind' => 'time', 'column' => 'Attribute.timestamp', 'selective' => true, 'level' => ['attribute']],
        'event_timestamp' => ['kind' => 'time', 'column' => 'Event.timestamp', 'level' => ['event']],
        'publish_timestamp' => ['kind' => 'time', 'column' => 'Event.publish_timestamp', 'level' => ['event']],
        'threat_level_id' => ['kind' => 'int', 'column' => 'Event.threat_level_id', 'level' => ['event']],
        'to_ids' => ['kind' => 'bool', 'column' => 'Attribute.to_ids', 'selective' => true, 'level' => ['attribute']],
        'published' => ['kind' => 'bool', 'column' => 'Event.published', 'level' => ['event']],
        'uuid' => ['kind' => 'string', 'column' => 'Attribute.uuid', 'ops' => self::EXACT_STRING_OPS, 'selective' => true, 'level' => ['attribute']],
        'type' => ['kind' => 'string', 'handler' => 'set_filter_type', 'selective' => true, 'level' => ['attribute']],
        'category' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'selective' => true, 'level' => ['attribute']],
        'object_relation' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'nullable' => 'Attribute.object_relation', 'selective' => true, 'level' => ['attribute']],
        'comment' => ['kind' => 'string', 'handler' => 'set_filter_comment', 'nullable' => 'Attribute.comment', 'level' => ['attribute']],
        'eventinfo' => ['kind' => 'string', 'handler' => 'set_filter_eventinfo', 'level' => ['event']],
        'value' => ['kind' => 'string', 'handler' => 'set_filter_value', 'selective' => true, 'level' => ['attribute']],
        'tags' => ['kind' => 'string', 'handler' => 'set_filter_tags', 'level' => ['attribute', 'event']],
        'org' => ['kind' => 'string', 'handler' => 'set_filter_org', 'ops' => self::EXACT_STRING_OPS, 'level' => ['event']],
    ];

    protected $model;
    protected $fields;
    private $limits;
    protected $errors;
    private $nodes;

    /**
     * @param object $model the scope's model: set_filter_* handlers, associations, subqueries
     * @param array $limits max_depth, max_nodes, max_list, max_value_length
     * @param array $fields the field registry of the scope, shaped like self::FIELDS
     */
    public function __construct($model, array $limits = [], array $fields = self::FIELDS)
    {
        $this->fields = $fields;
        $this->model = $model;
        $this->limits = $limits + [
            'max_depth' => 5,
            'max_nodes' => 50,
            'max_list' => 100,
            'max_value_length' => 1024,
        ];
    }

    /**
     * @return array the limits set in the MISP.complex_query_max_* settings
     */
    public static function limitsFromConfig()
    {
        $limits = [];
        foreach (['max_depth', 'max_nodes', 'max_list', 'max_value_length'] as $limit) {
            $value = Configure::read('MISP.complex_query_' . $limit);
            if ($value !== null && $value !== '') {
                $limits[$limit] = (int)$value;
            }
        }
        return $limits;
    }

    /**
     * Validate then compile.
     *
     * @param mixed $query
     * @return array a condition fragment to append to $conditions['AND']
     * @throws ComplexQueryException
     */
    public function conditions($query)
    {
        return $this->compile($this->validate($query));
    }

    /**
     * No database access happens here.
     *
     * @param mixed $query
     * @return array normalised tree
     * @throws ComplexQueryException
     */
    public function validate($query)
    {
        $this->errors = [];
        $this->nodes = 0;
        $tree = $this->node($query, 'query', 1);
        if (!empty($this->errors)) {
            throw new ComplexQueryException($this->errors);
        }
        return $tree;
    }

    /**
     * @param array $tree the result of validate()
     * @return array
     * @throws ComplexQueryException
     */
    public function compile(array $tree)
    {
        $this->errors = [];
        $fragment = $this->build($tree, 'query');
        if (!empty($this->errors)) {
            throw new ComplexQueryException($this->errors);
        }
        return $fragment;
    }

    /**
     * Rejects what AppModel::findOrder() would silently drop or ignore.
     *
     * @param mixed $order a "field [asc|desc]" string, comma separated, or a list of them
     * @param array $allowed model => list of sortable fields
     * @param string $defaultModel the model of a field named without one
     * @return void
     * @throws ComplexQueryException
     */
    public function validateOrder($order, array $allowed, $defaultModel = 'Attribute')
    {
        $this->errors = [];
        $rules = is_string($order) ? explode(',', $order) : $order;
        if (!is_array($rules) || $rules === [] || !array_is_list($rules)) {
            $this->fail('order', 'bad_shape', 'order takes a string or a list of strings');
        } else {
            foreach ($rules as $i => $rule) {
                $path = "order[$i]";
                if (!is_string($rule)) {
                    $this->fail($path, 'bad_type', 'a sort rule is a string');
                    continue;
                }
                $items = explode(' ', trim($rule));
                if (count($items) > 2 || (count($items) === 2 && !in_array(strtolower($items[1]), ['asc', 'desc'], true))) {
                    $this->fail($path, 'bad_shape', 'a sort rule is a field with an optional asc or desc');
                    continue;
                }
                $parts = explode('.', $items[0]);
                $model = count($parts) === 2 ? $parts[0] : $defaultModel;
                $field = strtolower(end($parts));
                if (count($parts) > 2 || !isset($allowed[$model]) || !in_array($field, $allowed[$model], true)) {
                    $this->fail($path, 'unknown_field', 'unknown sort field');
                }
            }
        }
        if (!empty($this->errors)) {
            throw new ComplexQueryException($this->errors);
        }
    }

    /**
     * Fields, operators and limits, as exposed by the discovery endpoint.
     *
     * @return array
     */
    public function describe()
    {
        $fields = [];
        foreach ($this->fields as $name => $def) {
            $name = str_ends_with($name, '.*') ? substr($name, 0, -1) . '<key>' : $name;
            $fields[$name] = [
                'type' => $def['kind'] === 'time' ? 'timestamp' : ($def['kind'] === 'string' ? 'string' : $def['kind']),
                'operators' => self::operatorsFor($def),
                'level' => $def['level'] ?? [],
            ];
        }
        return ['fields' => $fields, 'limits' => $this->limits];
    }

    /**
     * The response of a scope's queryDescribe endpoint.
     *
     * @param string $table
     * @param string $endpoint
     * @param array $orderFields model => sortable fields, as for validateOrder()
     * @param string $defaultModel the model whose sortable fields are named without it
     * @return array
     */
    public function discovery($table, $endpoint, array $orderFields, $defaultModel)
    {
        $description = $this->describe();
        $sortable = [];
        foreach ($orderFields as $model => $names) {
            foreach ($names as $name) {
                $sortable[] = $model === $defaultModel ? $name : "$model.$name";
            }
        }
        return [
            'tables' => [$table => [
                'endpoint' => $endpoint,
                'fields' => $description['fields'],
                'sortable' => $sortable,
            ]],
            'limits' => $description['limits'],
        ];
    }

    private static function operatorsFor(array $def)
    {
        if (isset($def['ops'])) {
            return $def['ops'];
        }
        switch ($def['kind']) {
            case 'bool':
                return self::BOOL_OPS;
            case 'string':
                return self::STRING_OPS;
            default:
                return self::NUMERIC_OPS;
        }
    }

    protected function fail($path, $code, $message)
    {
        if (count($this->errors) < self::MAX_ERRORS) {
            $this->errors[] = ['path' => $path, 'code' => $code, 'message' => $message];
        }
        return null;
    }

    private function node($node, $path, $depth)
    {
        if (++$this->nodes > $this->limits['max_nodes']) {
            if ($this->nodes === $this->limits['max_nodes'] + 1) {
                $this->fail($path, 'limit_exceeded', 'too many nodes');
            }
            return null;
        }
        if ($depth > $this->limits['max_depth']) {
            return $this->fail($path, 'limit_exceeded', 'tree too deep');
        }
        if (!is_array($node) || count($node) !== 1 || array_is_list($node)) {
            return $this->fail($path, 'bad_shape', 'a node is an object with exactly one key');
        }
        $key = key($node);
        $body = current($node);
        if ($key === 'AND' || $key === 'OR') {
            if (!is_array($body) || $body === [] || !array_is_list($body)) {
                return $this->fail("$path.$key", 'bad_shape', "$key takes a non-empty list of nodes");
            }
            $children = [];
            foreach ($body as $i => $child) {
                $children[] = $this->node($child, "{$path}.{$key}[{$i}]", $depth + 1);
                if ($this->nodes > $this->limits['max_nodes'] || count($this->errors) >= self::MAX_ERRORS) {
                    break;
                }
            }
            return [$key, $children];
        }
        if ($key === 'NOT') {
            return ['NOT', $this->node($body, "$path.NOT", $depth + 1)];
        }
        $def = $this->definition($key);
        if ($def === null) {
            return $this->fail("$path.<unknown>", 'unknown_field', 'unknown field');
        }
        // never the user's own key in a path
        $path .= '.' . ($def['name'] ?? $key);
        if (isset($def['key']) && strlen($def['key']) > $this->limits['max_value_length']) {
            return $this->fail($path, 'limit_exceeded', 'field name too long');
        }
        return $this->leaf($key, $body, $path);
    }

    /**
     * The field's definition, null for an unknown field. A name under a wildcard
     * entry gets that entry's, with the rest of the name as `key`.
     */
    private function definition($field)
    {
        if (!is_string($field)) {
            return null;
        }
        $dot = strpos($field, '.');
        if ($dot === false) {
            return $this->fields[$field] ?? null;
        }
        $prefix = substr($field, 0, $dot);
        if (!isset($this->fields["$prefix.*"]) || $dot === strlen($field) - 1) {
            return null;
        }
        return $this->fields["$prefix.*"] + ['key' => substr($field, $dot + 1), 'name' => "$prefix.<key>"];
    }

    private function leaf($field, $spec, $path)
    {
        $def = $this->definition($field);
        $op = '=';
        $operand = $spec;
        if (is_array($spec)) {
            if (count($spec) !== 1 || array_is_list($spec)) {
                return $this->fail($path, 'bad_shape', 'a field takes a value or one {operator: value}');
            }
            $op = key($spec);
            $operand = current($spec);
        }
        if (!is_string($op) || !in_array($op, self::operatorsFor($def), true)) {
            return $this->fail($path, 'unknown_operator', $this->operatorMessage($def, $op));
        }
        $isList = $op === 'IN' || $op === 'NOT IN';
        if ($isList) {
            if (!is_array($operand) || $operand === [] || !array_is_list($operand)) {
                return $this->fail($path, 'bad_shape', 'IN and NOT IN take a non-empty list');
            }
            if (count($operand) > $this->limits['max_list']) {
                return $this->fail($path, 'limit_exceeded', 'list too long');
            }
        }
        $values = [];
        foreach ($isList ? $operand : [$operand] as $value) {
            $value = $this->typed($def['kind'], $value, $op, $field, $path);
            if ($value === null) {
                return null;
            }
            $values[] = $value;
        }
        return ['leaf', $field, $op, $values];
    }

    /**
     * @param array $def
     * @param mixed $op unchecked user input, never part of the message
     * @return string
     */
    protected function operatorMessage(array $def, $op)
    {
        return 'operator not allowed for this field';
    }

    /**
     * @return int|string|null null after recording the error
     */
    protected function typed($kind, $value, $op, $field, $path)
    {
        switch ($kind) {
            case 'int':
                return is_int($value) ? $value : $this->fail($path, 'bad_type', 'this field expects an integer');
            case 'time':
                if (is_int($value) || (is_string($value) && preg_match('/^[0-9]{1,9}[dhms]$/', $value))) {
                    return $value;
                }
                return $this->fail($path, 'bad_type', 'this field expects an integer or a relative time such as 7d');
            case 'bool':
                return is_bool($value) ? (int)$value : $this->fail($path, 'bad_type', 'this field expects true or false');
        }
        if (!is_string($value) || $value === '') {
            return $this->fail($path, 'bad_type', 'this field expects a non-empty string');
        }
        if (strlen($value) > $this->limits['max_value_length']) {
            return $this->fail($path, 'limit_exceeded', 'value too long');
        }
        $edge = $value[0] === '%' || substr($value, -1) === '%';
        if ($op === 'LIKE' || $op === 'NOT LIKE') {
            $core = trim($value, '%');
            if (!$edge || $core === '' || strpos($core, '%') !== false) {
                return $this->fail($path, 'bad_type', 'LIKE takes a leading and/or trailing %, nothing else');
            }
        } elseif ($edge) {
            return $this->fail($path, 'bad_type', 'use LIKE for wildcards');
        }
        return $value;
    }

    private function build(array $node, $path, $selectiveSiblings = false)
    {
        switch ($node[0]) {
            case 'AND':
            case 'OR':
                $selective = $node[0] === 'AND' && $this->hasSelectiveLeaf($node[1]);
                $parts = [];
                foreach ($node[1] as $i => $child) {
                    $parts[] = $this->build($child, "{$path}.{$node[0]}[{$i}]", $selective);
                }
                return [$node[0] => $parts];
            case 'NOT':
                return ['NOT' => $this->build($node[1], "$path.NOT")];
        }
        $name = $this->definition($node[1])['name'] ?? $node[1];
        return $this->buildLeaf($node[1], $node[2], $node[3], "{$path}.{$name}", $selectiveSiblings);
    }

    private function hasSelectiveLeaf(array $children)
    {
        foreach ($children as $child) {
            if ($child[0] === 'leaf' && !empty($this->definition($child[1])['selective'])) {
                return true;
            }
        }
        return false;
    }

    protected function buildLeaf($field, $op, array $values, $path, $selectiveSiblings)
    {
        $def = $this->definition($field);
        $negate = isset(self::NEGATED_OPS[$op]);
        $positive = self::NEGATED_OPS[$op] ?? $op;
        if (isset($def['column'])) {
            $fragment = $this->native($def, $positive, $values);
            if (isset($def['key'])) {
                $fragment = ['AND' => [[$def['key_column'] => $def['key']], $fragment]];
            }
            if (isset($def['via'])) {
                $fragment = $this->subquery($this->model->{$def['via'][0]}, $def['via'][2] ?? 'id', [$fragment], $def['via'][1]);
            }
        } else {
            $fragment = $this->viaHandler($field, $def, $values, $path, $selectiveSiblings);
        }
        if ($fragment === null) {
            return null;
        }
        if (isset($def['reserved']) && array_intersect(array_map('mb_strtolower', $values), array_map('mb_strtolower', $def['reserved'][0]))) {
            $fragment = ['OR' => [$fragment, $def['reserved'][1]]];
        }
        if (!empty($def['nullable'])) {
            // never NULL, so that any NOT above it also matches the NULL rows
            $fragment = ['AND' => [$def['nullable'] . ' IS NOT NULL', $fragment]];
        }
        return $negate ? ['NOT' => $fragment] : $fragment;
    }

    private function native(array $def, $op, array $values)
    {
        if ($def['kind'] === 'time') {
            $values = array_map(function ($v) {
                return is_int($v) ? $v : $this->model->resolveTimeDelta($v);
            }, $values);
        }
        $columns = (array)$def['column'];
        if (!empty($def['lower'])) {
            $values = array_map('mb_strtolower', $values);
            $columns = array_map(function ($column) {
                return "LOWER($column)";
            }, $columns);
        }
        $fragments = [];
        foreach ($columns as $column) {
            if ($op === '=') {
                $fragments[] = [$column => $values[0]];
            } elseif ($op === 'IN') {
                $fragments[] = [$column => $values];
            } else {
                $fragments[] = ["$column $op" => $values[0]];
            }
        }
        return count($fragments) === 1 ? $fragments[0] : ['OR' => $fragments];
    }

    protected function subquery($model, $field, array $conditions, $lookupKey, $alias = null)
    {
        $alias = $alias ?? $model->alias;
        return $this->model->subQueryGenerator($model, [
            'alias' => $alias,
            'fields' => ["$alias.$field"],
            'conditions' => $conditions,
        ], $lookupKey);
    }

    private function viaHandler($field, array $def, array $values, $path, $selectiveSiblings)
    {
        $params = [$field => ['OR' => $values]];
        if ($field === 'tags' && $selectiveSiblings) {
            // the tag handler picks its plan from selective sibling params
            $params['type'] = true;
        }
        $options = ['filter' => $field, 'scope' => 'Attribute', 'pop' => false, 'context' => 'Attribute'];
        $handler = $def['handler'];
        $fragment = $handler === 'set_filter_tags'
            ? $this->model->set_filter_tags($params, [], $options)
            : $this->model->Event->$handler($params, [], $options);
        // an empty fragment would match everything
        if (empty($fragment)) {
            return $this->fail($path, 'bad_type', 'value not usable for this field');
        }
        return $fragment;
    }
}
