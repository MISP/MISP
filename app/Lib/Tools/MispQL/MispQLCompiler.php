<?php
require_once __DIR__ . '/MispQLParser.php';
require_once __DIR__ . '/MispQLTables.php';

/**
 * Compiles MispQL statements into plans: the restSearch request a search or a
 * count sends, and the spans placing each path of its body on the text.
 */
class MispQLCompiler
{
    const LANGUAGE = '1.0';

    // Rendered by the client from the JSON rows. Any other FORMAT word is
    // MISP's returnFormat, sent back as MISP exports it.
    const RENDERINGS = ['table', 'flat'];

    /** @var MispQLTables */
    private $tables;

    /** @var array path in the request body => [start, end] */
    private $spans = [];

    /** @var array the table of the statement being compiled */
    private $table;

    /** @var string */
    private $tableName;

    public function __construct(MispQLTables $tables)
    {
        $this->tables = $tables;
    }

    /**
     * The whole script is parsed before any statement is compiled, and
     * statements are compiled in order: the first error of the script wins.
     *
     * @param string $text
     * @return array[] one plan per statement
     * @throws MispQLException
     */
    public function compileScript($text)
    {
        $plans = [];
        foreach (MispQLParser::parse($text) as $statement) {
            $plans[] = $this->compile($statement);
        }
        return $plans;
    }

    /**
     * @param array $statement a node from MispQLParser
     * @return array
     * @throws MispQLException
     */
    public function compile(array $statement)
    {
        $plan = ['kind' => $statement['type'], 'start' => $statement['start'], 'end' => $statement['end']];
        switch ($statement['type']) {
            case 'show_tables':
                return $plan + ['endpoints' => $this->tables->discoveryEndpoints(), 'spans' => []];
            case 'show_databases':
            case 'whoami':
                return $plan + ['spans' => []];
            case 'use':
                return $plan + ['database' => $statement['database']['value'], 'spans' => []];
            case 'describe':
                $name = $this->table($statement['table']);
                return $plan + [
                    'table' => $name,
                    'endpoint' => $this->tables->discovery($name),
                    'spans' => [],
                ];
            default:
                return $this->select($statement);
        }
    }

    /**
     * Offsets of the text an error path points at, through the longest prefix
     * of the path the plan knows.
     *
     * @param array $spans a plan's spans
     * @param string $path
     * @return array|null [start, end]
     */
    public static function locate(array $spans, $path)
    {
        while ($path !== '') {
            if (array_key_exists($path, $spans)) {
                return $spans[$path];
            }
            $path = self::parentPath($path);
        }
        return null;
    }

    /**
     * @param string $path
     * @return string the path without its last step
     */
    public static function parentPath($path)
    {
        if (preg_match('/(\.[^.\[]+|\[\d+\])$/', $path, $match, PREG_OFFSET_CAPTURE)) {
            return substr($path, 0, $match[0][1]);
        }
        return '';
    }

    /**
     * @return string the table's name
     */
    private function table(array $name)
    {
        if (!$this->tables->has($name['value'])) {
            throw new MispQLException(
                'unknown table; use ' . self::oneOf($this->tables->names()),
                MispQLException::UNKNOWN_TABLE,
                $name['start'],
                $name['end']
            );
        }
        return $name['value'];
    }

    private static function oneOf(array $items)
    {
        $last = array_pop($items);
        return implode(', ', $items) . ' or ' . $last;
    }

    private function select(array $stmt)
    {
        $this->tableName = $this->table($stmt['table']);
        $this->table = $this->tables->get($this->tableName);
        $this->spans = [];
        if ($stmt['columns']['type'] === 'count') {
            return $this->count($stmt);
        }
        if ($stmt['where'] === null && $stmt['limit'] === null) {
            throw new MispQLException(
                'add a WHERE or a LIMIT: MISP takes no search without either',
                MispQLException::MISSING_CLAUSE,
                $stmt['start'],
                $stmt['end']
            );
        }
        $word = $stmt['format'] === null ? null : $stmt['format']['value'];
        if ($word === null) {
            $output = 'default';
        } else {
            $output = in_array($word, self::RENDERINGS, true) ? $word : 'verbatim';
        }
        $verbatim = $output === 'verbatim' ? $word : null;
        $columns = null;
        if ($stmt['columns']['type'] === 'fields') {
            $columns = [];
            foreach ($stmt['columns']['items'] as $column) {
                $name = $this->field($column);
                $columns[] = $this->table['aliases'][$name] ?? $name;
            }
        }
        $query = $stmt['where'] === null ? null : $this->node($stmt['where'], 'query');
        $order = $this->order($stmt);
        list($limit, $page, $skip) = $this->paging($stmt, $verbatim);
        if ($columns !== null && self::nonEmpty($verbatim)) {
            throw new MispQLException(
                'a column list needs FORMAT table, FORMAT flat or no FORMAT; '
                    . 'other formats are sent as MISP exports them',
                MispQLException::BAD_CLAUSE,
                $stmt['format']['start'],
                $stmt['format']['end']
            );
        }
        $body = ['returnFormat' => self::nonEmpty($verbatim) ? $verbatim : 'json'];
        if ($this->table['metadata'] && ($columns !== null || in_array($output, self::RENDERINGS, true))) {
            $body['metadata'] = 1;
        }
        if ($limit !== null) {
            $body['limit'] = $limit;
            $body['page'] = $page;
        }
        if (!empty($order)) {
            $body['order'] = $order;
        }
        if ($query !== null) {
            $body['query'] = $query;
        }
        return [
            'kind' => 'search',
            'start' => $stmt['start'],
            'end' => $stmt['end'],
            'table' => $this->tableName,
            'endpoint' => $this->tables->search($this->tableName),
            'body' => $body,
            'output' => $output,
            'columns' => $columns,
            'skip' => $skip,
            'spans' => $this->spans,
        ];
    }

    private static function nonEmpty($word)
    {
        return $word !== null && $word !== '';
    }

    private function count(array $stmt)
    {
        if ($stmt['where'] === null) {
            throw new MispQLException(
                'COUNT(*) needs a WHERE',
                MispQLException::MISSING_CLAUSE,
                $stmt['columns']['start'],
                $stmt['columns']['end']
            );
        }
        $query = $this->node($stmt['where'], 'query');
        $clauses = [
            'ORDER BY' => $stmt['order'][0] ?? null,
            'LIMIT' => $stmt['limit'],
            'OFFSET' => $stmt['offset'],
            'FORMAT' => $stmt['format'],
        ];
        foreach ($clauses as $clause => $node) {
            if ($node !== null) {
                throw new MispQLException(
                    "COUNT(*) takes no $clause",
                    MispQLException::BAD_CLAUSE,
                    $node['start'],
                    $node['end']
                );
            }
        }
        if ($this->table['count'] === 'header') {
            // metadata: no event, however large, is fetched whole just to be counted.
            $body = ['returnFormat' => 'json', 'limit' => 1, 'page' => 1, 'metadata' => 1];
        } else {
            $body = ['returnFormat' => 'count'];
        }
        $body['query'] = $query;
        return [
            'kind' => 'count',
            'start' => $stmt['start'],
            'end' => $stmt['end'],
            'table' => $this->tableName,
            'endpoint' => $this->tables->search($this->tableName),
            'body' => $body,
            'source' => $this->table['count'],
            'spans' => $this->spans,
        ];
    }

    private function node(array $node, $path)
    {
        $this->spans[$path] = [$node['start'], $node['end']];
        if ($node['type'] === 'and' || $node['type'] === 'or') {
            $key = strtoupper($node['type']);
            $items = [];
            foreach ($node['items'] as $i => $item) {
                $items[] = $this->node($item, "$path.{$key}[$i]");
            }
            return [$key => $items];
        }
        if ($node['type'] === 'not') {
            return ['NOT' => $this->node($node['item'], "$path.NOT")];
        }
        $name = $this->field($node['field']);
        $value = $node['value'];
        $this->spans["$path.<unknown>"] = [$node['field']['start'], $node['field']['end']];
        return [$name => $node['op'] === '=' ? $value : [$node['op'] => $value]];
    }

    private function field(array $field)
    {
        if ($field['table'] === null || $field['table'] === $this->tableName) {
            return $field['name'];
        }
        if ($this->tables->has($field['table'])) {
            throw new MispQLException(
                'this field is qualified with another table than the one queried',
                MispQLException::WRONG_TABLE,
                $field['start'],
                $field['end']
            );
        }
        // Not a table, so part of the name: meta.synonyms, or Event.Orgc.name
        // as a column.
        return $field['table'] . '.' . $field['name'];
    }

    private function order(array $stmt)
    {
        $sortable = $this->tables->sortable($this->tableName);
        $rules = [];
        foreach ($stmt['order'] as $i => $item) {
            if (empty($sortable)) {
                throw new MispQLException(
                    'this table cannot be sorted',
                    MispQLException::NOT_SORTABLE,
                    $item['start'],
                    $item['end']
                );
            }
            $name = $this->field($item['field']);
            if (!array_key_exists($name, $sortable)) {
                throw new MispQLException(
                    'cannot sort this table by that field; use ' . implode(', ', array_keys($sortable)),
                    MispQLException::NOT_SORTABLE,
                    $item['field']['start'],
                    $item['field']['end']
                );
            }
            $this->spans["order[$i]"] = [$item['start'], $item['end']];
            $rules[] = $sortable[$name] . ($item['descending'] ? ' desc' : ' asc');
        }
        return $rules;
    }

    /**
     * @return array limit, page and the rows to skip in that page
     */
    private function paging(array $stmt, $verbatim)
    {
        $limit = $stmt['limit'];
        $offset = $stmt['offset'];
        if ($limit === null) {
            if ($offset !== null) {
                throw new MispQLException(
                    'OFFSET needs a LIMIT',
                    MispQLException::MISSING_CLAUSE,
                    $offset['start'],
                    $offset['end']
                );
            }
            return [null, null, 0];
        }
        if ($limit['value'] === 0) {
            throw new MispQLException(
                'LIMIT must be at least 1',
                MispQLException::BAD_CLAUSE,
                $limit['start'],
                $limit['end']
            );
        }
        $first = $offset === null ? 0 : $offset['value'];
        $skip = $first % $limit['value'];
        if ($skip !== 0 && self::nonEmpty($verbatim)) {
            throw new MispQLException(
                'OFFSET must be a multiple of LIMIT with a format MISP exports',
                MispQLException::BAD_CLAUSE,
                $offset['start'],
                $offset['end']
            );
        }
        $pages = intdiv($first, $limit['value']);
        if ($pages === PHP_INT_MAX) {
            throw new MispQLException(
                'OFFSET too large for this LIMIT',
                MispQLException::BAD_CLAUSE,
                $offset['start'],
                $offset['end']
            );
        }
        return [$limit['value'], $pages + 1, $skip];
    }
}
