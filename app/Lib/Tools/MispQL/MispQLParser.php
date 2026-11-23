<?php
require_once __DIR__ . '/MispQLLexer.php';

/**
 * Parses a MispQL script into statement nodes. Nodes are arrays with a
 * `type` and their `start` / `end` offsets in the text.
 */
class MispQLParser
{
    // Parentheses and NOT inside one another in a condition. Redundant
    // parentheses leave no trace in the tree, so the tree's own depth limit
    // cannot stand in for this one.
    const MAX_DEPTH = 64;

    const COMPARISONS = [
        '=' => '=', '!=' => '!=', '<>' => '!=', '<' => '<', '>' => '>',
        '<=' => '<=', '>=' => '>=',
    ];

    const BACKTICK_HINT = '; quote it with backticks to use it as a name';

    /** @var MispQLLexer */
    private $lexer;
    /** @var array the current token */
    private $tok;
    /** @var array|null the token after it, once looked at */
    private $peeked = null;
    /** @var int end of the last token consumed */
    private $lastEnd = 0;
    /** @var int */
    private $depth = 0;

    /**
     * @param string $text
     * @throws MispQLException
     */
    public function __construct($text)
    {
        $this->lexer = new MispQLLexer($text);
        $this->tok = $this->lexer->next();
    }

    /**
     * The statements of a script, in order.
     *
     * @param string $text
     * @return array[]
     * @throws MispQLException at the first error
     */
    public static function parse($text)
    {
        return (new self($text))->script();
    }

    private function peek()
    {
        if ($this->peeked === null) {
            $this->peeked = $this->lexer->next();
        }
        return $this->peeked;
    }

    private function advance()
    {
        $tok = $this->tok;
        if ($tok['kind'] !== 'EOF') {
            $this->lastEnd = $tok['end'];
            if ($this->peeked !== null) {
                $this->tok = $this->peeked;
                $this->peeked = null;
            } else {
                $this->tok = $this->lexer->next();
            }
        }
        return $tok;
    }

    private function at($kind, $value = null)
    {
        return $this->tok['kind'] === $kind && ($value === null || $this->tok['value'] === $value);
    }

    private function accept($kind, $value = null)
    {
        return $this->at($kind, $value) ? $this->advance() : null;
    }

    private function keyword($word)
    {
        return $this->accept('KEYWORD', $word);
    }

    private function symbol($symbol)
    {
        return $this->accept('SYMBOL', $symbol);
    }

    private function expect($kind, $value, $expected)
    {
        $tok = $this->accept($kind, $value);
        if ($tok === null) {
            $this->fail($expected);
        }
        return $tok;
    }

    private function fail($expected, $hint = '')
    {
        throw new MispQLException(
            "expected $expected$hint",
            MispQLException::SYNTAX,
            $this->tok['start'],
            $this->tok['end'],
            $this->tok['kind'] === 'EOF'
        );
    }

    private static function node($type, array $tok, $value)
    {
        return ['type' => $type, 'value' => $value, 'start' => $tok['start'], 'end' => $tok['end']];
    }

    private function script()
    {
        $statements = [];
        while (true) {
            while ($this->symbol(';') !== null) {
            }
            if ($this->at('EOF')) {
                return $statements;
            }
            $statements[] = $this->statement();
            if (!($this->at('SYMBOL', ';') || $this->at('EOF'))) {
                $this->fail("';'");
            }
        }
    }

    private function statement()
    {
        $start = $this->tok['start'];
        if ($this->keyword('SELECT') !== null) {
            return $this->select($start);
        }
        if ($this->keyword('DESCRIBE') !== null || $this->keyword('DESC') !== null) {
            $table = $this->name('a table name');
            return ['type' => 'describe', 'table' => $table, 'start' => $start, 'end' => $table['end']];
        }
        if ($this->keyword('SHOW') !== null) {
            if ($this->keyword('DATABASES') !== null) {
                return ['type' => 'show_databases', 'start' => $start, 'end' => $this->lastEnd];
            }
            $tables = $this->expect('KEYWORD', 'TABLES', 'TABLES or DATABASES');
            return ['type' => 'show_tables', 'start' => $start, 'end' => $tables['end']];
        }
        if ($this->keyword('USE') !== null) {
            $database = $this->databaseName();
            return ['type' => 'use', 'database' => $database, 'start' => $start, 'end' => $database['end']];
        }
        if ($this->keyword('WHOAMI') !== null) {
            return ['type' => 'whoami', 'start' => $start, 'end' => $this->lastEnd];
        }
        $this->fail('SELECT, DESCRIBE, SHOW, USE or WHOAMI');
    }

    private function select($start)
    {
        $columns = $this->columns();
        $this->expect('KEYWORD', 'FROM', 'FROM');
        $stmt = [
            'type' => 'select',
            'columns' => $columns,
            'table' => $this->name('a table name'),
            'where' => null,
            'order' => [],
            'limit' => null,
            'offset' => null,
            'format' => null,
            'start' => $start,
            'end' => null,
        ];
        $following = ['WHERE', 'ORDER BY', 'LIMIT', 'OFFSET', 'FORMAT'];
        if ($this->keyword('WHERE') !== null) {
            $stmt['where'] = $this->expr();
            $following = ['AND', 'OR', 'ORDER BY', 'LIMIT', 'OFFSET', 'FORMAT'];
        }
        if ($this->keyword('ORDER') !== null) {
            $this->expect('KEYWORD', 'BY', 'BY');
            $stmt['order'][] = $this->orderItem();
            while ($this->symbol(',') !== null) {
                $stmt['order'][] = $this->orderItem();
            }
            $following = ["','", 'LIMIT', 'OFFSET', 'FORMAT'];
        }
        if ($this->keyword('LIMIT') !== null) {
            $stmt['limit'] = $this->wholeNumber('LIMIT');
            $following = ['OFFSET', 'FORMAT'];
        }
        if ($this->keyword('OFFSET') !== null) {
            $stmt['offset'] = $this->wholeNumber('OFFSET');
            $following = ['FORMAT'];
        }
        if ($this->keyword('FORMAT') !== null) {
            $stmt['format'] = $this->formatName();
            $following = [];
        }
        $stmt['end'] = $this->lastEnd;
        if (!($this->at('SYMBOL', ';') || $this->at('EOF'))) {
            $this->fail(self::oneOf(array_merge($following, ["';'"])));
        }
        return $stmt;
    }

    private static function oneOf(array $items)
    {
        if (count($items) === 1) {
            return $items[0];
        }
        $last = array_pop($items);
        return implode(', ', $items) . ' or ' . $last;
    }

    private function columns()
    {
        $first = $this->tok;
        if ($this->symbol('*') !== null) {
            return ['type' => 'star', 'start' => $first['start'], 'end' => $first['end']];
        }
        if ($this->keyword('COUNT') !== null) {
            $this->expect('SYMBOL', '(', "'('");
            $this->expect('SYMBOL', '*', "'*' (COUNT takes only *)");
            $close = $this->expect('SYMBOL', ')', "')'");
            return ['type' => 'count', 'start' => $first['start'], 'end' => $close['end']];
        }
        if ($this->at('NAME')) {
            $fields = [$this->field()];
            while ($this->symbol(',') !== null) {
                $fields[] = $this->field();
            }
            return ['type' => 'fields', 'items' => $fields];
        }
        $this->fail('*, COUNT(*) or field names');
    }

    private function name($expected)
    {
        if ($this->tok['kind'] !== 'NAME') {
            $this->fail($expected, $this->tok['kind'] === 'KEYWORD' ? self::BACKTICK_HINT : '');
        }
        $tok = $this->advance();
        return self::node('name', $tok, $tok['value']);
    }

    private function field()
    {
        $first = $this->name('a field name');
        if ($this->symbol('.') === null) {
            return [
                'type' => 'field',
                'name' => $first['value'],
                'table' => null,
                'start' => $first['start'],
                'end' => $first['end'],
            ];
        }
        $rest = [$this->name('a field name')];
        while ($this->symbol('.') !== null) {
            $rest[] = $this->name('a field name');
        }
        // Columns can reach deeper into a row (Event.Orgc.name): the first
        // part is the qualifier.
        return [
            'type' => 'field',
            'name' => implode('.', array_column($rest, 'value')),
            'table' => $first['value'],
            'start' => $first['start'],
            'end' => end($rest)['end'],
        ];
    }

    private function orderItem()
    {
        $field = $this->field();
        $item = [
            'type' => 'order_item',
            'field' => $field,
            'descending' => false,
            'start' => $field['start'],
            'end' => $field['end'],
        ];
        $direction = $this->keyword('DESC') ?? $this->keyword('ASC');
        if ($direction !== null) {
            $item['descending'] = $direction['value'] === 'DESC';
            $item['end'] = $direction['end'];
        }
        return $item;
    }

    private function wholeNumber($clause)
    {
        if ($this->tok['kind'] !== 'INT') {
            $this->fail("a whole number after $clause");
        }
        $tok = $this->advance();
        return self::node('literal', $tok, MispQLLexer::intValue($tok['value']));
    }

    private function formatName()
    {
        $kind = $this->tok['kind'];
        if ($kind === 'STRING' || ($kind === 'NAME' && $this->tok['quoted'])) {
            $tok = $this->advance();
            return self::node('name', $tok, $tok['value']);
        }
        if ($kind !== 'NAME' && $kind !== 'KEYWORD') {
            $this->fail('a format name');
        }
        return $this->hyphenated();
    }

    private function databaseName()
    {
        $kind = $this->tok['kind'];
        if ($kind === 'NAME' && $this->tok['quoted']) {
            $tok = $this->advance();
            return self::node('name', $tok, $tok['value']);
        }
        if ($kind !== 'NAME') {
            $this->fail('a database name', $kind === 'KEYWORD' ? self::BACKTICK_HINT : '');
        }
        return $this->hyphenated();
    }

    /**
     * Format and database names may hold hyphens (stix-json): the pieces
     * written without spaces are glued, lowercased.
     */
    private function hyphenated()
    {
        $first = $this->advance();
        $value = strtolower($first['value']);
        $end = $first['end'];
        while ($this->at('SYMBOL', '-') && $this->tok['start'] === $end) {
            $piece = $this->peek();
            if (!in_array($piece['kind'], ['NAME', 'KEYWORD', 'INT'], true)
                || $piece['quoted']
                || $piece['start'] !== $this->tok['end']
            ) {
                break;
            }
            $this->advance();
            $piece = $this->advance();
            $value .= '-' . strtolower($piece['value']);
            $end = $piece['end'];
        }
        return ['type' => 'name', 'value' => $value, 'start' => $first['start'], 'end' => $end];
    }

    private function expr()
    {
        return $this->chain('or', 'OR', 'andExpr');
    }

    private function andExpr()
    {
        return $this->chain('and', 'AND', 'notExpr');
    }

    private function chain($type, $word, $operand)
    {
        $start = $this->tok['start'];
        $items = [$this->$operand()];
        while ($this->keyword($word) !== null) {
            $items[] = $this->$operand();
        }
        if (count($items) === 1) {
            return $items[0];
        }
        $flat = [];
        foreach ($items as $item) {
            if ($item['type'] === $type) {
                array_push($flat, ...$item['items']);
            } else {
                $flat[] = $item;
            }
        }
        return ['type' => $type, 'items' => $flat, 'start' => $start, 'end' => $this->lastEnd];
    }

    private function notExpr()
    {
        $tok = $this->tok;
        if ($this->keyword('NOT') !== null) {
            $this->enter($tok);
            $item = $this->notExpr();
            $this->depth--;
            return ['type' => 'not', 'item' => $item, 'start' => $tok['start'], 'end' => $this->lastEnd];
        }
        if ($this->symbol('(') !== null) {
            $this->enter($tok);
            $inner = $this->expr();
            $this->expect('SYMBOL', ')', "')'");
            $this->depth--;
            return $inner;
        }
        return $this->predicate();
    }

    /**
     * One level deeper, at the NOT or '(' just read.
     */
    private function enter(array $tok)
    {
        $this->depth++;
        if ($this->depth > self::MAX_DEPTH) {
            throw new MispQLException(
                'nested too deep: at most ' . self::MAX_DEPTH . ' levels of parentheses and NOT',
                MispQLException::LIMIT_EXCEEDED,
                $tok['start'],
                $tok['end']
            );
        }
    }

    private function predicate()
    {
        $field = $this->field();
        if ($this->tok['kind'] === 'SYMBOL' && isset(self::COMPARISONS[$this->tok['value']])) {
            $op = self::COMPARISONS[$this->advance()['value']];
            return $this->comparison($field, $op, $this->literal()['value']);
        }
        $negated = $this->keyword('NOT') !== null;
        if ($this->keyword('IN') !== null) {
            return $this->comparison($field, $negated ? 'NOT IN' : 'IN', $this->literalList());
        }
        if ($this->keyword('LIKE') !== null) {
            return $this->comparison($field, $negated ? 'NOT LIKE' : 'LIKE', $this->pattern()['value']);
        }
        if ($negated) {
            $this->fail('IN or LIKE after NOT');
        }
        $this->fail('an operator (=, !=, <, >, <=, >=, IN, NOT IN, LIKE, NOT LIKE)');
    }

    /**
     * Only the value is kept, or for IN the list of values: nothing points
     * at the literal itself.
     *
     * @param array $field
     * @param string $op
     * @param mixed $value
     */
    private function comparison(array $field, $op, $value)
    {
        return [
            'type' => 'comparison',
            'field' => $field,
            'op' => $op,
            'value' => $value,
            'start' => $field['start'],
            'end' => $this->lastEnd,
        ];
    }

    private function literal()
    {
        $tok = $this->tok;
        if ($tok['kind'] === 'STRING') {
            return self::node('literal', $this->advance(), $tok['value']);
        }
        if ($tok['kind'] === 'INT') {
            return self::node('literal', $this->advance(), MispQLLexer::intValue($tok['value']));
        }
        if ($tok['kind'] === 'KEYWORD' && ($tok['value'] === 'TRUE' || $tok['value'] === 'FALSE')) {
            return self::node('literal', $this->advance(), $tok['value'] === 'TRUE');
        }
        if ($tok['kind'] === 'SYMBOL' && $tok['value'] === '-' && $this->peek()['kind'] === 'INT') {
            $this->advance();
            $number = $this->advance();
            return [
                'type' => 'literal',
                'value' => -MispQLLexer::intValue($number['value']),
                'start' => $tok['start'],
                'end' => $number['end'],
            ];
        }
        $hint = $tok['kind'] === 'NAME' && !$tok['quoted'] ? '; strings need quotes' : '';
        $this->fail("a value ('string', number, TRUE or FALSE)", $hint);
    }

    private function literalList()
    {
        $this->expect('SYMBOL', '(', "'(' after IN");
        if ($this->at('SYMBOL', ')')) {
            $this->fail('at least one value in IN (...)');
        }
        $values = [$this->literal()['value']];
        while ($this->symbol(',') !== null) {
            $values[] = $this->literal()['value'];
        }
        $this->expect('SYMBOL', ')', "',' or ')'");
        return $values;
    }

    private function pattern()
    {
        if ($this->tok['kind'] !== 'STRING') {
            $this->fail("a 'quoted pattern' after LIKE");
        }
        $tok = $this->advance();
        return self::node('literal', $tok, $tok['value']);
    }
}
