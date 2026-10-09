<?php
require_once __DIR__ . '/ValueConditionException.php';

/**
 * Carries find conditions on the value columns of one attribute or proposal
 * alias (value, value1, value2) over to the value ids, with the meaning they
 * had on the 2.x text columns: equality and LIKE in the dictionary
 * collation, and an empty value2 wherever value2_id is NULL.
 *
 * Terms become literal id lists before the find runs. A LIKE pattern that
 * matches more values than the overflow limit reads the dictionary inside
 * the statement instead, and so does an unanchored pattern in a find bounded
 * to a few events, objects or attributes, where scanning the dictionary up
 * front would cost more than the find.
 */
class ValueConditionRewriter
{
    const OVERFLOW = 50000;

    const BOUND = 100;

    const BOOL_OPS = ['and', 'or', 'not', 'and not', 'or not', 'xor', '||', '&&'];

    const OPERATORS = ['=', 'IN', '!=', '<>', 'NOT IN', 'LIKE', 'NOT LIKE'];

    const NEGATIVE = ['!=', '<>', 'NOT IN', 'NOT LIKE'];

    const SQL_TRUE = '1 = 1';

    const SQL_FALSE = '1 = 0';

    /** @var AttributeValue */
    private $dictionary;

    /** @var string */
    private $alias;

    /** @var bool */
    private $strict;

    /** @var int */
    private $overflow;

    /** @var bool */
    private $bounded = false;

    /** @var bool */
    private $alwaysBounded;

    /** @var array term => int[] */
    private $ci = [];

    /** @var array pattern => set */
    private $likes = [];

    /** @var array ['=' => [term => bool], 'LIKE' => [pattern => bool]] */
    private $empty = ['=' => [], 'LIKE' => []];

    /** @var bool Whether rewrites keep what they resolve, since prime() */
    private $primed = false;

    /**
     * @param AttributeValue $dictionary
     * @param string $alias
     * @param array $options 'strict': throw on a condition that cannot be
     *   carried over (default: debug mode); 'overflow': LIKE match limit;
     *   'bounded': the find reads few rows whatever its conditions say.
     */
    public function __construct(AttributeValue $dictionary, $alias, array $options = [])
    {
        $this->dictionary = $dictionary;
        $this->alias = $alias;
        $this->strict = isset($options['strict']) ? (bool)$options['strict'] : Configure::read('debug') > 0;
        $this->overflow = isset($options['overflow']) ? (int)$options['overflow'] : self::OVERFLOW;
        $this->alwaysBounded = !empty($options['bounded']);
    }

    /**
     * @param mixed $conditions A find's conditions.
     * @return mixed
     * @throws ValueConditionException In strict mode.
     */
    public function rewrite($conditions)
    {
        if (!$this->primed) {
            $this->ci = [];
            $this->likes = [];
            $this->empty = ['=' => [], 'LIKE' => []];
        }
        if (is_string($conditions)) {
            $this->checkRaw($conditions);
            return $conditions;
        }
        if (!is_array($conditions)) {
            return $conditions;
        }
        $this->bounded = $this->alwaysBounded || $this->isBounded($conditions);
        return $this->walk($conditions, false);
    }

    /**
     * Resolves the terms of a batch of finds in one statement, rather than
     * one per find. From then on, rewrites keep what they resolve.
     *
     * @param array $terms
     * @return void
     */
    public function prime(array $terms)
    {
        $this->primed = true;
        $terms = array_values(array_unique(array_map('strval', $terms)));
        if (!empty($terms)) {
            $this->resolve($terms);
            $this->emptyEquals($terms);
        }
    }

    /**
     * The key of the term's value group: the lowest id among its case
     * variants, resolved now if the term was not primed.
     *
     * @param string $term
     * @return int|null Null when the dictionary does not hold the term.
     */
    public function groupId($term)
    {
        $term = (string)$term;
        $this->resolve([$term]);
        return empty($this->ci[$term]) ? null : min($this->ci[$term]);
    }

    /**
     * @param array $conditions
     * @param bool $negated Under a NOT or an XOR, where a NULL result is not
     *   the same as false.
     * @return array
     */
    private function walk(array $conditions, $negated)
    {
        $out = [];
        foreach ($conditions as $key => $value) {
            if (is_numeric($key)) {
                if (is_array($value)) {
                    $value = $this->walk($value, $negated);
                } else if (is_string($value)) {
                    $this->checkRaw($value);
                }
                $out[] = $value;
                continue;
            }
            $bool = strtolower(trim($key));
            if (in_array($bool, self::BOOL_OPS, true)) {
                if (is_array($value)) {
                    $value = $this->walk($value, $negated || $bool === 'xor' || strpos($bool, 'not') !== false);
                } else if (is_string($value)) {
                    $this->checkRaw($value);
                }
                $out[$key] = $value;
                continue;
            }
            $parsed = $this->parseKey($key);
            if ($parsed === null) {
                $out[$key] = $value;
                continue;
            }
            $node = $parsed === false ? null : $this->leaf($parsed[0], $parsed[1], $value, $negated);
            if ($node === null) {
                $this->unrecognised([$key => $value]);
                $out[$key] = $value;
                continue;
            }
            $out[] = $this->render($node);
        }
        return $out;
    }

    /**
     * @param string $key
     * @return array|false|null [column, operator]; false for a value column
     *   in a form this class does not handle; null for any other column.
     */
    private function parseKey($key)
    {
        $parts = preg_split('/\s+/', trim($key), 2);
        $column = $this->ownColumn($parts[0]);
        if ($column === null) {
            return $this->mentionsValue($key) ? false : null;
        }
        $operator = isset($parts[1]) ? strtoupper(preg_replace('/\s+/', ' ', trim($parts[1]))) : '=';
        return in_array($operator, self::OPERATORS, true) ? [$column, $operator] : false;
    }

    /**
     * @param string $field
     * @return string|null
     */
    private function ownColumn($field)
    {
        $field = str_replace(['`', '"'], '', $field);
        if (!preg_match('/^(?:(\w+)\.)?(value|value1|value2)$/', $field, $match)) {
            return null;
        }
        return $match[1] === '' || $match[1] === $this->alias ? $match[2] : null;
    }

    /**
     * @param string $sql
     * @return bool
     */
    private function mentionsValue($sql)
    {
        $sql = preg_replace("/'(?:[^'\\\\]|\\\\.|'')*'/s", "''", $sql);
        $aliases = implode('|', array_map(function ($alias) {
            return preg_quote($alias, '/');
        }, array_unique(['Attribute', 'ShadowAttribute', $this->alias])));
        return preg_match('/(?<![\w$])value[12](?!\w)/i', $sql)
            || preg_match('/(?<![\w$])[`"]?(?:' . $aliases . ')[`"]?\.[`"]?value(?!\w)/', $sql);
    }

    /**
     * @param string $column
     * @param string $operator
     * @param mixed $value
     * @param bool $negated
     * @return array|null A node, or null for a value this class does not handle.
     */
    private function leaf($column, $operator, $value, $negated)
    {
        $negative = in_array($operator, self::NEGATIVE, true);
        if ($operator === 'LIKE' || $operator === 'NOT LIKE') {
            if (!self::isTerm($value)) {
                return null;
            }
            $pattern = (string)$value;
            if ($column === 'value') {
                $node = $this->valueLike($pattern);
                return $negative ? self::not($node) : $node;
            }
            $empty = $column === 'value2' && $this->emptyLike($pattern);
            return $this->columnNode($column, $this->likeSet($pattern), $empty, $negative, $negated);
        }
        $parsed = self::terms($operator, $value);
        if ($parsed === null) {
            return null;
        }
        list($terms, $null) = $parsed;
        if ($negative && $null) {
            return ['F'];
        }
        if (empty($terms)) {
            return $negative ? ['T'] : ['F'];
        }
        if ($column === 'value') {
            $node = $this->valueEquals($terms);
            return $negative ? self::not($node) : $node;
        }
        $this->resolve($terms);
        $empty = $column === 'value2' && in_array(true, $this->emptyEquals($terms), true);
        return $this->columnNode($column, ['ids', $this->idsFor($terms)], $empty, $negative, $negated);
    }

    /**
     * @param string $operator
     * @param mixed $value
     * @return array|null [string[] terms, bool whether a list held a NULL]
     */
    private static function terms($operator, $value)
    {
        $list = $operator === 'IN' || $operator === 'NOT IN';
        if ($value === null || self::isTerm($value)) {
            return $list ? null : [$value === null ? [] : [(string)$value], false];
        }
        if (!is_array($value) || array_keys($value) !== array_keys(array_values($value))) {
            return null;
        }
        if (empty($value) && $operator === 'NOT IN') {
            return null;
        }
        $terms = [];
        $null = false;
        foreach ($value as $item) {
            if ($item === null) {
                $null = true;
            } else if (self::isTerm($item)) {
                $terms[(string)$item] = true;
            } else {
                return null;
            }
        }
        return [array_map('strval', array_keys($terms)), $null];
    }

    /**
     * @param mixed $value
     * @return bool
     */
    private static function isTerm($value)
    {
        return is_string($value) || is_int($value) || is_float($value);
    }

    /**
     * One id column against a set, value2 with NULL standing for ''.
     *
     * @param string $column value1 or value2
     * @param array $set
     * @param bool $empty Whether '' matches the term or pattern.
     * @param bool $negative
     * @param bool $negated
     * @return array
     */
    private function columnNode($column, array $set, $empty, $negative, $negated)
    {
        if ($column === 'value1') {
            return $negative ? $this->notIn('value1', $set) : $this->in('value1', $set);
        }
        if ($set[0] === 'all') {
            if ($empty) {
                return $negative ? ['F'] : ['T'];
            }
            return $negative ? $this->isNull() : $this->notNull();
        }
        if ($negative) {
            return $empty
                ? self::all([$this->notNull(), $this->notIn('value2', $set)])
                : self::any([$this->isNull(), $this->notIn('value2', $set)]);
        }
        if ($empty) {
            return self::any([$this->isNull(), $this->in('value2', $set)]);
        }
        $in = $this->in('value2', $set);
        return $negated ? self::all([$this->notNull(), $in]) : $in;
    }

    /**
     * The value field is value1 when value2 is empty, else value1|value2, so
     * a term with a pipe can also match a composite split at any of its pipes.
     *
     * @param string[] $terms
     * @return array
     */
    private function valueEquals(array $terms)
    {
        $splits = [];
        $wanted = array_merge($terms, ['']);
        foreach ($terms as $term) {
            $offset = 0;
            while (($pipe = strpos($term, '|', $offset)) !== false) {
                $splits[] = [substr($term, 0, $pipe), substr($term, $pipe + 1)];
                $wanted[] = substr($term, 0, $pipe);
                $wanted[] = substr($term, $pipe + 1);
                $offset = $pipe + 1;
            }
        }
        $this->resolve($wanted);
        $blank = $this->ci[''];
        $readings = [];
        foreach ($splits as $split) {
            $first = $this->ci[$split[0]];
            $second = $this->ci[$split[1]];
            if (!empty($first) && !empty($second) && !array_intersect($second, $blank)) {
                $readings[] = self::all([$this->in('value1', ['ids', $first]), $this->in('value2', ['ids', $second])]);
            }
        }
        return self::any([
            self::all([$this->blank(), $this->in('value1', ['ids', $this->idsFor($terms)])]),
            self::all([$this->filled(), self::any($readings)]),
        ]);
    }

    /**
     * On a composite the separator can be matched by a literal pipe, by an
     * underscore or inside a percent sign of the pattern.
     *
     * @param string $pattern
     * @return array
     */
    private function valueLike($pattern)
    {
        $units = self::units($pattern);
        $readings = [];
        foreach ($units as $index => $unit) {
            if ($unit === '%') {
                $first = array_slice($units, 0, $index + 1);
                $second = array_slice($units, $index);
            } else if ($unit === '_' || $unit === '|') {
                $first = array_slice($units, 0, $index);
                $second = array_slice($units, $index + 1);
            } else {
                continue;
            }
            $readings[] = self::all([
                $this->in('value1', $this->likeSet(implode('', $first))),
                $this->in('value2', $this->likeSet(implode('', $second))),
            ]);
        }
        return self::any([
            self::all([$this->blank(), $this->in('value1', $this->likeSet($pattern))]),
            self::all([$this->filled(), self::any($readings)]),
        ]);
    }

    /**
     * A LIKE pattern as units: '%' and '_' are wildcards, every other unit is
     * one literal byte, escaped where LIKE needs it. Bytes of a multibyte
     * character never equal an ASCII byte, so splitting on bytes is safe.
     *
     * @param string $pattern
     * @return string[]
     */
    private static function units($pattern)
    {
        $units = [];
        $length = strlen($pattern);
        for ($i = 0; $i < $length; $i++) {
            $char = $pattern[$i];
            if ($char === '\\' && $i + 1 < $length) {
                $char = $pattern[++$i];
                $units[] = in_array($char, ['%', '_', '\\'], true) ? '\\' . $char : $char;
            } else {
                $units[] = $char === '\\' ? '\\\\' : $char;
            }
        }
        return $units;
    }

    /**
     * @param string $pattern
     * @return array ['all'], ['ids', int[]] or ['like', pattern]
     */
    private function likeSet($pattern)
    {
        if (isset($this->likes[$pattern])) {
            return $this->likes[$pattern];
        }
        $units = self::units($pattern);
        if (!empty($units) && array_diff($units, ['%']) === []) {
            $set = ['all'];
        } else if ($this->bounded && !empty($units) && ($units[0] === '%' || $units[0] === '_')) {
            $set = ['like', $pattern];
        } else {
            $found = $this->dictionary->resolveLike($pattern, $this->overflow);
            $set = $found['overflow'] ? ['like', $pattern] : ['ids', $found['ids']];
        }
        return $this->likes[$pattern] = $set;
    }

    /**
     * @param string[] $terms
     * @return void
     */
    private function resolve(array $terms)
    {
        $missing = [];
        foreach ($terms as $term) {
            if (!isset($this->ci[$term])) {
                $missing[$term] = true;
            }
        }
        if (!empty($missing)) {
            $this->ci = array_replace($this->ci, $this->dictionary->resolveCi(array_map('strval', array_keys($missing))));
        }
    }

    /**
     * @param string[] $terms
     * @return int[]
     */
    private function idsFor(array $terms)
    {
        $ids = [];
        foreach ($terms as $term) {
            foreach ($this->ci[$term] as $id) {
                $ids[$id] = true;
            }
        }
        $ids = array_keys($ids);
        sort($ids);
        return $ids;
    }

    /**
     * @param string[] $terms
     * @return bool[] [term => bool]
     */
    private function emptyEquals(array $terms)
    {
        $missing = array_diff($terms, array_map('strval', array_keys($this->empty['='])));
        if (!empty($missing)) {
            $this->empty['='] = array_replace($this->empty['='], $this->dictionary->matchesEmpty(array_values($missing)));
        }
        return array_intersect_key($this->empty['='], array_flip($terms));
    }

    /**
     * @param string $pattern
     * @return bool
     */
    private function emptyLike($pattern)
    {
        if (!isset($this->empty['LIKE'][$pattern])) {
            $this->empty['LIKE'] += $this->dictionary->matchesEmpty([$pattern], true);
        }
        return $this->empty['LIKE'][$pattern];
    }

    /**
     * Rows whose value2 is empty: NULL, or a value the collation equates
     * with '' (spaces only, under PAD SPACE).
     *
     * @return array
     */
    private function blank()
    {
        $this->resolve(['']);
        if (empty($this->ci[''])) {
            return $this->isNull();
        }
        return self::any([$this->isNull(), $this->in('value2', ['ids', $this->ci['']])]);
    }

    /**
     * @return array
     */
    private function filled()
    {
        $this->resolve(['']);
        if (empty($this->ci[''])) {
            return $this->notNull();
        }
        return self::all([$this->notNull(), $this->notIn('value2', ['ids', $this->ci['']])]);
    }

    /**
     * @param string $column
     * @param array $set
     * @return array
     */
    private function in($column, array $set)
    {
        $field = $this->alias . '.' . $column . '_id';
        switch ($set[0]) {
            case 'all':
                return $column === 'value1' ? ['T'] : $this->notNull();
            case 'like':
                return ['c', [$this->dictionary->likeCondition($field, $set[1])]];
        }
        return empty($set[1]) ? ['F'] : ['c', [$field . ' IN' => $set[1]]];
    }

    /**
     * NOT IN for the ids a column holds; callers decide what a NULL means.
     *
     * @param string $column
     * @param array $set
     * @return array
     */
    private function notIn($column, array $set)
    {
        $field = $this->alias . '.' . $column . '_id';
        switch ($set[0]) {
            case 'all':
                return ['F'];
            case 'like':
                return ['c', [$this->dictionary->likeCondition($field, $set[1], true)]];
        }
        return empty($set[1]) ? ['T'] : ['c', [$field . ' NOT IN' => $set[1]]];
    }

    /**
     * @return array
     */
    private function isNull()
    {
        return ['c', [$this->alias . '.value2_id' => null]];
    }

    /**
     * @return array
     */
    private function notNull()
    {
        return ['c', [$this->alias . '.value2_id !=' => null]];
    }

    /**
     * @param array[] $nodes
     * @return array
     */
    private static function all(array $nodes)
    {
        $out = [];
        foreach ($nodes as $node) {
            if ($node[0] === 'F') {
                return $node;
            }
            if ($node[0] === 'and') {
                array_push($out, ...$node[1]);
            } else if ($node[0] !== 'T') {
                $out[] = $node;
            }
        }
        if (empty($out)) {
            return ['T'];
        }
        return count($out) === 1 ? $out[0] : ['and', $out];
    }

    /**
     * @param array[] $nodes
     * @return array
     */
    private static function any(array $nodes)
    {
        $out = [];
        foreach ($nodes as $node) {
            if ($node[0] === 'T') {
                return $node;
            }
            foreach ($node[0] === 'or' ? $node[1] : [$node] as $operand) {
                if ($operand[0] !== 'F') {
                    $out[serialize($operand)] = $operand;
                }
            }
        }
        if (empty($out)) {
            return ['F'];
        }
        return count($out) === 1 ? reset($out) : ['or', array_values($out)];
    }

    /**
     * @param array $node
     * @return array
     */
    private static function not(array $node)
    {
        switch ($node[0]) {
            case 'T':
                return ['F'];
            case 'F':
                return ['T'];
            case 'not':
                return $node[1];
        }
        return ['not', $node];
    }

    /**
     * Cake negates every entry of a NOT group on its own, so a negated
     * conjunction goes in as a single nested group.
     *
     * @param array $node
     * @return array|string
     */
    private function render(array $node)
    {
        switch ($node[0]) {
            case 'T':
                return self::SQL_TRUE;
            case 'F':
                return self::SQL_FALSE;
            case 'c':
                return $node[1];
            case 'and':
                return array_map([$this, 'render'], $node[1]);
            case 'or':
                return ['OR' => array_map([$this, 'render'], $node[1])];
        }
        return ['NOT' => [$this->render($node[1])]];
    }

    /**
     * Whether the top level of the conditions ties the find to a few events,
     * objects or attributes.
     *
     * @param array $conditions
     * @return bool
     */
    private function isBounded(array $conditions)
    {
        foreach ($conditions as $key => $value) {
            if (is_numeric($key) || in_array(strtolower(trim($key)), ['and', '&&'], true)) {
                if (is_array($value) && $this->isBounded($value)) {
                    return true;
                }
                continue;
            }
            $parts = preg_split('/\s+/', trim($key), 2);
            $operator = isset($parts[1]) ? strtoupper(trim($parts[1])) : '=';
            $field = '/^(?:' . preg_quote($this->alias, '/') . '\.)?(?:event_id|object_id|id)$/';
            if (!in_array($operator, ['=', 'IN'], true) || !preg_match($field, $parts[0])) {
                continue;
            }
            if (is_scalar($value) || (is_array($value) && !empty($value) && count($value) <= self::BOUND)) {
                // object_id 0 stands for every attribute outside an object
                if (substr($parts[0], -9) === 'object_id' && in_array(0, (array)$value)) {
                    continue;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $sql
     * @return void
     */
    private function checkRaw($sql)
    {
        if ($this->mentionsValue($sql)) {
            $this->unrecognised($sql);
        }
    }

    /**
     * @param array|string $condition
     * @return void
     * @throws ValueConditionException
     */
    private function unrecognised($condition)
    {
        $text = is_string($condition) ? $condition : json_encode($condition);
        $message = sprintf(
            'A condition on the %s value columns cannot be moved to the value ids: %s',
            $this->alias,
            mb_strimwidth((string)$text, 0, 300, '...')
        );
        if ($this->strict) {
            throw new ValueConditionException($message);
        }
        $this->report($message);
    }

    /**
     * @param string $message
     * @return void
     */
    protected function report($message)
    {
        CakeLog::write('warning', $message);
    }
}
