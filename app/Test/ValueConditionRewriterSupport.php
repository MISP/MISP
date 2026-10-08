<?php
/**
 * Fakes for ValueConditionRewriterTest. Not a test file. Required from setUp,
 * see AttributeValueClassSupport.php.
 *
 * The dictionary compares like a ci collation with PAD SPACE: case folds and
 * trailing spaces are ignored by equality, not by LIKE. The evaluator runs a
 * Cake conditions array against one row in SQL's three-valued logic, either
 * on the text columns as 2.x stores them or on the value ids.
 */

require_once __DIR__ . '/AttributeValueClassSupport.php';
require_once __DIR__ . '/../Lib/Tools/ValueConditionRewriter.php';

class FakeValueDictionary extends AttributeValue
{
    /** @var array id => value */
    public $values = [];

    /** @var array[] method => list of arguments */
    public $calls = ['resolveCi' => [], 'resolveLike' => [], 'matchesEmpty' => []];

    public function __construct()
    {
    }

    /**
     * @param string $value
     * @return int
     */
    public function add($value)
    {
        $id = array_search($value, $this->values, true);
        if ($id === false) {
            $id = count($this->values) + 1;
            $this->values[$id] = $value;
        }
        return $id;
    }

    public function resolveCi(array $terms)
    {
        $this->calls['resolveCi'][] = $terms;
        $result = [];
        foreach ($terms as $term) {
            $result[(string)$term] = [];
            foreach ($this->values as $id => $value) {
                if (ValueConditionEvaluator::equals($value, (string)$term)) {
                    $result[(string)$term][] = $id;
                }
            }
        }
        return $result;
    }

    public function resolveLike($pattern, $limit)
    {
        $this->calls['resolveLike'][] = [$pattern, $limit];
        $ids = [];
        foreach ($this->values as $id => $value) {
            if (ValueConditionEvaluator::like($value, $pattern)) {
                $ids[] = $id;
            }
        }
        return count($ids) > $limit ? ['ids' => [], 'overflow' => true] : ['ids' => $ids, 'overflow' => false];
    }

    public function matchesEmpty(array $terms, $like = false)
    {
        $this->calls['matchesEmpty'][] = [$terms, $like];
        $result = [];
        foreach ($terms as $term) {
            $result[(string)$term] = $like
                ? ValueConditionEvaluator::like('', (string)$term)
                : ValueConditionEvaluator::equals('', (string)$term);
        }
        return $result;
    }

    public function likeCondition($field, $pattern, $not = false)
    {
        $expression = new stdClass();
        $expression->type = 'expression';
        $expression->value = sprintf('%s %sIN (LIKE %s)', $field, $not ? 'NOT ' : '', $pattern);
        $expression->field = $field;
        $expression->pattern = $pattern;
        $expression->not = $not;
        return $expression;
    }
}

class ValueConditionEvaluator
{
    /** @var FakeValueDictionary */
    private $dictionary;

    /** @var string */
    private $alias;

    public function __construct(FakeValueDictionary $dictionary, $alias)
    {
        $this->dictionary = $dictionary;
        $this->alias = $alias;
    }

    public static function equals($a, $b)
    {
        return rtrim(mb_strtolower($a), ' ') === rtrim(mb_strtolower($b), ' ');
    }

    public static function like($value, $pattern)
    {
        $regex = '';
        $chars = preg_split('//u', $pattern, -1, PREG_SPLIT_NO_EMPTY);
        for ($i = 0; $i < count($chars); $i++) {
            $char = $chars[$i];
            if ($char === '\\' && $i + 1 < count($chars)) {
                $regex .= preg_quote($chars[++$i], '/');
            } else if ($char === '%') {
                $regex .= '.*';
            } else if ($char === '_') {
                $regex .= '.';
            } else {
                $regex .= preg_quote($char, '/');
            }
        }
        return (bool)preg_match('/^' . $regex . '$/sui', $value);
    }

    /**
     * @param array|string $conditions
     * @param array $row ['value1' => , 'value2' => , 'value1_id' => , 'value2_id' => ]
     * @param bool $ids Evaluate on the ids rather than the text.
     * @return bool|null
     */
    public function evaluate($conditions, array $row, $ids)
    {
        if (!is_array($conditions)) {
            return $this->entry(0, $conditions, $row, $ids);
        }
        $results = [];
        foreach ($conditions as $key => $value) {
            $results[] = $this->entry($key, $value, $row, $ids);
        }
        return self::conjunction($results);
    }

    private function entry($key, $value, array $row, $ids)
    {
        if (is_numeric($key)) {
            if (is_array($value)) {
                return $this->evaluate($value, $row, $ids);
            }
            if (is_object($value)) {
                return $this->expression($value, $row);
            }
            if ($value === ValueConditionRewriter::SQL_TRUE) {
                return true;
            }
            if ($value === ValueConditionRewriter::SQL_FALSE) {
                return false;
            }
            throw new LogicException("Raw condition: $value");
        }
        switch (strtoupper(trim($key))) {
            case 'AND':
                return $this->evaluate($value, $row, $ids);
            case 'OR':
                $results = [];
                foreach ($value as $k => $v) {
                    $results[] = $this->entry($k, $v, $row, $ids);
                }
                return self::disjunction($results);
            case 'NOT':
                $results = [];
                foreach ($value as $k => $v) {
                    $results[] = self::negation($this->entry($k, $v, $row, $ids));
                }
                return self::conjunction($results);
            case 'XOR':
                $result = false;
                foreach ($value as $k => $v) {
                    $next = $this->entry($k, $v, $row, $ids);
                    $result = $result === null || $next === null ? null : $result !== $next;
                }
                return $result;
        }
        return $this->leaf($key, $value, $row, $ids);
    }

    private function leaf($key, $value, array $row, $ids)
    {
        $parts = preg_split('/\s+/', trim($key), 2);
        $operator = isset($parts[1]) ? strtoupper(trim($parts[1])) : '=';
        $field = preg_replace('/^' . preg_quote($this->alias, '/') . '\./', '', $parts[0]);
        if ($field === 'event_id') {
            return true;
        }
        if ($ids) {
            if (!in_array($field, ['value1_id', 'value2_id'], true)) {
                throw new LogicException("Text column on the id side: $key");
            }
            $id = $row[$field];
            if ($value === null) {
                return $operator === '=' ? $id === null : $id !== null;
            }
            if ($id === null) {
                return null;
            }
            $in = in_array($id, $value, true);
            return $operator === 'NOT IN' ? !$in : ($operator === 'IN' ? $in : $this->fail($key));
        }
        if (!in_array($field, ['value', 'value1', 'value2'], true)) {
            throw new LogicException("Unexpected column: $key");
        }
        $text = $field === 'value' ? $this->virtualValue($row) : $row[$field];
        if ($operator === 'LIKE' || $operator === 'NOT LIKE') {
            $match = self::like($text, (string)$value);
            return $operator === 'LIKE' ? $match : !$match;
        }
        if ($value === null || $value === []) {
            return in_array($operator, ['=', 'IN'], true) ? false : true;
        }
        $list = is_array($value) ? $value : [$value];
        $result = false;
        foreach ($list as $item) {
            $equal = $item === null ? null : self::equals($text, (string)$item);
            $result = self::disjunction([$result, $equal]);
        }
        return in_array($operator, ['=', 'IN'], true) ? $result : self::negation($result);
    }

    private function expression($expression, array $row)
    {
        $field = preg_replace('/^' . preg_quote($this->alias, '/') . '\./', '', $expression->field);
        $id = $row[$field];
        if ($id === null) {
            return null;
        }
        $match = self::like($this->dictionary->values[$id], $expression->pattern);
        return $expression->not ? !$match : $match;
    }

    private function virtualValue(array $row)
    {
        return self::equals($row['value2'], '') ? $row['value1'] : $row['value1'] . '|' . $row['value2'];
    }

    private function fail($key)
    {
        throw new LogicException("Unexpected id condition: $key");
    }

    public static function conjunction(array $results)
    {
        if (in_array(false, $results, true)) {
            return false;
        }
        return in_array(null, $results, true) ? null : true;
    }

    public static function disjunction(array $results)
    {
        if (in_array(true, $results, true)) {
            return true;
        }
        return in_array(null, $results, true) ? null : false;
    }

    public static function negation($result)
    {
        return $result === null ? null : !$result;
    }
}

class ReportingValueConditionRewriter extends ValueConditionRewriter
{
    /** @var string[] */
    public $reports = [];

    protected function report($message)
    {
        $this->reports[] = $message;
    }
}
