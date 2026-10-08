<?php
/**
 * Carries the value field of one attribute or proposal alias, which 2.x
 * computed in SQL from value1 and value2, over to the value ids. A field list
 * that names it reads the ids instead, for afterFind to fill in, and an order
 * on it sorts by the dictionary text, joined by primary key to the rows the
 * find reads.
 */
class ValueFieldTranslator
{
    const ID_FIELDS = ['value1_id', 'value2_id'];

    const VALUE_KEYS = ['value1', 'value2', 'value'];

    /** @var DboSource */
    private $db;

    /** @var string */
    private $alias;

    /** @var string */
    private $table;

    /** @var array|null */
    private $keys;

    /**
     * @param DboSource $db
     * @param string $alias
     * @param string $table The dictionary table, unprefixed.
     */
    public function __construct(DboSource $db, $alias, $table)
    {
        $this->db = $db;
        $this->alias = $alias;
        $this->table = $table;
    }

    /**
     * @param array $query A find query, as beforeFind receives it.
     * @return array
     */
    public function translate(array $query)
    {
        $this->keys = null;
        if (!empty($query['fields'])) {
            $query['fields'] = $this->fields($query['fields']);
        }
        if (!empty($query['order'])) {
            $order = $this->order($query['order']);
            if ($order !== null) {
                $query['order'] = $order;
                $query['joins'] = array_merge(empty($query['joins']) ? [] : $query['joins'], $this->joins());
            }
        }
        return $query;
    }

    /**
     * The value keys the field list named, null when it did not name the
     * value field.
     *
     * @return string[]|null
     */
    public function keys()
    {
        return $this->keys;
    }

    /**
     * @param array|string $fields
     * @return array|string
     */
    private function fields($fields)
    {
        if (is_string($fields)) {
            if (strpos($fields, '(') !== false) {
                return $fields;
            }
            $list = array_map('trim', explode(',', $fields));
        } else if (is_array($fields)) {
            $list = $fields;
        } else {
            return $fields;
        }
        $names = [];
        foreach ($list as $field) {
            if (is_string($field)) {
                $names[] = $this->bare($field);
            }
        }
        if (!in_array('value', $names, true)) {
            return $fields;
        }
        // Every column brings the ids, and with them all three value keys
        $everyColumn = in_array('*', $names, true);
        $translated = [];
        $added = $everyColumn;
        foreach ($list as $field) {
            if (!is_string($field) || $this->bare($field) !== 'value') {
                $translated[] = $field;
            } else if (!$added) {
                foreach (self::ID_FIELDS as $id) {
                    if (!in_array($id, $names, true)) {
                        $translated[] = $this->alias . '.' . $id;
                    }
                }
                $added = true;
            }
        }
        if (!$everyColumn) {
            $this->keys = array_values(array_intersect(self::VALUE_KEYS, $names));
        }
        return $translated;
    }

    /**
     * @param mixed $order The find's order, an array once buildQuery has run.
     * @return array|null The order with the value field replaced, null when
     *   it does not sort on it.
     */
    private function order($order)
    {
        $translated = [];
        $found = false;
        foreach ($this->orderItems((array)$order) as list($key, $direction, $fragment)) {
            if ($key !== null && $this->bare($key) === 'value') {
                $translated[] = $this->db->expression($this->sortKey() . ' ' . $direction);
                $found = true;
            } else {
                $translated[] = $fragment;
            }
        }
        return $found ? $translated : null;
    }

    /**
     * The order flattened as DboSource::order() reads it.
     *
     * @param array $order
     * @return array [[key or null, direction, the fragment it came from]]
     */
    private function orderItems(array $order)
    {
        $items = [];
        foreach ($order as $key => $value) {
            if (!is_numeric($key)) {
                $items[] = $this->orderItem($key, $value, [$key => $value]);
            } else if (is_array($value)) {
                $items = array_merge($items, $this->orderItems($value));
            } else if (!is_string($value)) {
                $items[] = [null, null, $value];
            } else if (strpos($value, ',') !== false && !preg_match('/\(.+\,.+\)/', $value)) {
                foreach (explode(',', $value) as $part) {
                    $items[] = $this->orderItem(trim($part), null, trim($part));
                }
            } else {
                $items[] = $this->orderItem($value, null, $value);
            }
        }
        return $items;
    }

    /**
     * @param string $key
     * @param mixed $direction
     * @param mixed $fragment
     * @return array
     */
    private function orderItem($key, $direction, $fragment)
    {
        if (preg_match('/\x20(ASC|DESC).*/i', $key, $match)) {
            $direction = $match[0];
            $key = preg_replace('/\x20(ASC|DESC).*/i', '', $key);
        }
        $direction = is_string($direction) && strtoupper(trim($direction)) === 'DESC' ? 'DESC' : 'ASC';
        return [trim($key), $direction, $fragment];
    }

    /**
     * @param string $field
     * @return string The field without this alias, if it had it.
     */
    private function bare($field)
    {
        $field = trim($field);
        $prefix = $this->alias . '.';
        return strpos($field, $prefix) === 0 ? substr($field, strlen($prefix)) : $field;
    }

    /**
     * The value as 2.x built it, from the dictionary rows of both ids.
     *
     * @return string
     */
    private function sortKey()
    {
        $value1 = $this->db->name($this->sortAlias(1) . '.value');
        $value2 = $this->db->name($this->sortAlias(2) . '.value');
        // 2.x tests value2 = '', which a PAD SPACE collation also holds for spaces
        return sprintf(
            "(CASE WHEN %s IS NULL OR LENGTH(TRIM(TRAILING ' ' FROM %s)) = 0 THEN %s ELSE CONCAT(%s, '|', %s) END)",
            $this->db->name($this->sortAlias(2) . '.id'),
            $value2,
            $value1,
            $value1,
            $value2
        );
    }

    /**
     * Left joins, so that the dictionary never drives the find.
     *
     * @return array
     */
    private function joins()
    {
        $joins = [];
        foreach ([1, 2] as $n) {
            $joins[] = [
                'table' => $this->table,
                'alias' => $this->sortAlias($n),
                'type' => 'LEFT',
                'conditions' => [sprintf('%s.id = %s.value%d_id', $this->sortAlias($n), $this->alias, $n)],
            ];
        }
        return $joins;
    }

    /**
     * @param int $n
     * @return string
     */
    private function sortAlias($n)
    {
        return $this->alias . 'SortValue' . $n;
    }
}
