<?php

/**
 * What happens to MISP's rows: unwrapped from restSearch's reply, flattened,
 * and projected on the columns a statement asks for.
 *
 * Works on JSON decoded without the associative flag, so that an empty
 * object (stdClass) and an empty list stay apart.
 */
class MispQLRows
{
    /**
     * The rows of a restSearch reply: its `response` holds them under the row
     * key, or is a list of objects each holding one row under the row key,
     * whose other keys join the row unless the row has them already.
     *
     * @param mixed $reply
     * @param string $rowKey
     * @return array
     * @throws UnexpectedValueException
     */
    public static function unwrap($reply, $rowKey)
    {
        if (!is_object($reply) || !property_exists($reply, 'response')) {
            throw new UnexpectedValueException('no response in the reply');
        }
        $found = $reply->response;
        if (is_object($found)) {
            if (!property_exists($found, $rowKey) || !is_array($found->$rowKey)) {
                throw new UnexpectedValueException('no rows in the reply');
            }
            return $found->$rowKey;
        }
        if (!is_array($found)) {
            throw new UnexpectedValueException('no rows in the reply');
        }
        $rows = [];
        foreach ($found as $item) {
            if (!is_object($item) || !property_exists($item, $rowKey) || !is_object($item->$rowKey)) {
                throw new UnexpectedValueException('no rows in the reply');
            }
            $row = clone $item->$rowKey;
            foreach ($item as $key => $value) {
                $key = (string)$key;
                if ($key !== $rowKey && !property_exists($row, $key)) {
                    $row->$key = $value;
                }
            }
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * Nested objects become dotted keys; a list under a Tag key, at any
     * depth, the names of its tags; other lists are kept when not empty and
     * holding no object or list, and are left out otherwise. An event can
     * hold a million attributes: they go with the lists left out.
     *
     * @param stdClass $row
     * @return stdClass
     */
    public static function flatten($row)
    {
        $flat = new stdClass();
        self::flattenInto($flat, $row, '');
        return $flat;
    }

    private static function flattenInto(stdClass $flat, $row, $prefix)
    {
        foreach ($row as $key => $value) {
            $key = (string)$key;
            $name = $prefix . $key;
            if (is_object($value)) {
                self::flattenInto($flat, $value, $name . '.');
            } elseif (is_array($value)) {
                if ($key === 'Tag') {
                    $names = [];
                    foreach ($value as $tag) {
                        if (is_object($tag)) {
                            $names[] = property_exists($tag, 'name') ? $tag->name : null;
                        }
                    }
                    $flat->$name = $names;
                } elseif (!empty($value) && !self::holdsStructures($value)) {
                    $flat->$name = $value;
                }
            } else {
                $flat->$name = $value;
            }
        }
    }

    private static function holdsStructures(array $list)
    {
        foreach ($list as $item) {
            if (is_array($item) || is_object($item)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The header, the cells and the warnings for flattened rows. The columns
     * wanted are the statement's column list or, without one, the table's
     * default columns; for FORMAT flat without one, every key of the rows in
     * the order first seen. Warnings come with a column list only.
     *
     * @param array $plan a search plan
     * @param stdClass[] $flatRows
     * @param string[] $tableColumns
     * @return array [columns, cells, warnings]
     */
    public static function project(array $plan, array $flatRows, array $tableColumns)
    {
        $warnings = [];
        if ($plan['columns'] !== null) {
            list($columns, $warnings) = self::columns($flatRows, $plan['columns']);
        } elseif ($plan['output'] === 'flat') {
            $columns = self::allColumns($flatRows);
        } else {
            list($columns) = self::columns($flatRows, $tableColumns);
        }
        $cells = [];
        foreach ($flatRows as $row) {
            $cells[] = self::cells($row, $columns);
        }
        return [$columns, $cells, $warnings];
    }

    /**
     * The wanted columns as the rows first spell them, matched without regard
     * to case, and a warning for each column no row has.
     *
     * @param stdClass[] $flatRows
     * @param string[] $wanted
     * @return array [columns, warnings]
     */
    public static function columns(array $flatRows, array $wanted)
    {
        $spelling = [];
        foreach ($flatRows as $row) {
            foreach ($row as $key => $value) {
                $lower = mb_strtolower((string)$key, 'UTF-8');
                if (!array_key_exists($lower, $spelling)) {
                    $spelling[$lower] = (string)$key;
                }
            }
        }
        $columns = [];
        $warnings = [];
        foreach ($wanted as $name) {
            $lower = mb_strtolower($name, 'UTF-8');
            $known = array_key_exists($lower, $spelling);
            $columns[] = $known ? $spelling[$lower] : $name;
            if (!$known && !empty($flatRows)) {
                $warnings[] = "no row has a column $name";
            }
        }
        return [$columns, $warnings];
    }

    /**
     * @param stdClass $flatRow
     * @param string[] $columns
     * @return array the value under each column, matched without regard to
     *   case, or null
     */
    public static function cells($flatRow, array $columns)
    {
        $byName = [];
        foreach ($flatRow as $key => $value) {
            $byName[mb_strtolower((string)$key, 'UTF-8')] = $value;
        }
        $cells = [];
        foreach ($columns as $column) {
            $lower = mb_strtolower($column, 'UTF-8');
            $cells[] = array_key_exists($lower, $byName) ? $byName[$lower] : null;
        }
        return $cells;
    }

    /**
     * @param stdClass[] $flatRows
     * @return string[] every key, in the order first seen
     */
    public static function allColumns(array $flatRows)
    {
        $seen = [];
        $columns = [];
        foreach ($flatRows as $row) {
            foreach ($row as $key => $value) {
                $key = (string)$key;
                if (!isset($seen[$key])) {
                    $seen[$key] = true;
                    $columns[] = $key;
                }
            }
        }
        return $columns;
    }
}
