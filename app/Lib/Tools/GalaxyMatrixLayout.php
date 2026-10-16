<?php

/**
 * How a galaxy matrix is laid out: the column order of merged tabs, and the
 * technique groups a column draws.
 */
class GalaxyMatrixLayout
{
    /**
     * One column order from several, keeping each one's relative order;
     * a column no sequence places is taken in first-appearance order.
     *
     * @param array $sequences lists of column names
     * @return array
     */
    public static function mergeColumnOrders(array $sequences)
    {
        $rank = [];
        $incoming = [];
        $next = [];
        foreach ($sequences as $columns) {
            $previous = null;
            foreach (array_values((array)$columns) as $column) {
                $column = (string)$column;
                if (!isset($rank[$column])) {
                    $rank[$column] = count($rank);
                    $incoming[$column] = 0;
                    $next[$column] = [];
                }
                if ($previous !== null && $previous !== $column && !isset($next[$previous][$column])) {
                    $next[$previous][$column] = true;
                    $incoming[$column]++;
                }
                $previous = $column;
            }
        }
        $order = [];
        while (!empty($incoming)) {
            $pick = null;
            foreach ($incoming as $column => $count) {
                $column = (string)$column;
                if ($count === 0 && ($pick === null || $rank[$column] < $rank[$pick])) {
                    $pick = $column;
                }
            }
            if ($pick === null) {
                // Sequences that disagree: take the earliest seen and carry on
                foreach (array_keys($incoming) as $column) {
                    $column = (string)$column;
                    if ($pick === null || $rank[$column] < $rank[$pick]) {
                        $pick = $column;
                    }
                }
            }
            $order[] = $pick;
            unset($incoming[$pick]);
            foreach (array_keys($next[$pick]) as $column) {
                if (isset($incoming[$column])) {
                    $incoming[$column]--;
                }
            }
        }
        return $order;
    }

    /**
     * ATT&CK's Enterprise tabs: every `attack-*` platform, PRE first so
     * reconnaissance leads the merged column order.
     *
     * @param array $killChain tab => columns
     * @return array tab names
     */
    public static function enterpriseTabs(array $killChain)
    {
        $tabs = array_values(array_filter(array_map('strval', array_keys($killChain)), function ($tab) {
            return strpos($tab, 'attack-') === 0 && $tab !== 'attack-enterprise';
        }));
        usort($tabs, function ($a, $b) {
            return ($b === 'attack-PRE') <=> ($a === 'attack-PRE');
        });
        return $tabs;
    }

    /**
     * A cell's name without the " - T1234" its value ends with.
     *
     * @param string $value
     * @param string $externalId
     * @return string
     */
    public static function cellLabel($value, $externalId)
    {
        $value = (string)$value;
        $externalId = (string)$externalId;
        if ($externalId !== '' && $value !== '' && strlen($value) >= strlen($externalId)
            && substr($value, -strlen($externalId)) === $externalId) {
            $label = rtrim(rtrim(substr($value, 0, -strlen($externalId))), " -");
            if ($label !== '') {
                return $label;
            }
        }
        return $value;
    }

    /** "defense-evasion" → "Defense Evasion". */
    public static function formatTactic($key)
    {
        return ucwords(str_replace('-', ' ', (string)$key));
    }

    /**
     * Parent technique id => name, over every column given, so a
     * sub-technique whose parent sits in another column still gets a name.
     *
     * @param array $columns column => cells
     * @return array
     */
    public static function parentNames(array $columns)
    {
        $names = [];
        foreach ($columns as $cells) {
            foreach ((array)$cells as $cell) {
                if (!is_array($cell)) {
                    continue;
                }
                $externalId = (string)($cell['external_id'] ?? '');
                if (preg_match('/^T\d+$/', $externalId)) {
                    $names[$externalId] = self::cellLabel($cell['value'] ?? '', $externalId);
                }
            }
        }
        return $names;
    }

    /**
     * A column's cells as technique groups, sub-techniques under their
     * parent id, in first-seen order. A group's `cell` is the parent's own
     * cell, null when only sub-techniques are present; a cell without a
     * T-id is a group of its own.
     *
     * @param array $cells each with value, external_id and anything else
     * @return array key => [key, cell, label, subs => [[cell, label, tid]]]
     */
    public static function groupColumn(array $cells)
    {
        $groups = [];
        foreach ($cells as $cell) {
            if (!is_array($cell)) {
                continue;
            }
            $externalId = (string)($cell['external_id'] ?? '');
            $label = self::cellLabel($cell['value'] ?? '', $externalId);
            if (preg_match('/^(T\d+)\.\d+$/', $externalId, $m)) {
                $key = $m[1];
                $sub = true;
            } elseif (preg_match('/^T\d+$/', $externalId)) {
                $key = $externalId;
                $sub = false;
            } else {
                $key = $externalId !== '' ? $externalId : ('_' . $label);
                $sub = false;
            }
            if (!isset($groups[$key])) {
                $groups[$key] = ['key' => $key, 'cell' => null, 'label' => null, 'subs' => []];
            }
            if ($sub) {
                $groups[$key]['subs'][] = ['cell' => $cell, 'label' => $label, 'tid' => $externalId];
            } else {
                $groups[$key]['cell'] = $cell;
                $groups[$key]['label'] = $label;
            }
        }
        return $groups;
    }

    /**
     * A group's name: its own cell's, else its parent's from elsewhere,
     * else the parent id itself.
     */
    public static function groupLabel(array $group, array $parentNames)
    {
        if (!empty($group['label'])) {
            return $group['label'];
        }
        return $parentNames[$group['key']] ?? $group['key'];
    }
}
