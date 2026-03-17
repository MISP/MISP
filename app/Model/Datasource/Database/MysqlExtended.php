<?php
App::uses('Mysql', 'Model/Datasource/Database');

/**
 * Overrides the default MySQL database implementation to support the following features:
 * - Set query hints to optimize queries
 */
class MysqlExtended extends Mysql
{
    public $supports = [
        'indexHints' => true,
        'ignoreIndexHints' => true,
        'reverseJoin' => true,
        'straightJoin' => true,
        'insertMulti' => true,
    ];

    const PDO_MAP = [
        'integer' => PDO::PARAM_INT,
        'float' => PDO::PARAM_STR,
        'boolean' => PDO::PARAM_BOOL,
        'string' => PDO::PARAM_STR,
        'text' => PDO::PARAM_STR
    ];

    const IDENTIFIER_QUOTE = '`';

    /**
     * Builds and generates a JOIN condition from an array. Handles final clean-up before conversion.
     *
     * @param array $join An array defining a JOIN condition in a query.
     * @return string An SQL JOIN condition to be used in a query.
     * @see DboSource::renderJoinStatement()
     * @see DboSource::buildStatement()
     */
    public function buildJoinStatement($join, $reversed_alias = null, $reversed_table = null) {
        $data = array_merge(array(
            'type' => null,
            'alias' => null,
            'table' => 'join_table',
            'conditions' => '',
        ), $join);

        if (!empty($reversed_alias)) {
            $data['alias'] = $this->name($reversed_alias);
        } else if (!empty($data['alias'])) {
            $data['alias'] = $this->alias . $this->name($data['alias']);
        }
        if (!empty($data['conditions'])) {
            $data['conditions'] = trim($this->conditions($data['conditions'], true, false));
        }
        if (!empty($reversed_table)) {
            $data['table'] = $reversed_table;
		} else if (!empty($data['table']) && (!is_string($data['table']) || strpos($data['table'], '(') !== 0)) {
			$data['table'] = $this->fullTableName($data['table']);
		}
		return $this->renderJoinStatement($data);
	}

    /**
     * Output SHA1 as binary, that is faster and uses less memory
     * @param string $value
     * @return string
     */
    public function cacheMethodHasher($value)
    {
        return sha1($value, true);
    }

        /**
     * Renders a final SQL JOIN statement
     *
     * @param array $data The data to generate a join statement for.
     * @return string
     */
    public function renderJoinStatement($data) {
        if (!empty($data['type']) && strtoupper($data['type']) === 'STRAIGHT') {
            return "STRAIGHT_JOIN {$data['table']} {$data['alias']} ON ({$data['conditions']})";
        }
        if (!empty($data['type']) && strtoupper($data['type']) === 'STRAIGHT_REVERSE') {
            return "STRAIGHT_JOIN {$data['table']} {$data['alias']} ON ({$data['conditions']})";
        }
        //Fixed deprecation notice in PHP8.1 - fall back to empty string
        if (strtoupper($data['type'] ?? "") === 'CROSS' || empty($data['conditions'])) {
            return "{$data['type']} JOIN {$data['table']} {$data['alias']}";
        }
        return trim("{$data['type']} JOIN {$data['table']} {$data['alias']} ON ({$data['conditions']})");
    }

    /**
     * Builds and generates an SQL statement from an array. Handles final clean-up before conversion.
     *
     * @param array $query An array defining an SQL query.
     * @param Model $Model The model object which initiated the query.
     * @return string An executable SQL statement.
     * @see DboSource::renderStatement()
     */
    public function buildStatement($query, Model $Model)
    {
        $query = array_merge($this->_queryDefaults, $query);

        $isReverseJoin = false;
        if (!empty($query['joins'])) {
            foreach ($query['joins'] as &$join) {
                if (is_array($join)) {
                    if (isset($join['type']) && $join['type'] === 'STRAIGHT_REVERSE') {
                        // we're dealing with a reverse join, this means we need to reverse the order of joins
                        $isReverseJoin = true;
                        $reversed_table = $join['table'];
                        $reversed_alias = $join['alias'];
                        // we'll pass two additional parameters: the table and alias that would have been used as the primary table. These will replace the join table/alias in the rendered JOIN statement to swap the order
                        $join = $this->buildJoinStatement($join, $query['alias'], $query['table']);
                    } else if ($isReverseJoin) {
                        // we have a STRAIGHT_REVERSE join already, can't add more joins (this is a limitation of the STRAIGHT reverse join code)
                        throw new InvalidArgumentException(
                            'Join type STRAIGHT_REVERSE can\'t be mixed with other joins.'
                        );
                    } else {
                        // we're dealing with a regular set of JOINs so far, continue normally
                        $join = $this->buildJoinStatement($join);
                    }
                    
                }
            }
        }

        if ($isReverseJoin) {
            $query['alias'] = $this->name($reversed_alias);
            $query['table'] = $this->fullTableName($reversed_table);
            return $this->renderStatement('select', array(
                'conditions' => $this->conditions($query['conditions'], true, true, $Model),
                'fields' => implode(', ', $query['fields']),
                'table' => $query['table'],
                'alias' => $this->alias . $this->name($query['alias']),
                'order' => $this->order($query['order'], 'ASC', $Model),
                'limit' => $this->limit($query['limit'], $query['offset']),
                'joins' => implode(' ', $query['joins']),
                'group' => $this->group($query['group'], $Model),
                'having' => $this->having($query['having'], true, $Model),
                'lock' => $this->getLockingHint($query['lock']),
                'indexHint' => $this->__buildIndexHint($query['forceIndexHint'] ?? null),
                'ignoreIndexHint' => $this->__buildIgnoreIndexHint($query['ignoreIndexHint'] ?? null),
            ));
        }

        return $this->renderStatement('select', array(
            'conditions' => $this->conditions($query['conditions'], true, true, $Model),
            'fields' => implode(', ', $query['fields']),
            'table' => $query['table'],
            'alias' => $this->alias . $this->name($query['alias']),
            'order' => $this->order($query['order'], 'ASC', $Model),
            'limit' => $this->limit($query['limit'], $query['offset']),
            'joins' => implode(' ', $query['joins']),
            'group' => $this->group($query['group'], $Model),
            'having' => $this->having($query['having'], true, $Model),
            'lock' => $this->getLockingHint($query['lock']),
            'indexHint' => $this->__buildIndexHint($query['forceIndexHint'] ?? null),
            'ignoreIndexHint' => $this->__buildIgnoreIndexHint($query['ignoreIndexHint'] ?? null),
        ));
    }

    /**
     * Builds an SQL statement.
     *
     * This is merely a convenient wrapper to DboSource::buildStatement().
     *
     * @param Model $Model The model to build an association query for.
     * @param array $queryData An array of queryData information containing keys similar to Model::find().
     * @return string String containing an SQL statement.
     * @see DboSource::buildStatement()
     * @see DboSource::buildAssociationQuery()
     */
    public function buildAssociationQuery(Model $Model, $queryData)
    {
        $queryData = $this->_scrubQueryData($queryData);

        return $this->buildStatement(
            array(
                'fields' => $this->prepareFields($Model, $queryData),
                'table' => $this->fullTableName($Model),
                'alias' => $Model->alias,
                'limit' => $queryData['limit'],
                'offset' => $queryData['offset'],
                'joins' => $queryData['joins'],
                'conditions' => $queryData['conditions'],
                'order' => $queryData['order'],
                'group' => $queryData['group'],
                'having' => $queryData['having'],
                'lock' => $queryData['lock'],
                'forceIndexHint' => $queryData['forceIndexHint'] ?? null,
                'ignoreIndexHint' => $queryData['ignoreIndexHint'] ?? null,
            ),
            $Model
        );
    }

    /**
     * Renders a final SQL statement by putting together the component parts in the correct order
     * 
     * Edit: Added support for query hints
     *
     * @param string $type type of query being run. e.g select, create, update, delete, schema, alter.
     * @param array $data Array of data to insert into the query.
     * @return string|null Rendered SQL expression to be run, otherwise null.\
     * @see DboSource::renderStatement()
     */
    public function renderStatement($type, $data)
    {
        if ($type === 'select') {
            extract($data);
            $having = !empty($having) ? " $having" : '';
            $lock = !empty($lock) ? " $lock" : '';
            return rtrim("SELECT {$fields} FROM {$table} {$alias} {$indexHint} {$joins} {$conditions} {$group}{$having} {$order} {$limit}{$lock}");
        }
        return parent::renderStatement($type, $data);
    }

    /**
     * Builds the force index hint for the query
     * 
     * @param string|null $forceIndexHint INDEX hint
     * @return string
     */
    private function __buildIndexHint($forceIndexHint = null): ?string
    {
        return isset($forceIndexHint) ? ('FORCE INDEX (' . $forceIndexHint . ')') : null;
    }

    /**
     * Builds the ignore index hint for the query
     * 
     * @param string|null $ignoreIndexHint INDEX hint
     * @return string
     */
    private function __buildIgnoreIndexHint($ignoreIndexHint = null): ?string
    {
        return isset($ignoreIndexHint) ? ('IGNORE INDEX (' . $ignoreIndexHint . ')') : null;
    }

    /**
     * - Do not call microtime when not necessary
     * - Count query count even when logging is disabled
     *
     * @param string $sql
     * @param array $options
     * @param array $params
     * @return mixed
     */
    public function execute($sql, $options = [], $params = [])
    {
        $log = $options['log'] ?? $this->fullDebug;
        if (Configure::read('Plugin.Benchmarking_enable')) {
            $log = true;
        }
        if ($log) {
            $t = microtime(true);
            $this->_result = $this->_execute($sql, $params);
            $this->took = round((microtime(true) - $t) * 1000);
            $this->numRows = $this->affected = $this->lastAffected();
            $this->logQuery($sql, $params);
        } else {
            $this->_result = $this->_execute($sql, $params);
            $this->_queriesCnt++;
        }

        return $this->_result;
    }

    /**
     * Reduce memory usage for insertMulti
     *
     * @param string $table
     * @param array $fields
     * @param array $values
     * @return bool
     */
    public function insertMulti($table, $fields, $values)
    {
        if (empty($values)) {
            return true;
        }

        $table = $this->fullTableName($table);
        $holder = substr(str_repeat('?,', count($fields)), 0, -1);
        $fields = implode(',', array_map([$this, 'name'], $fields));

        $columnMap = [];
        foreach ($values[key($values)] as $key => $val) {
            if (is_int($val)) {
                $columnMap[$key] = PDO::PARAM_INT;
            } elseif (is_bool($val)) {
                $columnMap[$key] = PDO::PARAM_BOOL;
            } else {
                $type = $this->introspectType($val);
                $columnMap[$key] = self::PDO_MAP[$type];
            }
        }

        $sql = "INSERT INTO $table ($fields) VALUES ";
        $sql .= substr(str_repeat("($holder),", count($values)), 0, -1);
        $statement = $this->_connection->prepare($sql);
        $valuesList = array();
        $i = 0;
        foreach ($values as $value) {
            foreach ($value as $col => $val) {
                if ($this->fullDebug) {
                    $valuesList[] = $val;
                }
                $statement->bindValue(++$i, $val, $columnMap[$col]);
            }
        }
        $result = $statement->execute();
        $statement->closeCursor();
        if ($this->fullDebug) {
            $this->logQuery($sql, $valuesList);
        }
        return $result;
    }

    /**
     * {@inheritDoc}
     */
    public function value($data, $column = null, $null = true)
    {
        // Fast check if data is int, then return value
        if (is_int($data)) {
            return $data;
        }

        // No need to quote bool values
        if (is_bool($data)) {
            return $data ? '1' : '0';
        }

        // No need to call expensive array_map
        if (is_array($data) && !empty($data)) {
            $output = [];
            foreach ($data as $d) {
                if (is_int($d)) {
                    $output[] = $d;
                } else {
                    $output[] = parent::value($d, $column);
                }
            }
            return $output;
        }

        return parent::value($data, $column, $null);
    }

    /**
     * @param $result
     * @return void
     */
    public function fetchVirtualField(&$result)
    {
        static $cache;

        if (isset($result[0]) && is_array($result[0])) {
            foreach ($result[0] as $field => $value) {
                if (!str_contains($field, $this->virtualFieldSeparator)) {
                    continue;
                }

                $virtualFields = $cache[$field] ?? null;
                if ($virtualFields === null) {
                    list($alias, $virtual) = explode($this->virtualFieldSeparator, $field);

                    /** @var Model $Model */
                    $Model = ClassRegistry::getObject($alias);
                    if ($Model === false) {
                        return;
                    }

                    $isVirtualField = $Model->isVirtualField($virtual);
                    $cache[$field] = $virtualFields = $isVirtualField ? [$alias, $virtual] : false;
                }

                if ($virtualFields) {
                    list($alias, $virtual) = $virtualFields;
                    $result[$alias][$virtual] = $value;
                    unset($result[0][$field]);
                }
            }
            if (empty($result[0])) {
                unset($result[0]);
            }
        }
    }
}
