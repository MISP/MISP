<?php
App::uses('Mysql', 'Model/Datasource/Database');

/**
 * Overrides the default MySQL database implementation to support the following features:
 * - Set query hints to optimize queries
 */
class MysqlExtended extends Mysql
{
    const PDO_MAP = [
        'integer' => PDO::PARAM_INT,
        'float' => PDO::PARAM_STR,
        'boolean' => PDO::PARAM_BOOL,
        'string' => PDO::PARAM_STR,
        'text' => PDO::PARAM_STR
    ];

    /**
     * Output MD5 as binary, that is faster and uses less memory
     * @param string $value
     * @return string
     */
    public function cacheMethodHasher($value)
    {
        return md5($value, true);
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

        if (!empty($query['joins'])) {
            $count = count($query['joins']);
            for ($i = 0; $i < $count; $i++) {
                if (is_array($query['joins'][$i])) {
                    $query['joins'][$i] = $this->buildJoinStatement($query['joins'][$i]);
                }
            }
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
            'ignoreIndexHint' => $this->__buildIgnoreIndexHint($query['ignoreIndexHint'] ?? null)
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
}
