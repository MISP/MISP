<?php
App::uses('Mysql', 'Model/Datasource/Database');

/**
 * Overrides the default MySQL database implementation to support the following features:
 * - Set query hints to optimize queries
 */
class MysqlExtended extends Mysql
{
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
            'indexHint' => $this->__buildIndexHint($query['useIndexHint'] ?? null),
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
                'useIndexHint' => $queryData['useIndexHint'] ?? null,
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
        if ($type === 'select' && $data['indexHint'] != null) {
            extract($data);
            $having = !empty($having) ? " $having" : '';
            return trim("SELECT {$fields} FROM {$table} {$alias} {$indexHint} {$joins} {$conditions} {$group}{$having} {$order} {$limit}{$lock}");
        } else {
            return parent::renderStatement($type, $data);
        }
    }

    /**
     * Builds the index hint for the query
     * 
     * @param string|null $useIndexHint USE INDEX hint
     * @return string
     */
    private function __buildIndexHint($useIndexHint = null): string
    {
        $index = '';
        if (isset($useIndexHint)) {
            $index = 'USE INDEX ' . $useIndexHint;
        }
        return $index;
    }
}
