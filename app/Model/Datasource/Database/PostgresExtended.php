<?php
App::uses('Postgres', 'Model/Datasource/Database');

class PostgresExtended extends Postgres
{
    /**
     * Fetches the next row from the current result set
     *
     * @return array
     */
    public function fetchResult()
    {
        if ($row = $this->_result->fetch(PDO::FETCH_NUM)) {
            $resultRow = array();

            foreach ($this->map as $index => $meta) {
                list($table, $column, $type) = $meta;

                switch ($type) {
                    case 'bool':
                        $resultRow[$table][$column] = $row[$index] === null ? null : $this->boolean($row[$index]);
                        break;
                        // This causes stream_get_contents() to be called on a string value, which is not what we want
                        // case 'binary':
                        // case 'bytea':
                        // 	$resultRow[$table][$column] = $row[$index] === null ? null : stream_get_contents($row[$index]);
                        // 	break;
                    default:
                        $resultRow[$table][$column] = $row[$index];
                }
            }
            return $resultRow;
        }
        $this->_result->closeCursor();
        return false;
    }
}
