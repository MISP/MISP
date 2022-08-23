<?php

class QueryTool
{
    const PDO_MAP = array(
        'integer' => PDO::PARAM_INT,
        'float' => PDO::PARAM_STR,
        'boolean' => PDO::PARAM_BOOL,
        'string' => PDO::PARAM_STR,
        'text' => PDO::PARAM_STR,
    );

    public function quickDelete($table, $field, $value, $model)
    {
        $db = $model->getDataSource();
        $connection = $db->getConnection();
        if (in_array($db->config['datasource'], ['Database/Mysql', 'Database/MysqlObserver', 'Database/MysqlExtended'])) {
            $query = $connection->prepare('DELETE FROM ' . $table . ' WHERE ' . $field . ' = :value');
        } elseif ($db->config['datasource'] == 'Database/Postgres' ) {
            $query = $connection->prepare('DELETE FROM "' . $table . '" WHERE "' . $field . '" = :value');
        }
        $query->bindValue(':value', $value, self::PDO_MAP[$db->introspectType($value)]);
        $query->execute();
    }
}
