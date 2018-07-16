<?php

class QueryTool {
	private $__pdoMap = array(
	'integer' => PDO::PARAM_INT,
	'float' => PDO::PARAM_STR,
	'boolean' => PDO::PARAM_BOOL,
	'string' => PDO::PARAM_STR,
	'text' => PDO::PARAM_STR
	);

	public function quickDelete($table, $field, $value, $model) {
		$db = $model->getDataSource();
		$connection = $db->getConnection();
		$query = $connection->prepare('DELETE FROM ' . $table . ' WHERE ' . $field . ' = :value');
		$query->bindValue(':value', $value, $this->__pdoMap[$db->introspectType($value)]);
		$query->execute();
	}
}
