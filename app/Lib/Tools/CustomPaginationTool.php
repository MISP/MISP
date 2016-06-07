<?php
class CustomPaginationTool {

	function createPaginationRules(&$items, $options, $model, $sort = 'id') {
		$params = array(
			'model' => $model,
			'current' => 1,
			'count' => count($items),
			'limit' => 60,
			'page' => 1,
			'sort' => $sort,
			'direction' => 'asc',
			'paramType' => 'named',
			'prevPage' => false,
			'nextPage' => false,
			'options' => array(
			),
		);
		$validOptions = array('sort', 'direction', 'page');
		if ($model == 'events') $validOptions[] = 'attributeFilter';
		foreach ($validOptions as $v) {
			if (isset($options[$v])) {
				$params[$v] = $options[$v];
				$params['options'][$v] = $options[$v];
			}
		}
		$maxPage = floor($params['count'] / $params['limit']);
		if ($params['count'] % $params['limit'] != 0) $maxPage += 1;
		if ($params['page'] == 0) {
			$params['limit'] = $params['count'];
			$params['current'] = 1;
		} else {
			$params['current'] = 1 + ($params['page'] - 1) * $params['limit'];
			if ($params['page'] > 1) $params['prevPage'] = true;
			if ($params['page'] < $maxPage) $params['nextPage'] = true;
		}
		$params['pageCount'] = $maxPage;
		return $params;
	}

	function truncateByPagination(&$items, $params) {
		if (empty($items)) return;
		$items = array_slice($items, $params['current'] - 1, $params['current'] + $params['limit']);
	}

	function applyRulesOnArray(&$items, $options, $model, $sort = 'id') {
		$params = $this->createPaginationRules($items, $options, $model, $sort);
		if (isset($params['sort'])) {
			$items = Set::sort($items, '{n}.' . $params['sort'], $params['direction']);
		}
		array_unshift($items, 'dummy');
		unset($items[0]);
		$this->truncateByPagination($items, $params);
		return $params;
	}

	function cmp($a, $b) {
		$multiplier = 1;
		if ($this->direction == 'desc') $multiplier = -1;
		return strcmp(strtolower($a[$this->filterField]), strtolower($b[$this->filterField])) * $multiplier;
	}
}
