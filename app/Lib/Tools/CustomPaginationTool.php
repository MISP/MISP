<?php
class CustomPaginationTool
{
    public function createPaginationRules($items, $options, $model, $sort = 'id', $focusKey = 'uuid')
    {
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
        $validOptions = array('sort', 'direction', 'page', 'focus');
        if ($model == 'events') {
            $validOptions[] = 'attributeFilter';
        }
        foreach ($validOptions as $v) {
            if (isset($options[$v])) {
                $params[$v] = $options[$v];
                $params['options'][$v] = $options[$v];
            }
        }
        $maxPage = floor($params['count'] / $params['limit']);
        if ($params['count'] % $params['limit'] != 0) {
            $maxPage += 1;
        }
        if ($params['page'] == 0) {
            $params['limit'] = $params['count'];
            $params['current'] = 1;
        } else {
            $params['current'] = 1 + ($params['page'] - 1) * $params['limit'];
            if ($params['page'] > 1) {
                $params['prevPage'] = true;
            }
            if ($params['page'] < $maxPage) {
                $params['nextPage'] = true;
            }
        }
        $params['pageCount'] = $maxPage;
        return $params;
    }

    public function truncateByPagination(&$items, $params)
    {
        if (empty($items)) {
            return;
        }
        $items = array_slice($items, $params['current'] - 1, $params['limit']);
    }

    public function sortArray($items, $params, $escapeReindex = false)
    {
        if (isset($params['sort'])) {
            $sortArray = array();
            foreach ($items as $k => $item) {
                $sortArray[$k] = empty($item[$params['sort']]) ? '' : $item[$params['sort']];
            }
            if (empty($params['options']['direction']) || $params['options']['direction'] == 'asc') {
                asort($sortArray);
            } else {
                arsort($sortArray);
            }

            foreach ($sortArray as $k => $sortedElement) {
                $sortArray[$k] = $items[$k];
            }
            $items = array();
            $items = $sortArray;
        }
        if (!$escapeReindex) {
            $items = array_values($items);
        }
        return $items;
    }

    public function applyRulesOnArray(&$items, $options, $model, $sort = 'id', $focusKey = 'uuid')
    {
        $params = $this->createPaginationRules($items, $options, $model, $sort, $focusKey);
        $items = $this->sortArray($items, $params);
        if (!empty($params['options']['focus'])) {
            foreach ($items as $k => $item) {
                if ($item[$focusKey] == $params['options']['focus']) {
                    $params['page'] = 1 + intval(floor($k / $params['limit']));
                    $params['current'] = 1 + ($params['page'] - 1) * 60;
                    continue;
                }
            }
            unset($params['options']['focus']);
        }
        array_unshift($items, 'dummy');
        unset($items[0]);
        $this->truncateByPagination($items, $params);
        return $params;
    }

    public function cmp($a, $b)
    {
        $multiplier = 1;
        if ($this->direction == 'desc') {
            $multiplier = -1;
        }
        return strcmp(strtolower($a[$this->filterField]), strtolower($b[$this->filterField])) * $multiplier;
    }
}
