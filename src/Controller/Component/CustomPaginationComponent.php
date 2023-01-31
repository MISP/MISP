<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Controller\ComponentRegistry;
use Cake\Http\Exception\NotFoundException;
use InvalidArgumentException;
use Cake\Controller\Component\PaginatorComponent;
use Cake\Datasource\Pagination\NumericPaginator;
use Cake\Utility\Hash;

class CustomPaginationComponent extends Component
{

    public function __construct(ComponentRegistry $registry, array $config = [])
    {
        parent::__construct($registry, $config);
    }

    protected $defaults = [
        'limit' => 10,
        'direction' => 'asc'
    ];

    protected $settings = [

    ];

    protected $validFields = [
        'limit',
        'page',
        'sort',
        'direction'
    ];

    public function paginate(array $data): array
    {

        $request = $this->_registry->getController()->getRequest();
        $params = $request->getQueryParams();
        $settings = $this->defaults;
        foreach ($this->validFields as $validField) {
            if (isset($params[$validField])) {
                $settings[$validField] = $params[$validField];
            }
        }
        $count = count($data);
        if (!empty($settings['sort'])) {
            $data = $this->_sortData($data, $settings);
        }
        if (!empty($settings['limit'])) {
            $data = $this->_truncateData($data, $settings);
        }
        $this->_setPagingParams($settings, $count, count($data));
        return $data;
    }

    protected function _sortData(array $data, array &$settings): array
    {
        return Hash::sort($data, '{n}.' . $settings['sort'], strtolower($settings['direction']));
    }

    protected function _truncateData(array $data, array $settings): array
    {
        $page = $settings['page'] ?? 1;
        $limit = $settings['limit'] ?? 50;
        $offset = ($page - 1) * $limit;
        return array_slice($data, $offset, $limit);
    }

    protected function _setPagingParams(array $settings, int $count, int $currentCount): void
    {
        $controller = $this->getController();
        $request = $controller->getRequest();
        $limit = $settings['limit'] ?? 0;
        $pageCount = empty($settings['limit']) ? 1 : ceil($count/$limit);
        $page = $settings['page'] ?? 1;
        $start = $end = 0;
        $prevPage = $page > 1;
        $nextPage = true;
        if ($count) {
            $nextPage = $count > ($page * $limit);
        }
        if ($currentCount > 0) {
            $start = (($page - 1) * $limit) + 1;
            $end = $start + $currentCount - 1;
        }
        $paging = [
            'count' => $count,
            'current' => $currentCount,
            'perPage' => $limit,
            'page' => $page,
            'requestedPage' => $settings['page'] ?? 1,
            'pageCount' => $pageCount,
            'start' => $start,
            'end' => $end,
            'prevPage' => $page > 1,
            'nextPage' => $nextPage
        ];
        $paging = ['organisations' => $paging + $settings];
        $controller->setRequest($request->withAttribute('paging', $paging));
    }
}
