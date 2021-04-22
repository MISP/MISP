<?php
App::uses('AppController', 'Controller');

/**
 * @property AuthKey $AuthKey
 */
class CorrelationsController extends AppController
{
    public function top_correlations()
    {
        $options = [
            'filters' => ['value', 'quickFilter'],
            'quickFilters' => ['value']
        ];
        $this->Correlation->virtualFields['count'] = 'COUNT(*)';
        $params = $this->IndexFilter->harvestParameters(empty($options['filters']) ? [] : $options['filters']);
        $query = [
            'fields' => ['value', 'count'],
            'group' => ['value'],
            'order' => 'count desc',
            'recursive' => -1
        ];
        if (!empty($this->params['named']['limit'])) {
            $query['limit'] = $this->params['named']['limit'];
        }
        if (!empty($this->params['named']['page'])) {
            $query['page'] = $this->params['named']['page'];
        }
        $query = $this->CRUD->setFilters($params, $query);
        $query = $this->CRUD->setQuickFilters($params, $query, empty($options['quickFilters']) ? [] : $options['quickFilters']);
        if ($this->IndexFilter->isRest()) {
            $data = $this->Correlation->find('all', $query);
            return $this->RestResponse->viewData($data, 'json');
        } else {
            if (empty($query['limit'])) {
                $query['limit'] = 20;
            }
            if (empty($query['page'])) {
                $query['page'] = 1;
            }
            $this->paginate = $query;
            $data = $this->Correlation->find('all', $query);
            $this->set('data', $data);
            $this->set('title_for_layout', __('Top correlations index'));
            $this->set('menuData', [
                'menuList' => 'correlationExclusions',
                'menuItem' => 'top_correlations'
            ]);
        }
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('title_for_layout', __('Correlation Exclusions index'));
        $this->set('menuData', [
            'menuList' => 'correlationExclusions',
            'menuItem' => 'index'
        ]);
    }
}
