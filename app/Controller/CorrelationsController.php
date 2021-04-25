<?php
App::uses('AppController', 'Controller');

/**
 * @property Correlation $Correlation
 */
class CorrelationsController extends AppController
{
    public $components = array('Security', 'RequestHandler');
    
    public function top()
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
        if ($this->_isRest()) {
            $data = $this->Correlation->find('all', $query);
            return $this->RestResponse->viewData($data, 'json');
        } else {
            $query['limit'] = empty($query['limit']) ? 20 : $query['limit'];
            $query['page'] = empty($query['page']) ? 1 : $query['page'];
            $this->paginate = $query;
            $data = $this->Correlation->find('all', $query);
            $this->set('data', $data);
            $this->set('title_for_layout', __('Top correlations index'));
            $this->set('menuData', [
                'menuList' => 'correlationExclusions',
                'menuItem' => 'top'
            ]);
        }
    }
}
