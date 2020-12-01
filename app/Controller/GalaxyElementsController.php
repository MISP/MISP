<?php
App::uses('AppController', 'Controller');

class GalaxyElementsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 20,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
            'order' => array(
                'GalaxyElement.key' => 'ASC'
            )
    );

    public function index($clusterId)
    {
        $aclConditions = $this->GalaxyElement->buildClusterConditions($this->Auth->user(), $clusterId);
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        }
        $searchConditions = array();
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $searchConditions = array(
                'OR' => array(
                    'LOWER(GalaxyElement.key) LIKE' => $searchall,
                    'LOWER(GalaxyElement.value) LIKE' => $searchall,
                ),
            );
        }
        $this->paginate['conditions'] = ['AND' => [$aclConditions, $searchConditions]];
        $this->paginate['contain'] = ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]];
        $elements = $this->paginate();
        $this->set('elements', $elements);
        $this->set('clusterId', $clusterId);
        $this->set('context', $filters['context']);
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit', 'delete'), false, false);
        $canModify = !empty($cluster['authorized']);
        $canModify = true;
        $this->set('canModify', $canModify);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    public function indexTree($clusterId)
    {
        $elements = $this->GalaxyElement->fetchElements($this->Auth->user(), $clusterId);
        $keyedValue = [];
        foreach ($elements as $i => $element) {
            $keyedValue[$element['key']][] = $element['value'];
        }
        $expanded = Hash::expand($keyedValue);
        return $this->RestResponse->viewData($expanded);
    }
}
