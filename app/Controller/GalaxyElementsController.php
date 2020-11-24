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
        $this->paginate['conditions'] = [$aclConditions];
        $this->paginate['contain'] = ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]];
        $clusters = $this->paginate();
        $this->set('list', $clusters);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }
}
