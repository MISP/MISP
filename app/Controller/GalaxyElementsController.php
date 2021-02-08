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
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
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
        $this->set('passedArgs', json_encode([
            'context' => $filters['context'],
            'searchall' => isset($filters['searchall']) ? $filters['searchall'] : ''
        ]));
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit', 'delete'), false, false);
        $canModify = !empty($cluster['authorized']);
        $canModify = true;
        $this->set('canModify', $canModify);
        if ($filters['context'] == 'JSONView') {
            $expanded = $this->GalaxyElement->getExpandedJSONFromElements($elements);
            $this->set('JSONElements', $expanded);
        }
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    public function delete($elementId)
    {
        $element = $this->GalaxyElement->find('first', array('conditions' => array('GalaxyElement.id' => $elementId)));
        if (empty($element)) {
            throw new Exception(__('Element not found'));
        }
        $this->set('element', $element);
        $clusterId = $element['GalaxyElement']['galaxy_cluster_id'];
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit'), true, false);
        if ($this->request->is('post')) {
            $deleteResult = $this->GalaxyElement->delete($elementId);
            if ($deleteResult) {
                $this->GalaxyElement->GalaxyCluster->editCluster($this->Auth->user(), $cluster, [], false);
                $message = __('Galaxy element %s deleted', $elementId);
                $this->Flash->success($message);
            } else {
                $message = __('Could not delete galaxy element');
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            } else {
                $this->layout = 'ajax';
                $this->set('elementId', $elementId);
                $this->render('ajax/delete');
            }
        }
    }

    public function flattenJson($clusterId)
    {
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit'), true, false);
        if ($this->request->is('post') || $this->request->is('put')) {
            $json = $this->GalaxyElement->jsonDecode($this->request->data['GalaxyElement']['jsonData']);
            $flattened = Hash::flatten($json);
            $newElements = [];
            foreach ($flattened as $k => $v) {
                $newElements[] = ['key' => $k, 'value' => $v];
            }
            $cluster['GalaxyCluster']['GalaxyElement'] = $newElements;
            $errors = $this->GalaxyElement->GalaxyCluster->editCluster($this->Auth->user(), $cluster, [], false);
            if (empty($errors)) {
                return $this->RestResponse->saveSuccessResponse('GalaxyElement', 'flattenJson', $clusterId, false);
            } else {
                $message = implode(', ', $errors);
                return $this->RestResponse->saveFailResponse('GalaxyElement', 'flattenJson', $clusterId, $message, false);
            }
        }
        $this->set('clusterId', $clusterId);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/flattenJson');
        }
    }
}
