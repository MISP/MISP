<?php

namespace App\Controller;

use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Utility\Hash;
use Exception;

class GalaxyElementsController extends AppController
{
    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 20,
        'recursive' => -1,
        'order' => [
            'GalaxyElement.key' => 'ASC'
        ]
    ];

    public function index($clusterId)
    {
        $user = $this->closeSession();
        $filters = $this->IndexFilter->harvestParameters(['context', 'searchall']);
        $aclConditions = $this->GalaxyElements->buildClusterConditions($user, $clusterId);
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        }
        $searchConditions = [];
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $searchConditions = [
                'OR' => [
                    'LOWER(GalaxyElement.key) LIKE' => $searchall,
                    'LOWER(GalaxyElement.value) LIKE' => $searchall,
                ],
            ];
        }
        $this->paginate['conditions'] = ['AND' => [$aclConditions, $searchConditions]];
        $this->paginate['contain'] = ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]];
        $elements = $this->paginate();
        $this->set('elements', $elements);
        $this->set('clusterId', $clusterId);
        $this->set('context', $filters['context']);
        $this->set(
            'passedArgs',
            json_encode(
                [
                    'context' => $filters['context'],
                    'searchall' => isset($filters['searchall']) ? $filters['searchall'] : ''
                ]
            )
        );
        $cluster = $this->GalaxyElements->GalaxyCluster->fetchIfAuthorized($user, $clusterId, ['edit', 'delete'], false, false);
        $canModify = !empty($cluster['authorized']);
        $this->set('canModify', $canModify);
        if ($filters['context'] === 'JSONView') {
            $expanded = $this->GalaxyElements->getExpandedJSONFromElements($elements);
            $this->set('JSONElements', $expanded);
        }
        $this->layout = false;
        $this->render('ajax/index');
    }

    public function delete($elementId)
    {
        $element = $this->GalaxyElements->find('all', ['conditions' => ['GalaxyElement.id' => $elementId]])->first();
        if (empty($element)) {
            throw new Exception(__('Element not found'));
        }
        $this->set('element', $element);
        $clusterId = $element['GalaxyElement']['galaxy_cluster_id'];
        $cluster = $this->GalaxyElements->GalaxyCluster->fetchIfAuthorized($this->ACL->getUser(), $clusterId, ['edit'], true, false);
        if ($this->request->is('post')) {
            $deleteResult = $this->GalaxyElements->delete($elementId);
            if ($deleteResult) {
                $this->GalaxyElements->GalaxyCluster->editCluster($this->ACL->getUser(), $cluster, [], false);
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
                $this->layout = false;
                $this->set('elementId', $elementId);
                $this->render('ajax/delete');
            }
        }
    }

    public function flattenJson($clusterId)
    {
        $cluster = $this->GalaxyElements->GalaxyCluster->fetchIfAuthorized($this->ACL->getUser(), $clusterId, ['edit'], true, false);
        if ($this->request->is('post') || $this->request->is('put')) {
            $json = $this->_jsonDecode($this->request->getData()['GalaxyElement']['jsonData']);
            $flattened = Hash::flatten($json);
            $newElements = [];
            foreach ($flattened as $k => $v) {
                $newElements[] = ['key' => $k, 'value' => $v];
            }
            $cluster['GalaxyCluster']['GalaxyElement'] = $newElements;
            $errors = $this->GalaxyElements->GalaxyCluster->editCluster($this->ACL->getUser(), $cluster, [], false);
            if (empty($errors)) {
                return $this->RestResponse->saveSuccessResponse('GalaxyElement', 'flattenJson', $clusterId, false);
            } else {
                $message = implode(', ', $errors);
                return $this->RestResponse->saveFailResponse('GalaxyElement', 'flattenJson', $clusterId, $message, false);
            }
        }
        $this->set('clusterId', $clusterId);
        if ($this->request->is('ajax')) {
            $this->layout = false;
            $this->render('ajax/flattenJson');
        }
    }
}
