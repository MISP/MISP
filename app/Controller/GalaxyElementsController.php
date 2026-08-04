<?php
App::uses('AppController', 'Controller');

/**
 * @property GalaxyElement $GalaxyElement
 */
class GalaxyElementsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 20,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
            'recursive' => -1,
            'order' => array(
                'GalaxyElement.key' => 'ASC'
            )
    );

    public function index($clusterId)
    {
        $user = $this->_closeSession();
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
        $aclConditions = $this->GalaxyElement->buildClusterConditions($user, $clusterId);
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
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($user, $clusterId, array('edit', 'delete'), false, false);
        $canModify = !isset($cluster['authorized']) || $cluster['authorized'] === true;
        $this->set('canModify', $canModify);
        if ($filters['context'] === 'JSONView') {
            $expanded = $this->GalaxyElement->getExpandedJSONFromElements($elements);
            $this->set('JSONElements', $expanded);
        }
        $this->layout = false;
        $this->render('ajax/index');
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
                $this->layout = false;
                $this->set('elementId', $elementId);
                $this->render('ajax/delete');
            }
        }
    }

    public function deleteSelection($id = null)
    {
        if ($this->request->is('post') || $this->request->is('put') || $this->request->is('delete')) {
            $ids = $this->_resolveElementIds($id);
            if (empty($ids)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $successes = 0;
            $clustersToBump = [];
            foreach ($ids as $eid) {
                $element = $this->GalaxyElement->find('first', [
                    'conditions' => ['GalaxyElement.id' => $eid],
                    'recursive' => -1,
                ]);
                if (empty($element)) {
                    continue;
                }
                $clusterId = $element['GalaxyElement']['galaxy_cluster_id'];
                $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit'), false, false);
                if (empty($cluster) || (isset($cluster['authorized']) && $cluster['authorized'] === false)) {
                    continue;
                }
                if ($this->GalaxyElement->delete($eid)) {
                    $successes++;
                    $clustersToBump[$clusterId] = $cluster;
                }
            }
            // Re-save the affected cluster(s) so caches/tags stay consistent.
            foreach ($clustersToBump as $cluster) {
                $this->GalaxyElement->GalaxyCluster->editCluster($this->Auth->user(), $cluster, [], false);
            }
            $message = __n('%s galaxy element deleted.', '%s galaxy elements deleted.', $successes, $successes);
            if ($this->request->is('ajax') || $this->_isRest()) {
                $saved = $successes > 0;
                return new CakeResponse([
                    'body' => json_encode(['saved' => $saved, 'success' => $message, 'errors' => $saved ? '' : __('No galaxy element deleted.')]),
                    'status' => 200,
                    'type' => 'json',
                ]);
            }
            if ($successes > 0) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error(__('No galaxy element deleted.'));
            }
            $this->redirect($this->referer());
        } else {
            $ids = $this->_resolveElementIds($id);
            $this->request->data['GalaxyElement']['id'] = json_encode($ids);
            $this->set('idArray', $ids);
            $this->layout = false;
            $this->render('ajax/galaxyElementDeleteConfirmationForm');
        }
    }

    private function _resolveElementIds($id)
    {
        if (isset($this->request->data['GalaxyElement']['id'])) {
            $raw = $this->request->data['GalaxyElement']['id'];
        } elseif ($id !== null) {
            $raw = $id;
        } else {
            return [];
        }
        if (is_array($raw)) {
            return $raw;
        }
        if (is_numeric($raw)) {
            return [$raw];
        }
        $decoded = json_decode(htmlspecialchars_decode(urldecode($raw)), true);
        return is_array($decoded) ? $decoded : [];
    }

    public function flattenJson($clusterId)
    {
        $cluster = $this->GalaxyElement->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $clusterId, array('edit'), true, false);
        if ($this->request->is('post') || $this->request->is('put')) {
            $json = $this->_jsonDecode($this->request->data['GalaxyElement']['jsonData']);
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
            $this->layout = false;
            $this->render('ajax/flattenJson');
        }
    }
}
