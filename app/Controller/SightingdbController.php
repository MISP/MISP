<?php
App::uses('AppController', 'Controller');

class SightingdbController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'Sightingdb.id' => 'DESC'
            ),
            'recursive' => -1,
            'contain' => array('SightingdbOrg' => 'Organisation')
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions = array('search');
    }

    public function add()
    {
        if ($this->request->is('post')) {
            if (empty($this->request->data['Sightingdb'])) {
                $this->request->data = array('Sightingdb' => $this->request->data);
            }
            $this->Sightingdb->create();
            $result = $this->Sightingdb->save($this->request->data);
            $message = $result ? __('SightingDB connection added.') : __('SightingDB connection could not be added.');
            if ($result) {
                if (isset($this->request->data['Sightingdb']['org_id'])) {
                    $this->Sightingdb->SightingdbOrg->resetOrgs($this->Sightingdb->id, $this->request->data['Sightingdb']['org_id']);
                }
            }
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Sightingdb', 'add', $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Sightingdb', 'add', $message, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                } else {
                    $message .= __(' Reason: %s', json_encode($this->Sightingdb->validationErrors, true));
                    $this->Flash->error($message);
                }
            }
        }
        $orgs = $this->Sightingdb->SightingdbOrg->Organisation->find('list', array(
            'conditions' => array('Organisation.local' => 1),
            'order' => array('LOWER(Organisation.name)'),
            'fields' => array('Organisation.id', 'Organisation.name')
        ));
        $this->set('orgs', $orgs);
    }

    public function edit($id)
    {
        $existingEntry = $this->Sightingdb->find('first', array(
            'recursive' => -1,
            'conditions' => array('Sightingdb.id' => $id),
            'contain' => array('SightingdbOrg.org_id')
        ));
        $existingEntry = $this->Sightingdb->extractOrgIds($existingEntry);
        if (empty($id) || empty($existingEntry)) {
            throw new NotFoundException(__('Invalid SightingDB entry.'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (empty($this->request->data['Sightingdb'])) {
                $this->request->data = array('Sightingdb' => $this->request->data);
            }
            $keys = array('host', 'port', 'description', 'name', 'owner', 'enabled', 'skip_proxy', 'ssl_skip_verification', 'namespace');
            foreach ($keys as $key) {
                if (!empty($this->request->data['Sightingdb'][$key])) {
                    $existingEntry['Sightingdb'][$key] = $this->request->data['Sightingdb'][$key];
                }
            }
            $result = $this->Sightingdb->save($existingEntry);
            if (isset($this->request->data['Sightingdb']['org_id'])) {
                $this->Sightingdb->SightingdbOrg->resetOrgs($this->Sightingdb->id, $this->request->data['Sightingdb']['org_id']);
            }
            $message = $result ? __('SightingDB connection updated.') : __('SightingDB connection could not be updated.');
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Sightingdb', 'edit', $id, $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Sightingdb', 'edit', $id, $message, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                } else {
                    $message .= __(' Reason: %s', json_encode($this->Sightingdb->validationErrors, true));
                    $this->Flash->error($message);
                }
            }
        } else {
            $this->request->data = $existingEntry;
        }
        $orgs = $this->Sightingdb->SightingdbOrg->Organisation->find('list', array(
            'conditions' => array('Organisation.local' => 1),
            'order' => array('LOWER(Organisation.name)'),
            'fields' => array('Organisation.id', 'Organisation.name')
        ));
        $this->set('id', $id);
        $this->set('orgs', $orgs);
        $this->render('/Sightingdb/add');
    }

    public function delete($id)
    {
        $existingEntry = $this->Sightingdb->find('first', array(
            'recursive' => -1,
            'conditions' => array('Sightingdb.id' => $id)
        ));
        if (empty($id) || empty($existingEntry)) {
            throw new NotFoundException(__('Invalid SightingDB entry.'));
        }
        if ($this->request->is('post') || $this->request->is('delete')) {
            $result = $this->Sightingdb->delete($existingEntry['Sightingdb']['id']);
            if ($result) {
                $message = __('SightingDB connection removed.');
            } else {
                $message = __('SightingDB connection could not be removed.');
            }
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Sightingdb', 'edit', $id, $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Sightingdb', 'edit', $id, $message, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                } else {
                    $message .= __(' Reason: %s', json_encode($this->Sightingdb->validationErrors, true));
                    $this->Flash->error($message);
                }
                $this->redirect(array('action' => 'index'));
            }
        }
    }

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(array('value'));
        if (!empty($filters['value'])) {
            if (is_array($filters['value'])) {
                foreach ($filters['value'] as &$value) {
                    $value = '%' . strtolower($value) . '%';
                }
            } else {
                $filters['value'] = '%' . strtolower($filters['value']) . '%';
            }
            $this->paginate['conditions']['AND'][] = array(
                'OR' => array(
                    'Sightingdb.name LIKE' => $filters['value'],
                    'Sightingdb.owner LIKE' => $filters['value'],
                    'Sightingdb.host LIKE' => $filters['value']
                )
            );
        }
        if ($this->_isRest()) {
            $params = array(
                'contain' => $this->paginate['contain'],
                'conditions' => empty($this->paginate['conditions']) ? array() : $this->paginate['conditions'],
            );
            $data = $this->Sightingdb->find('all', $params);
            $data = $this->Sightingdb->extractOrgIdsFromList($data);
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('data', $this->paginate());
        }
    }

    public function requestStatus($id)
    {
        $result = $this->Sightingdb->requestStatus($id);
        if (is_array($result)) {
            return $this->RestResponse->viewData($result, $this->response->type());
        } else {
            return $this->RestResponse->saveFailResponse('Sightingdb', 'requestStatus', $id, $result, $this->response->type());
        }
    }

    public function search($id)
    {
        if (empty($id)) {
            throw new InvalidArgumentException(__('Pass a valid SightingDB ID'));
        }
        $sightingdb = $this->Sightingdb->find('first', array(
            'recursive' => -1,
            'conditions' => array('Sightingdb.id' => $id),
            'contain' => array('SightingdbOrg')
        ));
        if (empty($sightingdb)) {
            throw new NotFoundException('Invalid sightingDB');
        }
        if (!empty($this->request->data['value'])) {
            $requestValue = trim($this->request->data['value']);
            $result = $this->Sightingdb->queryValues(array($requestValue => array()), $sightingdb);
            if (!empty($result[$requestValue][$sightingdb['Sightingdb']['id']])) {
                $result = $result[$requestValue][$sightingdb['Sightingdb']['id']];
                $result = array(
                    'first_seen' => date('Y-m-d H:i:s', $result['first_seen']),
                    'last_seen' => date('Y-m-d H:i:s', $result['last_seen']),
                    'count' => $result['count']
                );
            } else {
                $result = array('count' => 0);
            }
        } else {
            $result = array('count' => 0);
        }
        return $this->RestResponse->viewData($result, $this->response->type());
    }
}
