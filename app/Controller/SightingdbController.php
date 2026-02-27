<?php
App::uses('AppController', 'Controller');

class SightingdbController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
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
        $params = [
            'redirect' => ['action' => 'index'],
            'afterSave' => function ($data) {
                if (isset($this->request->data['Sightingdb']['org_id'])) {
                    $this->Sightingdb->SightingdbOrg->resetOrgs(
                        $this->Sightingdb->id,
                        $this->request->data['Sightingdb']['org_id']
                    );
                }
            }
        ];
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $orgs = $this->Sightingdb->SightingdbOrg->Organisation->find('list', [
            'conditions' => ['Organisation.local' => 1],
            'order' => ['LOWER(Organisation.name)'],
            'fields' => ['Organisation.id', 'Organisation.name']
        ]);
        $this->set('orgs', $orgs);
    }

    public function edit($id)
    {
        $params = [
            'fields' => ['host', 'port', 'description', 'name', 'owner', 'enabled', 'skip_proxy', 'ssl_skip_verification', 'namespace'],
            'contain' => ['SightingdbOrg.org_id'],
            'redirect' => ['action' => 'index'],
            'afterFind' => function ($data) {
                return $this->Sightingdb->extractOrgIds($data);
            },
            'afterSave' => function ($data) {
                if (isset($this->request->data['Sightingdb']['org_id'])) {
                    $this->Sightingdb->SightingdbOrg->resetOrgs(
                        $this->Sightingdb->id,
                        $this->request->data['Sightingdb']['org_id']
                    );
                }
            }
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $orgs = $this->Sightingdb->SightingdbOrg->Organisation->find('list', [
            'conditions' => ['Organisation.local' => 1],
            'order' => ['LOWER(Organisation.name)'],
            'fields' => ['Organisation.id', 'Organisation.name']
        ]);
        $this->set('id', $id);
        $this->set('orgs', $orgs);
        $this->render('/Sightingdb/add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id, [
            'redirect' => ['action' => 'index']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function index()
    {
        $params = [
            'filters' => ['name', 'owner', 'host'],
            'quickFilters' => ['name', 'owner', 'host'],
            'contain' => ['SightingdbOrg' => 'Organisation'],
            'afterFind' => function ($data) {
                return $this->Sightingdb->extractOrgIdsFromList($data);
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('data', $this->viewVars['data']);
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
