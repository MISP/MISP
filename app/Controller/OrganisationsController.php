<?php
App::uses('AppController', 'Controller');

class OrganisationsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => 'LOWER(Organisation.name)'
            //'order' => array(
            //		'Organisation.name' => 'ASC'
            //),
    );

    public function index()
    {
        if (!$this->Auth->user('Role')['perm_sharing_group'] && Configure::read('Security.hide_organisation_index_from_users')) {
            throw new MethodNotAllowedException('This feature is disabled on this instance for normal users.');
        }
        $conditions = array();
        // We can either index all of the organisations existing on this instance (default)
        // or we can pass the 'external' keyword in the URL to look at the added external organisations
        $scope = isset($this->passedArgs['scope']) ? $this->passedArgs['scope'] : 'local';
        if ($scope !== 'all') {
            $conditions['AND'][] = array('Organisation.local' => $scope === 'external' ? 0 : 1);
        }
        $passedArgs = $this->passedArgs;

        if (isset($this->request->data['searchall'])) {
            $searchall = $this->request->data['searchall'];
        } elseif (isset($this->passedArgs['all'])) {
            $searchall = $this->passedArgs['all'];
        } elseif (isset($this->passedArgs['searchall'])) {
            $searchall = $this->passedArgs['searchall'];
        }


        if (isset($searchall) && !empty($searchall)) {
            $passedArgs['searchall'] = $searchall;
            $allSearchFields = array('name', 'description', 'nationality', 'sector', 'type', 'contacts', 'restricted_to_domain', 'uuid');
            foreach ($allSearchFields as $field) {
                $conditions['OR'][] = array('LOWER(Organisation.' . $field . ') LIKE' => '%' . strtolower($passedArgs['searchall']) . '%');
            }
        }
        $this->set('passedArgs', json_encode($passedArgs));
        $this->paginate['conditions'] = $conditions;
        $usersPerOrg = $this->User->getMembersCount();
        if ($this->_isRest()) {
            unset($this->paginate['limit']);
            $orgs = $this->Organisation->find('all', $this->paginate);
        } else {
            if (isset($this->params['named']['viewall']) && $this->params['named']['viewall']) {
                $orgCount = $this->Organisation->find('count');
                $this->paginate['limit'] = $orgCount;
            }
            $this->set('viewall', isset($this->params['named']['viewall']) ? $this->params['named']['viewall'] : false);
            $orgs = $this->paginate();
        }
        $this->loadModel('User');
        $org_creator_ids = array();
        foreach ($orgs as $k => $org) {
            if (isset($usersPerOrg[$org['Organisation']['id']])) {
                $orgs[$k]['Organisation']['user_count'] = $usersPerOrg[$org['Organisation']['id']];
            }
            if ($this->_isSiteAdmin()) {
                if (!in_array($org['Organisation']['created_by'], array_keys($org_creator_ids))) {
                    $email = $this->User->find('first', array('recursive' => -1, 'fields' => array('id', 'email'), 'conditions' => array('id' => $org['Organisation']['created_by'])));
                    if (!empty($email)) {
                        $org_creator_ids[$org['Organisation']['created_by']] = $email['User']['email'];
                    } else {
                        $org_creator_ids[$org['Organisation']['created_by']] = 'Unknown';
                    }
                }
                $orgs[$k]['Organisation']['created_by_email'] = $org_creator_ids[$org['Organisation']['created_by']];
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($orgs, $this->response->type());
        } else {
            $this->set('named', $this->params['named']);
            $this->set('scope', $scope);
            $this->set('orgs', $orgs);
        }
    }

    public function admin_add()
    {
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (isset($this->request->data['request'])) {
                    $this->request->data = $this->request->data['request'];
                }
                if (!isset($this->request->data['Organisation'])) {
                    $this->request->data['Organisation'] = $this->request->data;
                }
                if (isset($this->request->data['Organisation']['id'])) {
                    unset($this->request->data['Organisation']['id']);
                }
            }
            $this->Organisation->create();
            $this->request->data['Organisation']['created_by'] = $this->Auth->user('id');
            if ($this->_isRest()) {
                if (!isset($this->request->data['Organisation']['local'])) {
                    $this->request->data['Organisation']['local'] = true;
                }
            }
            if ($this->Organisation->save($this->request->data)) {
                if (isset($this->request->data['Organisation']['logo']['size']) && $this->request->data['Organisation']['logo']['size'] > 0 && $this->request->data['Organisation']['logo']['error'] == 0) {
                    $filename = basename($this->Organisation->id . '.png');
                    if (preg_match("/^[0-9a-z\-\_\.]*\.(png)$/i", $filename)) {
                        if (!empty($this->request->data['Organisation']['logo']['tmp_name']) && is_uploaded_file($this->request->data['Organisation']['logo']['tmp_name'])) {
                            $result = move_uploaded_file($this->request->data['Organisation']['logo']['tmp_name'], APP . 'webroot/img/orgs/' . $filename);
                        }
                    }
                }
                if ($this->_isRest()) {
                    $org = $this->Organisation->find('first', array(
                            'conditions' => array('Organisation.id' => $this->Organisation->id),
                            'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($org, $this->response->type());
                } else {
                    $this->Flash->success('The organisation has been successfully added.');
                    $this->redirect(array('admin' => false, 'action' => 'index'));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Organisations', 'admin_add', false, $this->Organisation->validationErrors, $this->response->type());
                } else {
                    $this->Flash->error('The organisation could not be added.');
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Organisations', 'admin_add', false, $this->response->type());
            }
        }
        $this->set('countries', $this->_arrayToValuesIndexArray($this->Organisation->countries));
    }

    public function admin_edit($id)
    {
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException('Invalid organisation');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->_isRest()) {
                if (isset($this->request->data['request'])) {
                    $this->request->data = $this->request->data['request'];
                }
                if (!isset($this->request->data['Organisation'])) {
                    $this->request->data['Organisation'] = $this->request->data;
                }
                $existingOrg = $this->Organisation->find('first', array('conditions' => array('Organisation.id' => $id)));
                $changeFields = array('name', 'type', 'nationality', 'sector', 'contacts', 'description', 'local', 'uuid');
                $temp = array('Organisation' => array());
                foreach ($changeFields as $field) {
                    if (isset($this->request->data['Organisation'][$field])) {
                        $temp['Organisation'][$field] = $this->request->data['Organisation'][$field];
                    } else {
                        $temp['Organisation'][$field] = $existingOrg['Organisation'][$field];
                    }
                    $this->request->data = $temp;
                }
            }
            $this->request->data['Organisation']['id'] = $id;
            if ($this->Organisation->save($this->request->data)) {
                if (isset($this->request->data['Organisation']['logo']['size']) && $this->request->data['Organisation']['logo']['size'] > 0 && $this->request->data['Organisation']['logo']['error'] == 0) {
                    $filename = basename($this->request->data['Organisation']['id'] . '.png');
                    if (preg_match("/^[0-9a-z\-\_\.]*\.(png)$/i", $filename)) {
                        if (!empty($this->request->data['Organisation']['logo']['tmp_name']) && is_uploaded_file($this->request->data['Organisation']['logo']['tmp_name'])) {
                            $result = move_uploaded_file($this->request->data['Organisation']['logo']['tmp_name'], APP . 'webroot/img/orgs/' . $filename);
                        }
                    }
                }
                if ($this->_isRest()) {
                    $org = $this->Organisation->find('first', array(
                            'conditions' => array('Organisation.id' => $this->Organisation->id),
                            'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($org, $this->response->type());
                } else {
                    $this->Flash->success('Organisation updated.');
                    $this->redirect(array('admin' => false, 'action' => 'view', $this->Organisation->id));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Organisations', 'admin_edit', false, $this->Organisation->validationErrors, $this->response->type());
                } else {
                    if (isset($this->Organisation->validationErrors['uuid'])) {
                        $duplicate_org = $this->Organisation->find('first', array(
                            'recursive' => -1,
                            'conditions' => array('Organisation.uuid' => trim($this->request->data['Organisation']['uuid'])),
                            'fields' => array('Organisation.id')
                        ));
                        $this->set('duplicate_org', $duplicate_org['Organisation']['id']);
                    }
                    $this->Flash->error('The organisation could not be updated.');
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Organisations', 'admin_edit', false, $this->response->type());
            }
            $this->Organisation->read(null, $id);
            $this->request->data = $this->Organisation->data;
        }
        $this->set('countries', $this->_arrayToValuesIndexArray($this->Organisation->countries));
        $this->set('orgId', $id);
        if (is_array($this->request->data['Organisation']['restricted_to_domain'])) {
            $this->request->data['Organisation']['restricted_to_domain'] = implode("\n", $this->request->data['Organisation']['restricted_to_domain']);
        }
        $this->set('id', $id);
    }

    public function admin_delete($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('Action not allowed, post request expected.');
        }
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException('Invalid organisation');
        }

        $org = $this->Organisation->find('first', array(
                'conditions' => array('id' => $id),
                'recursive' => -1,
                'fields' => array('local')
        ));
        if ($org['Organisation']['local']) {
            $url = '/organisations/index';
        } else {
            $url = '/organisations/index/remote';
        }
        if ($this->Organisation->delete()) {
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Organisations', 'admin_delete', $id, $this->response->type());
            } else {
                $this->Flash->success(__('Organisation deleted'));
                $this->redirect($url);
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Organisations', 'admin_delete', $id, $this->Organisation->validationErrors, $this->response->type());
            } else {
                $this->Flash->error(__('Organisation could not be deleted. Generally organisations should never be deleted, instead consider moving them to the known remote organisations list. Alternatively, if you are certain that you would like to remove an organisation and are aware of the impact, make sure that there are no users or events still tied to this organisation before deleting it.'));
                $this->redirect($url);
            }
        }
    }

    public function admin_generateuuid()
    {
        $this->set('uuid', CakeText::uuid());
        $this->set('_serialize', array('uuid'));
    }

    public function view($id)
    {
        if (Validation::uuid($id)) {
            $temp = $this->Organisation->find('first', array('recursive' => -1, 'fields' => array('Organisation.id'), 'conditions' => array('Organisation.uuid' => $id)));
            if (empty($temp)) {
                throw new NotFoundException('Invalid organisation.');
            }
            $id = $temp['Organisation']['id'];
        } elseif (!is_numeric($id)) {
            $temp = $this->Organisation->find('first', array('recursive' => -1, 'fields' => array('Organisation.id'), 'conditions' => array('Organisation.name' => urldecode($id))));
            if (empty($temp)) {
                throw new NotFoundException('Invalid organisation.');
            }
            $id = $temp['Organisation']['id'];
        }
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException('Invalid organisation');
        }
        $fullAccess = false;
        $fields = array('id', 'name', 'date_created', 'date_modified', 'type', 'nationality', 'sector', 'contacts', 'description', 'local', 'uuid', 'restricted_to_domain');
        if ($this->_isSiteAdmin() || ($this->_isAdmin() && $this->Auth->user('Organisation')['id'] == $id)) {
            $fullAccess = true;
            $fields = array_merge($fields, array('created_by'));
        }
        $org = $this->Organisation->find('first', array(
                'conditions' => array('id' => $id),
                'fields' => $fields,
                'recursive' => -1
        ));
        if (!$this->Auth->user('Role')['perm_sharing_group'] && Configure::read('Security.hide_organisation_index_from_users')) {
            $this->loadModel('Event');
            $event = $this->Event->find('first', array(
                'fields' => array('Event.id'),
                'recursive' => -1,
                'conditions' => array('Event.orgc_id' => $org['Organisation']['id'])
            ));
            if (empty($event)) {
                $proposal = $this->Event->ShadowAttribute->find('first', array(
                    'fields' => array('ShadowAttribute.id'),
                    'recursive' => -1,
                    'conditions' => array('ShadowAttribute.org_id' => $org['Organisation']['id'])
                ));
                if (empty($proposal)) {
                    throw new NotFoundException('Invalid organisation');
                }
            }
        }
        $this->set('local', $org['Organisation']['local']);

        if ($fullAccess) {
            $creator = $this->Organisation->User->find(
                 'first',
                 array(
                    'conditions' => array('User.id' => $org['Organisation']['created_by']),
                    'fields' => array('email'),
                    'recursive' => -1
                )
             );
            if (!empty($creator)) {
                $org['Organisation']['created_by_email'] = $creator['User']['email'];
            }
        }
        if ($this->_isRest()) {
            $org['Organisation']['user_count'] = $this->Organisation->User->getMembersCount($org['Organisation']['id']);
            return $this->RestResponse->viewData($org, $this->response->type());
        } else {
            $this->set('fullAccess', $fullAccess);
            $this->set('org', $org);
            $this->set('id', $id);
        }
    }

    public function landingpage($id)
    {
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException('Invalid organisation');
        }
        $org = $this->Organisation->find('first', array('conditions' => array('id' => $id), 'fields' => array('landingpage', 'name')));
        $landingpage = $org['Organisation']['landingpage'];
        if (empty($landingpage)) {
            $landingpage = "No landing page has been created for this organisation.";
        }
        $this->set('landingPage', $landingpage);
        $this->set('org', $org['Organisation']['name']);
        $this->render('ajax/landingpage');
    }

    public function fetchOrgsForSG($idList = '{}', $type)
    {
        if ($type === 'local') {
            $local = 1;
        } else {
            $local = 0;
        }
        $idList = json_decode($idList, true);
        $id_exclusion_list = array_merge($idList, array($this->Auth->user('Organisation')['id']));
        $temp = $this->Organisation->find('all', array(
                'conditions' => array(
                        'local' => $local,
                        'id !=' => $id_exclusion_list,
                ),
                'recursive' => -1,
                'fields' => array('id', 'name'),
                'order' => array('lower(name) ASC')
        ));
        $orgs = array();
        foreach ($temp as $org) {
            $orgs[] = array('id' => $org['Organisation']['id'], 'name' => $org['Organisation']['name']);
        }
        $this->set('local', $local);
        $this->layout = false;
        $this->autoRender = false;
        $this->set('orgs', $orgs);
        $this->render('ajax/fetch_orgs_for_sg');
    }

    public function fetchSGOrgRow($id, $removable = false, $extend = false)
    {
        $this->layout = false;
        $this->autoRender = false;
        $this->set('id', $id);
        $this->set('removable', $removable);
        $this->set('extend', $extend);
        $this->render('ajax/sg_org_row_empty');
    }

    public function getUUIDs()
    {
        if (!$this->Auth->user('Role')['perm_sync']) {
            throw new MethodNotAllowedException('This action is restricted to sync users');
        }
        $temp = $this->Organisation->find('all', array(
                'recursive' => -1,
                'conditions' => array('local' => 1),
                'fields' => array('Organisation.uuid')
        ));
        $orgs = array();
        foreach ($temp as $t) {
            $orgs[] = $t['Organisation']['uuid'];
        }
        return new CakeResponse(array('body'=> json_encode($orgs), 'type' => 'json'));
    }

    public function admin_merge($id, $target_id = false)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('Post')) {
            $result = $this->Organisation->orgMerge($id, $this->request->data, $this->Auth->user());
            if ($result) {
                $this->Flash->success('The organisation has been successfully merged.');
                $this->redirect(array('admin' => false, 'action' => 'view', $result));
            } else {
                $this->Flash->error('There was an error while merging the organisations. To find out more about what went wrong, refer to the audit logs. If you would like to revert the changes, you can find a .sql file ');
            }
            $this->redirect(array('admin' => false, 'action' => 'index'));
        } else {
            $currentOrg = $this->Organisation->find('first', array('fields' => array('id', 'name', 'uuid', 'local'), 'recursive' => -1, 'conditions' => array('Organisation.id' => $id)));
            $orgs['local'] = $this->Organisation->find('all', array(
                    'fields' => array('id', 'name', 'uuid'),
                    'conditions' => array('Organisation.id !=' => $id, 'Organisation.local' => 1),
                    'order' => 'lower(Organisation.name) ASC'
            ));
            $orgs['external'] = $this->Organisation->find('all', array(
                    'fields' => array('id', 'name', 'uuid'),
                    'conditions' => array('Organisation.id !=' => $id, 'Organisation.local' => 0),
                    'order' => 'lower(Organisation.name) ASC'
            ));
            foreach (array('local', 'external') as $type) {
                $orgOptions[$type] = Hash::combine($orgs[$type], '{n}.Organisation.id', '{n}.Organisation.name');
                $orgs[$type] = Hash::combine($orgs[$type], '{n}.Organisation.id', '{n}');
            }
            if (!empty($target_id)) {
                $target = array();
                foreach (array('local', 'external') as $type) {
                    foreach ($orgOptions[$type] as $k => $v) {
                        if ($k == $target_id) {
                            $target = array('id' => $k, 'type' => $type);
                        }
                    }
                }
                if (!empty($target)) {
                    $this->set('target', $target);
                }
            }
            $this->set('orgs', json_encode($orgs));
            $this->set('orgOptions', $orgOptions);
            $this->set('currentOrg', $currentOrg);
            $this->layout = false;
            $this->autoRender = false;
            $this->render('ajax/merge');
        }
    }
}
