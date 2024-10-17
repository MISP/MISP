<?php
App::uses('AppController', 'Controller');

/**
 * @property Organisation $Organisation
 */
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
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => 'LOWER(Organisation.name)'
            //'order' => array(
            //      'Organisation.name' => 'ASC'
            //),
    );

    public function index()
    {
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
        } elseif (isset($this->passedArgs['quickFilter'])) {
            $searchall = $this->passedArgs['quickFilter'];
        }

        if (isset($searchall) && !empty($searchall)) {
            $passedArgs['searchall'] = $searchall;
            $allSearchFields = array('name', 'description', 'nationality', 'sector', 'type', 'contacts', 'restricted_to_domain', 'uuid');
            $searchTerm = '%' . strtolower($passedArgs['searchall']) . '%';
            foreach ($allSearchFields as $field) {
                $conditions['OR'][] = array('LOWER(Organisation.' . $field . ') LIKE' => $searchTerm);
            }
        }

        $this->paginate['conditions'] = $conditions;

        $this->Organisation->addCountField('user_count', $this->User, ['User.org_id = Organisation.id']);
        if ($this->_isRest()) {
            unset($this->paginate['limit']);
            $orgs = $this->Organisation->find('all', $this->paginate);
        } else {
            $viewAll = isset($this->params['named']['viewall']) && $this->params['named']['viewall'];
            if ($viewAll) {
                unset($this->paginate['limit']);
            }
            $this->set('viewall', $viewAll);
            $orgs = $this->paginate();
        }

        $this->loadModel('User');
        $org_creator_ids = array();
        foreach ($orgs as $k => $org) {
            if ($this->_isSiteAdmin()) {
                if (!isset($org_creator_ids[$org['Organisation']['created_by']])) {
                    $email = $this->User->find('first', array(
                        'recursive' => -1,
                        'fields' => array('id', 'email'),
                        'conditions' => array('id' => $org['Organisation']['created_by']))
                    );
                    if (!empty($email)) {
                        $org_creator_ids[$org['Organisation']['created_by']] = $email['User']['email'];
                    } else {
                        $org_creator_ids[$org['Organisation']['created_by']] = __('Unknown');
                    }
                }
                $orgs[$k]['Organisation']['created_by_email'] = $org_creator_ids[$org['Organisation']['created_by']];
            } else {
                unset($orgs[$k]['Organisation']['created_by']);
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($orgs, $this->response->type());
        }
        foreach ($orgs as &$org) {
            $org['Organisation']['country_code'] = $this->Organisation->getCountryCode($org['Organisation']['nationality']);
        }

        $this->set('named', $this->params['named']);
        $this->set('scope', $scope);
        $this->set('orgs', $orgs);
        $this->set('passedArgs', json_encode($passedArgs));
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
                $this->__uploadLogo($this->Organisation->id);
                if ($this->_isRest()) {
                    $org = $this->Organisation->find('first', array(
                        'conditions' => array('Organisation.id' => $this->Organisation->id),
                        'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($org, $this->response->type());
                } else {
                    $this->Flash->success(__('The organisation has been successfully added.'));
                    $this->redirect(array('admin' => false, 'action' => 'view', $this->Organisation->id));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Organisations', 'admin_add', false, $this->Organisation->validationErrors, $this->response->type());
                } else {
                    $this->Flash->error(__('The organisation could not be added.'));
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Organisations', 'admin_add', false, $this->response->type());
            } else {
                if (!empty($this->params['named']['name'])) {
                    $this->request->data['Organisation']['name'] = $this->params['named']['name'];
                }
                if (!empty($this->params['named']['uuid'])) {
                    $this->request->data['Organisation']['uuid'] = $this->params['named']['uuid'];
                }
            }
        }
        $countries = array_merge(['' => __('Not specified')], $this->_arrayToValuesIndexArray($this->Organisation->getCountries()));
        $this->set('countries', $countries);
        $this->set('action', 'add');
    }

    public function admin_edit($id)
    {
        if (Validation::uuid($id)) {
            $temp = $this->Organisation->find('first', array('recursive' => -1, 'fields' => array('Organisation.id'), 'conditions' => array('Organisation.uuid' => $id)));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid organisation.'));
            }
            $id = $temp['Organisation']['id'];
        }
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException(__('Invalid organisation'));
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
                $changeFields = array('name', 'type', 'nationality', 'sector', 'contacts', 'description', 'local', 'uuid', 'restricted_to_domain');
                $temp = array('Organisation' => array());
                foreach ($changeFields as $field) {
                    if (isset($this->request->data['Organisation'][$field])) {
                        $temp['Organisation'][$field] = $this->request->data['Organisation'][$field];
                    } else {
                        $temp['Organisation'][$field] = $existingOrg['Organisation'][$field];
                    }
                }
                $this->request->data = $temp;
            }
            $this->request->data['Organisation']['id'] = $id;
            if ($this->Organisation->save($this->request->data)) {
                $this->__uploadLogo($this->Organisation->id);
                if ($this->_isRest()) {
                    $org = $this->Organisation->find('first', array(
                            'conditions' => array('Organisation.id' => $this->Organisation->id),
                            'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($org, $this->response->type());
                } else {
                    $this->Flash->success(__('Organisation updated.'));
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
                    $this->Flash->error(__('The organisation could not be updated.'));
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Organisations', 'admin_edit', false, $this->response->type());
            }
            $this->Organisation->read(null, $id);
            $this->request->data = $this->Organisation->data;
        }

        $countries = array_merge(['' => __('Not specified')], $this->_arrayToValuesIndexArray($this->Organisation->getCountries()));
        if (!empty($this->Organisation->data['Organisation']['nationality'])) {
            $currentCountry = $this->Organisation->data['Organisation']['nationality'];
            if (!isset($countries[$currentCountry])) {
                // Append old country name to list to keep backward compatibility
                $countries[$currentCountry] = $currentCountry;
            }
        }

        $this->set('countries', $countries);
        $this->set('orgId', $id);
        if (is_array($this->request->data['Organisation']['restricted_to_domain'])) {
            $this->request->data['Organisation']['restricted_to_domain'] = implode("\n", $this->request->data['Organisation']['restricted_to_domain']);
        }
        $this->set('id', $id);
        $this->set('action', 'edit');
        $this->render('admin_add');
    }

    public function admin_delete($id)
    {
        if (!$this->request->is('post') && !$this->request->is('delete')) {
            throw new MethodNotAllowedException(__('Action not allowed, post or delete request expected.'));
        }
        if (Validation::uuid($id)) {
            $temp = $this->Organisation->find('first', array('recursive' => -1, 'fields' => array('Organisation.id'), 'conditions' => array('Organisation.uuid' => $id)));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid organisation'));
            }
            $id = $temp['Organisation']['id'];
        }
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException(__('Invalid organisation'));
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
        if (is_numeric($id)) {
            $conditions = ['Organisation.id' => $id];
        } else if (Validation::uuid($id)) {
            $conditions = ['Organisation.uuid' => $id];
        } else {
            $conditions = ['Organisation.name' => urldecode($id)];
        }

        if ($this->request->is('head')) { // Just check if org exists and user can access it
            $org = $this->Organisation->find('first', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => ['id'],
            ));
            $exists = $org && $this->Organisation->canSee($this->Auth->user(), $org['Organisation']['id']);
            return new CakeResponse(['status' => $exists ? 200 : 404]);
        }

        $fields = ['id', 'name', 'date_created', 'date_modified', 'type', 'nationality', 'sector', 'contacts', 'description', 'local', 'uuid', 'restricted_to_domain', 'created_by'];
        if ($this->_isRest()) {
            $this->Organisation->addCountField('user_count', $this->User, ['User.org_id = Organisation.id']);
            $fields[] = 'user_count';
        }

        $org = $this->Organisation->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => $fields,
        ));
        if (!$org || !$this->Organisation->canSee($this->Auth->user(), $org['Organisation']['id'])) {
            throw new NotFoundException(__('Invalid organisation'));
        }

        $fullAccess = $this->_isSiteAdmin() || ($this->_isAdmin() && $this->Auth->user('Organisation')['id'] == $org['Organisation']['id']);
        if ($fullAccess) {
            $creator = $this->Organisation->User->find('first', array(
                'conditions' => array('User.id' => $org['Organisation']['created_by']),
                'fields' => array('email'),
                'recursive' => -1
            ));
            if (!empty($creator)) {
                $org['Organisation']['created_by_email'] = $creator['User']['email'];
            }
        } else {
            unset($org['Organisation']['created_by']);
        }

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($org, $this->response->type());
        }

        $org['Organisation']['country_code'] = $this->Organisation->getCountryCode($org['Organisation']['nationality']);
        $this->set('local', $org['Organisation']['local']);
        $this->set('fullAccess', $fullAccess);
        $this->set('org', $org);
        $this->set('id', $org['Organisation']['id']);
        $this->set('title_for_layout', __('Organisation %s', $org['Organisation']['name']));
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
        $orgs = $this->Organisation->find('list', array(
            'conditions' => array(
                'local' => $local,
                'id !=' => $id_exclusion_list,
            ),
            'recursive' => -1,
            'fields' => array('id', 'name'),
            'order' => array('lower(name) ASC')
        ));
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
        $this->set('id', (int)$id);
        $this->set('removable', $removable);
        $this->set('extend', $extend);
        $this->render('ajax/sg_org_row_empty');
    }

    /**
     * @deprecated Probably not used anywhere.
     */
    public function getUUIDs()
    {
        if (Configure::read('Security.hide_organisation_index_from_users')) {
            throw new MethodNotAllowedException(__('This action is not enabled on this instance.'));
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
            throw new MethodNotAllowedException(__('You are not authorised to do that.'));
        }
        if ($this->request->is('Post')) {
            $result = $this->Organisation->orgMerge($id, $this->request->data, $this->Auth->user());
            if ($result) {
                $this->Flash->success(__('The organisation has been successfully merged.'));
                $this->redirect(array('admin' => false, 'action' => 'view', $result));
            } else {
                $this->Flash->error(__('There was an error while merging the organisations. To find out more about what went wrong, refer to the audit logs. If you would like to revert the changes, you can find a .sql file'));
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

    /**
     * @return bool
     */
    private function __uploadLogo($orgId)
    {
        if (!isset($this->request->data['Organisation']['logo']['size'])) {
            return false;
        }

        $logo = $this->request->data['Organisation']['logo'];
        if ($logo['size'] > 0 && $logo['error'] == 0) {
            $extension = pathinfo($logo['name'], PATHINFO_EXTENSION);
            $filename = $orgId . '.' . ($extension === 'svg' ? 'svg' : 'png');

            if ($logo['size'] > 250 * 1024) {
                $this->Flash->error(__('This organisation logo is too large, maximum file size allowed is 250 kB.'));
                return false;
            }

            if ($extension !== 'svg' && $extension !== 'png') {
                $this->Flash->error(__('Invalid file extension, Only PNG and SVG images are allowed.'));
                return false;
            }
            $matches = null;
            $tmp_name = $logo['tmp_name'];
            if (preg_match_all('/[\w\/\-\.]*/', $tmp_name, $matches) && file_exists($logo['tmp_name'])) {
                $tmp_name = $matches[0][0];
                $imgMime = mime_content_type($tmp_name);
            } else {
                throw new NotFoundException(__('Invalid file.'));    
            }
            if ($extension === 'png' && (function_exists('exif_imagetype') && !exif_imagetype($logo['tmp_name']))) {
                $this->Flash->error(__('This is not a valid PNG image.'));
                return false;
            }

            if ($extension === 'svg' && !($imgMime === 'image/svg+xml' || $imgMime === 'image/svg')) {
                $this->Flash->error(__('This is not a valid SVG image.'));
                return false;
            }

            if ($extension === 'svg' && !Configure::read('Security.enable_svg_logos')) {
                $this->Flash->error(__('Invalid file extension, SVG images are not allowed.'));
                return false;
            }

            if (!empty($tmp_name) && is_uploaded_file($tmp_name)) {
                return move_uploaded_file($tmp_name, APP . 'files/img/orgs/' . $filename);
            }
        }

        return false;
    }
}
