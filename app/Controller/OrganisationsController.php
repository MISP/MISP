<?php
App::uses('AppController', 'Controller');

/**
 * @property Organisation $Organisation
 */
class OrganisationsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'CRUD');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
            'order' => 'LOWER(Organisation.name)'
    );

    public function index()
    {
        $scope = isset($this->passedArgs['scope']) ? $this->passedArgs['scope'] : 'local';
        $conditions = [];
        if ($scope !== 'all') {
            $conditions['Organisation.local'] = $scope === 'external' ? 0 : 1;
        }

        $this->Organisation->addCountField('user_count', $this->User, ['User.org_id = Organisation.id']);

        $params = [
            'filters' => ['name', 'description', 'nationality', 'sector', 'type', 'uuid', 'local'],
            'quickFilters' => ['name', 'description', 'nationality', 'sector', 'type', 'contacts', 'restricted_to_domain', 'uuid'],
            'quickFilterParameter' => 'searchall',
            'conditions' => $conditions,
            'afterFind' => function (array $orgs) {
                $this->loadModel('User');
                $orgCreatorIds = [];
                foreach ($orgs as $k => $org) {
                    if ($this->_isSiteAdmin()) {
                        $createdBy = $org['Organisation']['created_by'];
                        if (!isset($orgCreatorIds[$createdBy])) {
                            $email = $this->User->find('first', [
                                'recursive' => -1,
                                'fields' => ['id', 'email'],
                                'conditions' => ['id' => $createdBy]
                            ]);
                            $orgCreatorIds[$createdBy] = !empty($email) ? $email['User']['email'] : __('Unknown');
                        }
                        $orgs[$k]['Organisation']['created_by_email'] = $orgCreatorIds[$createdBy];
                    } else {
                        unset($orgs[$k]['Organisation']['created_by']);
                    }
                    if (!$this->IndexFilter->isRest()) {
                        $orgs[$k]['Organisation']['country_code'] = $this->Organisation->getCountryCode($org['Organisation']['nationality']);
                    }
                }
                return $orgs;
            }
        ];

        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->set('named', $this->params['named']);
        $this->set('scope', $scope);
        $this->set('orgs', $this->viewVars['data']);
        $this->set('passedArgs', json_encode($this->passedArgs));
        $this->set('viewall', isset($this->params['named']['viewall']) && $this->params['named']['viewall']);
    }

    public function admin_add()
    {
        $params = [
            'beforeSave' => function (array $data) {
                $data['Organisation']['created_by'] = $this->Auth->user('id');
                if ($this->IndexFilter->isRest() && !isset($data['Organisation']['local'])) {
                    $data['Organisation']['local'] = true;
                }
                return $data;
            },
            'afterSave' => function (array $data) {
                $this->__uploadLogo($this->Organisation->id);
                if (!$this->IndexFilter->isRest()) {
                    $this->Flash->success(__('The organisation has been successfully added.'));
                    $this->redirect(['admin' => false, 'action' => 'view', $this->Organisation->id]);
                }
            }
        ];

        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        // Pre-fill from named parameters
        if (!empty($this->params['named']['name'])) {
            $this->request->data['Organisation']['name'] = $this->params['named']['name'];
        }
        if (!empty($this->params['named']['uuid'])) {
            $this->request->data['Organisation']['uuid'] = $this->params['named']['uuid'];
        }

        $countries = array_merge(['' => __('Not specified')], $this->_arrayToValuesIndexArray($this->Organisation->getCountries()));
        $this->set('countries', $countries);
        $this->set('action', 'add');
    }

    public function admin_edit($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Organisation, $id);

        $params = [
            'fields' => ['name', 'type', 'nationality', 'sector', 'contacts', 'description', 'local', 'uuid', 'restricted_to_domain'],
            'afterSave' => function (array $data) use ($id) {
                $this->__uploadLogo($this->Organisation->id);
                if (!$this->IndexFilter->isRest()) {
                    $this->Flash->success(__('Organisation updated.'));
                    $this->redirect(['admin' => false, 'action' => 'view', $id]);
                }
            }
        ];

        $this->CRUD->edit($id, $params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        // Handle duplicate UUID error display
        if (isset($this->Organisation->validationErrors['uuid'])) {
            $duplicateOrg = $this->Organisation->find('first', [
                'recursive' => -1,
                'conditions' => ['Organisation.uuid' => trim($this->request->data['Organisation']['uuid'])],
                'fields' => ['Organisation.id']
            ]);
            if (!empty($duplicateOrg)) {
                $this->set('duplicate_org', $duplicateOrg['Organisation']['id']);
            }
        }

        $countries = array_merge(['' => __('Not specified')], $this->_arrayToValuesIndexArray($this->Organisation->getCountries()));
        if (!empty($this->request->data['Organisation']['nationality'])) {
            $currentCountry = $this->request->data['Organisation']['nationality'];
            if (!isset($countries[$currentCountry])) {
                $countries[$currentCountry] = $currentCountry;
            }
        }

        $this->set('countries', $countries);
        $this->set('orgId', $id);
        if (isset($this->request->data['Organisation']['restricted_to_domain']) && is_array($this->request->data['Organisation']['restricted_to_domain'])) {
            $this->request->data['Organisation']['restricted_to_domain'] = implode("\n", $this->request->data['Organisation']['restricted_to_domain']);
        }
        $this->set('id', $id);
        $this->set('action', 'edit');
        $this->render('admin_add');
    }

    public function admin_delete($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Organisation, $id);

        $this->CRUD->delete($id, [
            'redirect' => ['controller' => 'organisations', 'action' => 'index']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
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

    public function getOrgLogo($id) {
        $org = $this->Organisation->find('first', array(
            'conditions' => array('Organisation.id' => intval($id)),
            'recursive' => -1
        ));
        if (empty($org)) {
            throw new NotFoundException(__('Invalid organisation'));
        }
        $path = APP . 'files/img/orgs/';
        $image = null;
        foreach (['id', 'name', 'uuid'] as $field) {
            foreach (['png', 'svg'] as $extensions) {
                if (file_exists($path . $org['Organisation'][$field] . '.' . $extensions)) {
                    $this->response->file($path . $org['Organisation'][$field] . '.' . $extensions, ['download' => false, 'name' => $org['Organisation']['id'] . '.' . $extensions]);
                    return $this->response;
                }
            }
        }
        if ($image) {
            $filePath = $path . $image;
            $this->response->file($filePath, array('download' => false, 'name' => $image));
            return $this->response;
        } else {
            throw new NotFoundException(__('Organisation logo not found'));
        }

    }
}
