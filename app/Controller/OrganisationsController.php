<?php
App::uses('AppController', 'Controller');
App::uses('OrganisationRailCards', 'Tools/RailCards');

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
        // The default theme lists only local organisations to keep the view
        // focused; the Overmind theme defaults to all organisations because its
        // filter bar makes narrowing the scope trivial.
        $defaultScope = ($this->theme === 'Overmind') ? 'all' : 'local';
        $scope = isset($this->passedArgs['scope']) ? $this->passedArgs['scope'] : $defaultScope;
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
        if ($this->theme === 'Overmind') {
            $this->loadModel('AnalystProfile');
            $this->set('orgGrading', $this->AnalystProfile->gradingFor($this->Auth->user()));
        }
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
        if ($this->theme === "Overmind") {
            $this->layout = false;
        }
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
        if ($this->theme === "Overmind") {
            $this->layout = false;
        }
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

    /**
     * Mass-delete organisations from the Overmind index (also backs the single
     * row "Delete" action). An organisation cannot be removed while it still has
     * users or events attached (mirrors Organisation::beforeDelete); such rows
     * are reported as blocked and skipped rather than silently failing.
     *
     * GET  (opened via openModal): renders the confirmation modal.
     * POST (from that modal): deletes the deletable selection.
     */
    public function admin_deleteSelection($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            $idList = $this->request->data['Organisation']['id'] ?? $id;
            if (!is_array($idList)) {
                $idList = (is_numeric($idList)) ? [$idList] : json_decode($idList, true);
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }

            $deleted = 0;
            $failed = 0;
            $blocked = [];
            foreach ($idList as $orgId) {
                $org = $this->Organisation->find('first', [
                    'conditions' => ['Organisation.id' => $orgId],
                    'recursive' => -1,
                    'fields' => ['Organisation.id', 'Organisation.name'],
                ]);
                if (empty($org)) {
                    $failed++;
                    continue;
                }
                if ($this->__orgDeletionBlocker($org['Organisation']['id']) !== null) {
                    $blocked[] = $org['Organisation']['name'];
                    continue;
                }
                if ($this->Organisation->delete($org['Organisation']['id'])) {
                    $deleted++;
                } else {
                    $failed++;
                }
            }

            $messages = [];
            if ($deleted) {
                $messages[] = __n('%s organisation deleted.', '%s organisations deleted.', $deleted, $deleted);
            }
            if (!empty($blocked)) {
                $messages[] = count($blocked) === 1
                    ? __('Organisation "%s" was not deleted because it still has users or events attached.', $blocked[0])
                    : __('%s organisations were not deleted because they still have users or events attached: %s', count($blocked), implode(', ', $blocked));
            }
            if ($failed) {
                $messages[] = __n('%s organisation could not be deleted.', '%s organisations could not be deleted.', $failed, $failed);
            }
            $message = trim(implode(' ', $messages));

            if ($this->IndexFilter->isRest()) {
                if ($deleted) {
                    return $this->RestResponse->saveSuccessResponse('Organisations', 'admin_deleteSelection', $id, $this->response->type(), $message);
                }
                return $this->RestResponse->saveFailResponse('Organisations', 'admin_deleteSelection', false, $message, $this->response->type());
            }

            if ($deleted && empty($blocked) && !$failed) {
                $this->Flash->success($message);
            } elseif ($deleted) {
                $this->Flash->warning($message);
            } else {
                $this->Flash->error($message ?: __('No organisations were deleted.'));
            }
            return $this->redirect(['action' => 'index', 'admin' => false]);
        }

        // GET → build the confirmation modal.
        $idList = is_numeric($id) ? [$id] : json_decode($id, true);
        if (empty($idList)) {
            throw new NotFoundException(__('Invalid input.'));
        }
        $orgs = $this->Organisation->find('all', [
            'conditions' => ['Organisation.id' => $idList],
            'recursive' => -1,
            'fields' => ['Organisation.id', 'Organisation.name'],
        ]);
        $deletable = [];
        $blocked = [];
        foreach ($orgs as $org) {
            $blocker = $this->__orgDeletionBlocker($org['Organisation']['id']);
            if ($blocker !== null) {
                $blocked[] = [
                    'name' => $org['Organisation']['name'],
                    'reason' => $blocker['reason'],
                    'count' => $blocker['count'],
                ];
            } else {
                $deletable[] = ['id' => $org['Organisation']['id'], 'name' => $org['Organisation']['name']];
            }
        }

        $this->request->data['Organisation']['id'] = json_encode($idList);
        $this->set('idArray', $idList);
        $this->set('deletable', $deletable);
        $this->set('blocked', $blocked);
        $this->layout = false;
        $this->render('/Organisations/ajax/orgDeleteConfirmationForm');
    }

    /**
     * Returns null when the organisation can be deleted, otherwise the reason it
     * is blocked ('users' or 'events') with the offending count. Mirrors the
     * guards in Organisation::beforeDelete().
     */
    private function __orgDeletionBlocker($orgId)
    {
        $userCount = $this->Organisation->User->find('count', [
            'conditions' => ['User.org_id' => $orgId],
            'recursive' => -1,
        ]);
        if ($userCount) {
            return ['reason' => 'users', 'count' => $userCount];
        }
        $eventCount = $this->Organisation->Event->find('count', [
            'conditions' => ['OR' => ['Event.org_id' => $orgId, 'Event.orgc_id' => $orgId]],
            'recursive' => -1,
        ]);
        if ($eventCount) {
            return ['reason' => 'events', 'count' => $eventCount];
        }
        return null;
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
        $orgId = (int)$org['Organisation']['id'];
        // Same gate as the Users tab: site admins, and admins of this organisation.
        $canViewUsers = $this->_isSiteAdmin()
            || (!empty($this->userRole['perm_admin']) && (int)$this->Auth->user('org_id') === $orgId);
        $this->set('orgUserSummary', $canViewUsers ? $this->__orgUserSummary($orgId) : null);
        // Same gate as sharing_groups/index's searchorg filter.
        $showSgOrgs = !empty($this->userRole['perm_sharing_group'])
            || !Configure::read('Security.hide_organisations_in_sharing_groups');
        $this->set('orgSharingGroups', $showSgOrgs ? $this->__orgSharingGroups($orgId) : null);
        $this->set('local', $org['Organisation']['local']);
        $this->set('fullAccess', $fullAccess);
        $this->set('org', $org);
        $this->set('id', $org['Organisation']['id']);
        $this->set('title_for_layout', __('Organisation %s', $org['Organisation']['name']));
        if ($this->theme === 'Overmind') {
            $railCards = new OrganisationRailCards();
            $this->set('railCards', RailCard::byId([
                $railCards->slot('org-glance', $org['Organisation']['id']),
                $railCards->slot('org-activity', $org['Organisation']['id']),
            ]));
        }
    }

    /**
     * Organisations for an index filter picker: GET ?q=<term>.
     */
    public function pickerSearch()
    {
        $this->request->allowMethod(['get']);
        App::uses('IndexPicker', 'Tools');
        return $this->RestResponse->viewData(
            IndexPicker::organisations($this->Auth->user(), $this->request->query('q')),
            'json'
        );
    }

    /**
     * One of the organisation page's lazy rail cards.
     *
     * @param int $id
     * @param string $cardId
     */
    public function railCard($id, $cardId)
    {
        $user = $this->Auth->user();
        if (!is_numeric($id) || !$this->Organisation->hasAny(['Organisation.id' => $id])
            || !$this->Organisation->canSee($user, $id)) {
            throw new NotFoundException(__('Invalid organisation'));
        }
        $may = [
            'users' => $this->_isSiteAdmin() || ($this->_isAdmin() && $user['org_id'] == $id),
            'sharingGroups' => $user['Role']['perm_sharing_group']
                || !Configure::read('Security.hide_organisations_in_sharing_groups'),
        ];
        $this->_renderRailCard((new OrganisationRailCards())->lazy($cardId, $user, $id, $may));
    }

    /**
     * Head count by role and state, plus the few accounts used most recently,
     * for the organisation view's Users card. Two grouped counts and one
     * limited query, whatever the size of the organisation.
     *
     * @param int $orgId
     * @return array
     */
    private function __orgUserSummary($orgId)
    {
        $this->loadModel('User');
        $byRole = $this->User->find('all', [
            'recursive' => -1,
            'fields' => ['User.role_id', 'User.disabled', 'COUNT(*) AS count'],
            'conditions' => ['User.org_id' => $orgId],
            'group' => ['User.role_id', 'User.disabled'],
        ]);
        $roleNames = $this->User->Role->find('list', ['fields' => ['Role.id', 'Role.name']]);
        $summary = ['total' => 0, 'disabled' => 0, 'roles' => [], 'recent' => []];
        foreach ($byRole as $row) {
            $count = (int)$row[0]['count'];
            $roleId = (int)$row['User']['role_id'];
            $summary['total'] += $count;
            if (!empty($row['User']['disabled'])) {
                $summary['disabled'] += $count;
            }
            if (!isset($summary['roles'][$roleId])) {
                $summary['roles'][$roleId] = ['name' => $roleNames[$roleId] ?? __('Unknown role'), 'count' => 0];
            }
            $summary['roles'][$roleId]['count'] += $count;
        }
        uasort($summary['roles'], function ($a, $b) {
            return $b['count'] <=> $a['count'];
        });
        $recent = $this->User->find('all', [
            'recursive' => -1,
            'fields' => ['User.id', 'User.email', 'User.role_id', 'User.disabled', 'User.last_login'],
            'conditions' => ['User.org_id' => $orgId],
            'order' => ['User.last_login DESC', 'User.id DESC'],
            'limit' => 6,
        ]);
        foreach ($recent as $user) {
            $user['User']['role_name'] = $roleNames[$user['User']['role_id']] ?? '';
            $summary['recent'][] = $user['User'];
        }
        return $summary;
    }

    /**
     * The sharing groups this organisation creates or belongs to, among those
     * the current user may see.
     *
     * @param int $orgId
     * @return array
     */
    private function __orgSharingGroups($orgId)
    {
        $this->loadModel('SharingGroup');
        $authorized = $this->SharingGroup->authorizedIds($this->Auth->user());
        if (empty($authorized)) {
            return [];
        }
        $memberships = $this->SharingGroup->SharingGroupOrg->find('list', [
            'fields' => ['SharingGroupOrg.sharing_group_id', 'SharingGroupOrg.extend'],
            'conditions' => [
                'SharingGroupOrg.org_id' => $orgId,
                'SharingGroupOrg.sharing_group_id' => $authorized,
            ],
        ]);
        $owned = $this->SharingGroup->find('column', [
            'fields' => ['SharingGroup.id'],
            'conditions' => ['SharingGroup.org_id' => $orgId, 'SharingGroup.id' => $authorized],
        ]);
        $ids = array_unique(array_merge(array_keys($memberships), $owned));
        if (empty($ids)) {
            return [];
        }
        $this->SharingGroup->addCountField('org_count', $this->SharingGroup->SharingGroupOrg, ['SharingGroupOrg.sharing_group_id = SharingGroup.id']);
        $groups = $this->SharingGroup->find('all', [
            'recursive' => -1,
            'fields' => ['SharingGroup.id', 'SharingGroup.name', 'SharingGroup.active', 'SharingGroup.roaming', 'SharingGroup.org_id', 'SharingGroup.org_count'],
            'conditions' => ['SharingGroup.id' => $ids],
            'order' => ['SharingGroup.name'],
        ]);
        $result = [];
        foreach ($groups as $group) {
            $sg = $group['SharingGroup'];
            $sg['owner'] = (int)$sg['org_id'] === $orgId;
            $sg['extend'] = !empty($memberships[$sg['id']]);
            $result[] = $sg;
        }
        return $result;
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

    /**
     * The legacy view is always opened for a given organisation, so the merge
     * source comes from the URL. The Overmind modal is opened from the index
     * header instead, where nothing is preselected: it posts both ends of the
     * merge as plain organisation ids (sourceOrg / targetOrg), which are
     * normalised below into the shape orgMerge() expects.
     */
    public function admin_merge($id = false, $target_id = false)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('You are not authorised to do that.'));
        }
        if ($this->request->is('Post')) {
            $data = $this->request->data;
            $sourceId = $id ?: (isset($data['Organisation']['sourceOrg']) ? $data['Organisation']['sourceOrg'] : false);
            if (!empty($data['Organisation']['targetOrg'])) {
                $targetOrg = $this->Organisation->find('first', array(
                    'recursive' => -1,
                    'fields' => array('id', 'local'),
                    'conditions' => array('Organisation.id' => $data['Organisation']['targetOrg'])
                ));
                if (empty($targetOrg)) {
                    throw new NotFoundException(__('Invalid target organisation.'));
                }
                $targetIsLocal = !empty($targetOrg['Organisation']['local']);
                $data['Organisation']['targetType'] = $targetIsLocal ? 0 : 1;
                $data['Organisation'][$targetIsLocal ? 'orgsLocal' : 'orgsExternal'] = $targetOrg['Organisation']['id'];
            }
            $targetId = empty($data['Organisation']['targetType'])
                ? (isset($data['Organisation']['orgsLocal']) ? $data['Organisation']['orgsLocal'] : false)
                : (isset($data['Organisation']['orgsExternal']) ? $data['Organisation']['orgsExternal'] : false);
            if (empty($sourceId) || empty($targetId)) {
                $this->Flash->error(__('Both the organisation to be merged and the organisation to merge it into have to be selected.'));
                $this->redirect(array('admin' => false, 'action' => 'index'));
            }
            if ($sourceId == $targetId) {
                $this->Flash->error(__('An organisation cannot be merged into itself.'));
                $this->redirect(array('admin' => false, 'action' => 'index'));
            }
            $result = $this->Organisation->orgMerge($sourceId, $data, $this->Auth->user());
            if ($result) {
                $this->Flash->success(__('The organisation has been successfully merged.'));
                $this->redirect(array('admin' => false, 'action' => 'view', $result));
            } else {
                $this->Flash->error(__('There was an error while merging the organisations. To find out more about what went wrong, refer to the audit logs. If you would like to revert the changes, you can find a .sql file'));
            }
            $this->redirect(array('admin' => false, 'action' => 'index'));
        } elseif ($this->theme === 'Overmind') {
            $this->Organisation->addCountField('user_count', $this->Organisation->User, array('User.org_id = Organisation.id'));
            $orgs = $this->Organisation->find('all', array(
                'recursive' => -1,
                'fields' => array('id', 'name', 'uuid', 'local', 'user_count'),
                'order' => 'lower(Organisation.name) ASC'
            ));
            $mergeOrgs = array();
            foreach ($orgs as $org) {
                $mergeOrgs[] = array(
                    'id' => (int)$org['Organisation']['id'],
                    'name' => $org['Organisation']['name'],
                    'uuid' => $org['Organisation']['uuid'],
                    'local' => !empty($org['Organisation']['local']),
                    'user_count' => (int)$org['Organisation']['user_count'],
                );
            }
            $this->set('mergeOrgs', $mergeOrgs);
            $this->set('mergeSourceId', $id ? (int)$id : null);
            $this->set('mergeTargetId', $target_id ? (int)$target_id : null);
            $this->layout = false;
            $this->autoRender = false;
            $this->render('ajax/merge');
        } else {
            if (empty($id)) {
                throw new NotFoundException(__('Invalid organisation.'));
            }
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
            // Only a genuine PHP upload may reach the filesystem probes below.
            // A forged tmp_name would otherwise leak file existence and image
            // type through the distinct validation messages that follow.
            if (empty($logo['tmp_name']) || !is_uploaded_file($logo['tmp_name'])) {
                return false;
            }
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
        $realBase = realpath($path);
        foreach (['id', 'name', 'uuid'] as $field) {
            foreach (['png', 'svg'] as $extension) {
                $candidate = realpath($path . $org['Organisation'][$field] . '.' . $extension);
                // realpath() resolves '..' and symlinks and returns false when the file does not
                // exist; the prefix check rejects anything that escapes the orgs directory. Without
                // it an attacker-controlled field such as the organisation name (e.g.
                // '../../../../AI-marketing') would allow path traversal to arbitrary png/svg files.
                if ($candidate !== false && $realBase !== false && str_starts_with($candidate, $realBase . DS)) {
                    $this->response->file($candidate, ['download' => false, 'name' => $org['Organisation']['id'] . '.' . $extension]);
                    // An SVG logo is a document, not a bitmap: sandbox it so
                    // whatever it carries cannot run here when opened directly.
                    $this->RestResponse->sandboxInlineFile($this->response, $extension);
                    return $this->response;
                }
            }
        }
        throw new NotFoundException(__('Organisation logo not found'));
    }
}
