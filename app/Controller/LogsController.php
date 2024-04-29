<?php
App::uses('AppController', 'Controller');

/**
 * @property Log $Log
 */
class LogsController extends AppController
{
    public $components = array(
        'RequestHandler',
        'AdminCrud' => array(
            'crud' => array('index')
        )
    );

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'Log.id' => 'DESC'
        )
    );

    public function beforeFilter()
    {
        parent::beforeFilter();

        // No need for CSRF tokens for a search
        if ('admin_search' === $this->request->params['action']) {
            $this->Security->csrfCheck = false;
        }
    }

    public function index()
    {
        $paramArray = array('id', 'title', 'created', 'model', 'model_id', 'action', 'user_id', 'change', 'email', 'org', 'description', 'ip');
        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->request->params['named'],
            'paramArray' => $paramArray,
            'ordered_url_params' => func_get_args()
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        unset($filterData);

        if ($this->_isRest()) {
            if ($filters === false) {
                return $exception;
            }
            $conditions = array();
            foreach ($filters as $filter => $data) {
                if ($filter === 'created') {
                    $tempData = $data;
                    if (!is_array($data)) {
                        $tempData = array($data);
                    }
                    foreach ($tempData as $k => $v) {
                        $tempData[$k] = $this->Log->resolveTimeDelta($v);
                    }
                    if (count($tempData) == 1) {
                        $conditions['AND']['created >='] = date("Y-m-d H:i:s", $tempData[0]);
                    } else {
                        if ($tempData[0] < $tempData[1]) {
                            $temp = $tempData[1];
                            $tempData[1] = $tempData[0];
                            $tempData[0] = $temp;
                        }
                        $conditions['AND'][] = array('created <= ' => date("Y-m-d H:i:s", $tempData[0]));
                        $conditions['AND'][] = array('created >= ' => date("Y-m-d H:i:s", $tempData[1]));
                    }
                } else if ($filter !== 'limit' && $filter !== 'page') {
                    $data = array('OR' => $data);
                    $conditions = $this->Log->generic_add_filter($conditions, $data, 'Log.' . $filter);
                }
            }
            if (!$this->_isSiteAdmin()) {
                if ($this->_isAdmin()) {
                    // ORG admins can see their own org info
                    $orgRestriction = $this->Auth->user('Organisation')['name'];
                    $conditions['Log.org'] = $orgRestriction;
                } else {
                    // users can see their own info
                    $conditions['Log.user_id'] = $this->Auth->user('id');
                }
            }
            $params = array(
                'conditions' => $conditions,
                'recursive' => -1
            );
            if (isset($filters['limit'])) {
                $params['limit'] = $filters['limit'];
            }
            if (isset($filters['page'])) {
                $params['page'] = $filters['page'];
            }
            $log_entries = $this->Log->find('all', $params);
            return $this->RestResponse->viewData($log_entries, 'json');
        }

        $this->set('isSearch', 0);
        $this->recursive = 0;
        $validFilters = $this->Log->logMeta;
        if ($this->_isSiteAdmin()) {
            $validFilters = array_merge_recursive($validFilters, $this->Log->logMetaAdmin);
        }
        else if (!$this->_isSiteAdmin() && $this->_isAdmin()) {
            // ORG admins can see their own org info
            $orgRestriction = $this->Auth->user('Organisation')['name'];
            $conditions['Log.org'] = $orgRestriction;
            $this->paginate['conditions'] = $conditions;
        } else {
            // users can see their own info
            $conditions['Log.email'] = $this->Auth->user('email');
            $this->paginate['conditions'] = $conditions;
        }
        if (isset($this->params['named']['filter']) && in_array($this->params['named']['filter'], array_keys($validFilters))) {
            $this->paginate['conditions']['Log.action'] = $validFilters[$this->params['named']['filter']]['values'];
        }
        foreach ($filters as $key => $value) {
            if ($key == 'page' || $key == 'limit') { // These should not be part of the condition parameter
                continue;
            }
            if ($key === 'created') {
                $key = 'created >=';
            }
            if ($key == 'page' || $key == 'limit') {
                continue;
            }
            $this->paginate['conditions']["Log.$key"] = $value;
        }
        $this->set('validFilters', $validFilters);
        $this->set('filter', isset($this->params['named']['filter']) ? $this->params['named']['filter'] : false);
        $this->set('list', $this->paginate());
    }

    public function admin_index()
    {
        $this->view = 'index';
        return $this->index();
    }

    // Shows a minimalistic history for the currently selected event
    public function event_index($id, $org = null)
    {
        $this->loadModel('Event');
        $event = $this->Event->fetchEvent($this->Auth->user(), array(
            'eventid' => $id,
            'sgReferenceOnly' => 1,
            'deleted' => [0, 1],
            'deleted_proposals' => 1,
            'noSightings' => true,
            'noEventReports' => true,
            'includeEventCorrelations' => false,
            'excludeGalaxy' => true,
        ));
        if (empty($event)) {
            throw new NotFoundException('Invalid event.');
        }
        $event = $event[0];
        $attribute_ids = array();
        $object_ids = array();
        $proposal_ids = array_column($event['ShadowAttribute'], 'id');
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $aa) {
                $attribute_ids[] = $aa['id'];
                if (!empty($aa['ShadowAttribute'])) {
                    foreach ($aa['ShadowAttribute'] as $sa) {
                        $proposal_ids[] = $sa['id'];
                    }
                }
            }
            unset($event['Attribute']);
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $ob) {
                foreach ($ob['Attribute'] as $aa) {
                    $attribute_ids[] = $aa['id'];
                    if (!empty($aa['ShadowAttribute'])) {
                        foreach ($aa['ShadowAttribute'] as $sa) {
                            $proposal_ids[] = $sa['id'];
                        }
                    }
                }
                $object_ids[] = $ob['id'];
            }
            unset($event['Object']);
        }
        $conditions = array();
        $conditions['OR'][] = array(
            'AND' => array(
                'model' => 'Event',
                'model_id' => $event['Event']['id']
            )
        );
        if (!empty($attribute_ids)) {
            $conditions['OR'][] = array(
                'AND' => array(
                    'model' => 'Attribute',
                    'model_id' => $attribute_ids
                )
            );
        }
        if (!empty($proposal_ids)) {
            $conditions['OR'][] = array(
                'AND' => array(
                    'model' => 'ShadowAttribute',
                    'model_id' => $proposal_ids
                )
            );
        }
        if (!empty($object_ids)) {
            $conditions['OR'][] = array(
                'AND' => array(
                    'model' => 'MispObject',
                    'model_id' => $object_ids
                )
            );
        }

        if ($org) {
            $conditions['org'] = $org;
        }

        $this->paginate['fields'] = array('title', 'created', 'model', 'model_id', 'action', 'change', 'org', 'email');
        $this->paginate['conditions'] = $conditions;

        $list = $this->paginate();
        if (!$this->_isSiteAdmin()) {
            $this->loadModel('User');
            $orgEmails = $this->User->find('column', array(
                'conditions' => array('User.org_id' => $this->Auth->user('org_id')),
                'fields' => array('User.email')
            ));
            foreach ($list as $k => $item) {
                if (!in_array($item['Log']['email'], $orgEmails, true)) {
                    $list[$k]['Log']['email'] = '';
                }
            }
        }
        if ($this->_isRest()) {
            $list = array('Log' => array_column($list, 'Log'));
            return $this->RestResponse->viewData($list, $this->response->type());
        }

        // send unauthorised people away. Only site admins and users of the same org may see events that are "your org only". Everyone else can proceed for all other levels of distribution
        $mineOrAdmin = true;
        if (!$this->_isSiteAdmin() && $event['Event']['org_id'] != $this->Auth->user('org_id')) {
            $mineOrAdmin = false;
        }

        $mayModify = false;
        if ($mineOrAdmin && $this->userRole['perm_modify']) {
            $mayModify = true;
        }

        $this->set('published', $event['Event']['published']);
        $this->set('event', $event);
        $this->set('list', $list);
        $this->set('eventId', $id);
        $this->set('mayModify', $mayModify);
    }

    public function admin_search($new = false)
    {
        $orgRestriction = null;
        if ($this->_isSiteAdmin()) {
            $orgRestriction = false;
        } else {
            $orgRestriction = $this->Auth->user('Organisation')['name'];
        }
        $this->set('orgRestriction', $orgRestriction);
        $validFilters = $this->Log->logMeta;
        if ($this->_isSiteAdmin()) {
            $validFilters = array_merge_recursive($validFilters, $this->Log->logMetaAdmin);
        }
        $this->set('validFilters', $validFilters);
        $this->set('filters', false);
        if ($new !== false) {
            $this->set('actionDefinitions', $this->{$this->defaultModel}->actionDefinitions);

            // reset the paginate_conditions
            //$this->Session->write('paginate_conditions_log', array());
            if ($this->request->is('post')) {
                $filters['email'] = $this->request->data['Log']['email'];
                if (!$orgRestriction) {
                    $filters['org'] = $this->request->data['Log']['org'];
                } else {
                    $filters['org'] = $this->Auth->user('Organisation')['name'];
                }
                $filters['action'] = $this->request->data['Log']['action'];
                $filters['model'] = $this->request->data['Log']['model'];
                $filters['model_id'] = $this->request->data['Log']['model_id'];
                $filters['title'] = $this->request->data['Log']['title'];
                if (!empty ($this->request->data['Log']['from'])) {
                    $filters['from'] = $this->request->data['Log']['from'];
                }
                if (!empty ($this->request->data['Log']['to'])) {
                    $filters['to'] = $this->request->data['Log']['to'];
                }
                $filters['change'] = $this->request->data['Log']['change'];
                if (Configure::read('MISP.log_client_ip')) {
                    $filters['ip'] = $this->request->data['Log']['ip'];
                }

                // for info on what was searched for
                $this->set('emailSearch', $filters['email']);
                $this->set('orgSearch', $filters['org']);
                $this->set('actionSearch', $filters['action']);
                $this->set('modelSearch', $filters['model']);
                $this->set('model_idSearch', $filters['model_id']);
                $this->set('titleSearch', $filters['title']);
                $this->set('fromSearch', $filters['from'] ?? null);
                $this->set('toSearch', $filters['to'] ?? null);
                $this->set('changeSearch', $filters['change']);
                if (Configure::read('MISP.log_client_ip')) {
                    $this->set('ipSearch', $filters['ip']);
                }
                $this->set('isSearch', 1);

                // search the db
                $conditions = $this->__buildSearchConditions($filters);
                $this->{$this->defaultModel}->recursive = 0;
                $this->paginate = array(
                    'limit' => 60,
                    'conditions' => $conditions,
                    'order' => array('Log.id' => 'DESC')
                );
                $list = $this->paginate();
                if (empty($this->Auth->user('Role')['perm_site_admin'])) {
                    $list = $this->Log->filterSiteAdminSensitiveLogs($list);
                }
                $this->set('list', $list);

                if ($this->_isRest()) {
                    return $this->RestResponse->viewData($list, $this->response->type());
                } else {
                    // and store into session
                    $this->Session->write('paginate_conditions_log', $this->paginate);
                    $this->Session->write('paginate_conditions_log_email', $filters['email']);
                    $this->Session->write('paginate_conditions_log_org', $filters['org']);
                    $this->Session->write('paginate_conditions_log_action', $filters['action']);
                    $this->Session->write('paginate_conditions_log_model', $filters['model']);
                    $this->Session->write('paginate_conditions_log_model_id', $filters['model_id']);
                    $this->Session->write('paginate_conditions_log_title', $filters['title']);
                    $this->Session->write('paginate_conditions_log_change', $filters['change']);
                    $this->Session->write('paginate_conditions_log_from', $filters['from'] ?? null);
                    $this->Session->write('paginate_conditions_log_to', $filters['to'] ?? null);
                    if (Configure::read('MISP.log_client_ip')) {
                        $this->Session->write('paginate_conditions_log_ip', $filters['ip']);
                    }
                    // set the same view as the index page
                    $this->render('index');
                }
            } else {
                // get from Session
                $filters['email'] = $this->Session->read('paginate_conditions_log_email');
                $filters['org'] = $this->Session->read('paginate_conditions_log_org');
                $filters['action'] = $this->Session->read('paginate_conditions_log_action');
                $filters['model'] = $this->Session->read('paginate_conditions_log_model');
                $filters['model_id'] = $this->Session->read('paginate_conditions_log_model_id');
                $filters['title'] = $this->Session->read('paginate_conditions_log_title');
                $filters['change'] = $this->Session->read('paginate_conditions_log_change');
                $filters['from'] = $this->Session->read('paginate_conditions_log_from') ?? null;
                $filters['to'] = $this->Session->read('paginate_conditions_log_to') ?? null;
                if (Configure::read('MISP.log_client_ip')) {
                    $filters['ip'] = $this->Session->read('paginate_conditions_log_ip');
                }
                // for info on what was searched for
                $this->set('emailSearch', $filters['email']);
                $this->set('orgSearch', $filters['org']);
                $this->set('actionSearch', $filters['action']);
                $this->set('modelSearch', $filters['model']);
                $this->set('model_idSearch', $filters['model_id']);
                $this->set('titleSearch', $filters['title']);
                $this->set('changeSearch', $filters['change']);
                $this->set('changeSearch', $filters['from'] ?? null);
                $this->set('changeSearch', $filters['to'] ?? null);
                if (Configure::read('MISP.log_client_ip')) {
                    $this->set('ipSearch', $filters['ip']);
                }
                $this->set('isSearch', 1);

                // re-get pagination
                $this->{$this->defaultModel}->recursive = 0;
                $this->paginate = array_replace_recursive($this->paginate, $this->Session->read('paginate_conditions_log'));
                if (!isset($this->paginate['order'])) {
                    $this->paginate['order'] = array('Log.id' => 'DESC');
                }
                $conditions = $this->__buildSearchConditions($filters);
                $this->paginate['conditions'] = $conditions;
                $list = $this->paginate();
                if (empty($this->Auth->user('Role')['perm_site_admin'])) {
                    $list = $this->Log->filterSiteAdminSensitiveLogs($list);
                }
                $this->set('list', $list);

                // set the same view as the index page
                $this->render('index');
            }
        } else {
            // no search keyword is given, show the search form

            // combobox for actions
            $actions = array('' => array('ALL' => 'ALL'), 'actions' => array());
            $actions['actions'] = array_merge($actions['actions'], $this->_arrayToValuesIndexArray($this->{$this->defaultModel}->validate['action']['rule'][1]));
            $this->set('actions', $actions);

            // combobox for models
            $models = [
                'Attribute',
                'Allowedlist',
                'AuthKey',
                'Event',
                'EventBlocklist',
                'EventTag',
                'Feed',
                'DecayingModel',
                'EventGraph',
                'EventReport',
                'MispObject',
                'Organisation',
                'Post',
                'Regexp',
                'Role',
                'Server',
                'ShadowAttribute',
                'SharingGroup',
                'Tag',
                'Task',
                'Taxonomy',
                'Template',
                'Thread',
                'User',
                'Galaxy',
                'GalaxyCluster',
                'GalaxyClusterRelation',
                'Workflow',
            ];
            sort($models);
            $models = array('' => 'ALL') + $this->_arrayToValuesIndexArray($models);
            $this->set('models', $models);
            $this->set('actionDefinitions', $this->{$this->defaultModel}->actionDefinitions);
        }
    }

    private function __buildSearchConditions($filters)
    {
        $conditions = array();
        if (isset($filters['email']) && !empty($filters['email'])) {
            $conditions['LOWER(Log.email) LIKE'] = '%' . strtolower($filters['email']) . '%';
        }
        if (isset($filters['org']) && !empty($filters['org'])) {
            $conditions['LOWER(Log.org) LIKE'] = '%' . strtolower($filters['org']) . '%';
        }
        if ($filters['action'] != 'ALL') {
            $conditions['Log.action'] = $filters['action'];
        }
        if ($filters['model'] != '') {
            $conditions['Log.model'] = $filters['model'];
        }
        if ($filters['model_id'] != '') {
            $conditions['Log.model_id'] = $filters['model_id'];
        }
        if (isset($filters['title']) && !empty($filters['title'])) {
            $conditions['LOWER(Log.title) LIKE'] = '%' . strtolower($filters['title']) . '%';
        }
        if (isset($filters['change']) && !empty($filters['change'])) {
            $conditions['LOWER(Log.change) LIKE'] = '%' . strtolower($filters['change']) . '%';
        }
        if (isset($filters['from']) && !empty($filters['from'])) {
            $conditions['Log.created >='] = $filters['from'];
        }
        if (isset($filters['to']) && !empty($filters['to'])) {
            $conditions['Log.created <='] = $filters['to'];
        }
        if (Configure::read('MISP.log_client_ip') && isset($filters['ip']) && !empty($filters['ip'])) {
            $conditions['Log.ip LIKE'] = '%' . $filters['ip'] . '%';
        }
        return $conditions;
    }

    public function returnDates($org = 'all')
    {
        if (!$this->Auth->user('Role')['perm_sharing_group'] && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            if ($org !== 'all' && $org !== $this->Auth->user('Organisation')['name']) {
                throw new MethodNotAllowedException('Invalid organisation.');
            }
        }
        $data = $this->Log->returnDates($org);
        $this->set('data', $data);
        $this->set('_serialize', 'data');
    }

    public function pruneUpdateLogs()
    {
        if (!$this->request->is('post')) {
            //throw new MethodNotAllowedException('This functionality is only accessible via POST requests');
        }
        $this->Log->pruneUpdateLogsRouter($this->Auth->user());
        if (Configure::read('MISP.background_jobs')) {
            $this->Flash->success('The pruning job is queued.');
        } else {
            $this->Flash->success('The pruning is complete.');
        }
        $this->redirect($this->referer());
    }

    public function testForStolenAttributes()
    {
        $logs = $this->Log->find('list', array(
            'recursive' => -1,
            'conditions' => array(
                'Log.model' => 'Attribute',
                'Log.action' => 'edit'
            ),
            'fields' => array('Log.title')
        ));
        $ids = array();
        foreach ($logs as $log) {
            preg_match('/Attribute \(([0-9]+?)\)/', $log, $attribute_id);
            preg_match('/Event \(([0-9]+?)\)/', $log, $event_id);
            if (!isset($attribute_id[1])) {
                continue;
            }
            if (empty($ids[$attribute_id[1]]) || !in_array($event_id[1], $ids[$attribute_id[1]])) {
                $ids[$attribute_id[1]][] = $event_id[1];
            }
        }
        $issues = array();
        foreach ($ids as $aid => $eids) {
            if (count($eids) > 1) {
                $issues[$aid] = $eids;
            }
        }
        $this->set('issues', $issues);
    }
}
