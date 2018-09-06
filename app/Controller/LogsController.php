<?php

App::uses('AppController', 'Controller');

class LogsController extends AppController
{
    public $components = array(
        'Security',
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

        // permit reuse of CSRF tokens on the search page.
        if ('admin_search' == $this->request->params['action']) {
            $this->Security->csrfUseOnce = false;
        }
    }

    public function admin_index()
    {
        if (!$this->userRole['perm_audit']) {
            $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
        }
        $this->set('isSearch', 0);
        $this->recursive = 0;
        $validFilters = $this->Log->logMeta;
        if (!$this->_isSiteAdmin()) {
            $orgRestriction = $this->Auth->user('Organisation')['name'];
            $conditions['Log.org'] = $orgRestriction;
            $this->paginate = array(
                    'limit' => 60,
                    'conditions' => $conditions,
                    'order' => array('Log.id' => 'DESC')
            );
        } else {
            $validFilters = array_merge_recursive($validFilters, $this->Log->logMetaAdmin);
        }
        if (isset($this->params['named']['filter']) && in_array($this->params['named']['filter'], array_keys($validFilters))) {
            $this->paginate['conditions']['Log.action'] = $validFilters[$this->params['named']['filter']]['values'];
        }
        $this->set('validFilters', $validFilters);
        $this->set('filter', isset($this->params['named']['filter']) ? $this->params['named']['filter'] : false);
        $this->set('list', $this->paginate());
    }

    // Shows a minimalistic history for the currently selected event
    public function event_index($id, $org = null)
    {
        // check if the user has access to this event...
        $mayModify = false;
        $mineOrAdmin = false;
        $this->loadModel('Event');
        if (!is_numeric($id) || $id < 1) {
            $id = -1;
        }
        $event = $this->Event->fetchEvent($this->Auth->user(), array(
            'eventid' => $id,
            'includeAllTags' => 1,
            'sgReferenceOnly' => 1,
        ));
        $conditions = array(
            'OR' => array(
                array(
                    'AND' => array(
                        'Log.model' => 'Event',
                        'Log.model_id' => $id
                    )
                )
            )
        );
        if (empty($event)) {
            throw new MethodNotFoundException('Invalid event.');
        }
        $event = $event[0];
        $attribute_ids = array();
        $object_ids = array();
        $proposal_ids = array();
        $event_tag_ids = array();
        $attribute_tag_ids = array();
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
        // send unauthorised people away. Only site admins and users of the same org may see events that are "your org only". Everyone else can proceed for all other levels of distribution
        $mineOrAdmin = true;
        if (!$this->_isSiteAdmin() && $event['Event']['org_id'] != $this->Auth->user('org_id')) {
            $mineOrAdmin = false;
        }
        $this->set('published', $event['Event']['published']);
        if ($mineOrAdmin && $this->userRole['perm_modify']) {
            $mayModify = true;
        }

        $fieldList = array('title', 'created', 'model', 'model_id', 'action', 'change', 'org', 'email');
        $this->paginate = array(
                'limit' => 60,
                'conditions' => $conditions,
                'order' => array('Log.id' => 'DESC'),
                'fields' => $fieldList
        );
        $list = $this->paginate();
        if (!$this->_isSiteAdmin()) {
            $this->loadModel('User');
            $emails = $this->User->find('list', array(
                    'conditions' => array('User.org_id' => $this->Auth->user('org_id')),
                    'fields' => array('User.id', 'User.email')
            ));
            foreach ($list as $k => $item) {
                if (!in_array($item['Log']['email'], $emails)) {
                    $list[$k]['Log']['email'] = '';
                }
            }
        }
        if ($this->_isRest()) {
            foreach ($list as $k => $item) {
                $list[$k] = $item['Log'];
            }
            $list = array('Log' => $list);
            return $this->RestResponse->viewData($list, $this->response->type());
        } else {
            $this->set('event', $event);
            $this->set('list', $list);
            $this->set('eventId', $id);
            $this->set('mayModify', $mayModify);
        }
    }

    public $helpers = array('Js' => array('Jquery'), 'Highlight');

    public function admin_search($new = false)
    {
        if (!$this->userRole['perm_audit']) {
            $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
        }
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
            $this->Session->write('paginate_conditions_log', array());
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
                $this->set('list', $this->paginate());

                // and store into session
                $this->Session->write('paginate_conditions_log', $this->paginate);
                $this->Session->write('paginate_conditions_log_email', $filters['email']);
                $this->Session->write('paginate_conditions_log_org', $filters['org']);
                $this->Session->write('paginate_conditions_log_action', $filters['action']);
                $this->Session->write('paginate_conditions_log_model', $filters['model']);
                $this->Session->write('paginate_conditions_log_model_id', $filters['model_id']);
                $this->Session->write('paginate_conditions_log_title', $filters['title']);
                $this->Session->write('paginate_conditions_log_change', $filters['change']);
                if (Configure::read('MISP.log_client_ip')) {
                    $this->Session->write('paginate_conditions_log_ip', $filters['ip']);
                }

                // set the same view as the index page
                $this->render('admin_index');
            } else {
                // get from Session
                $filters['email'] = $this->Session->read('paginate_conditions_log_email');
                $filters['org'] = $this->Session->read('paginate_conditions_log_org');
                $filters['action'] = $this->Session->read('paginate_conditions_log_action');
                $filters['model'] = $this->Session->read('paginate_conditions_log_model');
                $filters['model_id'] = $this->Session->read('paginate_conditions_log_model_id');
                $filters['title'] = $this->Session->read('paginate_conditions_log_title');
                $filters['change'] = $this->Session->read('paginate_conditions_log_change');
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
                if (Configure::read('MISP.log_client_ip')) {
                    $this->set('ipSearch', $filters['ip']);
                }
                $this->set('isSearch', 1);

                // re-get pagination
                $this->{$this->defaultModel}->recursive = 0;
                $this->paginate = $this->Session->read('paginate_conditions_log');
                if (!isset($this->paginate['order'])) {
                    $this->paginate['order'] = array('Log.id' => 'DESC');
                }
                $conditions = $this->__buildSearchConditions($filters);
                $this->paginate['conditions'] = $conditions;
                $this->set('list', $this->paginate());

                // set the same view as the index page
                $this->render('admin_index');
            }
        } else {
            // no search keyword is given, show the search form

            // combobox for actions
            $actions = array('' => array('ALL' => 'ALL'), 'actions' => array());
            $actions['actions'] = array_merge($actions['actions'], $this->_arrayToValuesIndexArray($this->{$this->defaultModel}->validate['action']['rule'][1]));
            $this->set('actions', $actions);

            // combobox for models
            $models = array('Attribute', 'Event', 'EventBlacklist', 'EventTag', 'MispObject', 'Organisation', 'Post', 'Regexp', 'Role', 'Server', 'ShadowAttribute', 'SharingGroup', 'Tag', 'Task', 'Taxonomy', 'Template', 'Thread', 'User', 'Whitelist');
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
