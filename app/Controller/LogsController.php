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
        if ('search' === $this->request->params['action'] || 'index' === $this->request->params['action']) {
            $this->Security->csrfCheck = false;
            $this->Security->unlockedActions[] = $this->request->params['action'];
        }
    }

    public function index()
    {
        $paramArray = array('id', 'title', 'created', 'model', 'model_id', 'action', 'user_id', 'change', 'email', 'org', 'description', 'ip', 'search_token');
        $passedArgs = $this->passedArgs;
        if (isset($this->request->data['Log'])) {
            $this->request->data = $this->request->data['Log'];
        }
        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->request->params['named'],
            'paramArray' => $paramArray,
            'ordered_url_params' => func_get_args()
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        foreach ($filters as $k => $filter) {
            if ($filter === '') {
                unset($filters[$k]);
            }
        }
        unset($filterData);
        if (!$this->_isRest()) {
            if ($this->request->is('post') && empty($filters['search_token'])) {
                $search_token = $this->Log->setSearchParamsByToken($this->request->data);
                $this->set('search_token', $search_token);
            } else if (!empty($filters['search_token'])) {
                $filters = $this->Log->getSearchParamsByToken($filters);
                $this->set('search_token', $filters['search_token']);
            }
        }
        $filters = array_filter($filters, fn($value) => !empty($value));
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
                } else if ($filter !== 'limit' && $filter !== 'page'  && $filter !== 'search_token') {
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
            $this->paginate['conditions']['AND'][] = $conditions;
        } else {
            // users can see their own info
            $conditions['Log.user_id'] = $this->Auth->user('id');
            $this->paginate['conditions']['AND'][] = $conditions;
        }
        if (isset($this->params['named']['filter']) && in_array($this->params['named']['filter'], array_keys($validFilters))) {
            $this->paginate['conditions']['Log.action'] = $validFilters[$this->params['named']['filter']]['values'];
        }
        foreach ($filters as $key => $value) {
            if ($key == 'page' || $key == 'limit' || $key == 'search_token') { // These should not be part of the condition parameter
                continue;
            }
            if ($key === 'created') {
                $key = 'created >=';
            }
            if (in_array($key, $paramArray)) {
                $this->paginate['conditions']["Log.$key"] = $value;
            }
        }
        $this->set('validFilters', $validFilters);
        $this->set('filter', $filters);
        $this->set('data', $this->paginate());
        $this->set('paramArray', $paramArray);
        $this->set('passedArgsArray', $passedArgs);
        $this->set('menuData', ['menuList' => 'logs', 'menuItem' => 'index']);
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

    public function search()
    {
        $this->set('orgRestriction', $this->_isSiteAdmin() ? false : $this->Auth->user('Organisation')['name']);
        $models = $this->Log->searchModelList;
        sort($models);
        $models = array('' => 'ALL') + $this->_arrayToValuesIndexArray($models);
        $actions = array('' => 'ALL') + $this->_arrayToValuesIndexArray($this->Log->validate['action']['rule'][1]);
        $this->set('dropdownData', [
            'model' => $models,
            'actions' => $actions

        ]);
        $this->set('models', $models);
        $this->set('fieldDesc', [
            'email' => __('The e-mail address of the user that triggered the log entry.'),
            'org' => __('The organisation name of the user that triggered the log entry (at the time when the entry was added).'),
            'model' => __('The log entry\'s target object type. When a modification to a user is made, this would be "User".'),
            'model_id' => __('The log entry\'s target object ID. When a modification to a specific attribute is made, this would be the Attribute\'s local ID.'),
            'from' => __('Format is YYYY-MM-DD'),
            'to' => __('Format is YYYY-MM-DD')
        ]);
        $this->set('menuData', ['menuList' => 'logs', 'menuItem' => 'search']);
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
        if ($filters['action'] != 'ALL' && $filters['action'] !== null) {
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
        foreach (['from' => '>=', 'to' => '<='] as $keyword => $operator) {
            if (!empty($filters[$keyword])) {
                $date = $filters[$keyword];
                if (!empty($filters[$keyword . '_time'])) {
                    $date .= ' ' . $filters[$keyword . '_time'];
                } else {
                    $date .= ' ' . ($keyword == 'from' ? '00:00:00': '23:59:59');
                }
                $conditions['Log.created ' . $operator] = $date;
            }
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
