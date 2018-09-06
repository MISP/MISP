<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

class FeedsController extends AppController
{
    public $components = array('Security' ,'RequestHandler');	// XXX ACL component

    public $paginate = array(
            'limit' => 60,
            'recursive' => -1,
            'contain' => array('Tag', 'SharingGroup'),
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
            'order' => array(
                    'Feed.default' => 'DESC',
                    'Feed.id' => 'ASC'
            ),
    );

    public $uses = array('Feed');

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions = array('previewIndex');
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('You don\'t have the required privileges to do that.'));
        }
    }

    public function index()
    {
        $this->Feed->load_default_feeds();
        $scope = isset($this->passedArgs['scope']) ? $this->passedArgs['scope'] : 'all';
        if ($scope !== 'all') {
            if ($scope == 'enabled') {
                $this->paginate['conditions'][] = array(
                    'OR' => array(
                        'Feed.enabled' => 1,
                        'Feed.caching_enabled' => 1
                    )
                );
            } else {
                $this->paginate['conditions'][] = array(
                    'Feed.default' => $scope == 'custom' ? 0 : 1
                );
            }
        }
        $data = $this->paginate();
        $this->loadModel('Event');
        foreach ($data as $key => $value) {
            if ($value['Feed']['event_id'] != 0 && $value['Feed']['fixed_event']) {
                $event = $this->Event->find('first', array('conditions' => array('Event.id' => $value['Feed']['event_id']), 'recursive' => -1, 'fields' => array('Event.id')));
                if (empty($event)) {
                    $data[$key]['Feed']['event_error'] = true;
                }
            }
        }
        if ($this->_isSiteAdmin()) {
            $data = $this->Feed->attachFeedCacheTimestamps($data);
        }
        if ($this->_isRest()) {
            foreach ($data as $k => $v) {
                unset($data[$k]['SharingGroup']);
                if (empty($data[$k]['Tag']['id'])) {
                    unset($data[$k]['Tag']);
                }
            }
            return $this->RestResponse->viewData($data, $this->response->type());
        }
        $this->set('scope', $scope);
        $this->set('feeds', $data);
        $this->loadModel('Event');
        $this->set('feed_types', $this->Feed->feed_types);
        $this->set('distributionLevels', $this->Event->distributionLevels);
    }

    public function view($feedId)
    {
        $feed = $this->Feed->find('first', array(
            'conditions' => array('Feed.id' => $feedId),
            'recursive' => -1,
            'contain' => array('Tag')
        ));
        if ($this->_isRest()) {
            if (empty($feed['Tag']['id'])) {
                unset($feed['Tag']);
            }
            return $this->RestResponse->viewData($feed, $this->response->type());
        }
    }

    public function importFeeds()
    {
        if ($this->request->is('post')) {
            $results = $this->Feed->importFeeds($this->request->data['Feed']['json'], $this->Auth->user());
            if ($results['successes'] > 0) {
                $flashType = 'success';
                $message = $results['successes'] . ' new feeds added.';
            } else {
                $flashType = 'info';
                $message = 'No new feeds to add.';
            }
            if ($results['fails']) {
                $message .= ' ' . $results['fails'] . ' feeds could not be added (possibly because they already exist)';
            }
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Feed', 'importFeeds', false, $this->response->type(), $message);
            } else {
                $this->Flash->{$flashType}($message);
                $this->redirect(array('controller' => 'Feeds', 'action' => 'index', 'all'));
            }
        }
    }

    public function add()
    {
        $this->loadModel('Event');
        $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $distributionLevels = $this->Event->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        $this->set('sharingGroups', $sgs);
        $this->set('feed_types', $this->Feed->getFeedTypesOptions());
        $tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
        $tags[0] = 'None';
        $this->set('tags', $tags);
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (empty($this->request->data['Feed'])) {
                    $this->request->data['Feed'] = $this->request->data;
                    if (empty($this->request->data['Feed']['source_format'])) {
                        $this->request->data['Feed']['source_format'] = 'freetext';
                    }
                    if (empty($this->request->data['Feed']['fixed_event'])) {
                        $this->request->data['Feed']['source_format'] = 1;
                    }
                }
            }
            $error = false;
            if (isset($this->request->data['Feed']['pull_rules'])) {
                $this->request->data['Feed']['rules'] = $this->request->data['Feed']['pull_rules'];
            }
            if (!isset($this->request->data['Feed']['distribution'])) {
                $this->request->data['Feed']['distribution'] = 0;
            }
            if ($this->request->data['Feed']['distribution'] != 4) {
                $this->request->data['Feed']['sharing_group_id'] = 0;
            }
            $this->request->data['Feed']['default'] = 0;
            if ($this->request->data['Feed']['source_format'] == 'freetext') {
                if ($this->request->data['Feed']['fixed_event'] == 1) {
                    if (!empty($this->request->data['Feed']['target_event']) && is_numeric($this->request->data['Feed']['target_event'])) {
                        $this->request->data['Feed']['event_id'] = $this->request->data['Feed']['target_event'];
                    }
                }
            }
            if (!isset($this->request->data['Feed']['settings'])) {
                $this->request->data['Feed']['settings'] = array();
            } else {
                if (!empty($this->request->data['Feed']['settings']['common']['excluderegex']) && !$this->__checkRegex($this->request->data['Feed']['settings']['common']['excluderegex'])) {
                    $this->Flash->error('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                    return true;
                }
            }
            if (isset($this->request->data['Feed']['settings']['delimiter']) && empty($this->request->data['Feed']['settings']['delimiter'])) {
                $this->request->data['Feed']['settings']['delimiter'] = ',';
            }
            if (empty($this->request->data['Feed']['target_event'])) {
                $this->request->data['Feed']['target_event'] = 0;
            }
            if (empty($this->request->data['Feed']['lookup_visible'])) {
                $this->request->data['Feed']['lookup_visible'] = 0;
            }
            if (empty($this->request->data['Feed']['input_source'])) {
                $this->request->data['Feed']['input_source'] = 'network';
            } else {
                $this->request->data['Feed']['input_source'] = strtolower($this->request->data['Feed']['input_source']);
            }
            if (!in_array($this->request->data['Feed']['input_source'], array('network', 'local'))) {
                $this->request->data['Feed']['input_source'] = 'network';
            }
            if (!isset($this->request->data['Feed']['delete_local_file'])) {
                $this->request->data['Feed']['delete_local_file'] = 0;
            }
            $this->request->data['Feed']['settings'] = json_encode($this->request->data['Feed']['settings']);
            $this->request->data['Feed']['event_id'] = !empty($this->request->data['Feed']['fixed_event']) ? $this->request->data['Feed']['target_event'] : 0;
            if (!$error) {
                $result = $this->Feed->save($this->request->data);
                if ($result) {
                    $message = __('Feed added.');
                    if ($this->_isRest()) {
                        $feed = $this->Feed->find('first', array('conditions' => array('Feed.id' => $this->Feed->id), 'recursive' => -1));
                        return $this->RestResponse->viewData($feed, $this->response->type());
                    }
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
                } else {
                    $message = __('Feed could not be added. Invalid field: %s', array_keys($this->Feed->validationErrors)[0]);
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Feeds', 'add', false, $message, $this->response->type());
                    }
                    $this->Flash->error($message);
                    $this->request->data['Feed']['settings'] = json_decode($this->request->data['Feed']['settings'], true);
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Feeds', 'add', false, $this->response->type());
        }
    }

    private function __checkRegex($pattern)
    {
        if (@preg_match($pattern, null) === false) {
            return false;
        }
        return true;
    }

    public function edit($feedId)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        $this->loadModel('Event');
        $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $distributionLevels = $this->Event->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        $this->set('sharingGroups', $sgs);
        $tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
        $tags[0] = 'None';
        $this->set('feed_types', $this->Feed->getFeedTypesOptions());
        $this->set('tags', $tags);
        if (!empty($this->Feed->data['Feed']['settings'])) {
            $this->Feed->data['Feed']['settings'] = json_decode($this->Feed->data['Feed']['settings'], true);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->_isRest()) {
                if (empty($this->request->data['Feed'])) {
                    $this->request->data['Feed'] = $this->request->data;
                }
            }
            if (isset($this->request->data['Feed']['pull_rules'])) {
                $this->request->data['Feed']['rules'] = $this->request->data['Feed']['pull_rules'];
            }
            if (isset($this->request->data['Feed']['distribution']) && $this->request->data['Feed']['distribution'] != 4) {
                $this->request->data['Feed']['sharing_group_id'] = 0;
            }
            $this->request->data['Feed']['id'] = $feedId;
            if (!empty($this->request->data['Feed']['source_format']) && ($this->request->data['Feed']['source_format'] == 'freetext' || $this->request->data['Feed']['source_format'] == 'csv')) {
                if ($this->request->data['Feed']['fixed_event'] == 1) {
                    if (isset($this->request->data['Feed']['target_event']) && is_numeric($this->request->data['Feed']['target_event'])) {
                        $this->request->data['Feed']['event_id'] = $this->request->data['Feed']['target_event'];
                    } else {
                        $this->request->data['Feed']['event_id'] = 0;
                    }
                }
            }
            if (!isset($this->request->data['Feed']['settings'])) {
                $this->request->data['Feed']['settings'] = array();
            } else {
                if (!empty($this->request->data['Feed']['settings']['common']['excluderegex']) && !$this->__checkRegex($this->request->data['Feed']['settings']['common']['excluderegex'])) {
                    $this->Flash->error('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                    return true;
                }
            }
            if (isset($this->request->data['Feed']['settings']['delimiter']) && empty($this->request->data['Feed']['settings']['delimiter'])) {
                $this->request->data['Feed']['settings']['delimiter'] = ',';
            }
            $this->request->data['Feed']['settings'] = json_encode($this->request->data['Feed']['settings']);
            $fields = array('id', 'name', 'provider', 'enabled', 'caching_enabled','rules', 'url', 'distribution', 'sharing_group_id', 'tag_id', 'fixed_event', 'event_id', 'publish', 'delta_merge', 'source_format', 'override_ids', 'settings', 'input_source', 'delete_local_file', 'lookup_visible', 'headers');
            $feed = array();
            foreach ($fields as $field) {
                if (isset($this->request->data['Feed'][$field])) {
                    $feed[$field] = $this->request->data['Feed'][$field];
                }
            }
            $result = $this->Feed->save($feed);
            if ($result) {
                $feedCache = APP . 'tmp' . DS . 'cache' . DS . 'misp_feed_' . intval($feedId) . '.cache';
                if (file_exists($feedCache)) {
                    unlink($feedCache);
                }
                $message = __('Feed added.');
                if ($this->_isRest()) {
                    $feed = $this->Feed->find('first', array('conditions' => array('Feed.id' => $this->Feed->id), 'recursive' => -1));
                    return $this->RestResponse->viewData($feed, $this->response->type());
                }
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
            } else {
                $message = __('Feed could not be updated. Invalid fields: %s', implode(', ', array_keys($this->Feed->validationErrors)));
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Feeds', 'add', false, $message, $this->response->type());
                }
                $this->Flash->error($message);
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Feeds', 'edit', false, $this->response->type());
            }
            if (!isset($this->request->data['Feed'])) {
                $this->request->data = $this->Feed->data;
                if ($this->Feed->data['Feed']['event_id']) {
                    $this->request->data['Feed']['target_event'] = $this->Feed->data['Feed']['event_id'];
                }
            }
            $this->request->data['Feed']['pull_rules'] = $this->request->data['Feed']['rules'];
        }
    }

    public function delete($feedId)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This action requires a post request.'));
        }
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        if ($this->Feed->delete($feedId)) {
            $message = 'Feed deleted.';
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Feeds', 'delete', $feedId, false, $message);
            }
            $this->Flash->success($message);
        } else {
            $message = 'Feed could not be deleted.';
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Feeds', 'delete', false, $message, $this->response->type());
            }
            $this->Flash->error($message);
        }
        $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
    }

    public function fetchFromFeed($feedId)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        if (!empty($this->Feed->data['Feed']['settings'])) {
            $this->Feed->data['Feed']['settings'] = json_decode($this->Feed->data['Feed']['settings'], true);
        }
        if (!$this->Feed->data['Feed']['enabled']) {
            $this->Flash->info(__('Feed is currently not enabled. Make sure you enable it.'));
            $this->redirect(array('action' => 'index'));
        }
        if (Configure::read('MISP.background_jobs')) {
            $this->loadModel('Job');
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'fetch_feeds',
                    'job_input' => 'Feed: ' . $feedId,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $this->Auth->user('Organisation')['name'],
                    'message' => __('Starting fetch from Feed.'),
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
            $process_id = CakeResque::enqueue(
                    'default',
                    'ServerShell',
                    array('fetchFeed', $this->Auth->user('id'), $feedId, $jobId),
                    true
            );
            $this->Job->saveField('process_id', $process_id);
            $message = __('Pull queued for background execution.');
        } else {
            $result = $this->Feed->downloadFromFeedInitiator($feedId, $this->Auth->user());
            if (!$result) {
                if ($this->_isRest()) {
                    return $this->RestResponse->viewData(array('result' => __('Fetching the feed has failed.')), $this->response->type());
                } else {
                    $this->Flash->error(__('Fetching the feed has failed.'));
                    $this->redirect(array('action' => 'index'));
                }
            }
            $message = __('Fetching the feed has successfuly completed.');
            if ($this->Feed->data['Feed']['source_format'] == 'misp') {
                if (isset($result['add'])) {
                    $message['result'] .= ' Downloaded ' . count($result['add']) . ' new event(s).';
                }
                if (isset($result['edit'])) {
                    $message['result'] .= ' Updated ' . count($result['edit']) . ' event(s).';
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('result' => $message), $this->response->type());
        } else {
            $this->Flash->success($message);
            $this->redirect(array('action' => 'index'));
        }
    }

    public function fetchFromAllFeeds()
    {
        $feeds = $this->Feed->find('all', array(
            'recursive' => -1,
            'fields' => array('id')
        ));
        foreach ($feeds as $feed) {
            $feedId = $feed['Feed']['id'];
            $this->Feed->id = $feedId;
            $this->Feed->read();
            if (!empty($this->Feed->data['Feed']['settings'])) {
                $this->Feed->data['Feed']['settings'] = json_decode($this->Feed->data['Feed']['settings'], true);
            }
            if (!$this->Feed->data['Feed']['enabled']) {
                continue;
            }
            if (Configure::read('MISP.background_jobs')) {
                $this->loadModel('Job');
                $this->Job->create();
                $data = array(
                    'worker' => 'default',
                    'job_type' => 'fetch_feed',
                    'job_input' => 'Feed: ' . $feedId,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $this->Auth->user('Organisation')['name'],
                    'message' => __('Starting fetch from Feed.'),
                );
                $this->Job->save($data);
                $jobId = $this->Job->id;
                $process_id = CakeResque::enqueue(
                    'default',
                    'ServerShell',
                    array('fetchFeed', $this->Auth->user('id'), $feedId, $jobId),
                    true
                );
                $this->Job->saveField('process_id', $process_id);
                $message = 'Pull queued for background execution.';
            } else {
                $result = $this->Feed->downloadFromFeedInitiator($feedId, $this->Auth->user());
                if (!$result) {
                    continue;
                }
                $message = __('Fetching the feed has successfully completed.');
                if ($this->Feed->data['Feed']['source_format'] == 'misp') {
                    if (isset($result['add'])) {
                        $message['result'] .= ' Downloaded ' . count($result['add']) . ' new event(s).';
                    }
                    if (isset($result['edit'])) {
                        $message['result'] .= ' Updated ' . count($result['edit']) . ' event(s).';
                    }
                }
            }
        }
        $this->Flash->success($message);
        $this->redirect(array('action' => 'index'));
    }

    public function getEvent($feedId, $eventUuid, $all = false)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        if (!$this->Feed->data['Feed']['enabled']) {
            $this->Flash->info(__('Feed is currently not enabled. Make sure you enable it.'));
            $this->redirect(array('action' => 'previewIndex', $feedId));
        }
        $result = $this->Feed->downloadAndSaveEventFromFeed($this->Feed->data, $eventUuid, $this->Auth->user());
        if (isset($result['action'])) {
            if ($result['result']) {
                if ($result['action'] == 'add') {
                    $this->Flash->success(__('Event added.'));
                } else {
                    if ($result['result'] === 'No change') {
                        $this->Flash->info(__('Event already up to date.'));
                    } else {
                        $this->Flash->success(__('Event updated.'));
                    }
                }
            } else {
                $this->Flash->error(__('Could not %s event.', $result['action']));
            }
        } else {
            $this->Flash->error(__('Download failed.'));
        }
        $this->redirect(array('action' => 'previewIndex', $feedId));
    }

    public function previewIndex($feedId)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        if (!empty($this->Feed->data['Feed']['settings'])) {
            $this->Feed->data['Feed']['settings'] = json_decode($this->Feed->data['Feed']['settings'], true);
        }
        $params = array();
        if ($this->request->is('post')) {
            $params = $this->request->data['Feed'];
        }
        if ($this->Feed->data['Feed']['source_format'] == 'misp') {
            return $this->__previewIndex($this->Feed->data, $params);
        } elseif (in_array($this->Feed->data['Feed']['source_format'], array('freetext', 'csv'))) {
            return $this->__previewFreetext($this->Feed->data);
        }
    }

    private function __previewIndex($feed, $filterParams = array())
    {
        if (isset($this->passedArgs['pages'])) {
            $currentPage = $this->passedArgs['pages'];
        } else {
            $currentPage = 1;
        }
        $urlparams = '';
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $passedArgs = array();
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocketFeed($feed);
        $events = $this->Feed->getManifest($feed, $HttpSocket);
        if (!is_array($events)) {
            $this->Flash->info($events);
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }
        foreach ($filterParams as $k => $filter) {
            if (!empty($filter)) {
                $filterParams[$k] = json_decode($filter);
            }
        }
        if (!empty($filterParams['eventid'])) {
            foreach ($events as $k => $event) {
                if (!in_array($k, $filterParams['eventid'])) {
                    unset($events[$k]);
                    continue;
                }
            }
        }
        $params = $customPagination->createPaginationRules($events, $this->passedArgs, $this->alias);
        $this->params->params['paging'] = array($this->modelClass => $params);
        $events = $customPagination->sortArray($events, $params, true);
        if (is_array($events)) {
            $customPagination->truncateByPagination($events, $params);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($events, $this->response->type());
        }
        if (isset($events['code'])) {
            throw new NotFoundException(__('Feed could not be fetched. The HTTP error code returned was: ', $events['code']));
        }
        $pageCount = count($events);
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        if ($this->_isRest()) {
            if (!isset($this->passedArgs['page'])) {
                $this->passedArgs['page'] = 0;
            }
        }
        $this->set('events', $events);
        $this->loadModel('Event');
        $threat_levels = $this->Event->ThreatLevel->find('all');
        $this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');
        $this->set('shortDist', $shortDist);
        $this->set('id', $feed['Feed']['id']);
        $this->set('feed', $feed);
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgs);
    }

    private function __previewFreetext($feed)
    {
        if (isset($this->passedArgs['page'])) {
            $currentPage = $this->passedArgs['page'];
        } elseif (isset($this->passedArgs['page'])) {
            $currentPage = $this->passedArgs['page'];
        } else {
            $currentPage = 1;
        }
        $urlparams = '';
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        if (!in_array($feed['Feed']['source_format'], array('freetext', 'csv'))) {
            throw new MethodNotAllowedException(__('Invalid feed type.'));
        }
        $HttpSocket = $syncTool->setupHttpSocketFeed($feed);
        $params = array();
        // params is passed as reference here, the pagination happens in the method, which isn't ideal but considering the performance gains here it's worth it
        $resultArray = $this->Feed->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format'], $currentPage, 60, $params);
        // we want false as a valid option for the split fetch, but we don't want it for the preview
        if (!is_array($resultArray)) {
            $this->Flash->info($resultArray);
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        $resultArray = $this->Feed->getFreetextFeedCorrelations($resultArray, $feed['Feed']['id']);
        // remove all duplicates
        $correlatingEvents = array();
        //debug($resultArray);
        foreach ($resultArray as $k => $v) {
            if (!empty($resultArray[$k]['correlations'])) {
                foreach ($resultArray[$k]['correlations'] as $correlatingEvent) {
                    if (!in_array($correlatingEvent, $correlatingEvents)) {
                        $correlatingEvents[] = $correlatingEvent;
                    }
                }
            }
        }
        $resultArray = array_values($resultArray);
        $this->loadModel('Attribute');
        $correlatingEventInfos = $this->Attribute->Event->find('list', array(
            'fields' => array('Event.id', 'Event.info'),
            'conditions' => array('Event.id' => $correlatingEvents)
        ));
        $this->set('correlatingEventInfos', $correlatingEventInfos);
        $this->set('distributionLevels', $this->Attribute->distributionLevels);
        $this->set('feed', $feed);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($resultArray, $this->response->type());
        }
        $this->set('attributes', $resultArray);
        $this->render('freetext_index');
    }

    private function __previewCSV($feed)
    {
        if (isset($this->passedArgs['pages'])) {
            $currentPage = $this->passedArgs['pages'];
        } else {
            $currentPage = 1;
        }
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        if ($feed['Feed']['source_format'] != 'csv') {
            throw new MethodNotAllowedException(__('Invalid feed type.'));
        }
        $HttpSocket = $syncTool->setupHttpSocketFeed($feed);
        $resultArray = $this->Feed->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format'], $currentPage);
        // we want false as a valid option for the split fetch, but we don't want it for the preview
        if ($resultArray == false) {
            $resultArray = array();
        }
        $resultArray = $this->Feed->getFreetextFeedCorrelations($resultArray, $feed['Feed']['id']);
        $resultArray = $this->Feed->getFreetextFeed2FeedCorrelations($resultArray);
        // remove all duplicates
        foreach ($resultArray as $k => $v) {
            for ($i = 0; $i < $k; $i++) {
                if (isset($resultArray[$i]) && $v == $resultArray[$i]) {
                    unset($resultArray[$k]);
                }
            }
        }
        $resultArray = array_values($resultArray);
        $this->loadModel('Attribute');
        $this->set('distributionLevels', $this->Attribute->distributionLevels);
        $this->set('feed', $feed);
        $this->set('attributes', $resultArray);
        $this->render('freetext_index');
    }


    public function previewEvent($feedId, $eventUuid, $all = false)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        $event = $this->Feed->downloadEventFromFeed($this->Feed->data, $eventUuid, $this->Auth->user());
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($event, $this->response->type());
        }
        if (is_array($event)) {
            $this->loadModel('Event');
            $params = $this->Event->rearrangeEventForView($event, $this->passedArgs, $all);
            $this->params->params['paging'] = array('Feed' => $params);
            $this->set('event', $event);
            $this->set('feed', $this->Feed->data);
            $this->loadModel('Event');
            $dataForView = array(
                    'Attribute' => array('attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels'),
                    'Event' => array('eventDescriptions' => 'fieldDescriptions', 'analysisLevels' => 'analysisLevels')
            );
            foreach ($dataForView as $m => $variables) {
                if ($m === 'Event') {
                    $currentModel = $this->Event;
                } elseif ($m === 'Attribute') {
                    $currentModel = $this->Event->Attribute;
                }
                foreach ($variables as $alias => $variable) {
                    $this->set($alias, $currentModel->{$variable});
                }
            }
            $threat_levels = $this->Event->ThreatLevel->find('all');
            $this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
        } else {
            if ($event === 'blocked') {
                throw new MethodNotAllowedException(__('This event is blocked by the Feed filters.'));
            } else {
                throw new NotFoundException(__('Could not download the selected Event'));
            }
        }
    }

    public function enable($id)
    {
        $result = $this->__toggleEnable($id, true);
        $this->set('name', $result['message']);
        $this->set('message', $result['message']);
        $this->set('url', $this->here);
        if ($result) {
            $this->set('_serialize', array('name', 'message', 'url'));
        } else {
            $this->set('errors', $result);
            $this->set('_serialize', array('name', 'message', 'url', 'errors'));
        }
    }

    public function disable($id)
    {
        $result = $this->__toggleEnable($id, false);
        $this->set('name', $result['message']);
        $this->set('message', $result['message']);
        $this->set('url', $this->here);
        if ($result['result']) {
            $this->set('_serialize', array('name', 'message', 'url'));
        } else {
            $this->set('errors', $result);
            $this->set('_serialize', array('name', 'message', 'url', 'errors'));
        }
    }

    private function __toggleEnable($id, $enable = true)
    {
        if (!is_numeric($id)) {
            throw new MethodNotAllowedException(__('Invalid Feed.'));
        }
        $this->Feed->id = $id;
        if (!$this->Feed->exists()) {
            throw new MethodNotAllowedException(__('Invalid Feed.'));
        }
        $feed = $this->Feed->find('first', array(
                'conditions' => array('Feed.id' => $id),
                'recursive' => -1
        ));
        $feed['Feed']['enabled'] = $enable;
        $result = array('result' => $this->Feed->save($feed));
        $fail = false;
        if (!$result['result']) {
            $fail = true;
            $result['result'] = $this->Feed->validationErrors;
        }
        $action = $enable ? 'enable' : 'disable';
        $result['message'] = $fail ? 'Could not ' . $action . ' feed.' : 'Feed ' . $action . 'd.';
        return $result;
    }

    public function fetchSelectedFromFreetextIndex($id)
    {
        if (!$this->request->is('Post')) {
            throw new MethodNotAllowedException(__('Only POST requests are allowed.'));
        }
        $this->Feed->id = $id;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Feed not found.'));
        }
        $feed = $this->Feed->read();
        if (!empty($feed['Feed']['settings'])) {
            $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
        }
        $data = json_decode($this->request->data['Feed']['data'], true);
        $result = $this->Feed->saveFreetextFeedData($feed, $data, $this->Auth->user());
        if ($result === true) {
            $this->Flash->success(__('Data pulled.'));
        } else {
            $this->Flash->error(__('Could not pull the selected data. Reason: %s', $result));
        }
        $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
    }

    public function cacheFeeds($scope = 'freetext')
    {
        if (Configure::read('MISP.background_jobs')) {
            $this->loadModel('Job');
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'cache_feeds',
                    'job_input' => $scope,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $this->Auth->user('Organisation')['name'],
                    'message' => __('Starting feed caching.'),
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
            $process_id = CakeResque::enqueue(
                    'default',
                    'ServerShell',
                    array('cacheFeed', $this->Auth->user('id'), $scope, $jobId),
                    true
            );
            $this->Job->saveField('process_id', $process_id);
            $message = 'Feed caching job initiated.';
        } else {
            $result = $this->Feed->cacheFeedInitiator($this->Auth->user(), false, $scope);
            if (!$result) {
                $this->Flash->error(__('Caching the feeds has failed.'));
                $this->redirect(array('action' => 'index'));
            }
            $message = __('Caching the feeds has successfully completed.');
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Feed', 'cacheFeed', false, $this->response->type(), $message);
        } else {
            $this->Flash->error($message);
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }
    }

    public function compareFeeds($id = false)
    {
        $feeds = $this->Feed->compareFeeds($id);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($feeds, $this->response->type());
        } else {
            $this->set('feeds', $feeds);
        }
    }

    public function toggleSelected($enable = false, $cache = false, $feedList = false)
    {
        $field = $cache ? 'caching_enabled' : 'enabled';
        if (!empty($enable)) {
            $enable = 1;
        } else {
            $enable = 0;
        }
        try {
            $feedIds = json_decode($feedList, true);
        } catch (Exception $e) {
            $this->Flash->error(__('Invalid feed list received.'));
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }
        if ($this->request->is('post')) {
            $feeds = $this->Feed->find('all', array(
                'conditions' => array('Feed.id' => $feedIds),
                'recursive' => -1
            ));
            $count = 0;
            foreach ($feeds as $feed) {
                if ($feed['Feed'][$field] != $enable) {
                    $feed['Feed'][$field] = $enable;
                    $this->Feed->save($feed);
                    $count++;
                }
            }
            if ($count > 0) {
                $this->Flash->success($count . ' feeds ' . array('disabled', 'enabled')[$enable] . '.');
                $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
            } else {
                $this->Flash->info('All selected feeds are already ' . array('disabled', 'enabled')[$enable] . ', nothing to update.');
                $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
            }
        } else {
            $this->set('feedList', $feedList);
            $this->set('enable', $enable);
            $this->render('ajax/feedToggleConfirmation');
        }
    }
}
