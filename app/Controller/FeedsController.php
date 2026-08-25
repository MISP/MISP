<?php
App::uses('AppController', 'Controller');

/**
 * @property Feed $Feed
 */
class FeedsController extends AppController
{
    public $components = array(
        'CRUD',
        'RequestHandler'
    );   // XXX ACL component

    public $paginate = array(
        'limit' => 60,
        'recursive' => -1,
        'contain' => array(
            'Tag',
            'SharingGroup',
            'Orgc' => array(
                'fields' => array(
                    'Orgc.id',
                    'Orgc.uuid',
                    'Orgc.name',
                    'Orgc.local'
                )
            )
        ),
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
        $this->Security->unlockedActions[] = 'previewIndex';
        $this->Security->unlockedActions[] = 'feedCoverage';
    }

    public function loadDefaultFeeds()
    {
        if ($this->request->is('post')) {
            $this->Feed->load_default_feeds();
            $message = __('Default feed metadata loaded.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Feed', 'loadDefaultFeeds', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'Feeds', 'action' => 'index'));
            }
        }
    }

    public function index()
    {
        $conditions = [];
        $scope = isset($this->passedArgs['scope']) ? $this->passedArgs['scope'] : 'all';
        if ($scope !== 'all') {
            if ($scope == 'enabled') {
                $conditions[] = array(
                    'OR' => array(
                        'Feed.enabled' => 1,
                        'Feed.caching_enabled' => 1
                    )
                );
            } else {
                $conditions[] = array(
                    'Feed.default' => $scope == 'custom' ? 0 : 1
                );
            }
        }
        $host_org_id = (int)Configure::read('MISP.host_org_id');
        if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') !== $host_org_id) {
            $conditions[] =  ['Feed.lookup_visible' => 1];
        }
        $loggedUser = $this->Auth->user();
        $this->loadModel('TagCollection');
        $this->CRUD->index([
            'filters' => [
                'Feed.name',
                'url',
                'provider',
                'source_format',
                'enabled',
                'caching_enabled',
                'default',
                'input_source',
                'distribution',
                'lookup_visible',
                'orgc_id'
            ],
            'quickFilters' => [
                'Feed.name',
                'url',
                'provider',
                'source_format'
            ],
            'conditions' => $conditions,
            'afterFind' => function (array $feeds) use ($loggedUser) {
                if ($this->_isSiteAdmin()) {
                    $feeds = $this->Feed->attachFeedCacheTimestamps($feeds);
                }
                if ($this->IndexFilter->isRest()) {
                    foreach ($feeds as &$feed) {
                        unset($feed['SharingGroup']);
                        if (empty($feed['Tag']['id'])) {
                            unset($feed['Tag']);
                        }
                    }
                }

                foreach ($feeds as &$feed) {
                    if (!empty($feed['Feed']['headers'])) {
                        $feed['Feed']['headers'] = '****';
                    }
                    if (!empty($feed['Feed']['tag_collection_id'])) {
                        $tagCollection = $this->TagCollection->fetchTagCollection($loggedUser, [
                            'conditions' => [
                                'TagCollection.id' => $feed['Feed']['tag_collection_id'],
                            ]
                        ]);
                        if (!empty($tagCollection)) {
                            $feed['TagCollection'] = $tagCollection;
                        }
                    }
                }

                return $feeds;
            }
        ]);

        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->set('title_for_layout', __('Feeds'));
        $this->set('menuData', [
            'menuList' => 'feeds',
            'menuItem' => 'index'
        ]);
        $this->loadModel('Event');
        $distributionLevels = $this->Event->distributionLevels;
        $distributionLevels[5] = __('Inherit from feed');
        $this->set('distributionLevels', $distributionLevels);
        $this->set('scope', $scope);

        $providers = $this->Feed->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => ['DISTINCT Feed.provider'],
            'order' => ['Feed.provider ASC'],
        ]);
        $providerOptions = [];
        foreach (Hash::extract($providers, '{n}.Feed.provider') as $provider) {
            if ($provider !== null && $provider !== '') {
                $providerOptions[$provider] = $provider;
            }
        }
        $this->set('providerOptions', $providerOptions);

        $feedOrgIds = $this->Feed->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => ['DISTINCT Feed.orgc_id'],
        ]);
        $orgOptions = [];
        $feedOrgIds = array_filter(Hash::extract($feedOrgIds, '{n}.Feed.orgc_id'));
        if (!empty($feedOrgIds)) {
            $orgOptions = $this->Feed->Orgc->find('list', [
                'conditions' => ['Orgc.id' => $feedOrgIds],
                'fields' => ['Orgc.id', 'Orgc.name'],
                'order' => ['Orgc.name' => 'ASC'],
                'recursive' => -1,
            ]);
        }
        $this->set('orgOptions', $orgOptions);

        $inputSources = ['network' => __('Network')];
        if (empty(Configure::read('Security.disable_local_feed_access'))) {
            $inputSources['local'] = __('Local');
        }
        $this->set('inputSourceOptions', $inputSources);
        $this->set('feedTypeOptions', $this->Feed->getFeedTypesOptions());
    }

    public function view($feedId)
    {
        $this->CRUD->view($feedId, [
            'contain' => ['Tag', 'SharingGroup', 'Orgc'],
            'afterFind' => function (array $feed) {
                if (!$this->_isSiteAdmin()) {
                    unset($feed['Feed']['headers']);
                }
                if (!empty($feed['Feed']['headers'])) {
                    $feed['Feed']['headers'] = '****';
                }
                $feed['Feed']['cached_elements'] = $this->Feed->getCachedElements($feed['Feed']['id']);
                $feed['Feed']['coverage_by_other_feeds'] = $this->Feed->getFeedCoverage($feed['Feed']['id'], 'feed', 'all') . '%';

                if ($this->_isRest()) {
                    unset($feed['SharingGroup'], $feed['Orgc']);
                    if (empty($feed['Tag']['id'])) {
                        unset($feed['Tag']);
                    }
                }

                return $feed;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $otherFeeds = $this->Feed->getAllCachingEnabledFeeds($feedId, true);
        $this->set('other_feeds', $otherFeeds);
        $this->set('feedId', $feedId);

        $this->loadModel('Event');
        $distributionLevels = $this->Event->distributionLevels;
        $distributionLevels[5] = __('Inherit from feed');
        $this->set('distributionLevels', $distributionLevels);

        if (!empty($this->viewVars['data']['Feed']['tag_collection_id'])) {
            $this->loadModel('TagCollection');
            $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), [
                'conditions' => [
                    'TagCollection.id' => $this->viewVars['data']['Feed']['tag_collection_id'],
                ]
            ]);
            $this->set('tagCollection', empty($tagCollection) ? null : $tagCollection[0]);
        }
    }

    public function feedCoverage($feedId)
    {
        $feed = $this->Feed->find('first', array(
            'conditions' => array('Feed.id' => $feedId),
            'recursive' => -1,
            'contain' => array('Tag')
        ));
        $result = $this->Feed->getFeedCoverage($feed['Feed']['id'], 'feed', $this->request->data);
        return $this->RestResponse->viewData($result, $this->response->type());
    }

    public function importFeeds()
    {
        if ($this->request->is('post')) {
            if (isset($this->request->data['Feed']['json'])) {
                $this->request->data = $this->request->data['Feed']['json'];
            }
            $results = $this->Feed->importFeeds($this->request->data, $this->Auth->user());
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
        if ($this->theme === 'Overmind') {
            $this->layout = false;
            // Feed::importFeeds() skips an entry whose url is already known, so the
            // form can tell beforehand which of the pasted feeds are actually new.
            $this->set('existingFeedUrls', $this->Feed->find('column', [
                'fields' => ['Feed.url']
            ]));
        }
    }

    public function add()
    {
        $params = [
            'beforeSave' => function (array $feed) {
                if ($this->IndexFilter->isRest()) {
                    if (empty($feed['Feed']['source_format'])) {
                        $feed['Feed']['source_format'] = 'freetext';
                    }
                    if (!isset($feed['Feed']['fixed_event'])) {
                        $feed['Feed']['fixed_event'] = '1';
                    }
                }

                if (isset($feed['Feed']['pull_rules'])) {
                    $feed['Feed']['rules'] = $feed['Feed']['pull_rules'];
                }
                if (!isset($feed['Feed']['distribution'])) {
                    $feed['Feed']['distribution'] = '0';
                }
                if ($feed['Feed']['distribution'] != 4) {
                    $feed['Feed']['sharing_group_id'] = '0';
                }
                $feed['Feed']['default'] = '0';
                if (!isset($feed['Feed']['source_format'])) {
                    $feed['Feed']['source_format'] = 'freetext';
                }
                if (!empty($feed['Feed']['source_format']) && ($feed['Feed']['source_format'] == 'misp')) {
                    if (!empty($feed['Feed']['orgc_id'])) {
                        $feed['Feed']['orgc_id'] = '0';
                    }
                }
                if ($feed['Feed']['source_format'] == 'freetext') {
                    if ($feed['Feed']['fixed_event'] == 1) {
                        if (!empty($feed['Feed']['target_event']) && is_numeric($feed['Feed']['target_event'])) {
                            $feed['Feed']['event_id'] = $feed['Feed']['target_event'];
                        }
                    }
                }
                if (!isset($feed['Feed']['settings'])) {
                    $feed['Feed']['settings'] = array();
                } else {
                    if (!empty($feed['Feed']['settings']['common']['excluderegex']) && !$this->__checkRegex($feed['Feed']['settings']['common']['excluderegex'])) {
                        $regexErrorMessage = __('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                        if (!$this->IndexFilter->isRest()) {
                            $this->Flash->error($regexErrorMessage);
                        } else {
                            return $this->RestResponse->saveFailResponse(
                                'Feeds',
                                'add',
                                false,
                                $regexErrorMessage,
                                $this->response->type()
                            );
                        }
                    }
                }
                if (isset($feed['Feed']['settings']['delimiter']) && empty($feed['Feed']['settings']['delimiter'])) {
                    $feed['Feed']['settings']['delimiter'] = ',';
                }
                if (empty($feed['Feed']['target_event'])) {
                    $feed['Feed']['target_event'] = 0;
                }
                if (empty($feed['Feed']['lookup_visible'])) {
                    $feed['Feed']['lookup_visible'] = 0;
                }
                if (empty($feed['Feed']['lock_events'])) {
                    $feed['Feed']['lock_events'] = 0;
                }
                if (empty($feed['Feed']['input_source'])) {
                    $feed['Feed']['input_source'] = 'network';
                } else {
                    $feed['Feed']['input_source'] = strtolower($feed['Feed']['input_source']);
                }
                if (!in_array($feed['Feed']['input_source'], array('network', 'local'))) {
                    $feed['Feed']['input_source'] = 'network';
                }
                if (!isset($feed['Feed']['delete_local_file'])) {
                    $feed['Feed']['delete_local_file'] = 0;
                }
                $feed['Feed']['settings'] = json_encode($feed['Feed']['settings']);
                $feed['Feed']['event_id'] = !empty($feed['Feed']['fixed_event']) ? $feed['Feed']['target_event'] : 0;

                return $feed;
            }
        ];

        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->loadModel('Event');
        $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $distributionLevels = $this->Event->distributionLevels;
        $distributionLevels[5] = __('Inherit from feed');
        if (empty($sharingGroups)) {
            unset($distributionLevels[4]);
        }
        $inputSources = array('network' => 'Network');
        if (empty(Configure::read('Security.disable_local_feed_access'))) {
            $inputSources['local'] = 'Local';
        }
        $tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
        $tags[0] = 'None';
        $this->loadModel('TagCollection');
        $tagCollections = $this->TagCollection->fetchTagCollection($this->Auth->user());
        $tagCollections = Hash::combine($tagCollections, '{n}.TagCollection.id', '{n}.TagCollection.name');
        $tagCollections[0] = 'None';

        $this->loadModel('Server');
        $allTypes = $this->Server->getAllTypes();

        $dropdownData = [
            'orgs' => $this->Event->Orgc->find('list', array(
                'fields' => array('id', 'name'),
                'order' => 'LOWER(name)'
            )),
            'tags' => $tags,
            'tag_collections' => $tagCollections,
            'feedTypes' => $this->Feed->getFeedTypesOptions(),
            'sharingGroups' => $sharingGroups,
            'distributionLevels' => $distributionLevels,
            'inputSources' => $inputSources
        ];
        $this->set('allAttributeTypes', $allTypes['attribute']);
        $this->set('allObjectTypes', $allTypes['object']);
        $this->set('supportedUrlparams', Feed::SUPPORTED_URL_PARAM_FILTERS);
        $this->set(compact('dropdownData'));
        $this->set('defaultPullRules', json_encode(Feed::DEFAULT_FEED_PULL_RULES));
        $this->set('menuData', array('menuList' => 'feeds', 'menuItem' => 'add'));
        $this->set('pull_scope', 'feed');
        if ($this->theme === "Overmind") {
            $this->layout = false;
            $this->render('add');
        }
    }

    private function __checkRegex($pattern)
    {
        if (@preg_match($pattern, '') === false) {
            return false;
        }
        return true;
    }

    public function edit($feedId)
    {
        $this->CRUD->edit($feedId, [
            'fields' => [
                'name',
                'provider',
                'enabled',
                'caching_enabled',
                'pull_rules',
                'rules',
                'url',
                'distribution',
                'sharing_group_id',
                'tag_id',
                'tag_collection_id',
                'event_id',
                'publish',
                'delta_merge',
                'source_format',
                'override_ids',
                'settings',
                'input_source',
                'delete_local_file',
                'lookup_visible',
                'headers',
                'orgc_id',
                'fixed_event',
                'lock_events'
            ],
            'afterFind' => function (array $feed) {
                $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
                if ($feed['Feed']['source_format'] == 'misp' && empty($feed['Feed']['rules'])) {
                    $feed['Feed']['rules'] = json_encode(Feed::DEFAULT_FEED_PULL_RULES);
                }

                return $feed;
            },
            'beforeSave' => function (array $feed) use ($feedId) {
                if (!empty($feed['Feed']['settings']) && !is_array($feed['Feed']['settings'])) {
                    $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
                }

                if (isset($feed['Feed']['pull_rules'])) {
                    $feed['Feed']['rules'] = $feed['Feed']['pull_rules'];
                }
                if (isset($feed['Feed']['distribution']) && $feed['Feed']['distribution'] != 4) {
                    $feed['Feed']['sharing_group_id'] = '0';
                }
                $feed['Feed']['id'] = $feedId;
                if (!empty($feed['Feed']['source_format']) && ($feed['Feed']['source_format'] == 'misp')) {
                    if (!empty($feed['Feed']['orgc_id'])) {
                        $feed['Feed']['orgc_id'] = '0';
                    }
                }
                if (!empty($feed['Feed']['source_format']) && ($feed['Feed']['source_format'] == 'freetext' || $feed['Feed']['source_format'] == 'csv')) {
                    if ($feed['Feed']['fixed_event'] == 1) {
                        if (isset($feed['Feed']['target_event']) && is_numeric($feed['Feed']['target_event'])) {
                            $feed['Feed']['event_id'] = $feed['Feed']['target_event'];
                        } else if (!empty($feed['Feed']['event_id'])) {
                            $feed['Feed']['event_id'] = $feed['Feed']['event_id'];
                        } else {
                            $feed['Feed']['event_id'] = '0';
                        }
                    }
                }
                if (!isset($feed['Feed']['settings'])) {
                    if (!empty($feed['Feed']['settings'])) {
                        $feed['Feed']['settings'] = $feed['Feed']['settings'];
                    } else {
                        $feed['Feed']['settings'] = array();
                    }
                } else {
                    if (!empty($feed['Feed']['settings']['common']['excluderegex']) && !$this->__checkRegex($feed['Feed']['settings']['common']['excluderegex'])) {
                        $regexErrorMessage = __('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                        if (!$this->IndexFilter->isRest()) {
                            $this->Flash->error($regexErrorMessage);
                            return true;
                        } else {
                            return $this->RestResponse->saveFailResponse(
                                'Feeds',
                                'edit',
                                false,
                                $regexErrorMessage,
                                $this->response->type()
                            );
                        }
                    }
                }
                if (isset($feed['Feed']['settings']['delimiter']) && empty($feed['Feed']['settings']['delimiter'])) {
                    $feed['Feed']['settings']['delimiter'] = ',';
                }
                $feed['Feed']['settings'] = json_encode($feed['Feed']['settings']);

                return $feed;
            },
            'afterSave' => function (array $feed) {
                $feedCache = APP . 'tmp' . DS . 'cache' . DS . 'misp_feed_' . intval($feed['Feed']['id']) . '.cache';
                if (file_exists($feedCache)) {
                    unlink($feedCache);
                }
                return $feed;
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->loadModel('Event');
        $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $distributionLevels = $this->Event->distributionLevels;
        $distributionLevels[5] = __('Inherit from feed');
        if (empty($sharingGroups)) {
            unset($distributionLevels[4]);
        }
        $inputSources = array('network' => 'Network');
        if (empty(Configure::read('Security.disable_local_feed_access'))) {
            $inputSources['local'] = 'Local';
        }
        $tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
        $tags[0] = 'None';
        $this->loadModel('TagCollection');
        $tagCollections = $this->TagCollection->fetchTagCollection($this->Auth->user());
        $tagCollections = Hash::combine($tagCollections, '{n}.TagCollection.id', '{n}.TagCollection.name');
        $tagCollections[0] = 'None';

        $this->loadModel('Server');
        $allTypes = $this->Server->getAllTypes();
        $this->set('allAttributeTypes', $allTypes['attribute']);
        $this->set('allObjectTypes', $allTypes['object']);
        $this->set('supportedUrlparams', Feed::SUPPORTED_URL_PARAM_FILTERS);

        $dropdownData = [
            'orgs' => $this->Event->Orgc->find('list', array(
                'fields' => array('id', 'name'),
                'order' => 'LOWER(name)'
            )),
            'tags' => $tags,
            'tag_collections' => $tagCollections,
            'feedTypes' => $this->Feed->getFeedTypesOptions(),
            'sharingGroups' => $sharingGroups,
            'distributionLevels' => $distributionLevels,
            'inputSources' => $inputSources
        ];
        $this->set(compact('dropdownData'));
        $this->set('menuData', [
            'menuList' => 'feeds',
            'menuItem' => 'edit',
        ]);

        $this->set('feedId', $feedId);
        if(!empty($this->request->data['Feed']['rules'])){
            $this->request->data['Feed']['pull_rules'] = $this->request->data['Feed']['rules'];
        }
        $this->set('pull_scope', 'feed');
        if ($this->theme === "Overmind") {
            $this->layout = false;
        }
        $this->render('add');
    }

    public function delete($feedId)
    {
        $this->CRUD->delete($feedId);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'Feed',
            'restName' => 'Feeds',
            'itemName' => 'feed',
            'view' => 'ajax/feedDeleteConfirmationForm',
            'checkModifyCallback' => function () {
                return $this->_isSiteAdmin();
            },
            'multiSuccessMessageCallback' => function ($count) {
                return __n('%s feed deleted.', '%s feeds deleted.', $count, $count);
            }
        ]);
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
            if ($this->_isRest()) {
                return $this->RestResponse->viewData(
                    array('result' => __('Feed is currently not enabled. Make sure you enable it.')),
                    $this->response->type()
                );
            } else {
                $this->Flash->error(__('Feed is currently not enabled. Make sure you enable it.'));
                $this->redirect(array('action' => 'index'));
            }
        }
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $this->Auth->user(),
                Job::WORKER_DEFAULT,
                'fetch_feeds',
                'Feed: ' . $feedId,
                __('Starting fetch from Feed.')
            );

            $this->Feed->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'fetchFeed',
                    $this->Auth->user('id'),
                    $feedId,
                    $jobId
                ],
                true,
                $jobId
            );

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
            $message = __('Fetching the feed has successfully completed.');
            if ($this->Feed->data['Feed']['source_format'] == 'misp') {
                if (isset($result['add'])) {
                    $message .= ' Downloaded ' . count($result['add']) . ' new event(s).';
                }
                if (isset($result['edit'])) {
                    $message .= ' Updated ' . count($result['edit']) . ' event(s).';
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

                /** @var Job $job */
                $job = ClassRegistry::init('Job');
                $jobId = $job->createJob(
                    $this->Auth->user(),
                    Job::WORKER_DEFAULT,
                    'fetch_feed',
                    'Feed: ' . $feedId,
                    __('Starting fetch from Feed.')
                );

                $this->Feed->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::DEFAULT_QUEUE,
                    BackgroundJobsTool::CMD_SERVER,
                    [
                        'fetchFeed',
                        $this->Auth->user('id'),
                        $feedId,
                        $jobId
                    ],
                    true,
                    $jobId
                );

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
        if (!isset($message)) {
            $message = __('No feed enabled.');
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('result' => $message), $this->response->type());
        } else {
            $this->Flash->success($message);
            $this->redirect(array('action' => 'index'));
        }
    }


    public function fetchSelectedFeeds($idList = null)
    {
        $isPost = $this->request->is(array('post', 'put'));
        if ($isPost && isset($this->request->data['Feed']['id'])) {
            $idList = $this->request->data['Feed']['id'];
        }
        // Header action "Fetch and store all feed data" — same modal, but the
        // selection is every enabled feed. The modal posts the resolved list
        // back, so this only ever has to resolve on the GET.
        $isAll = ($idList === 'all');
        if ($isAll) {
            $idList = $this->Feed->find('column', array(
                'conditions' => array('Feed.enabled' => 1),
                'fields' => array('Feed.id'),
            ));
        }
        if (!is_array($idList)) {
            $idList = is_numeric($idList) ? array($idList) : json_decode($idList, true);
        }
        $ids = array();
        foreach ((array)$idList as $feedId) {
            if (is_numeric($feedId)) {
                $ids[] = (int)$feedId;
            }
        }

        if (empty($ids) && !$isAll) {
            throw new NotFoundException(__('Invalid input.'));
        }

        $feeds = $this->Feed->find('all', array(
            'conditions' => array('Feed.id' => $ids),
            'recursive' => -1,
            'fields' => array('Feed.id', 'Feed.name', 'Feed.enabled'),
        ));

        // A disabled feed cannot be pulled — list those separately so the modal
        // can say what it is going to leave out.
        $fetchable = array();
        $skipped = array();
        foreach ($feeds as $feed) {
            if (empty($feed['Feed']['enabled'])) {
                $skipped[] = array('name' => $feed['Feed']['name'], 'reason' => __('not enabled'));
            } else {
                $fetchable[] = $feed['Feed'];
            }
        }

        if (!$isPost) {
            $this->request->data['Feed']['id'] = json_encode($ids);
            $this->set('fetchable', $fetchable);
            $this->set('skipped', $skipped);
            $this->set('isAll', $isAll);
            $this->set('backgroundJobs', (bool)Configure::read('MISP.background_jobs'));
            $this->layout = false;
            return $this->render('ajax/fetchFeedsConfirmationForm');
        }

        $queued = 0;
        $succeeded = 0;
        $failed = 0;
        foreach ($fetchable as $feed) {
            $outcome = $this->__fetchSingleFeed($feed['id']);
            if ($outcome === 'queued') {
                $queued++;
            } elseif ($outcome === 'success') {
                $succeeded++;
            } else {
                $failed++;
            }
        }

        $messages = array();
        if ($queued) {
            $messages[] = __n('Pull queued for %s feed.', 'Pull queued for %s feeds.', $queued, $queued);
        }
        if ($succeeded) {
            $messages[] = __n('%s feed fetched.', '%s feeds fetched.', $succeeded, $succeeded);
        }
        if ($failed) {
            $messages[] = __n('%s feed could not be fetched.', '%s feeds could not be fetched.', $failed, $failed);
        }
        if (!empty($skipped)) {
            $messages[] = __n(
                '%s feed skipped (not enabled or invalid target event).',
                '%s feeds skipped (not enabled or invalid target event).',
                count($skipped),
                count($skipped)
            );
        }
        $message = implode(' ', $messages);

        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('result' => $message), $this->response->type());
        }
        if (!$queued && !$succeeded) {
            $this->Flash->error($message ?: __('No feed was fetched, none of the selected feeds is enabled.'));
        } elseif ($failed || !empty($skipped)) {
            $this->Flash->warning($message);
        } else {
            $this->Flash->success($message);
        }
        $this->redirect(array('action' => 'index'));
    }

    /**
     * Pull a single feed the same way fetchFromFeed does: through a background
     * job when those are enabled, inline otherwise.
     *
     * @param int $feedId
     * @return string 'queued', 'success' or 'failed'
     */
    private function __fetchSingleFeed($feedId)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $this->Auth->user(),
                Job::WORKER_DEFAULT,
                'fetch_feeds',
                'Feed: ' . $feedId,
                __('Starting fetch from Feed.')
            );
            $this->Feed->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                array('fetchFeed', $this->Auth->user('id'), $feedId, $jobId),
                true,
                $jobId
            );
            return 'queued';
        }
        try {
            $result = $this->Feed->downloadFromFeedInitiator($feedId, $this->Auth->user());
        } catch (Exception $e) {
            $result = false;
        }
        return empty($result) ? 'failed' : 'success';
    }

    public function getEvent($feedId, $eventUuid, $all = false)
    {
        $this->Feed->id = $feedId;
        if (!$this->Feed->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feed->read();
        try {
            $result = $this->Feed->downloadAndSaveEventFromFeed($this->Feed->data, $eventUuid, $this->Auth->user());
        } catch (Exception $e) {
            $this->Flash->error(__('Download failed.') . ' ' . $e->getMessage());
            $this->redirect(array('action' => 'previewIndex', $feedId));
        }

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

    /**
     * A galaxy cluster is attached to an event both as a Galaxy entry and as a
     * plain tag; strip the tag side so the two are not rendered twice. Mirrors
     * ServersController::__removeGalaxyClusterTags, but tolerates the keys being
     * absent — a feed event is remote JSON, not a local find() result.
     *
     * @param array $event rearranged event, modified in place
     * @return void
     */
    private function __removeGalaxyClusterTags(array &$event)
    {
        if (empty($event['Galaxy']) || empty($event['Tag'])) {
            return;
        }
        $galaxyTagIds = [];
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] ?? [] as $galaxyCluster) {
                if (isset($galaxyCluster['tag_id'])) {
                    $galaxyTagIds[$galaxyCluster['tag_id']] = true;
                }
            }
        }
        if (empty($galaxyTagIds)) {
            return;
        }
        foreach ($event['Tag'] as $k => $eventTag) {
            if (isset($eventTag['id'], $galaxyTagIds[$eventTag['id']])) {
                unset($event['Tag'][$k]);
            }
        }
        $event['Tag'] = array_values($event['Tag']);
    }

    /**
     * Fetch a selection of events off a feed's manifest, driven by the mass-fetch
     * toolbar of the Overmind feed preview index.
     *
     * GET  renders the confirmation modal, POST performs the fetches. Events are
     * downloaded one at a time in-request, mirroring getEvent().
     *
     * @param int $feedId
     * @param string $uuidList JSON-encoded list of event uuids, or a single uuid
     * @return CakeResponse|void
     */
    public function getSelectedEvents($feedId, $uuidList = null)
    {
        $feed = $this->Feed->find('first', array(
            'conditions' => array('Feed.id' => $feedId),
            'recursive' => -1
        ));
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        if (empty($feed['Feed']['enabled'])) {
            throw new MethodNotAllowedException(__('Feed is currently not enabled. Make sure you enable it.'));
        }

        $isPost = $this->request->is(array('post', 'put'));
        if ($isPost && isset($this->request->data['Feed']['uuids'])) {
            $uuidList = $this->request->data['Feed']['uuids'];
        }
        if (!is_array($uuidList)) {
            $uuidList = Validation::uuid($uuidList) ? array($uuidList) : json_decode($uuidList, true);
        }
        $uuids = array();
        foreach ((array)$uuidList as $uuid) {
            if (Validation::uuid($uuid)) {
                $uuids[] = $uuid;
            }
        }
        if (empty($uuids)) {
            throw new NotFoundException(__('Invalid input.'));
        }

        if (!$isPost) {
            $this->request->data['Feed']['uuids'] = json_encode($uuids);
            $this->set('feed', $feed);
            $this->set('uuids', $uuids);
            $this->layout = false;
            return $this->render('ajax/fetchEventsConfirmationForm');
        }

        if (!empty($feed['Feed']['settings'])) {
            $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
        }
        $added = 0;
        $updated = 0;
        $unchanged = 0;
        $failed = 0;
        foreach ($uuids as $uuid) {
            try {
                $result = $this->Feed->downloadAndSaveEventFromFeed($feed, $uuid, $this->Auth->user());
            } catch (Exception $e) {
                $result = false;
            }
            if (empty($result['action']) || empty($result['result'])) {
                $failed++;
            } elseif ($result['result'] === 'No change') {
                $unchanged++;
            } elseif ($result['action'] === 'add') {
                $added++;
            } else {
                $updated++;
            }
        }

        $messages = array();
        if ($added) {
            $messages[] = __n('%s event added.', '%s events added.', $added, $added);
        }
        if ($updated) {
            $messages[] = __n('%s event updated.', '%s events updated.', $updated, $updated);
        }
        if ($unchanged) {
            $messages[] = __n('%s event already up to date.', '%s events already up to date.', $unchanged, $unchanged);
        }
        if ($failed) {
            $messages[] = __n('%s event could not be fetched.', '%s events could not be fetched.', $failed, $failed);
        }
        $message = implode(' ', $messages);

        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('result' => $message), $this->response->type());
        }
        if ($failed && !($added || $updated || $unchanged)) {
            $this->Flash->error($message);
        } elseif ($failed) {
            $this->Flash->warning($message);
        } else {
            $this->Flash->success($message);
        }
        $this->redirect(array('action' => 'previewIndex', $feedId));
    }

    public function previewIndex($feedId)
    {
        $feed = $this->Feed->find('first', [
            'conditions' => ['id' => $feedId],
            'recursive' => -1,
        ]);

        if (empty($feed) || !$this->__canViewFeed($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }

        if (!empty($feed['Feed']['settings'])) {
            $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
        }
        $params = array();
        if ($this->request->is('post')) {
            $params = $this->request->data['Feed'];
        }
        if ($feed['Feed']['source_format'] === 'misp') {
            return $this->__previewIndex($feed, $params);
        } elseif (in_array($feed['Feed']['source_format'], ['freetext', 'csv'], true)) {
            return $this->__previewFreetext($feed);
        } else {
            throw new Exception("Invalid feed format `{$feed['Feed']['source_format']}`.");
        }
    }

    private function __previewIndex(array $feed, $filterParams = array())
    {
        $urlparams = '';
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $passedArgs = array();
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocketFeed();
        try {
            $events = $this->Feed->getManifest($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->Flash->error("Could not fetch manifest for feed: {$e->getMessage()}");
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }

        if (!empty($this->params['named']['searchall'])) {
            $searchAll = trim(mb_strtolower($this->params['named']['searchall']));
            foreach ($events as $uuid => $event) {
                if ($uuid === $searchAll) {
                    continue;
                }
                if (strpos(mb_strtolower($event['info']), $searchAll) !== false) {
                    continue;
                }
                if (strpos(mb_strtolower($event['Orgc']['name']), $searchAll) !== false) {
                    continue;
                }
                if (!empty($event['Tag'])) {
                    foreach ($event['Tag'] as $tag) {
                        if (strpos(mb_strtolower($tag['name']), $searchAll) !== false) {
                            continue 2;
                        }
                    }
                }
                unset($events[$uuid]);
            }
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
        $customPagination->truncateByPagination($events, $params);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($events, $this->response->type());
        }
        $this->set('events', $events);
        $this->loadModel('Event');
        $this->set('threatLevels', $this->Event->ThreatLevel->listThreatLevels());
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

    private function __previewFreetext(array $feed)
    {
        if (isset($this->passedArgs['page'])) {
            $currentPage = $this->passedArgs['page'];
        } elseif (isset($this->passedArgs['page'])) {
            $currentPage = $this->passedArgs['page'];
        } else {
            $currentPage = 1;
        }
        if (!in_array($feed['Feed']['source_format'], array('freetext', 'csv'))) {
            throw new MethodNotAllowedException(__('Invalid feed type.'));
        }
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocketFeed();
        // params is passed as reference here, the pagination happens in the method, which isn't ideal but considering the performance gains here it's worth it
        try {
            $resultArray = $this->Feed->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format']);
        } catch (Exception $e) {
            $this->Flash->error("Could not fetch feed: {$e->getMessage()}");
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }

        if (!empty($this->params['named']['searchall'])) {
            $searchAll = trim(mb_strtolower($this->params['named']['searchall']));
            $resultArray = array_values(array_filter($resultArray, function (array $item) use ($searchAll) {
                foreach (array('value', 'default_type', 'category', 'comment') as $field) {
                    if (!empty($item[$field]) && strpos(mb_strtolower($item[$field]), $searchAll) !== false) {
                        return true;
                    }
                }
                return false;
            }));
        }

        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($resultArray, array('page' => $currentPage, 'limit' => 60), 'Feed', $sort = false);
        if (!empty($currentPage) && $currentPage !== 'all') {
            $start = ($currentPage - 1) * 60;
            if ($start > count($resultArray)) {
                return false;
            }
            $resultArray = array_slice($resultArray, $start, 60);
        }

        $this->params->params['paging'] = array($this->modelClass => $params);
        $resultArray = $this->Feed->getFreetextFeedCorrelations($resultArray, $feed['Feed']['id']);
        // remove all duplicates
        $correlatingEvents = array();
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
        $this->loadModel('MispAttribute');
        $correlatingEventInfos = $this->MispAttribute->Event->find('list', array(
            'fields' => array('Event.id', 'Event.info'),
            'conditions' => array('Event.id' => $correlatingEvents)
        ));
        if ((int)$feed['Feed']['distribution'] === 4 && !empty($feed['Feed']['sharing_group_id'])) {
            $feed['SharingGroup'] = $this->Feed->SharingGroup->find('first', array(
                'conditions' => array('SharingGroup.id' => $feed['Feed']['sharing_group_id']),
                'fields' => array('SharingGroup.id', 'SharingGroup.name'),
                'recursive' => -1,
            ))['SharingGroup'] ?? array('name' => __('Unknown sharing group'));
        }
        $this->set('correlatingEventInfos', $correlatingEventInfos);
        $this->set('distributionLevels', $this->MispAttribute->distributionLevels);
        $this->set('feed', $feed);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($resultArray, $this->response->type());
        }
        $this->set('attributes', $resultArray);
        $this->render('freetext_index');
    }

    private function __canViewFeed($feed)
    {
        $host_org_id = (int)Configure::read('MISP.host_org_id');
        if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') !== $host_org_id && !$feed['Feed']['lookup_visible']) {
            return false;
        }
        return true;
    }

    public function previewEvent($feedId, $eventUuid, $all = false)
    {
        $feed = $this->Feed->find('first', [
            'conditions' => ['id' => $feedId],
            'recursive' => -1,
        ]);
        if (empty($feed) || !$this->__canViewFeed($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        try {
            $error_message = null;
            $event = $this->Feed->downloadEventFromFeed($feed, $eventUuid, true, $error_message);
        } catch (Exception $e) {
            throw new Exception($e->getMessage(), 0, $e);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($event, $this->response->type());
        }
        if (!empty($event['Event']['error_message'])) {
            $this->Flash->error('ERROR: ' . $event['Event']['error_message']);
        }
        if (is_array($event)) {
            if (isset($event['Event']['Attribute'])) {
                $this->loadModel('Warninglist');
                $this->Warninglist->attachWarninglistToAttributes($event['Event']['Attribute']);
            }

            $this->loadModel('Event');

            if ($this->theme === 'Overmind') {
                $all = true;
            }
            $params = $this->Event->rearrangeEventForView($event, $this->passedArgs, $all);
            // Galaxy clusters are also carried as event tags; drop them so the
            // tags card does not repeat what the galaxy card already shows.
            $this->__removeGalaxyClusterTags($event);
            $this->params->params['paging'] = array('Feed' => $params);
            $this->set('event', $event);
            $this->set('feed', $feed);
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
            $this->set('threatLevels', $this->Event->ThreatLevel->find('list'));
            $this->set('title_for_layout', __('Feed event preview'));
            $this->set('previewContext', $this->__feedPreviewContext($feed, $eventUuid));
        } else {
            if ($event === 'blocked') {
                throw new MethodNotAllowedException(__('This event is blocked by the Feed filters.'));
            } else {
                throw new NotFoundException(__('Could not download the selected Event'));
            }
        }
    }

    /**
     * Attributes tab of the Overmind feed event preview, as a lazily loaded
     * fragment. Keeping the big tables out of previewEvent is what makes that
     * page load quickly on events with thousands of attributes/objects.
     *
     * @param int $feedId
     * @param string $eventUuid
     * @return void
     */
    public function previewEventAttributes($feedId, $eventUuid, $all = false)
    {
        $this->__previewEventFragment($feedId, $eventUuid, 'preview_event_attributes', $all);
    }

    /**
     * Objects tab of the Overmind feed event preview, as a lazily loaded fragment.
     *
     * @param int $feedId
     * @param string $eventUuid
     * @return void
     */
    public function previewEventObjects($feedId, $eventUuid, $all = false)
    {
        $this->__previewEventFragment($feedId, $eventUuid, 'preview_event_objects', $all);
    }

    /**
     * Shared body of the two preview tab fragments: re-download the remote event,
     * rearrange it whole and render one tab's partial without a layout.
     *
     * @param int $feedId
     * @param string $eventUuid
     * @param string $view themed view under Feeds/ajax/
     * @return void
     */
    private function __previewEventFragment($feedId, $eventUuid, $view, $all = false)
    {
        $feed = $this->Feed->find('first', [
            'conditions' => ['Feed.id' => $feedId],
            'recursive' => -1,
        ]);
        if (empty($feed) || !$this->__canViewFeed($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        try {
            $event = $this->Feed->downloadEventFromFeed($feed, $eventUuid, true);
        } catch (Exception $e) {
            throw new NotFoundException(__('Could not download the selected Event'));
        }
        if (!is_array($event)) {
            throw new NotFoundException(__('Could not download the selected Event'));
        }
        if (isset($event['Event']['Attribute'])) {
            $this->loadModel('Warninglist');
            $this->Warninglist->attachWarninglistToAttributes($event['Event']['Attribute']);
        }

        $this->loadModel('Event');
        // The fragment always carries the whole tab, never a 60-row slice.
        $params = $this->Event->rearrangeEventForView($event, $this->passedArgs, true);
        $this->params->params['paging'] = array('Feed' => $params);
        $this->set('event', $event);
        $this->set('feed', $feed);
        $this->set('showAllAttributes', !empty($all));
        $this->set('previewContext', $this->__feedPreviewContext($feed, $eventUuid));
        $this->layout = false;
        $this->render('ajax/' . $view);
    }

    /**
     * Tells the shared preview partials how to address this feed: events are keyed
     * by uuid (a server previews by id) and the remote index can only be filtered
     * with a free-text searchall.
     *
     * @param array $feed
     * @param string $eventUuid
     * @return array
     */
    private function __feedPreviewContext(array $feed, $eventUuid)
    {
        // AppController::beforeFilter normalises this (trailing slash stripped).
        $baseurl = $this->baseurl;
        $feedId = (int)$feed['Feed']['id'];
        $canFetch = !empty($feed['Feed']['enabled']) && $this->_isSiteAdmin();

        return [
            'eventUrl' => $baseurl . '/feeds/previewEvent/' . $feedId . '/%id%',
            'eventKey' => 'uuid',
            'tagFilterUrl' => $baseurl . '/feeds/previewIndex/' . $feedId . '/searchall:%tag%',
            'tagFilterKey' => 'name',
            'pagingModel' => 'Feed',
            // The attributes tab caps how many rows it renders; this reloads it uncapped.
            'viewAllUrl' => $baseurl . '/feeds/previewEventAttributes/' . $feedId
                . '/' . $eventUuid . '/all',
            'fetchUrl' => $canFetch
                ? $baseurl . '/feeds/getSelectedEvents/' . $feedId . '/' . $eventUuid
                : null,
        ];
    }

    public function enable($id)
    {
        $result = $this->__toggleEnable($id, true);
        if (!$this->_isRest()) {
            return $this->__redirectAfterToggleEnable($result);
        }
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
        if (!$this->_isRest()) {
            return $this->__redirectAfterToggleEnable($result);
        }
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

    /**
     * There is no enable/disable view, so browser calls (the feed index row
     * action) get a flash message and are sent back where they came from.
     *
     * @param array $result outcome of __toggleEnable()
     * @return CakeResponse
     */
    private function __redirectAfterToggleEnable(array $result)
    {
        if (empty($result['success'])) {
            $this->Flash->error($result['message']);
        } else {
            $this->Flash->success($result['message']);
        }
        return $this->redirect($this->referer(array('action' => 'index')));
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
        $result['success'] = !$fail;
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
        try {
            $this->Feed->saveFreetextFeedData($feed, $data, $this->Auth->user());
            $this->Flash->success(__('Data pulled.'));
        } catch (Exception $e) {
            $this->Flash->error(__('Could not pull the selected data. Reason: %s', $e->getMessage()));
        }
        if ($this->theme === 'Overmind') {
            // Back to the preview the selection was made in, where the pulled
            // values now show up as correlations.
            $this->redirect(array('controller' => 'feeds', 'action' => 'previewIndex', $id));
        }
        $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
    }

    public function cacheFeeds($scope = 'freetext')
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $this->Auth->user(),
                Job::WORKER_DEFAULT,
                'cache_feeds',
                $scope,
                __('Starting feed caching.')
            );

            $this->Feed->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'cacheFeed',
                    $this->Auth->user('id'),
                    $scope,
                    $jobId
                ],
                true,
                $jobId
            );

            $message = 'Feed caching job initiated.';
        } else {
            $result = $this->Feed->cacheFeedInitiator($this->Auth->user(), false, $scope);
            if ($result['fails'] > 0) {
                $this->Flash->error(__('Caching the feeds has failed.'));
                $this->redirect(array('action' => 'index'));
            }
            $message = __('Caching the feeds has successfully completed.');
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Feed', 'cacheFeed', false, $this->response->type(), $message);
        } else {
            $this->Flash->info($message);
            $this->redirect(array('controller' => 'feeds', 'action' => 'index'));
        }
    }

    public function compareFeeds($id = false)
    {
        $limited = !$this->_isSiteAdmin() && $this->Auth->user('org_id') !== (int)Configure::read('MISP.host_org_id');
        $feeds = $this->Feed->compareFeeds($limited);
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
            $this->set('cache', $cache);
            if ($this->theme === 'Overmind') {
                $this->layout = false;
            }
            $this->render('ajax/feedToggleConfirmation');
        }
    }

    public function searchCaches()
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
        $value = false;
        if ($this->request->is('post')) {
            if (isset($this->request->data['Feed'])) {
                $this->request->data = $this->request->data['Feed'];
            }
            if (isset($this->request->data['value'])) {
                $this->request->data = $this->request->data['value'];
            }
            $value = $this->request->data;
        }
        if (!empty($this->params['named']['value'])) {
            $value = $this->params['named']['value'];
        }
        $host_org_id = (int)Configure::read('MISP.host_org_id');
        $limited = !$this->_isSiteAdmin() && $this->Auth->user('org_id') !== $host_org_id;
        $hits = $this->Feed->searchCaches($value, $limited);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($hits, $this->response->type());
        } else {
            $this->set('hits', $hits);
        }
        $params = $customPagination->createPaginationRules($hits, $this->passedArgs, $this->alias);
        $this->params->params['paging'] = array('Feed' => $params);
        $hits = $customPagination->sortArray($hits, $params, true);
        if (is_array($hits)) {
            $customPagination->truncateByPagination($hits, $params);
        }
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgs);
    }
}
