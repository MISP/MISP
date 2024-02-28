<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\CustomPaginationTool;
use App\Lib\Tools\SyncTool;
use App\Model\Entity\Analysis;
use App\Model\Entity\Distribution;
use App\Model\Entity\Feed;
use App\Model\Entity\Job;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Exception;

class FeedsController extends AppController
{
    public $paginate = [
        'limit' => 60,
        'order' => [
            'Feed.default' => 'DESC',
            'Feed.id' => 'ASC'
        ],
    ];

    public $uses = ['Feed'];

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);
        $this->Security->setConfig('unlockedActions', ['previewIndex', 'feedCoverage']);
    }

    public function loadDefaultFeeds()
    {
        if ($this->request->is('post')) {
            $this->Feeds->load_default_feeds();
            $message = __('Default feed metadata loaded.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Feed', 'loadDefaultFeeds', false, $this->response->getType(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(['controller' => 'Feeds', 'action' => 'index']);
            }
        }
    }

    public function index()
    {
        $conditions = [];
        $scope = isset($this->request->getQueryParams()['scope']) ? $this->request->getQueryParams()['scope'] : 'all';
        if ($scope !== 'all') {
            if ($scope == 'enabled') {
                $conditions[] = [
                    'OR' => [
                        'Feed.enabled' => 1,
                        'Feed.caching_enabled' => 1
                    ]
                ];
            } else {
                $conditions[] = [
                    'Feed.default' => $scope == 'custom' ? 0 : 1
                ];
            }
        }

        $this->CRUD->index(
            [
                'filters' => [
                    'Feed.name',
                    'url',
                    'provider',
                    'source_format',
                    'enabled',
                    'caching_enabled',
                    'default'
                ],
                'quickFilters' => [
                    'Feed.name',
                    'url',
                    'provider',
                    'source_format'
                ],
                'contain' =>  [
                    'Tags',
                    'SharingGroups',
                    'Orgc' => [
                        'fields' => [
                            'Orgc.id',
                            'Orgc.uuid',
                            'Orgc.name',
                            'Orgc.local'
                        ]
                    ]
                ],
                'conditions' => $conditions,
                'afterFind' => function (Feed $feed) {
                    if ($this->isSiteAdmin()) {
                        $feed = $this->Feeds->attachFeedCacheTimestamps($feed);
                    }

                    if ($this->ParamHandler->isRest()) {
                        unset($feed['SharingGroup']);
                        if (empty($feed['Tag']['id'])) {
                            unset($feed['Tag']);
                        }
                    }

                    return $feed;
                }
            ]
        );

        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        $this->set('title_for_layout', __('Feeds'));
        $this->set(
            'menuData',
            [
                'menuList' => 'feeds',
                'menuItem' => 'index'
            ]
        );
        $distributionLevels = Distribution::ALL;
        $distributionLevels[5] = __('Inherit from feed');
        $this->set('distributionLevels', $distributionLevels);
        $this->set('scope', $scope);
    }

    public function view($feedId)
    {
        $this->CRUD->view(
            $feedId,
            [
                'contain' => ['Tags'],
                'afterFind' => function (Feed $feed) {
                    if (!$this->isSiteAdmin()) {
                        unset($feed['headers']);
                    }

                    $feed['cached_elements'] = $this->Feeds->getCachedElements($feed['id']);
                    $feed['coverage_by_other_feeds'] = $this->Feeds->getFeedCoverage($feed['id'], 'feed', 'all') . '%';

                    if ($this->ParamHandler->isRest()) {
                        if (empty($feed['Tag']['id'])) {
                            unset($feed['Tag']);
                        }
                    }

                    return $feed;
                }
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        $otherFeeds = $this->Feeds->getAllCachingEnabledFeeds($feedId, true);
        $this->set('other_feeds', $otherFeeds);
        $this->set('feedId', $feedId);
    }

    public function feedCoverage($feedId)
    {
        $feed = $this->Feeds->find(
            'all',
            [
                'conditions' => ['Feed.id' => $feedId],
                'recursive' => -1,
                'contain' => ['Tag']
            ]
        )->first();
        $result = $this->Feeds->getFeedCoverage($feed['Feed']['id'], 'feed', $this->request->getData());
        return $this->RestResponse->viewData($result, $this->response->getType());
    }

    public function importFeeds()
    {
        if ($this->request->is('post')) {
            $data = $this->request->getData();
            if (isset($data['Feed']['json'])) {
                $data = $data['Feed']['json'];
            }
            $results = $this->Feeds->importFeeds($data, $this->ACL->getUser());
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
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Feed', 'importFeeds', false, $this->response->getType(), $message);
            } else {
                $this->Flash->{$flashType}($message);
                $this->redirect(['controller' => 'Feeds', 'action' => 'index', 'all']);
            }
        }
    }

    public function add()
    {
        $params = [
            'beforeSave' => function (Feed $feed) {
                if ($this->ParamHandler->isRest()) {
                    if (empty($feed['source_format'])) {
                        $feed['source_format'] = 'freetext';
                    }
                    if (!isset($feed['fixed_event'])) {
                        $feed['fixed_event'] = '1';
                    }
                }

                if (!isset($feed['distribution'])) {
                    $feed['distribution'] = '0';
                }
                if ($feed['distribution'] != 4) {
                    $feed['sharing_group_id'] = '0';
                }
                $feed['default'] = '0';
                if (!isset($feed['source_format'])) {
                    $feed['source_format'] = 'freetext';
                }
                if (!empty($feed['source_format']) && ($feed['source_format'] == 'misp')) {
                    if (!empty($feed['orgc_id'])) {
                        $feed['orgc_id'] = '0';
                    }
                }
                if ($feed['source_format'] == 'freetext') {
                    if ($feed['fixed_event'] == 1) {
                        if (!empty($feed['target_event']) && is_numeric($feed['target_event'])) {
                            $feed['event_id'] = $feed['target_event'];
                        }
                    }
                }
                if (!isset($feed['settings'])) {
                    $feed['settings'] = [];
                } else {
                    if (!empty($feed['settings']['common']['excluderegex']) && !$this->__checkRegex($feed['settings']['common']['excluderegex'])) {
                        $regexErrorMessage = __('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                        if (!$this->ParamHandler->isRest()) {
                            $this->Flash->error($regexErrorMessage);
                        } else {
                            return $this->RestResponse->saveFailResponse(
                                'Feeds',
                                'add',
                                false,
                                $regexErrorMessage,
                                $this->response->getType()
                            );
                        }
                    }
                }
                if (isset($feed['settings']['delimiter']) && empty($feed['settings']['delimiter'])) {
                    $feed['settings']['delimiter'] = ',';
                }
                if (empty($feed['target_event'])) {
                    $feed['target_event'] = 0;
                }
                if (empty($feed['lookup_visible'])) {
                    $feed['lookup_visible'] = 0;
                }
                if (empty($feed['input_source'])) {
                    $feed['input_source'] = 'network';
                } else {
                    $feed['input_source'] = strtolower($feed['input_source']);
                }
                if (!in_array($feed['input_source'], ['network', 'local'])) {
                    $feed['input_source'] = 'network';
                }
                if (!isset($feed['delete_local_file'])) {
                    $feed['delete_local_file'] = 0;
                }
                $feed['event_id'] = !empty($feed['fixed_event']) ? $feed['target_event'] : 0;

                return $feed;
            }
        ];

        $this->CRUD->add($params);
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        $EventsTable = $this->fetchTable('Events');

        $sharingGroups = $EventsTable->SharingGroup->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);
        $distributionLevels = Distribution::ALL;
        $distributionLevels[5] = __('Inherit from feed');
        if (empty($sharingGroups)) {
            unset($distributionLevels[4]);
        }
        $inputSources = ['network' => 'Network'];
        if (empty(Configure::read('Security.disable_local_feed_access'))) {
            $inputSources['local'] = 'Local';
        }
        $tags = $EventsTable->EventTag->Tag->find('list', ['fields' => ['Tag.name'], 'order' => ['lower(Tag.name) asc']]);
        $tags[0] = 'None';

        $ServersTable = $this->fetchTable('Servers');
        $allTypes = $ServersTable->getAllTypes();

        $dropdownData = [
            'orgs' => $EventsTable->Orgc->find(
                'list',
                [
                    'fields' => ['id', 'name'],
                    'order' => 'LOWER(name)'
                ]
            ),
            'tags' => $tags,
            'feedTypes' => $this->Feeds->getFeedTypesOptions(),
            'sharingGroups' => $sharingGroups,
            'distributionLevels' => $distributionLevels,
            'inputSources' => $inputSources
        ];
        $this->set('allAttributeTypes', $allTypes['attribute']);
        $this->set('allObjectTypes', $allTypes['object']);
        $this->set('supportedUrlparams', Feed::SUPPORTED_URL_PARAM_FILTERS);
        $this->set(compact('dropdownData'));
        $this->set('defaultPullRules', json_encode(Feed::DEFAULT_FEED_PULL_RULES));
        $this->set('menuData', ['menuList' => 'feeds', 'menuItem' => 'add']);
        $this->set('pull_scope', 'feed');
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
        $this->CRUD->edit(
            $feedId,
            [
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
                    'fixed_event'
                ],
                'beforeSave' => function (Feed $feed) use ($feedId) {
                    if (isset($feed['pull_rules'])) {
                        $feed['rules'] = $feed['pull_rules'];
                    }
                    if (isset($feed['distribution']) && $feed['distribution'] != 4) {
                        $feed['sharing_group_id'] = '0';
                    }
                    $feed['id'] = $feedId;
                    if (!empty($feed['source_format']) && ($feed['source_format'] == 'misp')) {
                        if (!empty($feed['orgc_id'])) {
                            $feed['orgc_id'] = '0';
                        }
                    }
                    if (!empty($feed['source_format']) && ($feed['source_format'] == 'freetext' || $feed['source_format'] == 'csv')) {
                        if ($feed['fixed_event'] == 1) {
                            if (isset($feed['target_event']) && is_numeric($feed['target_event'])) {
                                $feed['event_id'] = $feed['target_event'];
                            } else if (!empty($feed['event_id'])) {
                                $feed['event_id'] = $feed['event_id'];
                            } else {
                                $feed['event_id'] = '0';
                            }
                        }
                    }
                    if (!isset($feed['settings'])) {
                        if (!empty($feed['settings'])) {
                            $feed['settings'] = $feed['settings'];
                        } else {
                            $feed['settings'] = [];
                        }
                    } else {
                        if (!empty($feed['settings']['common']['excluderegex']) && !$this->__checkRegex($feed['settings']['common']['excluderegex'])) {
                            $regexErrorMessage = __('Invalid exclude regex. Make sure it\'s a delimited PCRE regex pattern.');
                            if (!$this->ParamHandler->isRest()) {
                                $this->Flash->error($regexErrorMessage);
                                return true;
                            } else {
                                return $this->RestResponse->saveFailResponse(
                                    'Feeds',
                                    'edit',
                                    false,
                                    $regexErrorMessage,
                                    $this->response->getType()
                                );
                            }
                        }
                    }
                    if (isset($feed['settings']['delimiter']) && empty($feed['settings']['delimiter'])) {
                        $feed['settings']['delimiter'] = ',';
                    }

                    return $feed;
                },
                'afterSave' => function (Feed $feed) {
                    $feedCache = APP . 'tmp' . DS . 'cache' . DS . 'misp_feed_' . intval($feed['id']) . '.cache';
                    if (file_exists($feedCache)) {
                        unlink($feedCache);
                    }
                    return $feed;
                }
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        $EventsTable = $this->fetchTable('Events');
        $sharingGroups = $EventsTable->SharingGroup->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);
        $distributionLevels = Distribution::ALL;
        $distributionLevels[5] = __('Inherit from feed');
        if (empty($sharingGroups)) {
            unset($distributionLevels[4]);
        }
        $inputSources = ['network' => 'Network'];
        if (empty(Configure::read('Security.disable_local_feed_access'))) {
            $inputSources['local'] = 'Local';
        }
        $tags = $this->Event->EventTag->Tag->find('list', ['fields' => ['Tag.name'], 'order' => ['lower(Tag.name) asc']]);
        $tags[0] = 'None';

        $ServersTable = $this->fetchTable('Servers');
        $allTypes = $ServersTable->getAllTypes();
        $this->set('allAttributeTypes', $allTypes['attribute']);
        $this->set('allObjectTypes', $allTypes['object']);
        $this->set('supportedUrlparams', Feed::SUPPORTED_URL_PARAM_FILTERS);

        $dropdownData = [
            'orgs' => $this->Event->Orgc->find(
                'list',
                [
                    'fields' => ['id', 'name'],
                    'order' => 'LOWER(name)'
                ]
            ),
            'tags' => $tags,
            'feedTypes' => $this->Feeds->getFeedTypesOptions(),
            'sharingGroups' => $sharingGroups,
            'distributionLevels' => $distributionLevels,
            'inputSources' => $inputSources
        ];
        $this->set(compact('dropdownData'));
        $this->set(
            'menuData',
            [
                'menuList' => 'feeds',
                'menuItem' => 'edit',
            ]
        );

        $this->set('feedId', $feedId);
        $this->set('pull_scope', 'feed');
        $this->render('add');
    }

    public function delete($feedId)
    {
        $this->CRUD->delete($feedId);
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function fetchFromFeed($feedId)
    {
        $feed = $this->Feeds->get($feedId);

        if (!$feed instanceof Feed) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        if (!$feed['enabled']) {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->viewData(
                    ['result' => __('Feed is currently not enabled. Make sure you enable it.')],
                    $this->response->getType()
                );
            } else {
                $this->Flash->error(__('Feed is currently not enabled. Make sure you enable it.'));
                $this->redirect(['action' => 'index']);
            }
        }
        if (Configure::read('BackgroundJobs.enabled')) {

            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $this->ACL->getUser(),
                Job::WORKER_DEFAULT,
                'fetch_feeds',
                'Feed: ' . $feedId,
                __('Starting fetch from Feed.')
            );

            $this->Feeds->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_FEEDS,
                [
                    'fetchFeed',
                    $this->ACL->getUser()->id,
                    $feedId,
                    $jobId
                ],
                true,
                $jobId
            );

            $message = __('Pull queued for background execution.');
        } else {
            $result = $this->Feeds->downloadFromFeedInitiator($feedId, $this->ACL->getUser());
            if (!$result) {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->viewData(['result' => __('Fetching the feed has failed.')], $this->response->getType());
                } else {
                    $this->Flash->error(__('Fetching the feed has failed.'));
                    $this->redirect(['action' => 'index']);
                }
            }
            $message = __('Fetching the feed has successfully completed.');
            if ($feed['source_format'] == 'misp') {
                if (isset($result['add'])) {
                    $message .= ' Downloaded ' . count($result['add']['success']) . ' new event(s).';
                }
                if (isset($result['edit'])) {
                    $message .= ' Updated ' . count($result['edit']['success']) . ' event(s).';
                }
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(['result' => $message], $this->response->getType());
        } else {
            $this->Flash->success($message);
            $this->redirect(['action' => 'index']);
        }
    }

    public function fetchFromAllFeeds()
    {
        $feeds = $this->Feeds->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['id']
            ]
        );
        foreach ($feeds as $feed) {
            $feedId = $feed['Feed']['id'];
            $this->Feeds->id = $feedId;
            $this->Feeds->read();
            if (!$this->Feeds->data['Feed']['enabled']) {
                continue;
            }
            if (Configure::read('BackgroundJobs.enabled')) {

                /** @var Job $job */
                $JobsTable = $this->fetchTable('Jobs');

                $jobId = $JobsTable->createJob(
                    $this->ACL->getUser(),
                    Job::WORKER_DEFAULT,
                    'fetch_feed',
                    'Feed: ' . $feedId,
                    __('Starting fetch from Feed.')
                );

                $this->Feeds->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::DEFAULT_QUEUE,
                    BackgroundJobsTool::CMD_FEEDS,
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
                $result = $this->Feeds->downloadFromFeedInitiator($feedId, $this->ACL->getUser());
                if (!$result) {
                    continue;
                }
                $message = __('Fetching the feed has successfully completed.');
                if ($this->Feeds->data['Feed']['source_format'] == 'misp') {
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
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(['result' => $message], $this->response->getType());
        } else {
            $this->Flash->success($message);
            $this->redirect(['action' => 'index']);
        }
    }

    public function getEvent($feedId, $eventUuid, $all = false)
    {
        $this->Feeds->id = $feedId;
        if (!$this->Feeds->exists()) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $this->Feeds->read();
        if (!$this->Feeds->data['Feed']['enabled']) {
            $this->Flash->error(__('Feed is currently not enabled. Make sure you enable it.'));
            $this->redirect(['action' => 'previewIndex', $feedId]);
        }
        try {
            $result = $this->Feeds->downloadAndSaveEventFromFeed($this->Feeds->data, $eventUuid, $this->ACL->getUser());
        } catch (Exception $e) {
            $this->Flash->error(__('Download failed.') . ' ' . $e->getMessage());
            $this->redirect(['action' => 'previewIndex', $feedId]);
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
        $this->redirect(['action' => 'previewIndex', $feedId]);
    }

    public function previewIndex($feedId)
    {
        $feed = $this->Feeds->find(
            'all',
            [
                'conditions' => ['id' => $feedId],
                'recursive' => -1,
            ]
        )->first();
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $params = [];
        if ($this->request->is('post')) {
            $params = $this->request->getData()['Feed'];
        }
        if ($feed['Feed']['source_format'] === 'misp') {
            return $this->__previewIndex($feed, $params);
        } elseif (in_array($feed['Feed']['source_format'], ['freetext', 'csv'], true)) {
            return $this->__previewFreetext($feed);
        } else {
            throw new Exception("Invalid feed format `{$feed['Feed']['source_format']}`.");
        }
    }

    private function __previewIndex(array $feed, $filterParams = [])
    {
        $urlparams = '';
        $customPagination = new CustomPaginationTool();
        $passedArgs = [];
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocketFeed();
        try {
            $events = $this->Feeds->getManifest($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->Flash->error("Could not fetch manifest for feed: {$e->getMessage()}");
            $this->redirect(['controller' => 'feeds', 'action' => 'index']);
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
        $params = $customPagination->createPaginationRules($events, $this->request->getQueryParams(), $this->alias);
        $this->params->params['paging'] = ['Feeds' => $params];
        $events = $customPagination->sortArray($events, $params, true);
        $customPagination->truncateByPagination($events, $params);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($events, $this->response->getType());
        }
        $this->set('events', $events);
        $EventsTable = $this->fetchTable('Events');
        $this->set('threatLevels', $EventsTable->ThreatLevel->listThreatLevels());
        $this->set('eventDescriptions', Distribution::DESCRIPTIONS);
        $this->set('analysisLevels', Analysis::ALL);
        $this->set('distributionLevels', Distribution::ALL);
        $shortDist = [0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group'];
        $this->set('shortDist', $shortDist);
        $this->set('id', $feed['Feed']['id']);
        $this->set('feed', $feed);
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgs);
    }

    private function __previewFreetext(array $feed)
    {
        if (isset($this->request->getQueryParams()['page'])) {
            $currentPage = $this->request->getQueryParams()['page'];
        } elseif (isset($this->request->getQueryParams()['page'])) {
            $currentPage = $this->request->getQueryParams()['page'];
        } else {
            $currentPage = 1;
        }
        if (!in_array($feed['Feed']['source_format'], ['freetext', 'csv'])) {
            throw new MethodNotAllowedException(__('Invalid feed type.'));
        }
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocketFeed();
        // params is passed as reference here, the pagination happens in the method, which isn't ideal but considering the performance gains here it's worth it
        try {
            $resultArray = $this->Feeds->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format']);
        } catch (Exception $e) {
            $this->Flash->error("Could not fetch feed: {$e->getMessage()}");
            $this->redirect(['controller' => 'feeds', 'action' => 'index']);
        }

        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($resultArray, ['page' => $currentPage, 'limit' => 60], 'Feed', $sort = false);
        if (!empty($currentPage) && $currentPage !== 'all') {
            $start = ($currentPage - 1) * 60;
            if ($start > count($resultArray)) {
                return false;
            }
            $resultArray = array_slice($resultArray, $start, 60);
        }

        $this->params->params['paging'] = ['Feeds' => $params];
        $resultArray = $this->Feeds->getFreetextFeedCorrelations($resultArray, $feed['Feed']['id']);
        // remove all duplicates
        $correlatingEvents = [];
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
        $AttributesTable = $this->fetchTable('Attributes');
        $correlatingEventInfos = $AttributesTable->Event->find(
            'list',
            [
                'fields' => ['Events.id', 'Events.info'],
                'conditions' => ['Events.id IN' => $correlatingEvents]
            ]
        );
        $this->set('correlatingEventInfos', $correlatingEventInfos);
        $this->set('distributionLevels', Distribution::ALL);
        $this->set('feed', $feed);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($resultArray, $this->response->getType());
        }
        $this->set('attributes', $resultArray);
        $this->render('freetext_index');
    }

    public function previewEvent($feedId, $eventUuid, $all = false)
    {
        $feed = $this->Feeds->find(
            'all',
            [
                'conditions' => ['id' => $feedId],
                'recursive' => -1,
            ]
        )->first();
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        try {
            $event = $this->Feeds->downloadEventFromFeed($feed, $eventUuid);
        } catch (Exception $e) {
            throw new Exception(__('Could not download the selected Event'), 0, $e);
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($event, $this->response->getType());
        }
        if (is_array($event)) {
            if (isset($event['Event']['Attribute'])) {
                $WarninglistsTable = $this->fetchTable('Warninglists');
                $WarninglistsTable->attachWarninglistToAttributes($event['Event']['Attribute']);
            }

            $EventsTable = $this->fetchTable('Events');
            $params = $EventsTable->rearrangeEventForView($event, $this->request->getQueryParams(), $all);
            $this->params->params['paging'] = ['Feed' => $params];
            $this->set('event', $event);
            $this->set('feed', $feed);
            $dataForView = [
                'Attribute' => ['attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels'],
                'Event' => ['eventDescriptions' => 'fieldDescriptions', 'analysisLevels' => 'analysisLevels']
            ];
            foreach ($dataForView as $m => $variables) {
                if ($m === 'Event') {
                    $currentModel = $EventsTable;
                } elseif ($m === 'Attribute') {
                    $currentModel = $this->fetchTable('Attributes');
                }
                foreach ($variables as $alias => $variable) {
                    $this->set($alias, $currentModel->{$variable});
                }
            }
            $this->set('threatLevels', $EventsTable->ThreatLevel->find('list'));
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
        $this->set('url', $this->request->getAttribute('here'));
        if ($result) {
            $this->viewBuilder()->setOption('serialize', ['name', 'message', 'url']);
        } else {
            $this->set('errors', $result);
        }
    }

    public function disable($id)
    {
        $result = $this->__toggleEnable($id, false);
        $this->set('name', $result['message']);
        $this->set('message', $result['message']);
        $this->set('url', $this->request->getAttribute('here'));
        if ($result['result']) {
            $this->viewBuilder()->setOption('serialize', ['name', 'message', 'url']);
        } else {
            $this->set('errors', $result);
            $this->viewBuilder()->setOption('serialize', ['name', 'message', 'url', 'errors']);
        }
    }

    private function __toggleEnable($id, $enable = true)
    {
        if (!is_numeric($id)) {
            throw new MethodNotAllowedException(__('Invalid Feed.'));
        }
        $feed = $this->Feeds->get($id);
        if (!$feed) {
            throw new MethodNotAllowedException(__('Invalid Feed.'));
        }
        $feed['enabled'] = $enable;
        $result = ['result' => $this->Feeds->save($feed)];
        $fail = false;
        if (!$result['result']) {
            $fail = true;
            $result['result'] = $this->Feeds->validationErrors;
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
        $this->Feeds->id = $id;
        if (!$this->Feeds->exists()) {
            throw new NotFoundException(__('Feed not found.'));
        }
        $feed = $this->Feeds->read();
        $data = json_decode($this->request->getData()['Feed']['data'], true);
        try {
            $this->Feeds->saveFreetextFeedData($feed, $data, $this->ACL->getUser());
            $this->Flash->success(__('Data pulled.'));
        } catch (Exception $e) {
            $this->Flash->error(__('Could not pull the selected data. Reason: %s', $e->getMessage()));
        }
        $this->redirect(['controller' => 'feeds', 'action' => 'index']);
    }

    public function cacheFeeds($scope = 'freetext')
    {
        if (Configure::read('BackgroundJobs.enabled')) {

            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $this->ACL->getUser(),
                Job::WORKER_DEFAULT,
                'cache_feeds',
                $scope,
                __('Starting feed caching.')
            );

            $this->Feeds->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_FEEDS,
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
            $result = $this->Feeds->cacheFeedInitiator($this->ACL->getUser(), false, $scope);
            if ($result['fails'] > 0) {
                $this->Flash->error(__('Caching the feeds has failed.'));
                $this->redirect(['action' => 'index']);
            }
            $message = __('Caching the feeds has successfully completed.');
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Feed', 'cacheFeed', false, $this->response->getType(), $message);
        } else {
            $this->Flash->info($message);
            $this->redirect(['controller' => 'feeds', 'action' => 'index']);
        }
    }

    public function compareFeeds($id = false)
    {
        $feeds = $this->Feeds->compareFeeds($id);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($feeds, $this->response->getType());
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
            $this->redirect(['controller' => 'feeds', 'action' => 'index']);
        }
        if ($this->request->is('post')) {
            $feeds = $this->Feeds->find(
                'all',
                [
                    'conditions' => ['Feed.id' => $feedIds],
                    'recursive' => -1
                ]
            );
            $count = 0;
            foreach ($feeds as $feed) {
                if ($feed['Feed'][$field] != $enable) {
                    $feed['Feed'][$field] = $enable;
                    $this->Feeds->save($feed);
                    $count++;
                }
            }
            if ($count > 0) {
                $this->Flash->success($count . ' feeds ' . ['disabled', 'enabled'][$enable] . '.');
                $this->redirect(['controller' => 'feeds', 'action' => 'index']);
            } else {
                $this->Flash->info('All selected feeds are already ' . ['disabled', 'enabled'][$enable] . ', nothing to update.');
                $this->redirect(['controller' => 'feeds', 'action' => 'index']);
            }
        } else {
            $this->set('feedList', $feedList);
            $this->set('enable', $enable);
            $this->render('ajax/feedToggleConfirmation');
        }
    }

    public function searchCaches()
    {
        if (isset($this->request->getQueryParams()['pages'])) {
            $currentPage = $this->request->getQueryParams()['pages'];
        } else {
            $currentPage = 1;
        }
        $urlparams = '';
        $customPagination = new CustomPaginationTool();
        $passedArgs = [];
        $value = false;
        $data = $this->request->getData();
        if ($this->request->is('post')) {
            if (isset($data['Feed'])) {
                $data = $data['Feed'];
            }
            if (isset($data['value'])) {
                $data = $data['value'];
            }
            $value = $data;
        }
        if (!empty($this->params['named']['value'])) {
            $value = $this->params['named']['value'];
        }
        $hits = $this->Feeds->searchCaches($value);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($hits, $this->response->getType());
        } else {
            $this->set('hits', $hits);
        }
        $params = $customPagination->createPaginationRules($hits, $this->request->getQueryParams(), $this->alias);
        $this->params->params['paging'] = ['Feed' => $params];
        $hits = $customPagination->sortArray($hits, $params, true);
        if (is_array($hits)) {
            $customPagination->truncateByPagination($hits, $params);
        }
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgs);
    }
}
