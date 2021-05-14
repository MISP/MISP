<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');
App::uses('TmpFileTool', 'Tools');

class Feed extends AppModel
{
    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'change' => 'full'
        ),
        'Trim',
        'Containable'
    );

    public $belongsTo = array(
            'SharingGroup' => array(
                    'className' => 'SharingGroup',
                    'foreignKey' => 'sharing_group_id',
            ),
            'Tag' => array(
                    'className' => 'Tag',
                    'foreignKey' => 'tag_id',
            ),
            'Orgc' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'orgc_id'
            )
    );

    public $validate = array(
        'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
            'rule' => array('urlOrExistingFilepath')
        ),
        'provider' => 'valueNotEmpty',
        'name' => [
            'rule' => 'valueNotEmpty',
            'required' => true,
        ],
        'event_id' => array(
            'rule' => array('numeric'),
            'message' => 'Please enter a numeric event ID or leave this field blank.',
        ),
        'input_source' => array(
            'rule' => 'validateInputSource',
            'message' => ''
        )
    );

    // currently we only have an internal name and a display name, but later on we can expand this with versions, default settings, etc
    public $feed_types = array(
        'misp' => array(
            'name' => 'MISP Feed'
        ),
        'freetext' => array(
            'name' => 'Freetext Parsed Feed'
        ),
        'csv' => array(
            'name' => 'Simple CSV Parsed Feed'
        )
    );

    /*
     *  Cleanup of empty belongsto relationships
     */
    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($result['SharingGroup']) && empty($result['SharingGroup']['id'])) {
                unset($results[$k]['SharingGroup']);
            }
            if (isset($result['Tag']) && empty($result['Tag']['id'])) {
                unset($results[$k]['Tag']);
            }
            if (isset($result['Orgc']) && empty($result['Orgc']['id'])) {
                unset($results[$k]['Orgc']);
            }
        }
        return $results;
    }

    public function validateInputSource($fields)
    {
        if (!empty($this->data['Feed']['input_source'])) {
            $localAllowed = empty(Configure::read('Security.disable_local_feed_access'));
            $validOptions = array('network');
            if ($localAllowed) {
                $validOptions[] = 'local';
            }
            if (!in_array($this->data['Feed']['input_source'], $validOptions)) {
                return __(
                    'Invalid input source. The only valid options are %s. %s',
                    implode(', ', $validOptions),
                    (!$localAllowed && $this->data['Feed']['input_source'] === 'local') ?
                    __('Security.disable_local_feed_access is currently enabled, local feeds are thereby not allowed.') :
                    ''
                );
            }
        }
        return true;
    }

    public function urlOrExistingFilepath($fields)
    {
        if ($this->isFeedLocal($this->data)) {
            if ($this->data['Feed']['source_format'] == 'misp') {
                if (!is_dir($this->data['Feed']['url'])) {
                    return 'For MISP type local feeds, please specify the containing directory.';
                }
            } else {
                if (!file_exists($this->data['Feed']['url'])) {
                    return 'Invalid path or file not found. Make sure that the path points to an existing file that is readable and watch out for typos.';
                }
            }
        } else {
            if (!filter_var($this->data['Feed']['url'], FILTER_VALIDATE_URL)) {
                return false;
            }
        }
        return true;
    }

    public function getFeedTypesOptions()
    {
        $result = array();
        foreach ($this->feed_types as $key => $value) {
            $result[$key] = $value['name'];
        }
        return $result;
    }

    /**
     * Gets the event UUIDs from the feed by ID
     * Returns an array with the UUIDs of events that are new or that need updating.
     *
     * @param array $feed
     * @param HttpSocket|null $HttpSocket
     * @return array
     * @throws Exception
     */
    public function getNewEventUuids($feed, HttpSocket $HttpSocket = null)
    {
        $manifest = $this->downloadManifest($feed, $HttpSocket);
        $this->Event = ClassRegistry::init('Event');
        $events = $this->Event->find('all', array(
            'conditions' => array(
                'Event.uuid' => array_keys($manifest),
            ),
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.uuid', 'Event.timestamp')
        ));
        $result = array('add' => array(), 'edit' => array());
        foreach ($events as $event) {
            $eventUuid = $event['Event']['uuid'];
            if ($event['Event']['timestamp'] < $manifest[$eventUuid]['timestamp']) {
                $result['edit'][] = array('uuid' => $eventUuid, 'id' => $event['Event']['id']);
            } else {
                $this->__cleanupFile($feed, '/' . $eventUuid . '.json');
            }
            unset($manifest[$eventUuid]);
        }
        // Rest events in manifest does't exists, they will be added
        $result['add'] = array_keys($manifest);
        return $result;
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return Generator
     * @throws Exception
     */
    public function getCache(array $feed, HttpSocket $HttpSocket = null)
    {
        $uri = $feed['Feed']['url'] . '/hashes.csv';
        $data = $this->feedGetUri($feed, $uri, $HttpSocket);

        if (empty($data)) {
            throw new Exception("File '$uri' with hashes for cache filling is empty.");
        }

        // CSV file can be pretty big to do operations in memory, so we save content to temp and iterate line by line.
        $tmpFile = new TmpFileTool();
        $tmpFile->write(trim($data));
        unset($data);

        return $tmpFile->intoParsedCsv();
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    private function downloadManifest($feed, HttpSocket $HttpSocket = null)
    {
        $manifestUrl = $feed['Feed']['url'] . '/manifest.json';
        $data = $this->feedGetUri($feed, $manifestUrl, $HttpSocket, true);

        try {
            return $this->jsonDecode($data);
        } catch (Exception $e) {
            throw new Exception("Could not parse '$manifestUrl' manifest JSON", 0, $e);
        }
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    public function getManifest(array $feed, HttpSocket $HttpSocket = null)
    {
        $events = $this->downloadManifest($feed, $HttpSocket);
        $events = $this->__filterEventsIndex($events, $feed);
        return $events;
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @param string $type
     * @param int|string $page
     * @param int $limit
     * @param array $params
     * @return array|bool
     * @throws Exception
     */
    public function getFreetextFeed($feed, HttpSocket $HttpSocket = null, $type = 'freetext', $page = 1, $limit = 60, &$params = array())
    {
        $isLocal = $this->isFeedLocal($feed);
        $data = false;

        if (!$isLocal) {
            $feedCache = APP . 'tmp' . DS . 'cache' . DS . 'misp_feed_' . intval($feed['Feed']['id']) . '.cache';
            if (file_exists($feedCache)) {
                $file = new File($feedCache);
                if (time() - $file->lastChange() < 600) {
                    $data = $file->read();
                    if ($data === false) {
                        throw new Exception("Could not read feed cache file '$feedCache'.");
                    }
                }
            }
        }

        if ($data === false) {
            $feedUrl = $feed['Feed']['url'];
            $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket, true);

            if (!$isLocal) {
                file_put_contents($feedCache, $data); // save to cache
            }
        }

        App::uses('ComplexTypeTool', 'Tools');
        $complexTypeTool = new ComplexTypeTool();
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
        $settings = array();
        if (!empty($feed['Feed']['settings']) && !is_array($feed['Feed']['settings'])) {
            $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
        }
        if (isset($feed['Feed']['settings'][$type])) {
            $settings = $feed['Feed']['settings'][$type];
        }
        if (isset($feed['Feed']['settings']['common'])) {
            $settings = array_merge($settings, $feed['Feed']['settings']['common']);
        }
        $resultArray = $complexTypeTool->checkComplexRouter($data, $type, $settings);
        $this->Attribute = ClassRegistry::init('Attribute');
        foreach ($resultArray as $key => $value) {
            $resultArray[$key]['category'] = $this->Attribute->typeDefinitions[$value['default_type']]['default_category'];
        }
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($resultArray, array('page' => $page, 'limit' => $limit), 'Feed', $sort = false);
        if (!empty($page) && $page != 'all') {
            $start = ($page - 1) * $limit;
            if ($start > count($resultArray)) {
                return false;
            }
            $resultArray = array_slice($resultArray, $start, $limit);
        }
        return $resultArray;
    }

    public function getFreetextFeedCorrelations($data, $feedId)
    {
        $values = array();
        foreach ($data as $key => $value) {
            $values[] = $value['value'];
        }
        $this->Attribute = ClassRegistry::init('Attribute');
        $redis = $this->setupRedis();
        if ($redis !== false) {
            $feeds = $this->find('all', array(
                'recursive' => -1,
                'conditions' => array('Feed.id !=' => $feedId),
                'fields' => array('id', 'name', 'url', 'provider', 'source_format')
            ));
            foreach ($feeds as $k => $v) {
                if (!$redis->exists('misp:feed_cache:' . $v['Feed']['id'])) {
                    unset($feeds[$k]);
                }
            }
        } else {
            return array();
        }
        // Adding a 3rd parameter to a list find seems to allow grouping several results into a key. If we ran a normal list with value => event_id we'd only get exactly one entry for each value
        // The cost of this method is orders of magnitude lower than getting all id - event_id - value triplets and then doing a double loop comparison
        $correlations = $this->Attribute->find('list', array('conditions' => array('Attribute.value1' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value1')));
        $correlations2 = $this->Attribute->find('list', array('conditions' => array('Attribute.value2' => $values, 'Attribute.deleted' => 0), 'fields' => array('Attribute.event_id', 'Attribute.event_id', 'Attribute.value2')));
        $correlations = array_merge_recursive($correlations, $correlations2);
        foreach ($data as $key => $value) {
            if (isset($correlations[$value['value']])) {
                $data[$key]['correlations'] = array_values($correlations[$value['value']]);
            }
            if ($redis) {
                foreach ($feeds as $k => $v) {
                    if ($redis->sismember('misp:feed_cache:' . $v['Feed']['id'], md5($value['value']))) {
                        $data[$key]['feed_correlations'][] = array($v);
                    }
                }
            }
        }
        return $data;
    }

    /**
     * Attach correlations from cached servers or feeds.
     *
     * @param array $attributes
     * @param array $user
     * @param array $event
     * @param bool $overrideLimit Override hardcoded limit for 10 000 correlations.
     * @param string $scope `Feed` or `Server`
     * @return array
     */
    public function attachFeedCorrelations(array $attributes, array $user, array &$event, $overrideLimit = false, $scope = 'Feed')
    {
        if (empty($attributes)) {
            return $attributes;
        }

        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return $attributes;
        }

        $cachePrefix = 'misp:' . strtolower($scope) . '_cache:';

        // Skip if redis cache for $scope is empty.
        if ($redis->sCard($cachePrefix . 'combined') === 0) {
            return $attributes;
        }

        if (!isset($this->Attribute)) {
            $this->Attribute = ClassRegistry::init('Attribute');
        }
        $compositeTypes = $this->Attribute->getCompositeTypes();

        $pipe = $redis->multi(Redis::PIPELINE);
        $hashTable = [];
        $redisResultToAttributePosition = [];

        foreach ($attributes as $k => $attribute) {
            if (in_array($attribute['type'], $this->Attribute->nonCorrelatingTypes, true)) {
                continue; // attribute type is not correlateable
            }
            if (!empty($attribute['disable_correlation'])) {
                continue; // attribute correlation is disabled
            }

            if (in_array($attribute['type'], $compositeTypes, true)) {
                list($value1, $value2) = explode('|', $attribute['value']);
                $parts = [$value1];

                if (!in_array($attribute['type'], $this->Attribute->primaryOnlyCorrelatingTypes, true)) {
                    $parts[] = $value2;
                }
            } else {
                $parts = [$attribute['value']];

                // Some feeds contains URL without protocol, so if attribute is URL and value contains protocol,
                // we will check also value without protocol.
                if ($attribute['type'] === 'url' || $attribute['type'] === 'uri') {
                    $protocolPos = strpos($attribute['value'], '://');
                    if ($protocolPos !== false) {
                        $parts[] = substr($attribute['value'], $protocolPos + 3);
                    }
                }
            }

            foreach ($parts as $part) {
                $md5 = md5($part);
                $hashTable[] = $md5;
                $redis->sismember($cachePrefix . 'combined', $md5);
                $redisResultToAttributePosition[] = $k;
            }
        }

        if (empty($redisResultToAttributePosition)) {
            // No attribute that can be correlated
            $pipe->discard();
            return $attributes;
        }

        $results = $pipe->exec();

        $hitIds = [];
        foreach ($results as $k => $result) {
            if ($result) {
                $hitIds[] = $k;
            }
        }

        if (empty($hitIds)) {
            return $attributes; // nothing matches, skip
        }

        $hitCount = count($hitIds);
        if (!$overrideLimit && $hitCount > 10000) {
            $event['FeedCount'] = $hitCount;
            foreach ($hitIds as $k) {
                $attributes[$redisResultToAttributePosition[$k]]['FeedHit'] = true;
            }
            return $attributes;
        }

        $sources = $this->getCachedFeedsOrServers($user, $scope);
        foreach ($sources as $source) {
            $sourceId = $source[$scope]['id'];

            $pipe = $redis->multi(Redis::PIPELINE);
            foreach ($hitIds as $k) {
                $redis->sismember($cachePrefix . $sourceId, $hashTable[$k]);
            }
            $sourceHits = $pipe->exec();
            $sourceHasHit = false;
            foreach ($sourceHits as $k => $hit) {
                if ($hit) {
                    if (!isset($event[$scope][$sourceId])) {
                        $event[$scope][$sourceId] = $source[$scope];
                    }

                    $attributePosition = $redisResultToAttributePosition[$hitIds[$k]];
                    $alreadyAttached = isset($attributes[$attributePosition][$scope]) &&
                        in_array($sourceId, array_column($attributes[$attributePosition][$scope], 'id'));
                    if (!$alreadyAttached) {
                        $attributes[$attributePosition][$scope][] = $source[$scope];
                    }
                    $sourceHasHit = true;
                }
            }
            // Append also exact MISP feed or server event UUID
            // TODO: This can be optimised in future to do that in one pass
            if ($sourceHasHit && ($scope === 'Server' || $source[$scope]['source_format'] === 'misp')) {
                $pipe = $redis->multi(Redis::PIPELINE);
                $eventUuidHitPosition = [];
                foreach ($hitIds as $sourceHitPos => $k) {
                    if ($sourceHits[$sourceHitPos]) {
                        $redis->smembers($cachePrefix . 'event_uuid_lookup:' . $hashTable[$k]);
                        $eventUuidHitPosition[] = $redisResultToAttributePosition[$k];
                    }
                }
                $mispFeedHits = $pipe->exec();
                foreach ($mispFeedHits as $sourceHitPos => $feedUuidMatches) {
                    if (empty($feedUuidMatches)) {
                        continue;
                    }
                    foreach ($feedUuidMatches as $url) {
                        list($feedId, $eventUuid) = explode('/', $url);
                        if ($feedId != $sourceId) {
                            continue; // just process current source, skip others
                        }

                        if (empty($event[$scope][$feedId]['event_uuids']) || !in_array($eventUuid, $event[$scope][$feedId]['event_uuids'])) {
                            $event[$scope][$feedId]['event_uuids'][] = $eventUuid;
                        }
                        $attributePosition = $eventUuidHitPosition[$sourceHitPos];
                        foreach ($attributes[$attributePosition][$scope] as $tempKey => $tempFeed) {
                            if ($tempFeed['id'] == $feedId) {
                                if (empty($attributes[$attributePosition][$scope][$tempKey]['event_uuids']) || !in_array($eventUuid, $attributes[$attributePosition][$scope][$tempKey]['event_uuids'])) {
                                    $attributes[$attributePosition][$scope][$tempKey]['event_uuids'][] = $eventUuid;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (isset($event[$scope])) {
            $event[$scope] = array_values($event[$scope]);
        }

        return $attributes;
    }

    /**
     * Return just feeds or servers that has some data in Redis cache.
     * @param array $user
     * @param string $scope 'Feed' or 'Server'
     * @return array
     */
    private function getCachedFeedsOrServers(array $user, $scope)
    {
        if ($scope === 'Feed') {
            $params = array(
                'recursive' => -1,
                'fields' => array('id', 'name', 'url', 'provider', 'source_format')
            );
            if (!$user['Role']['perm_site_admin']) {
                $params['conditions'] = array('Feed.lookup_visible' => 1);
            }
            $sources = $this->find('all', $params);
        } else {
            $params = array(
                'recursive' => -1,
                'fields' => array('id', 'name', 'url')
            );
            if (!$user['Role']['perm_site_admin']) {
                $params['conditions'] = array('Server.caching_enabled' => 1);
            }
            $this->Server = ClassRegistry::init('Server');
            $sources = $this->Server->find('all', $params);
        }

        try {
            $redis = $this->setupRedisWithException();
            $pipe = $redis->multi(Redis::PIPELINE);
            $cachePrefix = 'misp:' . strtolower($scope) . '_cache:';
            foreach ($sources as $source) {
                $pipe->exists($cachePrefix . $source[$scope]['id']);
            }
            $results = $pipe->exec();
            foreach ($sources as $k => $source) {
                if (!$results[$k]) {
                    unset($sources[$k]);
                }
            }
        } catch (Exception $e) {}

        return $sources;
    }

    /**
     * @param array $actions
     * @param array $feed
     * @param HttpSocket|null $HttpSocket
     * @param array $user
     * @param int|false $jobId
     * @return array
     * @throws Exception
     */
    private function downloadFromFeed(array $actions, array $feed, HttpSocket $HttpSocket = null, array $user, $jobId = false)
    {
        $total = count($actions['add']) + count($actions['edit']);
        $currentItem = 0;
        $this->Event = ClassRegistry::init('Event');
        $results = array();
        $filterRules = $this->__prepareFilterRules($feed);

        foreach ($actions['add'] as $uuid) {
            try {
                $result = $this->__addEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
                if ($result === true) {
                    $results['add']['success'] = $uuid;
                } else if ($result !== 'blocked') {
                    $results['add']['fail'] = ['uuid' => $uuid, 'reason' => $result];
                    $this->log("Could not add event '$uuid' from feed {$feed['Feed']['id']}: $result", LOG_WARNING);
                }
            } catch (Exception $e) {
                $this->logException("Could not add event '$uuid' from feed {$feed['Feed']['id']}.", $e);
                $results['add']['fail'] = array('uuid' => $uuid, 'reason' => $e->getMessage());
            }

            $this->__cleanupFile($feed, '/' . $uuid . '.json');
            $this->jobProgress($jobId, null, 100 * (($currentItem + 1) / $total));
            $currentItem++;
        }

        foreach ($actions['edit'] as $editTarget) {
            $uuid = $editTarget['uuid'];
            try {
                $result = $this->__updateEventFromFeed($HttpSocket, $feed, $uuid, $editTarget['id'], $user, $filterRules);
                if ($result === true) {
                    $results['add']['success'] = $uuid;
                } else if ($result !== 'blocked') {
                    $results['add']['fail'] = ['uuid' => $uuid, 'reason' => $result];
                    $this->log("Could not edit event '$uuid' from feed {$feed['Feed']['id']}: $result", LOG_WARNING);
                }
            } catch (Exception $e) {
                $this->logException("Could not edit event '$uuid' from feed {$feed['Feed']['id']}.", $e);
                $results['edit']['fail'] = array('uuid' => $uuid, 'reason' => $e->getMessage());
            }

            $this->__cleanupFile($feed, '/' . $uuid . '.json');
            if ($currentItem % 10 === 0) {
                $this->jobProgress($jobId, null, 100 * (($currentItem + 1) / $total));
            }
            $currentItem++;
        }

        return $results;
    }

    private function __createFeedRequest($headers = false)
    {
        $version = $this->checkMISPVersion();
        $version = implode('.', $version);

        $result = array(
            'header' => array(
                'Accept' => array('application/json', 'text/plain', 'text/*'),
                'MISP-version' => $version,
                'MISP-uuid' => Configure::read('MISP.uuid'),
            )
        );

        $commit = $this->checkMIPSCommit();
        if ($commit) {
            $result['header']['commit'] = $commit;
        }
        if (!empty($headers)) {
            $lines = explode("\n", $headers);
            foreach ($lines as $line) {
                if (!empty($line)) {
                    $kv = explode(':', $line);
                    if (!empty($kv[0]) && !empty($kv[1])) {
                        if (!in_array($kv[0], array('commit', 'MISP-version', 'MISP-uuid'))) {
                            $result['header'][trim($kv[0])] = trim($kv[1]);
                        }
                    }
                }
            }
        }
        return $result;
    }

    private function __checkIfEventBlockedByFilter($event, $filterRules)
    {
        $fields = array('tags' => 'Tag', 'orgs' => 'Orgc');
        $prefixes = array('OR', 'NOT');
        foreach ($fields as $field => $fieldModel) {
            foreach ($prefixes as $prefix) {
                if (!empty($filterRules[$field][$prefix])) {
                    $found = false;
                    if (isset($event['Event'][$fieldModel]) && !empty($event['Event'][$fieldModel])) {
                        if (!isset($event['Event'][$fieldModel][0])) {
                            $event['Event'][$fieldModel] = array(0 => $event['Event'][$fieldModel]);
                        }
                        foreach ($event['Event'][$fieldModel] as $object) {
                            foreach ($filterRules[$field][$prefix] as $temp) {
                                if (stripos($object['name'], $temp) !== false) {
                                    $found = true;
                                    break 2;
                                }
                            }
                        }
                    }
                    if ($prefix === 'OR' && !$found) {
                        return false;
                    }
                    if ($prefix !== 'OR' && $found) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private function __filterEventsIndex(array $events, array $feed)
    {
        $filterRules = $this->__prepareFilterRules($feed);
        if (!$filterRules) {
            $filterRules = array();
        }
        foreach ($events as $k => $event) {
            if (isset($event['orgc']) && !isset($event['Orgc'])) { // fix key case
                $event['Orgc'] = $event['orgc'];
                unset($event['orgc']);
                $events[$k] = $event;
            }

            if (isset($filterRules['orgs']['OR']) && !empty($filterRules['orgs']['OR']) && !in_array($event['Orgc']['name'], $filterRules['orgs']['OR'])) {
                unset($events[$k]);
                continue;
            }
            if (isset($filterRules['orgs']['NO']) && !empty($filterRules['orgs']['NOT']) && in_array($event['Orgc']['name'], $filterRules['orgs']['OR'])) {
                unset($events[$k]);
                continue;
            }
            if (isset($filterRules['tags']['OR']) && !empty($filterRules['tags']['OR'])) {
                if (!isset($event['Tag']) || empty($event['Tag'])) {
                    unset($events[$k]);
                }
                $found = false;
                foreach ($event['Tag'] as $tag) {
                    foreach ($filterRules['tags']['OR'] as $filterTag) {
                        if (strpos(strtolower($tag['name']), strtolower($filterTag))) {
                            $found = true;
                        }
                    }
                }
                if (!$found) {
                    unset($k);
                    continue;
                }
            }
            if (isset($filterRules['tags']['NOT']) && !empty($filterRules['tags']['NOT'])) {
                if (isset($event['Tag']) && !empty($event['Tag'])) {
                    $found = false;
                    foreach ($event['Tag'] as $tag) {
                        foreach ($filterRules['tags']['NOT'] as $filterTag) {
                            if (strpos(strtolower($tag['name']), strtolower($filterTag))) {
                                $found = true;
                            }
                        }
                    }
                    if ($found) {
                        unset($k);
                    }
                }
            }
        }
        return $events;
    }

    /**
     * @param array $feed
     * @param string $uuid
     * @param array $user
     * @return array|bool
     * @throws Exception
     */
    public function downloadAndSaveEventFromFeed(array $feed, $uuid, array $user)
    {
        $event = $this->downloadEventFromFeed($feed, $uuid);
        if (!is_array($event) || isset($event['code'])) {
            return false;
        }
        return $this->__saveEvent($event, $user);
    }

    /**
     * @param array $feed
     * @param string $uuid
     * @return bool|string|array
     * @throws Exception
     */
    public function downloadEventFromFeed(array $feed, $uuid)
    {
        $filerRules = $this->__prepareFilterRules($feed);
        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket($feed);
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        return $this->__prepareEvent($event, $feed, $filerRules);
    }

    /**
     * @param array $event
     * @param array $user
     * @return array
     */
    private function __saveEvent(array $event, array $user)
    {
        $this->Event = ClassRegistry::init('Event');
        $existingEvent = $this->Event->find('first', array(
                'conditions' => array('Event.uuid' => $event['Event']['uuid']),
                'recursive' => -1,
                'fields' => array('Event.uuid', 'Event.id', 'Event.timestamp')
        ));
        $result = array();
        if (!empty($existingEvent)) {
            $result['action'] = 'edit';
            if ($existingEvent['Event']['timestamp'] < $event['Event']['timestamp']) {
                $result['result'] = $this->Event->_edit($event, $user);
            } else {
                $result['result'] = 'No change';
            }
        } else {
            $result['action'] = 'add';
            $result['result'] = $this->Event->_add($event, true, $user);
        }
        return $result;
    }

    /**
     * @param array $event
     * @param array $feed
     * @param array $filterRules
     * @return array|string
     */
    private function __prepareEvent($event, array $feed, $filterRules)
    {
        if (isset($event['response'])) {
            $event = $event['response'];
        }
        if (isset($event[0])) {
            $event = $event[0];
        }
        if (!isset($event['Event']['uuid'])) {
            throw new InvalidArgumentException("Event UUID field missing.");
        }
        if (isset($event['Event']['orgc']) && !isset($event['Event']['Orgc'])) { // fix key case
            $event['Event']['Orgc'] = $event['Event']['orgc'];
            unset($event['Event']['orgc']);
        }
        $event['Event']['distribution'] = $feed['Feed']['distribution'];
        $event['Event']['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
        if (!empty($event['Event']['Attribute'])) {
            foreach ($event['Event']['Attribute'] as $key => $attribute) {
                $event['Event']['Attribute'][$key]['distribution'] = 5;
            }
        }
        if ($feed['Feed']['tag_id']) {
            if (!isset($event['Event']['Tag'])) {
                $event['Event']['Tag'] = array();
            }
            $found = false;
            foreach ($event['Event']['Tag'] as $tag) {
                if (strtolower($tag['name']) === strtolower($feed['Tag']['name'])) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $feedTag = $this->Tag->find('first', array('conditions' => array('Tag.id' => $feed['Feed']['tag_id']), 'recursive' => -1, 'fields' => array('Tag.name', 'Tag.colour', 'Tag.exportable')));
                if (!empty($feedTag)) {
                    $event['Event']['Tag'][] = $feedTag['Tag'];
                }
            }
        }
        if ($feed['Feed']['sharing_group_id']) {
            $sg = $this->SharingGroup->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('SharingGroup.id' => $feed['Feed']['sharing_group_id'])
            ));
            if (!empty($sg)) {
                $event['Event']['SharingGroup'] = $sg['SharingGroup'];
            } else {
                // We have an SG ID for the feed, but the SG is gone. Make the event private as a fall-back.
                $event['Event']['distribution'] = 0;
                $event['Event']['sharing_group_id'] = 0;
            }
        }
        if (!$this->__checkIfEventBlockedByFilter($event, $filterRules)) {
            return 'blocked';
        }
        return $event;
    }

    /**
     * @param array $feed
     * @return bool|mixed
     * @throws Exception
     */
    private function __prepareFilterRules($feed)
    {
        $filterRules = false;
        if (isset($feed['Feed']['rules']) && !empty($feed['Feed']['rules'])) {
            $filterRules = json_decode($feed['Feed']['rules'], true);
            if ($filterRules === null) {
                throw new Exception('Could not parse feed filter rules JSON: ' . json_last_error_msg(), json_last_error());
            }
        }
        return $filterRules;
    }

    private function __setupHttpSocket($feed)
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        return $syncTool->setupHttpSocketFeed($feed);
    }

    /**
     * @param HttpSocket|null $HttpSocket
     * @param array $feed
     * @param string $uuid
     * @param array $user
     * @param array|bool $filterRules
     * @return array|bool|string
     * @throws Exception
     */
    private function __addEventFromFeed(HttpSocket $HttpSocket = null, $feed, $uuid, $user, $filterRules)
    {
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        $event = $this->__prepareEvent($event, $feed, $filterRules);
        if (is_array($event)) {
            return $this->Event->_add($event, true, $user);
        } else {
            return $event;
        }
    }

    /**
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @param array $feed
     * @param string $uuid
     * @param int $eventId
     * @param $user
     * @param array|bool $filterRules
     * @return mixed
     * @throws Exception
     */
    private function __updateEventFromFeed(HttpSocket $HttpSocket = null, $feed, $uuid, $eventId, $user, $filterRules)
    {
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        $event = $this->__prepareEvent($event, $feed, $filterRules);
        $this->Event = ClassRegistry::init('Event');
        return $this->Event->_edit($event, $user, $uuid, $jobId = null);
    }

    public function addDefaultFeeds($newFeeds)
    {
        foreach ($newFeeds as $newFeed) {
            $existingFeed = $this->find('list', array('conditions' => array('Feed.url' => $newFeed['url'])));
            $success = true;
            if (empty($existingFeed)) {
                $this->create();
                $feed = array(
                        'name' => $newFeed['name'],
                        'provider' => $newFeed['provider'],
                        'url' => $newFeed['url'],
                        'enabled' => $newFeed['enabled'],
                        'caching_enabled' => !empty($newFeed['caching_enabled']) ? $newFeed['caching_enabled'] : 0,
                        'distribution' => 3,
                        'sharing_group_id' => 0,
                        'tag_id' => 0,
                        'default' => true,
                );
                $result = $this->save($feed) && $success;
            }
        }
        return $success;
    }

    public function downloadFromFeedInitiator($feedId, $user, $jobId = false)
    {
        $this->id = $feedId;
        $this->read();
        if (isset($this->data['Feed']['settings']) && !empty($this->data['Feed']['settings'])) {
            $this->data['Feed']['settings'] = json_decode($this->data['Feed']['settings'], true);
        }

        $HttpSocket = $this->isFeedLocal($this->data) ? null : $this->__setupHttpSocket($this->data);
        if ($this->data['Feed']['source_format'] === 'misp') {
            $this->jobProgress($jobId, 'Fetching event manifest.');
            try {
                $actions = $this->getNewEventUuids($this->data, $HttpSocket);
            } catch (Exception $e) {
                $this->logException("Could not get new event uuids for feed $feedId.", $e);
                $this->jobProgress($jobId, 'Could not fetch event manifest. See error log for more details.');
                return false;
            }

            if (empty($actions['add']) && empty($actions['edit'])) {
                return true;
            }

            $total = count($actions['add']) + count($actions['edit']);
            $this->jobProgress($jobId, __("Fetching %s events.", $total));
            $result = $this->downloadFromFeed($actions, $this->data, $HttpSocket, $user, $jobId);
            $this->__cleanupFile($this->data, '/manifest.json');
        } else {
            $this->jobProgress($jobId, 'Fetching data.');
            try {
                $temp = $this->getFreetextFeed($this->data, $HttpSocket, $this->data['Feed']['source_format'], 'all');
            } catch (Exception $e) {
                $this->logException("Could not get freetext feed $feedId", $e);
                $this->jobProgress($jobId, 'Could not fetch freetext feed. See error log for more details.');
                return false;
            }

            if (empty($temp)) {
                return true;
            }

            $data = array();
            foreach ($temp as $value) {
                $data[] = array(
                    'category' => $value['category'],
                    'type' => $value['default_type'],
                    'value' => $value['value'],
                    'to_ids' => $value['to_ids']
                );
            }

            $this->jobProgress($jobId, 'Saving data.', 50);

            try {
                $result = $this->saveFreetextFeedData($this->data, $data, $user, $jobId);
            } catch (Exception $e) {
                $this->logException("Could not save freetext feed data for feed $feedId.", $e);
                return false;
            }

            $this->__cleanupFile($this->data, '');
        }
        return $result;
    }

    private function __cleanupFile($feed, $file)
    {
        if ($this->isFeedLocal($feed)) {
            if (isset($feed['Feed']['delete_local_file']) && $feed['Feed']['delete_local_file']) {
                if (file_exists($feed['Feed']['url'] . $file)) {
                    unlink($feed['Feed']['url'] . $file);
                }
            }
        }
        return true;
    }

    /**
     * @param array $feed
     * @param array $data
     * @param array $user
     * @param int|bool $jobId
     * @return bool
     * @throws Exception
     */
    public function saveFreetextFeedData(array $feed, array $data, array $user, $jobId = false)
    {
        $this->Event = ClassRegistry::init('Event');

        if ($feed['Feed']['fixed_event'] && $feed['Feed']['event_id']) {
            $event = $this->Event->find('first', array('conditions' => array('Event.id' => $feed['Feed']['event_id']), 'recursive' => -1));
            if (empty($event)) {
                throw new Exception("The target event is no longer valid. Make sure that the target event {$feed['Feed']['event_id']} exists.");
            }
        } else {
            $this->Event->create();
            $orgc_id = $user['org_id'];
            if (!empty($feed['Feed']['orgc_id'])) {
                $orgc_id = $feed['Feed']['orgc_id'];
            }
            $event = array(
                    'info' => $feed['Feed']['name'] . ' feed',
                    'analysis' => 2,
                    'threat_level_id' => 4,
                    'orgc_id' => $orgc_id,
                    'org_id' => $user['org_id'],
                    'date' => date('Y-m-d'),
                    'distribution' => $feed['Feed']['distribution'],
                    'sharing_group_id' => $feed['Feed']['sharing_group_id'],
                    'user_id' => $user['id']
            );
            $result = $this->Event->save($event);
            if (!$result) {
                throw new Exception('Something went wrong while creating a new event.');
            }
            $event = $this->Event->find('first', array('conditions' => array('Event.id' => $this->Event->id), 'recursive' => -1));
            if (empty($event)) {
                throw new Exception("The newly created event is no longer valid. Make sure that the target event {$this->Event->id} exists.");
            }
            if ($feed['Feed']['fixed_event']) {
                $feed['Feed']['event_id'] = $event['Event']['id'];
                if (!empty($feed['Feed']['settings'])) {
                    $feed['Feed']['settings'] = json_encode($feed['Feed']['settings']);
                }
                $this->save($feed);
            }
        }
        if ($feed['Feed']['fixed_event']) {
            $existsAttributesValueToId = $this->Event->Attribute->find('list', array(
                'conditions' => array(
                    'Attribute.deleted' => 0,
                    'Attribute.event_id' => $event['Event']['id']
                ),
                'recursive' => -1,
                'fields' => array('value', 'id')
            ));

            // Create event diff. After this cycle, `$data` will contains just attributes that do not exists in current
            // event and in `$existsAttributesValueToId` will contains just attributes that do not exists in current feed.
            foreach ($data as $k => $dataPoint) {
                if (isset($existsAttributesValueToId[$dataPoint['value']])) {
                    unset($data[$k]);
                    unset($existsAttributesValueToId[$dataPoint['value']]);
                    continue;
                }

                // Because some types can be saved in modified version (for example, IPv6 address is convert to compressed
                // format, we should also check if current event contains modified value.
                $modifiedValue = $this->Event->Attribute->modifyBeforeValidation($dataPoint['type'], $dataPoint['value']);
                if (isset($existsAttributesValueToId[$modifiedValue])) {
                    unset($data[$k]);
                    unset($existsAttributesValueToId[$modifiedValue]);
                }
            }
            if ($feed['Feed']['delta_merge'] && !empty($existsAttributesValueToId)) {
                $attributesToDelete = $this->Event->Attribute->find('all', array(
                    'conditions' => array(
                        'Attribute.id' => array_values($existsAttributesValueToId)
                    ),
                    'recursive' => -1
                ));
                foreach ($attributesToDelete as $k => $attribute) {
                    $attributesToDelete[$k]['Attribute']['deleted'] = 1;
                    unset($attributesToDelete[$k]['Attribute']['timestamp']);
                }
                $this->Event->Attribute->saveMany($attributesToDelete); // We need to trigger callback methods
                if (!empty($attributesToDelete)) {
                    $this->Event->unpublishEvent($feed['Feed']['event_id']);
                }
            }
        }
        if (empty($data) && empty($attributesToDelete)) {
            return true;
        }

        $uniqueValues = array();
        foreach ($data as $key => $value) {
            if (isset($uniqueValues[$value['value']])) {
                unset($data[$key]);
                continue;
            }
            $data[$key]['event_id'] = $event['Event']['id'];
            $data[$key]['distribution'] = $feed['Feed']['distribution'];
            $data[$key]['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
            $data[$key]['to_ids'] = $feed['Feed']['override_ids'] ? 0 : $value['to_ids'];
            $uniqueValues[$value['value']] = true;
        }
        $data = array_values($data);
        foreach ($data as $k => $chunk) {
            $this->Event->Attribute->create();
            $this->Event->Attribute->save($chunk);
            if ($k % 100 === 0) {
                $this->jobProgress($jobId, null, 50 + round(($k + 1) / count($data) * 50));
            }
        }
        if (!empty($data) || !empty($attributesToDelete)) {
            unset($event['Event']['timestamp']);
            unset($event['Event']['attribute_count']);
            $this->Event->save($event);
        }
        if ($feed['Feed']['publish']) {
            $this->Event->publishRouter($event['Event']['id'], null, $user);
        }
        if ($feed['Feed']['tag_id']) {
            $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $feed['Feed']['tag_id']]);
        }
        return true;
    }

    /**
     * @param $user - Not used
     * @param int|bool $jobId
     * @param string $scope
     * @return array
     * @throws Exception
     */
    public function cacheFeedInitiator($user, $jobId = false, $scope = 'freetext')
    {
        $params = array(
            'conditions' => array('caching_enabled' => 1),
            'recursive' => -1,
            'fields' => array('source_format', 'input_source', 'url', 'id', 'settings', 'headers')
        );
        $redis = $this->setupRedisWithException();
        if ($scope !== 'all') {
            if (is_numeric($scope)) {
                $params['conditions']['id'] = $scope;
            } elseif ($scope == 'freetext' || $scope == 'csv') {
                $params['conditions']['source_format'] = array('csv', 'freetext');
            } elseif ($scope == 'misp') {
                $redis->del($redis->keys('misp:feed_cache:event_uuid_lookup:*'));
                $params['conditions']['source_format'] = 'misp';
            } else {
                throw new InvalidArgumentException("Invalid value for scope, it must be integer or 'freetext', 'csv', 'misp' or 'all' string.");
            }
        } else {
            $redis->del('misp:feed_cache:combined');
            $redis->del($redis->keys('misp:feed_cache:event_uuid_lookup:*'));
        }
        $feeds = $this->find('all', $params);

        $results = array('successes' => 0, 'fails' => 0);
        foreach ($feeds as $k => $feed) {
            if ($this->__cacheFeed($feed, $redis, $jobId)) {
                $message = 'Feed ' . $feed['Feed']['id'] . ' cached.';
                $results['successes']++;
            } else {
                $message = 'Failed to cache feed ' . $feed['Feed']['id'] . '. See logs for more details.';
                $results['fails']++;
            }

            $this->jobProgress($jobId, $message, 100 * $k / count($feeds));
        }
        return $results;
    }

    /**
     * @param array $feeds
     * @return array
     */
    public function attachFeedCacheTimestamps(array $feeds)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return $feeds;
        }

        $pipe = $redis->multi(Redis::PIPELINE);
        foreach ($feeds as $feed) {
            $pipe->get('misp:feed_cache_timestamp:' . $feed['Feed']['id']);
        }
        $result = $redis->exec();
        foreach ($feeds as $k => $feed) {
            $feeds[$k]['Feed']['cache_timestamp'] = $result[$k];
        }
        return $feeds;
    }

    private function __cacheFeed($feed, $redis, $jobId = false)
    {
        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket($feed);
        if ($feed['Feed']['source_format'] === 'misp') {
            return $this->__cacheMISPFeed($feed, $redis, $HttpSocket, $jobId);
        } else {
            return $this->__cacheFreetextFeed($feed, $redis, $HttpSocket, $jobId);
        }
    }

    /**
     * @param array $feed
     * @param Redis $redis
     * @param HttpSocket|null $HttpSocket
     * @param int|false $jobId
     * @return bool
     */
    private function __cacheFreetextFeed(array $feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];

        $this->jobProgress($jobId, __("Feed %s: Fetching.", $feedId));

        try {
            $values = $this->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format'], 'all');
        } catch (Exception $e) {
            $this->logException("Could not get freetext feed $feedId", $e);
            $this->jobProgress($jobId, __('Could not fetch freetext feed %s. See error log for more details.', $feedId));
            return false;
        }

        // Convert values to MD5 hashes
        $md5Values = array_map('md5', array_column($values, 'value'));

        $redis->del('misp:feed_cache:' . $feedId);
        foreach (array_chunk($md5Values, 5000) as $k => $chunk) {
            $pipe = $redis->multi(Redis::PIPELINE);
            if (method_exists($redis, 'sAddArray')) {
                $redis->sAddArray('misp:feed_cache:' . $feedId, $chunk);
                $redis->sAddArray('misp:feed_cache:combined', $chunk);
            } else {
                foreach ($chunk as $value) {
                    $redis->sAdd('misp:feed_cache:' . $feedId, $value);
                    $redis->sAdd('misp:feed_cache:combined', $value);
                }
            }
            $pipe->exec();
            $this->jobProgress($jobId, __('Feed %s: %s/%s values cached.', $feedId, $k * 5000, count($md5Values)));
        }
        $redis->set('misp:feed_cache_timestamp:' . $feedId, time());
        return true;
    }

    private function __cacheMISPFeedTraditional($feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];
        try {
            $manifest = $this->getManifest($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->logException("Could not get manifest for feed $feedId.", $e);
            return false;
        }

        $redis->del('misp:feed_cache:' . $feedId);

        $k = 0;
        foreach ($manifest as $uuid => $event) {
            try {
                $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
            } catch (Exception $e) {
                $this->logException("Could not get and parse event '$uuid' for feed $feedId.", $e);
                return false;
            }

            if (!empty($event['Event']['Attribute'])) {
                $this->Attribute = ClassRegistry::init('Attribute');
                $pipe = $redis->multi(Redis::PIPELINE);
                foreach ($event['Event']['Attribute'] as $attribute) {
                    if (!in_array($attribute['type'], $this->Attribute->nonCorrelatingTypes)) {
                        if (in_array($attribute['type'], $this->Attribute->getCompositeTypes())) {
                            $value = explode('|', $attribute['value']);
                            if (in_array($attribute['type'], $this->Attribute->primaryOnlyCorrelatingTypes)) {
                                unset($value[1]);
                            }
                        } else {
                            $value = [$attribute['value']];
                        }

                        foreach ($value as $v) {
                            $md5 = md5($v);
                            $redis->sAdd('misp:feed_cache:' . $feedId, $md5);
                            $redis->sAdd('misp:feed_cache:combined', $md5);
                            $redis->sAdd('misp:feed_cache:event_uuid_lookup:' . $md5, $feedId . '/' . $event['Event']['uuid']);
                        }
                    }
                }
                $pipe->exec();
            }

            $k++;
            if ($k % 10 == 0) {
                $this->jobProgress($jobId, "Feed $feedId: $k/" . count($manifest) . " events cached.");
            }
        }
        return true;
    }

    private function __cacheMISPFeedCache($feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];

        try {
            $cache = $this->getCache($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->logException("Could not get cache file for $feedId.", $e, LOG_NOTICE);
            return false;
        }

        $pipe = $redis->multi(Redis::PIPELINE);
        $redis->del('misp:feed_cache:' . $feedId);
        foreach ($cache as $v) {
            list($hash, $eventUuid) = $v;
            $redis->sAdd('misp:feed_cache:' . $feedId, $hash);
            $redis->sAdd('misp:feed_cache:combined', $hash);
            $redis->sAdd('misp:feed_cache:event_uuid_lookup:' . $hash, "$feedId/$eventUuid");
        }
        $pipe->exec();
        $this->jobProgress($jobId, "Feed $feedId: cached via quick cache.");
        return true;
    }

    private function __cacheMISPFeed($feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $result = true;
        if (!$this->__cacheMISPFeedCache($feed, $redis, $HttpSocket, $jobId)) {
            $result = $this->__cacheMISPFeedTraditional($feed, $redis, $HttpSocket, $jobId);
        }
        if ($result) {
            $redis->set('misp:feed_cache_timestamp:' . $feed['Feed']['id'], time());
        }
        return $result;
    }

    public function compareFeeds($id = false)
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return array();
        }
        $fields = array('id', 'input_source', 'source_format', 'url', 'provider', 'name', 'default');
        $feeds = $this->find('all', array(
            'recursive' => -1,
            'fields' => $fields,
            'conditions' => array('Feed.caching_enabled' => 1)
        ));
        // we'll use this later for the intersect
        $fields[] = 'values';
        $fields = array_flip($fields);
        // Get all of the feed cache cardinalities for all feeds - if a feed is not cached remove it from the list
        foreach ($feeds as $k => $feed) {
            if (!$redis->exists('misp:feed_cache:' . $feed['Feed']['id'])) {
                unset($feeds[$k]);
                continue;
            }
            $feeds[$k]['Feed']['values'] = $redis->sCard('misp:feed_cache:' . $feed['Feed']['id']);
        }
        $feeds = array_values($feeds);
        $this->Server = ClassRegistry::init('Server');
        $servers = $this->Server->find('all', array(
            'recursive' => -1,
            'fields' => array('id', 'url', 'name'),
            'contain' => array('RemoteOrg' => array('fields' => array('RemoteOrg.id', 'RemoteOrg.name'))),
            'conditions' => array('Server.caching_enabled' => 1)
        ));
        foreach ($servers as $k => $server) {
            if (!$redis->exists('misp:server_cache:' . $server['Server']['id'])) {
                unset($servers[$k]);
                continue;
            }
            $servers[$k]['Server']['input_source'] = 'network';
            $servers[$k]['Server']['source_format'] = 'misp';
            $servers[$k]['Server']['provider'] = $servers[$k]['RemoteOrg']['name'];
            $servers[$k]['Server']['default'] = false;
            $servers[$k]['Server']['is_misp_server'] = true;
            $servers[$k]['Server']['values'] = $redis->sCard('misp:server_cache:' . $server['Server']['id']);
        }
        foreach ($feeds as $k => $feed) {
            foreach ($feeds as $k2 => $feed2) {
                if ($k == $k2) {
                    continue;
                }
                $intersect = $redis->sInter('misp:feed_cache:' . $feed['Feed']['id'], 'misp:feed_cache:' . $feed2['Feed']['id']);
                $feeds[$k]['Feed']['ComparedFeed'][] = array_merge(array_intersect_key($feed2['Feed'], $fields), array(
                    'overlap_count' => count($intersect),
                    'overlap_percentage' => round(100 * count($intersect) / $feeds[$k]['Feed']['values']),
                ));
            }
            foreach ($servers as $k2 => $server) {
                $intersect = $redis->sInter('misp:feed_cache:' . $feed['Feed']['id'], 'misp:server_cache:' . $server['Server']['id']);
                $feeds[$k]['Feed']['ComparedFeed'][] = array_merge(array_intersect_key($server['Server'], $fields), array(
                    'overlap_count' => count($intersect),
                    'overlap_percentage' => round(100 * count($intersect) / $feeds[$k]['Feed']['values']),
                ));
            }
        }
        foreach ($servers as $k => $server) {
            foreach ($feeds as $k2 => $feed2) {
                $intersect = $redis->sInter('misp:server_cache:' . $server['Server']['id'], 'misp:feed_cache:' . $feed2['Feed']['id']);
                $servers[$k]['Server']['ComparedFeed'][] = array_merge(array_intersect_key($feed2['Feed'], $fields), array(
                    'overlap_count' => count($intersect),
                    'overlap_percentage' => round(100 * count($intersect) / $servers[$k]['Server']['values']),
                ));
            }
            foreach ($servers as $k2 => $server2) {
                if ($k == $k2) {
                    continue;
                }
                $intersect = $redis->sInter('misp:server_cache:' . $server['Server']['id'], 'misp:server_cache:' . $server2['Server']['id']);
                $servers[$k]['Server']['ComparedFeed'][] = array_merge(array_intersect_key($server2['Server'], $fields), array(
                    'overlap_count' => count($intersect),
                    'overlap_percentage' => round(100 * count($intersect) / $servers[$k]['Server']['values']),
                ));
            }
        }
        foreach ($servers as $k => $server) {
            $server['Feed'] = $server['Server'];
            unset($server['Server']);
            $feeds[] = $server;
        }
        return $feeds;
    }

    public function importFeeds($feeds, $user, $default = false)
    {
        if (is_string($feeds)) {
            $feeds = json_decode($feeds, true);
        }
        if ($feeds && !isset($feeds[0])) {
            $feeds = array($feeds);
        }
        $results = array('successes' => 0, 'fails' => 0);
        if (empty($feeds)) {
            return $results;
        }
        $existingFeeds = $this->find('all', array());
        foreach ($feeds as $feed) {
            if ($default) {
                $feed['Feed']['default'] = 1;
            } else {
                $feed['Feed']['default'] = 0;
            }
            if (isset($feed['Feed']['id'])) {
                unset($feed['Feed']['id']);
            }
            $found = false;
            foreach ($existingFeeds as $existingFeed) {
                if ($existingFeed['Feed']['url'] == $feed['Feed']['url']) {
                    $found = true;
                }
            }
            if (!$found) {
                $feed['Feed']['tag_id'] = 0;
                if (isset($feed['Tag'])) {
                    $tag_id = $this->Tag->captureTag($feed['Tag'], $user);
                    if ($tag_id) {
                        $feed['Feed']['tag_id'] = $tag_id;
                    }
                }
                $this->create();
                if (!$this->save($feed, true, array('name', 'provider', 'url', 'rules', 'source_format', 'fixed_event', 'delta_merge', 'override_ids', 'publish', 'settings', 'tag_id', 'default', 'lookup_visible', 'headers'))) {
                    $results['fails']++;
                } else {
                    $results['successes']++;
                }
            }
        }
        return $results;
    }

    public function load_default_feeds()
    {
        $user = array('Role' => array('perm_tag_editor' => 1, 'perm_site_admin' => 1));
        $json = file_get_contents(APP . 'files/feed-metadata/defaults.json');
        $this->importFeeds($json, $user, true);
        return true;
    }

    public function setEnableFeedCachingDefaults()
    {
        $feeds = $this->find('all', array(
            'conditions' => array(
                'Feed.enabled' => 1
            ),
            'recursive' => -1
        ));
        if (empty($feeds)) {
            return true;
        }
        foreach ($feeds as $feed) {
            $feed['Feed']['caching_enabled'] = 1;
            $this->save($feed);
        }
        return true;
    }

    public function getFeedCoverage($id, $source_scope = 'feed', $dataset = 'all')
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return 'Could not reach Redis.';
        }
        $this->Server = ClassRegistry::init('Server');
        $feed_conditions = array('Feed.caching_enabled' => 1);
        $server_conditions = array('Server.caching_enabled' => 1);
        if ($source_scope === 'feed') {
            $feed_conditions['NOT'] = array('Feed.id' => $id);
        } else {
            $server_conditions['NOT'] = array('Server.id' => $id);
        }
        if ($dataset !== 'all') {
            if (empty($dataset['Feed'])) {
                $feed_conditions['OR'] = array('Feed.id' => -1);
            } else {
                $feed_conditions['OR'] = array('Feed.id' => $dataset['Feed']);
            }
            if (empty($dataset['Server'])) {
                $server_conditions['OR'] = array('Server.id' => -1);
            } else {
                $server_conditions['OR'] = array('Server.id' => $dataset['Server']);
            }
        }
        $other_feeds = $this->find('list', array(
            'recursive' => -1,
            'conditions' => $feed_conditions,
            'fields' => array('Feed.id', 'Feed.id')
        ));
        $other_servers = $this->Server->find('list', array(
            'recursive' => -1,
            'conditions' => $server_conditions,
            'fields' => array('Server.id', 'Server.id')
        ));
        $feed_element_count = $redis->scard('misp:feed_cache:' . $id);
        $temp_store = (new RandomTool())->random_str(false, 12);
        $params = array('misp:feed_temp:' . $temp_store);
        foreach ($other_feeds as $other_feed) {
            $params[] = 'misp:feed_cache:' . $other_feed;
        }
        foreach ($other_servers as $other_server) {
            $params[] = 'misp:server_cache:' . $other_server;
        }
        if (count($params) != 1 && $feed_element_count > 0) {
            call_user_func_array(array($redis, 'sunionstore'), $params);
            call_user_func_array(array($redis, 'sinterstore'), array('misp:feed_temp:' . $temp_store . '_intersect', 'misp:feed_cache:' . $id, 'misp:feed_temp:' . $temp_store));
            $cardinality_intersect = $redis->scard('misp:feed_temp:' . $temp_store . '_intersect');
            $coverage = round(100 * $cardinality_intersect / $feed_element_count, 2);
            $redis->del('misp:feed_temp:' . $temp_store);
            $redis->del('misp:feed_temp:' . $temp_store . '_intersect');
        } else {
            $coverage = 0;
        }
        return $coverage;
    }

    public function getCachedElements($feedId)
    {
        $redis = $this->setupRedis();
        $cardinality = $redis->sCard('misp:feed_cache:' . $feedId);
        return $cardinality;
    }

    public function getAllCachingEnabledFeeds($feedId, $intersectingOnly = false) {
        if ($intersectingOnly) {
            $redis = $this->setupRedis();
        }
        $result['Feed'] = $this->find('all', array(
            'conditions' => array(
                'Feed.id !=' => $feedId,
                'caching_enabled' => 1
            ),
            'recursive' => -1,
            'fields' => array('Feed.id', 'Feed.name', 'Feed.url')
        ));
        $this->Server = ClassRegistry::init('Server');
        $result['Server'] = $this->Server->find('all', array(
            'conditions' => array(
                'caching_enabled' => 1
            ),
            'recursive' => -1,
            'fields' => array('Server.id', 'Server.name', 'Server.url')
        ));
        $scopes = array('Feed', 'Server');
        foreach ($scopes as $scope) {
            foreach ($result[$scope] as $k => $v) {
                $result[$scope][$k] = $v[$scope];
            }
        }
        if ($intersectingOnly) {
            foreach ($scopes as $scope) {
                if (!empty($result[$scope])) {
                    foreach ($result[$scope] as $k => $feed) {
                        $intersect = $redis->sInter('misp:feed_cache:' . $feedId, 'misp:' . lcfirst($scope) . '_cache:' . $feed['id']);
                        if (empty($intersect)) {
                            unset($result[$scope][$k]);
                        } else {
                            $result[$scope][$k]['matching_values'] = count($intersect);
                        }
                    }
                }
            }
        }
        return $result;
    }

    public function searchCaches($value)
    {
        $hits = array();
        $this->Server = ClassRegistry::init('Server');
        $result['Server'] = $this->Server->find('all', array(
            'conditions' => array(
                'caching_enabled' => 1
            ),
            'recursive' => -1,
            'fields' => array('Server.id', 'Server.name', 'Server.url')
        ));
        $redis = $this->setupRedis();
        $is_array = true;
        if (!is_array($value)) {
            $is_array = false;
            if (empty($value)) {
                // old behaviour allowd for empty values to return all data
                $value = [false];
            } else {
                $value = [$value];
            }
        }
        foreach ($value as $v) {
            if ($v !== false) {
                $v = strtolower(trim($v));
            }
            if ($v === false || $redis->sismember('misp:feed_cache:combined', md5($v))) {
                $feeds = $this->find('all', array(
                    'conditions' => array(
                        'caching_enabled' => 1
                    ),
                    'recursive' => -1,
                    'fields' => array('Feed.id', 'Feed.name', 'Feed.url', 'Feed.source_format')
                ));
                foreach ($feeds as $feed) {
                    if (($v === false) || $redis->sismember('misp:feed_cache:' . $feed['Feed']['id'], md5($v))) {
                        if ($feed['Feed']['source_format'] === 'misp') {
                            $uuid = $redis->smembers('misp:feed_cache:event_uuid_lookup:' . md5($v));
                            foreach ($uuid as $k => $url) {
                                $uuid[$k] = explode('/', $url)[1];
                            }
                            $feed['Feed']['uuid'] = $uuid;
                            if (!empty($feed['Feed']['uuid'])) {
                                foreach ($feed['Feed']['uuid'] as $uuid) {
                                    $feed['Feed']['direct_urls'][] = array(
                                        'url' => sprintf(
                                            '%s/feeds/previewEvent/%s/%s',
                                            Configure::read('MISP.baseurl'),
                                            h($feed['Feed']['id']),
                                            h($uuid)
                                        ),
                                        'name' => __('Event %s', $uuid)
                                    );
                                }
                            }
                            $feed['Feed']['type'] = 'MISP Feed';
                        } else {
                            $feed['Feed']['type'] = 'Feed';
                            if (!empty($v)) {
                                $feed['Feed']['direct_urls'][] = array(
                                    'url' => sprintf(
                                        '%s/feeds/previewIndex/%s',
                                        Configure::read('MISP.baseurl'),
                                        h($feed['Feed']['id'])
                                    ),
                                    'name' => __('Feed %s', $feed['Feed']['id'])
                                );
                            }
                        }
                        if ($is_array) {
                            $hits[$v][] = $feed;
                        } else {
                            $hits[] = $feed;
                        }
                    }
                }
            }
            if ($v === false || $redis->sismember('misp:server_cache:combined', md5($v))) {
                $this->Server = ClassRegistry::init('Server');
                $servers = $this->Server->find('all', array(
                    'conditions' => array(
                        'caching_enabled' => 1
                    ),
                    'recursive' => -1,
                    'fields' => array('Server.id', 'Server.name', 'Server.url')
                ));
                foreach ($servers as $server) {
                    if ($v === false || $redis->sismember('misp:server_cache:' . $server['Server']['id'], md5($v))) {
                        $uuid = $redis->smembers('misp:server_cache:event_uuid_lookup:' . md5($v));
                        if (!empty($uuid)) {
                            foreach ($uuid as $k => $url) {
                                $uuid[$k] = explode('/', $url)[1];
                                $server['Server']['direct_urls'][] = array(
                                    'url' => sprintf(
                                        '%s/servers/previewEvent/%s/%s',
                                        Configure::read('MISP.baseurl'),
                                        h($server['Server']['id']),
                                        h($uuid[$k])
                                    ),
                                    'name' => __('Event %s', h($uuid[$k]))
                                );
                            }
                        }
                        $server['Server']['uuid'] = $uuid;
                        $server['Server']['type'] = 'MISP Server';
                        if ($is_array) {
                            $hits[$v][] = array('Feed' => $server['Server']);
                        } else {
                            $hits[] = array('Feed' => $server['Server']);
                        }
                    }
                }
            }
        }
        return $hits;
    }

    /**
     * Download and parse event from feed.
     *
     * @param array $feed
     * @param string $eventUuid
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    private function downloadAndParseEventFromFeed($feed, $eventUuid, HttpSocket $HttpSocket = null)
    {
        if (!Validation::uuid($eventUuid)) {
            throw new InvalidArgumentException("Given event UUID '$eventUuid' is invalid.");
        }

        $path = $feed['Feed']['url'] . '/' . $eventUuid . '.json';
        $data = $this->feedGetUri($feed, $path, $HttpSocket);

        try {
            return $this->jsonDecode($data);
        } catch (Exception $e) {
            throw new Exception("Could not parse event JSON with UUID '$eventUuid' from feed", 0, $e);
        }
    }

    /**
     * @param array $feed
     * @param string $uri
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @param bool $followRedirect
     * @return string
     * @throws Exception
     */
    private function feedGetUri($feed, $uri, HttpSocket $HttpSocket = null, $followRedirect = false)
    {
        if ($this->isFeedLocal($feed)) {
            if (file_exists($uri)) {
                $data = file_get_contents($uri);
                if ($data === false) {
                    throw new Exception("Could not read local file '$uri'.");
                }
                return $data;
            } else {
                throw new Exception("Local file '$uri' doesn't exists.");
            }
        }

        if ($HttpSocket === null) {
            throw new Exception("Feed {$feed['Feed']['name']} is not local, but HttpSocket is not initialized.");
        }

        $request = $this->__createFeedRequest($feed['Feed']['headers']);

        try {
            if ($followRedirect) {
                $response = $this->getFollowRedirect($HttpSocket, $uri, $request);
            } else {
                $response = $HttpSocket->get($uri, array(), $request);
            }
        } catch (Exception $e) {
            throw new Exception("Fetching the '$uri' failed with exception: {$e->getMessage()}", 0, $e);
        }

        if ($response->code != 200) { // intentionally !=
            throw new Exception("Fetching the '$uri' failed with HTTP error {$response->code}: {$response->reasonPhrase}");
        }

        $data = $response->body;

        $contentType = $response->getHeader('Content-Type');
        if ($contentType === 'application/zip') {
            $zipFile = new File($this->tempFileName());
            $zipFile->write($data);
            $zipFile->close();

            try {
                $data = $this->unzipFirstFile($zipFile);
            } catch (Exception $e) {
                throw new Exception("Fetching the '$uri' failed: {$e->getMessage()}");
            } finally {
                $zipFile->delete();
            }
        }

        return $data;
    }

    /**
     * It should be possible to use 'redirect' $request attribute, but because HttpSocket contains bug that require
     * certificate for first domain even when redirect to another domain, we need to use own solution.
     *
     * @param HttpSocket $HttpSocket
     * @param string $url
     * @param array $request
     * @param int $iterations
     * @return false|HttpSocketResponse
     * @throws Exception
     */
    private function getFollowRedirect(HttpSocket $HttpSocket, $url, $request, $iterations = 5)
    {
        for ($i = 0; $i < $iterations; $i++) {
            $response = $HttpSocket->get($url, array(), $request);
            if ($response->isRedirect()) {
                $HttpSocket = $this->__setupHttpSocket(null); // Replace $HttpSocket with fresh instance
                $url = trim($response->getHeader('Location'), '=');
            } else {
                return $response;
            }
        }

        throw new Exception("Maximum number of iteration reached.");
    }

    /**
     * @param array $feed
     * @return bool
     */
    private function isFeedLocal($feed)
    {
        return isset($feed['Feed']['input_source']) && $feed['Feed']['input_source'] === 'local';
    }

    /**
     * @param int|null $jobId
     * @param string|null $message
     * @param int|null $progress
     */
    private function jobProgress($jobId = null, $message = null, $progress = null)
    {
        if ($jobId) {
            if (!isset($this->Job)) {
                $this->Job = ClassRegistry::init('Job');
            }
            $this->Job->saveProgress($jobId, $message, $progress);
        }
    }

    /**
     * remove all events tied to a feed. Returns int on success, error message
     * as string on failure
     */
    public function cleanupFeedEvents($user_id, $id)
    {
        $feed = $this->find('first', array(
            'conditions' => array('Feed.id' => $id),
            'recursive' => -1
        ));
        if (empty($feed)) {
            return __('Invalid feed id.');
        }
        if (!in_array($feed['Feed']['source_format'], array('csv', 'freetext'))) {
            return __('Feed has to be either a CSV or a freetext feed for the purging to work.');
        }
        $this->User = ClassRegistry::init('User');
        $user = $this->User->getAuthUser($user_id);
        if (empty($user)) {
            return __('Invalid user id.');
        }
        $conditions = array('Event.info' => $feed['Feed']['name'] . ' feed');
        $this->Event = ClassRegistry::init('Event');
        $events = $this->Event->find('list', array(
            'conditions' => $conditions,
            'fields' => array('Event.id', 'Event.id')
        ));
        $count = count($events);
        foreach ($events as $event_id) {
            $this->Event->delete($event_id);
        }
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
                'org' => 'SYSTEM',
                'model' => 'Feed',
                'model_id' => $id,
                'email' => $user['email'],
                'action' => 'purge_events',
                'title' => __('Events related to feed %s purged.', $id),
                'change' => null,
        ));
        $feed['Feed']['fixed_event'] = 1;
        $feed['Feed']['event_id'] = 0;
        $this->save($feed);
        return $count;
    }

    /**
     * @param File $zipFile
     * @return string Uncompressed data
     * @throws Exception
     */
    private function unzipFirstFile(File $zipFile)
    {
        if (!class_exists('ZipArchive')) {
            throw new Exception('ZIP archive decompressing is not supported. ZIP extension is missing in PHP.');
        }

        $zip = new ZipArchive();
        $result = $zip->open($zipFile->pwd());
        if ($result !== true) {
            $errorCodes = [
                ZipArchive::ER_EXISTS => 'file already exists',
                ZipArchive::ER_INCONS => 'zip archive inconsistent',
                ZipArchive::ER_INVAL => 'invalid argument',
                ZipArchive::ER_MEMORY => 'malloc failure',
                ZipArchive::ER_NOENT => 'no such file',
                ZipArchive::ER_NOZIP => 'not a zip archive',
                ZipArchive::ER_OPEN => 'can\'t open file',
                ZipArchive::ER_READ => 'read error',
                ZipArchive::ER_SEEK => 'seek error',
            ];
            $message = isset($errorCodes[$result]) ? $errorCodes[$result] : 'error ' . $result;
            throw new Exception("Remote server returns ZIP file, that cannot be open ($message)");
        }

        if ($zip->numFiles !== 1) {
            throw new Exception("Remote server returns ZIP file, that contains multiple files.");
        }

        $filename = $zip->getNameIndex(0);
        if ($filename === false) {
            throw new Exception("Remote server returns ZIP file, but there is a problem with reading filename.");
        }

        $zip->close();

        $destinationFile = $this->tempFileName();
        $result = copy("zip://{$zipFile->pwd()}#$filename", $destinationFile);
        if ($result === false) {
            throw new Exception("Remote server returns ZIP file, that contains '$filename' file, but this file cannot be extracted.");
        }

        $unzipped = new File($destinationFile);
        $data = $unzipped->read();
        if ($data === false) {
            throw new Exception("Couldn't read extracted file content.");
        }
        $unzipped->delete();
        return $data;
    }
}
