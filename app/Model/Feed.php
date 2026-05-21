<?php

use MaxMind\Exception\InvalidInputException;

App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('AttributeValidationTool', 'Tools');

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
        ),
        'stix' => array(
            'name' => 'STIX Feed'
        )
    );

    const DEFAULT_FEED_PULL_RULES = [
        'tags' => [
            "OR" => [],
            "NOT" => [],
        ],
        'orgs' => [
            "OR" => [],
            "NOT" => [],
        ],
        'url_params' => ''
    ];

    const SUPPORTED_URL_PARAM_FILTERS = [
        'timestamp',
        'publish_timestamp',
    ];

    const CACHE_DIR = APP . 'tmp' . DS . 'cache' . DS . 'feeds' . DS;

    /*
     *  Cleanup of empty belongsTo relationships
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

    public function afterSave($created, $options = array())
    {
        if (!$created) {
            $this->cleanFileCache($this->data['Feed']['id']);
        }
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
            $path = mb_ereg_replace("/\:\/\//", '', $this->data['Feed']['url']);
            if ($this->data['Feed']['source_format'] == 'misp') {
                if (!is_dir($path)) {
                    return 'For MISP type local feeds, please specify the containing directory.';
                }
            } elseif ($this->data['Feed']['source_format'] == 'stix') {
                if (!file_exists($path)) {
                    return 'Invalid path or file/directory not found. For STIX feeds you can specify either a file or a directory containing STIX files.';
                }
            } else {
                if (!file_exists($path)) {
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

    private function checkEventAgainstRules(array $event, array $rules): bool
    {
        $tags = [];
        if (!empty($event['Tag'])) {
            $tags = Hash::extract($event, 'Tag.{n}.name');
        }

        // Check the tag rules
        if (!empty($rules['tags']['OR'])) {
            if (empty(array_intersect($rules['tags']['OR'], $tags))) {
                return false;
            }
        }
        if (!empty($rules['tags']['NOT'])) {
            if (!empty(array_intersect($rules['tags']['NOT'], $tags))) {
                return false;
            }
        }

        // check the org rules
        if (!empty($rules['orgs']['OR'])) {
            if (!in_array($event['Orgc']['uuid'], $rules['orgs']['OR']) && !in_array($event['Orgc']['name'], $rules['orgs']['OR'])) {
                return false;
            }
        }

        if (!empty($rules['orgs']['NOT'])) {
            if (in_array($event['Orgc']['uuid'], $rules['orgs']['NOT']) || in_array($event['Orgc']['name'], $rules['orgs']['NOT'])) {
                return false;
            }
        }

        //check misc rules
        $url_params = empty($rules['url_params']) ? null : json_decode($rules['url_params'], true);
        if ($url_params) {
            if (isset($url_params['timestamp'])) {
                $timestamp = $this->resolveTimeDelta($url_params['timestamp']);
                if ($event['timestamp'] < $timestamp) {
                    return false;
                }
            }
        }
        return true;
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
        $manifest = $this->isFeedLocal($feed) ? $this->downloadManifest($feed) : $this->getRemoteManifest($feed, $HttpSocket);
        $this->Event = ClassRegistry::init('Event');
        $rules = json_decode($feed['Feed']['rules'], true);
        if ($rules != NULL) {
            foreach ($manifest as $k => $event) {
                if (!$this->checkEventAgainstRules($event, $rules)) {
                    unset($manifest[$k]);
                }
            }
        }
        $events = $this->Event->find('all', array(
            'conditions' => array(
                'Event.uuid' => array_keys($manifest),
            ),
            'recursive' => -1,
            'fields' => array('Event.uuid', 'Event.timestamp')
        ));
        $result = array('add' => array(), 'edit' => array());
        foreach ($events as $event) {
            $eventUuid = $event['Event']['uuid'];
            if ($event['Event']['timestamp'] < $manifest[$eventUuid]['timestamp']) {
                $result['edit'][] = $eventUuid;
            } else {
                $this->__cleanupFile($feed, '/' . $eventUuid . '.json');
            }
            unset($manifest[$eventUuid]);
        }
        // Rest events in manifest don't exist, they will be added
        $result['add'] = array_keys($manifest);
        return $result;
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return Generator<string>
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
        $data = $this->feedGetUri($feed, $manifestUrl, $HttpSocket);

        try {
            return JsonTool::decodeArray($data);
        } catch (Exception $e) {
            throw new Exception("Could not parse '$manifestUrl' manifest JSON", 0, $e);
        }
    }

    /**
     * @param int $feedId
     */
    private function cleanFileCache($feedId)
    {
        $cacheFiles = [
            "misp_feed_{$feedId}_manifest.cache.gz",
            "misp_feed_{$feedId}_manifest.cache",
            "misp_feed_{$feedId}_manifest.etag",
            "misp_feed_$feedId.cache.gz",
            "misp_feed_$feedId.cache", // old file name
            "misp_feed_$feedId.etag",
        ];
        foreach ($cacheFiles as $fileName) {
            FileAccessTool::deleteFileIfExists(self::CACHE_DIR . $fileName);
        }
    }

    /**
     * Get remote manifest for feed with etag checking.
     * @param array $feed
     * @param HttpSocketExtended $HttpSocket
     * @return array
     * @throws HttpSocketHttpException
     * @throws JsonException
     */
    private function getRemoteManifest(array $feed, HttpSocketExtended $HttpSocket)
    {
        $feedCache = self::CACHE_DIR . 'misp_feed_' . (int)$feed['Feed']['id'] . '_manifest.cache.gz';
        $feedCacheEtag = self::CACHE_DIR . 'misp_feed_' . (int)$feed['Feed']['id'] . '_manifest.etag';

        $etag = null;
        if (file_exists($feedCache) && file_exists($feedCacheEtag)) {
            $etag = file_get_contents($feedCacheEtag);
        }

        $manifestUrl = $feed['Feed']['url'] . '/manifest.json';

        try {
            $response = $this->feedGetUriRemote($feed, $manifestUrl, $HttpSocket, $etag);
        } catch (HttpSocketHttpException $e) {
            if ($e->getCode() === 304) { // not modified
                try {
                    return JsonTool::decodeArray(FileAccessTool::readCompressedFile($feedCache));
                } catch (Exception $e) {
                    return $this->feedGetUriRemote($feed, $manifestUrl, $HttpSocket)->json(); // cache file is not readable, fetch without etag
                }
            } else {
                throw $e;
            }
        }

        if ($response->getHeader('etag')) {
            try {
                FileAccessTool::writeCompressedFile($feedCache, $response->body);
                FileAccessTool::writeToFile($feedCacheEtag, $response->getHeader('etag'));
            } catch (Exception $e) {
                FileAccessTool::deleteFileIfExists($feedCacheEtag);
                $this->logException("Could not save file `$feedCache` to cache.", $e, LOG_NOTICE);
            }
        } else {
            FileAccessTool::deleteFileIfExists($feedCacheEtag);
        }

        return $response->json();
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    public function getManifest(array $feed, HttpSocket $HttpSocket = null)
    {
        $events = $this->isFeedLocal($feed) ? $this->downloadManifest($feed) : $this->getRemoteManifest($feed, $HttpSocket);
        $events = $this->__filterEventsIndex($events, $feed);
        return $events;
    }

    /**
     * Load remote file with cache support and etag checking.
     * @param array $feed
     * @param HttpSocket $HttpSocket
     * @return string
     * @throws HttpSocketHttpException
     */
    private function getFreetextFeedRemote(array $feed, HttpSocket $HttpSocket)
    {
        $feedCache = self::CACHE_DIR . 'misp_feed_' . (int)$feed['Feed']['id'] . '.cache.gz';
        $feedCacheEtag = self::CACHE_DIR . 'misp_feed_' . (int)$feed['Feed']['id'] . '.etag';

        $etag = null;
        if (file_exists($feedCache)) {
            if (time() - filemtime($feedCache) < 600) {
                try {
                    return FileAccessTool::readCompressedFile($feedCache);
                } catch (Exception $e) {
                    // ignore
                }
            } else if (file_exists($feedCacheEtag)) {
                $etag = file_get_contents($feedCacheEtag);
            }
        }

        try {
            $response = $this->feedGetUriRemote($feed, $feed['Feed']['url'], $HttpSocket, $etag);
        } catch (HttpSocketHttpException $e) {
            if ($e->getCode() === 304) { // not modified
                try {
                    return FileAccessTool::readCompressedFile($feedCache);
                } catch (Exception $e) {
                    return $this->feedGetUriRemote($feed, $feed['Feed']['url'], $HttpSocket); // cache file is not readable, fetch without etag
                }
            } else {
                throw $e;
            }
        }

        try {
            FileAccessTool::writeCompressedFile($feedCache, $response->body);
            if ($response->getHeader('etag')) {
                FileAccessTool::writeToFile($feedCacheEtag, $response->getHeader('etag'));
            }
        } catch (Exception $e) {
            FileAccessTool::deleteFileIfExists($feedCacheEtag);
            $this->logException("Could not save file `$feedCache` to cache.", $e, LOG_NOTICE);
        }

        return $response->body;
    }

    /**
     * @param array $feed
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @param string $type
     * @return array|bool
     * @throws Exception
     */
    public function getFreetextFeed($feed, HttpSocket $HttpSocket = null, $type = 'freetext')
    {
        if ($this->isFeedLocal($feed)) {
            $feedUrl = $feed['Feed']['url'];
            $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket);
        } else {
            $data = $this->getFreetextFeedRemote($feed, $HttpSocket);
        }

        App::uses('ComplexTypeTool', 'Tools');
        $complexTypeTool = new ComplexTypeTool();
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
        $complexTypeTool->setSecurityVendorDomains($this->Warninglist->fetchSecurityVendorDomains());
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
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $typeDefinitions = $this->Attribute->typeDefinitions;
        foreach ($resultArray as &$value) {
            $definition = $typeDefinitions[$value['default_type']];
            $value['category'] = $definition['default_category'];
            $value['to_ids'] = $definition['to_ids'];
        }
        return $resultArray;
    }

    public function getFreetextFeedCorrelations($data, $feedId)
    {
        $values = array();
        foreach ($data as $key => $value) {
            $values[] = $value['value'];
        }
        $this->Attribute = ClassRegistry::init('MispAttribute');
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
        if (!isset($user['Role']['perm_view_feed_correlations']) || $user['Role']['perm_view_feed_correlations'] != true) {
            return $attributes;
        }
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
            $this->Attribute = ClassRegistry::init('MispAttribute');
        }
        $compositeTypes = $this->Attribute->getCompositeTypes();

        $pipe = $redis->pipeline();
        $hashTable = [];
        $redisResultToAttributePosition = [];

        foreach ($attributes as $k => $attribute) {
            if (in_array($attribute['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
                continue; // attribute type is not correlateable
            }
            if (!empty($attribute['disable_correlation'])) {
                continue; // attribute correlation is disabled
            }

            if (in_array($attribute['type'], $compositeTypes, true)) {
                list($value1, $value2) = explode('|', $attribute['value']);
                $parts = [$value1];

                if (!in_array($attribute['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
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
        if ($scope == 'Server' && !$user['Role']['perm_site_admin'] && $user['org_id'] != Configure::read('MISP.host_org_id')) {
            // Filter fields that shouldn't be visible to everyone
            $allowedFieldsForAllUsers = array_flip(['id', 'name',]);
            $sources = array_map(function ($source) use ($scope, $allowedFieldsForAllUsers) {
                return [$scope => array_intersect_key($source[$scope], $allowedFieldsForAllUsers)];
            }, $sources);
        }
        foreach ($sources as $source) {
            $sourceId = $source[$scope]['id'];

            $pipe = $redis->pipeline();
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
                if (
                    $scope === 'Server' &&
                    !$user['Role']['perm_site_admin'] && $user['org_id'] != Configure::read('MISP.host_org_id')
                ) {
                    continue; // Non-privileged users cannot see the hits for server
                }
                $pipe = $redis->pipeline();
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
                'fields' => array('id', 'name', 'url', 'provider', 'source_format', 'lookup_visible')
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
            $pipe = $redis->pipeline();
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
        } catch (Exception $e) {
        }

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

        foreach ($actions['edit'] as $uuid) {
            try {
                $result = $this->__updateEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
                if ($result === true) {
                    $results['add']['success'] = $uuid;
                } else if ($result !== 'blocked') {
                    $results['add']['fail'] = ['uuid' => $uuid, 'reason' => $result];
                    $this->log("Could not edit event '$uuid' from feed {$feed['Feed']['id']}: " . json_encode($result), LOG_WARNING);
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
        $commit = $this->checkMIPSCommit();
        $result = array(
            'header' => array(
                'Accept' => array('application/json', 'text/plain', 'text/*'),
                'MISP-version' => $version,
                'MISP-uuid' => Configure::read('MISP.uuid'),
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            )
        );

        if ($commit) {
            $result['header']['commit'] = $commit;
        }

        if (!empty($headers)) {
            $lines = explode("\n", $headers);
            foreach ($lines as $line) {
                if (!empty($line)) {
                    $kv = explode(':', $line);
                    if (!empty($kv[0]) && !empty($kv[1])) {
                        if (!in_array($kv[0], array('commit', 'MISP-version', 'MISP-uuid', 'User-Agent'))) {
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
        $url_params = !empty($filterRules['url_params']) ? $filterRules['url_params'] : [];
        if (!$this->passesURLParamFilters($url_params, $event['Event'])) {
            return false;
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
                    unset($events[$k]);
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
                        unset($events[$k]);
                    }
                }
            }
            $url_params = !empty($filterRules['url_params']) ? $filterRules['url_params'] : [];
            if (!$this->passesURLParamFilters($url_params, $event)) {
                unset($events[$k]);
            }
        }
        return $events;
    }

    private function passesURLParamFilters($url_params, $event): bool
    {
        $this->Attribute = ClassRegistry::init('MispAttribute');
        if (!empty($url_params['timestamp'])) {
            $timestamps = $this->Attribute->setTimestampConditions($url_params['timestamp'], [], '', true);
            if (is_array($timestamps)) {
                if ($event['timestamp'] < $timestamps[0] || $event['timestamp'] > $timestamps[1]) {
                    return false;
                }
            } else {
                if ($event['timestamp'] < $timestamps) {
                    return false;
                }
            }
        }
        if (!empty($url_params['publish_timestamp'])) {
            $timestamps = $this->Attribute->setTimestampConditions($url_params['publish_timestamp'], [], '', true);
            if (is_array($timestamps)) {
                if ($event['timestamp'] < $timestamps[0] || $event['timestamp'] > $timestamps[1]) {
                    return false;
                }
            } else {
                if ($event['timestamp'] < $timestamps) {
                    return false;
                }
            }
        }
        return true;
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
    public function downloadEventFromFeed(array $feed, $uuid, $permissive = false, &$error_message = null)
    {
        $filerRules = $this->__prepareFilterRules($feed);
        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket();
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket, $permissive, $error_message);
        if ($permissive) {
            $event['Event']['error_message'] = $error_message;
        }
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
        if (5 == $feed['Feed']['distribution'] && isset($event['Event']['distribution'])) {
            // We inherit the distribution from the feed and should not rewrite the distributions.
            // MISP magically parses the Sharing Group info and creates the SG if it didn't exist.
        } else {
            // rewrite the distributions to the one configured by the Feed settings
            // overwrite Event distribution
            if (5 == $feed['Feed']['distribution']) {
                // We said to inherit the distribution from the feed, but the feed does not contain distribution
                // rewrite the event to My org only distribution, and set all attributes to inherit the event distribution
                $event['Event']['distribution'] = 0;
                $event['Event']['sharing_group_id'] = 0;
            } else {
                $event['Event']['distribution'] = $feed['Feed']['distribution'];
                $event['Event']['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
                $event['Event']['locked'] = !empty($feed['Feed']['lock_events']) ? 1 : 0;
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
            }
            // overwrite Attributes and Objects distribution to Inherit
            if (!empty($event['Event']['Attribute'])) {
                foreach ($event['Event']['Attribute'] as $key => $attribute) {
                    $event['Event']['Attribute'][$key]['distribution'] = 5;
                }
            }
            if (!empty($event['Event']['Object'])) {
                foreach ($event['Event']['Object'] as $key => $object) {
                    $event['Event']['Object'][$key]['distribution'] = 5;
                    if (!empty($event['Event']['Object'][$key]['Attribute'])) {
                        foreach ($event['Event']['Object'][$key]['Attribute'] as $a_key => $attribute) {
                            $event['Event']['Object'][$key]['Attribute'][$a_key]['distribution'] = 5;
                        }
                    }
                }
            }
        }
        if ($feed['Feed']['tag_id'] || $feed['Feed']['tag_collection_id']) {
            if (empty($feed['Tag']['name'])) {
                $feed_tag = $this->Tag->find('first', [
                    'conditions' => [
                        'Tag.id' => $feed['Feed']['tag_id']
                    ],
                    'recursive' => -1,
                    'fields' => ['Tag.name', 'Tag.colour', 'Tag.id']
                ]);
                if (!empty($feed_tag)) {
                    $feed['Tag'] = $feed_tag['Tag'];
                }
            }
            if (!isset($event['Event']['Tag'])) {
                $event['Event']['Tag'] = array();
            }

            if (!empty($feed['Feed']['tag_collection_id'])) {
                $this->TagCollection = ClassRegistry::init('TagCollection');
                $tagCollectionID = $feed['Feed']['tag_collection_id'];
                $tagCollection = $this->TagCollection->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'TagCollection.id' => $tagCollectionID,
                    ],
                    'contain' => [
                        'TagCollectionTag' => ['Tag'],
                    ]
                ]);
                foreach ($tagCollection['TagCollectionTag'] as $collectionTag) {
                    $event['Event']['Tag'][] = $collectionTag['Tag'];
                }
            } else {
                $feedTag = $this->Tag->find('first', array('conditions' => array('Tag.id' => $feed['Feed']['tag_id']), 'recursive' => -1, 'fields' => array('Tag.name', 'Tag.colour', 'Tag.exportable')));
                if (!empty($feedTag)) {
                    $found = false;
                    foreach ($event['Event']['Tag'] as $tag) {
                        if (strtolower($tag['name']) === strtolower($feedTag['Tag']['name'])) {
                            $found = true;
                            break;
                        }
                    }
                    if (!$found) {
                        $event['Event']['Tag'][] = $feedTag['Tag'];
                    }
                }
            }
        }
        if (!$this->__checkIfEventBlockedByFilter($event, $filterRules)) {
            return 'blocked';
        }
        if (!empty($feed['Feed']['settings'])) {
            if (!empty($feed['Feed']['settings']['disable_correlation'])) {
                $event['Event']['disable_correlation'] = (bool) $feed['Feed']['settings']['disable_correlation'];
            }
            if (!empty($feed['Feed']['settings']['unpublish_event'])) {
                $event['Event']['published'] = false;
            }
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
        if (!empty($feed['Feed']['rules'])) {
            $filterRules = JsonTool::decode($feed['Feed']['rules']);
            $filterRules['url_params'] = !empty($filterRules['url_params']) ? JsonTool::decodeArray($filterRules['url_params']) : [];
        }
        return $filterRules;
    }

    private function __setupHttpSocket()
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        return $syncTool->setupHttpSocketFeed();
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
     * @param $user
     * @param array|bool $filterRules
     * @return mixed
     * @throws Exception
     */
    private function __updateEventFromFeed(HttpSocket $HttpSocket = null, $feed, $uuid, $user, $filterRules)
    {
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        $event = $this->__prepareEvent($event, $feed, $filterRules);
        if (is_array($event)) {
            return $this->Event->_edit($event, $user, $uuid, $jobId = null);
        } else {
            return $event;
        }
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

    /**
     * @param int $feedId
     * @param array $user
     * @param int|false $jobId
     * @return array|bool
     * @throws Exception
     */
    public function downloadFromFeedInitiator($feedId, $user, $jobId = false)
    {
        $feed = $this->find('first', array(
            'conditions' => ['Feed.id' => $feedId],
            'recursive' => -1,
        ));
        if (empty($feed)) {
            throw new Exception("Feed with ID $feedId not found.");
        }

        if (!empty($feed['Feed']['settings'])) {
            $feed['Feed']['settings'] = json_decode($feed['Feed']['settings'], true);
        }

        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket();
        if ($feed['Feed']['source_format'] === 'misp') {
            $this->jobProgress($jobId, 'Fetching event manifest.');
            try {
                $actions = $this->getNewEventUuids($feed, $HttpSocket);
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
            $result = $this->downloadFromFeed($actions, $feed, $HttpSocket, $user, $jobId);
            $this->__cleanupFile($feed, '/manifest.json');
        } elseif ($feed['Feed']['source_format'] === 'stix') {
            $this->jobProgress($jobId, 'Fetching STIX data.');
            try {
                $result = $this->downloadStixFeed($feed, $HttpSocket, $user, $jobId);
            } catch (Exception $e) {
                $this->logException("Could not process STIX feed $feedId", $e);
                $this->jobProgress($jobId, 'Could not fetch STIX feed. See error log for more details.');
                return false;
            }
        } else {
            $this->jobProgress($jobId, 'Fetching data.');
            try {
                $temp = $this->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format']);
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
            unset($temp);

            $this->jobProgress($jobId, 'Saving data.', 50);

            try {
                $result = $this->saveFreetextFeedData($feed, $data, $user, $jobId);
            } catch (Exception $e) {
                $this->logException("Could not save freetext feed data for feed $feedId.", $e);
                return false;
            }

            $this->__cleanupFile($feed, '');
        }
        return $result;
    }

    /**
     * Download and convert a STIX feed for preview only (no import/save).
     * Returns events shaped as a UUID-keyed array matching the manifest format
     * expected by preview_index.ctp.
     *
     * @param array $feed
     * @param HttpSocket|null $HttpSocket
     * @return array UUID-keyed array of event data
     * @throws Exception
     */
    public function downloadStixFeedForPreview(array $feed, HttpSocket $HttpSocket = null)
    {
        $rawEvents = $this->__convertStixToRawEvents($feed, $HttpSocket);

        // Reshape into UUID-keyed manifest format for preview_index.ctp
        $events = [];
        foreach ($rawEvents as $item) {
            $e = $item['Event'] ?? [];
            $uuid = !empty($e['uuid']) ? $e['uuid'] : RandomTool::random_str(false, 36);

            $orgc = ['name' => 'Unknown'];
            if (!empty($e['Orgc']['name'])) {
                $orgc = $e['Orgc'];
            } elseif (!empty($e['orgc']['name'])) {
                $orgc = $e['orgc'];
            } elseif (!empty($feed['Feed']['provider'])) {
                $orgc = ['name' => $feed['Feed']['provider']];
            }

            $events[$uuid] = [
                'uuid'           => $uuid,
                'info'           => !empty($e['info']) ? $e['info'] : $feed['Feed']['name'],
                'date'           => !empty($e['date']) ? $e['date'] : date('Y-m-d'),
                'timestamp'      => !empty($e['timestamp']) ? $e['timestamp'] : time(),
                'threat_level_id'=> isset($e['threat_level_id']) ? $e['threat_level_id'] : 4,
                'analysis'       => isset($e['analysis']) ? $e['analysis'] : 0,
                'distribution'   => isset($e['distribution']) ? $e['distribution'] : $feed['Feed']['distribution'],
                'Orgc'           => $orgc,
                'Tag'            => !empty($e['Tag']) ? $e['Tag'] : [],
            ];
        }

        return $events;
    }

    /**
     * Download and convert a STIX feed, returning the full MISP event matching
     * the given UUID. Used by previewEvent for STIX feeds.
     *
     * @param array $feed
     * @param string $uuid
     * @param HttpSocket|null $HttpSocket
     * @return array Full MISP event structure (['Event' => [...]])
     * @throws Exception|NotFoundException
     */
    public function downloadStixEventForPreview(array $feed, $uuid, HttpSocket $HttpSocket = null)
    {
        $rawEvents = $this->__convertStixToRawEvents($feed, $HttpSocket);

        foreach ($rawEvents as $item) {
            if (!empty($item['Event']['uuid']) && $item['Event']['uuid'] === $uuid) {
                return $item;
            }
        }

        throw new NotFoundException(__('Event with UUID %s not found in STIX feed.', $uuid));
    }

    /**
     * Download a STIX feed and convert it to an array of full MISP event
     * structures (['Event' => [...]]), shared by the preview methods.
     *
     * @param array $feed
     * @param HttpSocket|null $HttpSocket
     * @return array
     * @throws Exception
     */
    private function __convertStixToRawEvents(array $feed, HttpSocket $HttpSocket = null)
    {
        $stixVersion = '2';
        if (!empty($feed['Feed']['settings']['stix_version'])) {
            $stixVersion = $feed['Feed']['settings']['stix_version'];
        }

        $feedUrl = $this->__resolveStixFeedPath($feed);
        $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket);

        if (empty($data)) {
            throw new Exception(__('Feed %s: STIX data is empty.', $feed['Feed']['id']));
        }

        $tmpFile = FileAccessTool::createTempFile();
        FileAccessTool::writeToFile($tmpFile, $data);
        unset($data);

        $this->Event = ClassRegistry::init('Event');

        try {
            $decoded = $this->Event->convertStixToMisp(
                $stixVersion,
                $tmpFile,
                $feed['Feed']['distribution'],
                $feed['Feed']['sharing_group_id'],
                false,
                true,
                0,
                null,
                Configure::read('MISP.uuid') ?: 'no-uuid',
                false
            );
        } catch (Exception $e) {
            FileAccessTool::deleteFileIfExists($tmpFile);
            throw new Exception("STIX conversion failed for preview: " . $e->getMessage(), 0, $e);
        }

        FileAccessTool::deleteFileIfExists($tmpFile);

        if (empty($decoded['success'])) {
            $errorMsg = !empty($decoded['error']) ? $decoded['error'] : 'Unknown error during STIX conversion';
            throw new Exception("STIX conversion failed for preview: $errorMsg");
        }

        $convertedData = JsonTool::decodeArray($decoded['converted']);

        $rawEvents = [];
        if (isset($convertedData['Event'])) {
            $rawEvents[] = $convertedData;
        } elseif (isset($convertedData[0])) {
            foreach ($convertedData as $item) {
                $rawEvents[] = isset($item['Event']) ? $item : ['Event' => $item];
            }
        } else {
            $rawEvents[] = ['Event' => $convertedData];
        }

        return $rawEvents;
    }

    /**
     * Resolve a STIX feed URL/path to the actual file to process.
     * If the path points to a local directory, scan for STIX files and return
     * the path to the most recently modified one.
     *
     * @param array $feed Feed data array
     * @return string The resolved feed URL or file path
     * @throws Exception If directory contains no STIX files
     */
    private function __resolveStixFeedPath(array $feed)
    {
        $feedUrl = $feed['Feed']['url'];

        // Only apply directory scanning for local feeds
        if (!$this->isFeedLocal($feed)) {
            return $feedUrl;
        }

        // Normalize the path (remove protocol prefix like feedGetUri does)
        $localPath = mb_ereg_replace("/\:\/\//", '', $feedUrl);

        // If it's a file, use it directly
        if (is_file($localPath)) {
            return $feedUrl;
        }

        // If it's a directory, find the most recent STIX file
        if (is_dir($localPath)) {
            $stixExtensions = ['json', 'xml', 'stix', 'stix2', 'stix1'];
            $newestFile = null;
            $newestMtime = 0;

            $dirIterator = new DirectoryIterator($localPath);
            foreach ($dirIterator as $fileInfo) {
                if ($fileInfo->isDot() || !$fileInfo->isFile()) {
                    continue;
                }
                $ext = strtolower($fileInfo->getExtension());
                if (!in_array($ext, $stixExtensions, true)) {
                    continue;
                }
                $mtime = $fileInfo->getMTime();
                if ($mtime > $newestMtime) {
                    $newestMtime = $mtime;
                    $newestFile = $fileInfo->getPathname();
                }
            }

            if ($newestFile === null) {
                throw new Exception("STIX feed directory '$localPath' contains no STIX files (expected extensions: " . implode(', ', $stixExtensions) . ")");
            }

            $this->log("STIX feed: resolved directory '$localPath' to most recent file '$newestFile'", LOG_INFO);
            return $newestFile;
        }

        // Not a file and not a directory — let feedGetUri handle the error
        return $feedUrl;
    }

    /**
     * Apply user-defined custom STIX-to-MISP field mappings to converted events.
     *
     * For event-level mappings: searches all STIX objects and uses the first match.
     * For attribute-level mappings: builds a per-value lookup by tracing each STIX SCO
     * back to its parent observed-data/indicator via object_refs, so each MISP attribute
     * gets the correct field value from its own IOC group (1-to-1 mapping).
     *
     * @param array $events Array of converted MISP events (by reference)
     * @param string $rawStixData The original raw STIX JSON/XML data
     * @param array $customMapping The custom mapping config with 'event' and 'attribute' keys
     * @return void
     */
    private function __applyStixCustomMapping(array &$events, $rawStixData, array $customMapping)
    {
        if (empty($customMapping)) {
            return;
        }

        // Try to parse raw STIX data as JSON for key extraction
        $stixParsed = json_decode($rawStixData, true);
        if ($stixParsed === null) {
            $this->log("Custom STIX mapping: could not parse raw STIX data as JSON, skipping custom mapping.", LOG_NOTICE);
            return;
        }

        // Collect all STIX objects into a flat list for lookup, indexed by ID
        $stixObjects = [];
        $stixObjectsById = [];
        if (isset($stixParsed['objects']) && is_array($stixParsed['objects'])) {
            $stixObjects = $stixParsed['objects'];
            foreach ($stixObjects as $obj) {
                if (isset($obj['id'])) {
                    $stixObjectsById[$obj['id']] = $obj;
                }
            }
        } elseif (isset($stixParsed['type'])) {
            $stixObjects = [$stixParsed];
            if (isset($stixParsed['id'])) {
                $stixObjectsById[$stixParsed['id']] = $stixParsed;
            }
        }

        // Helper: resolve a dot-notation key path from an associative array
        $resolveKey = function ($obj, $keyPath) use (&$resolveKey) {
            $parts = explode('.', $keyPath, 2);
            $key = $parts[0];
            if (!isset($obj[$key])) {
                return null;
            }
            if (count($parts) === 1) {
                return is_scalar($obj[$key]) ? (string)$obj[$key] : json_encode($obj[$key]);
            }
            if (is_array($obj[$key])) {
                return $resolveKey($obj[$key], $parts[1]);
            }
            return null;
        };

        // Apply event-level mappings (first-match is correct here — one value per event)
        if (!empty($customMapping['event'])) {
            foreach ($events as &$event) {
                foreach ($customMapping['event'] as $stixKey => $mispField) {
                    foreach ($stixObjects as $stixObj) {
                        $value = $resolveKey($stixObj, $stixKey);
                        if ($value !== null) {
                            $event['Event'][$mispField] = $value;
                            break;
                        }
                    }
                }
            }
            unset($event);
        }

        // Apply attribute-level mappings with per-IOC resolution
        if (!empty($customMapping['attribute'])) {
            // Build a lookup: normalised IOC value → array of {stixKey => resolved value}
            // by tracing SCO values through parent observed-data/indicator object_refs
            $valueLookup = $this->__buildStixValueLookup($stixObjects, $stixObjectsById, $customMapping['attribute'], $resolveKey);

            foreach ($events as &$event) {
                if (!empty($event['Event']['Attribute'])) {
                    foreach ($event['Event']['Attribute'] as &$attribute) {
                        $this->__applyAttributeLevelMapping($attribute, $valueLookup, $customMapping['attribute'], $stixObjects, $resolveKey);
                    }
                    unset($attribute);
                }
                if (!empty($event['Event']['Object'])) {
                    foreach ($event['Event']['Object'] as &$object) {
                        if (!empty($object['Attribute'])) {
                            foreach ($object['Attribute'] as &$objAttr) {
                                $this->__applyAttributeLevelMapping($objAttr, $valueLookup, $customMapping['attribute'], $stixObjects, $resolveKey);
                            }
                            unset($objAttr);
                        }
                    }
                    unset($object);
                }
            }
            unset($event);
        }
    }

    /**
     * Build a lookup table mapping normalised IOC values to their parent STIX object's
     * custom field values. This allows 1-to-1 attribute-level mapping by tracing each
     * SCO back to its observed-data or indicator parent via object_refs.
     *
     * @param array $stixObjects All STIX objects from the bundle
     * @param array $stixObjectsById STIX objects indexed by their STIX ID
     * @param array $attributeMapping The attribute-level custom mapping (stixKey => mispField)
     * @param callable $resolveKey Helper to resolve dot-notation key paths
     * @return array Normalised value => [stixKey => resolved value, ...]
     */
    private function __buildStixValueLookup(array $stixObjects, array $stixObjectsById, array $attributeMapping, callable $resolveKey)
    {
        $valueLookup = [];

        // Find all parent objects that have object_refs (observed-data, indicators, etc.)
        foreach ($stixObjects as $parentObj) {
            // Check if this parent object has any of the mapped keys
            $parentValues = [];
            $hasAnyKey = false;
            foreach ($attributeMapping as $stixKey => $mispField) {
                $resolved = $resolveKey($parentObj, $stixKey);
                if ($resolved !== null) {
                    $parentValues[$stixKey] = $resolved;
                    $hasAnyKey = true;
                }
            }
            if (!$hasAnyKey) {
                continue;
            }

            // Extract IOC values from referenced SCOs via object_refs
            if (!empty($parentObj['object_refs']) && is_array($parentObj['object_refs'])) {
                foreach ($parentObj['object_refs'] as $refId) {
                    if (!isset($stixObjectsById[$refId])) {
                        continue;
                    }
                    $sco = $stixObjectsById[$refId];
                    $scoValues = $this->__extractScoValues($sco);
                    foreach ($scoValues as $val) {
                        $normVal = $this->__normaliseValueForLookup($val);
                        if ($normVal !== '') {
                            // Merge parent values; later parents don't overwrite earlier for same value
                            if (!isset($valueLookup[$normVal])) {
                                $valueLookup[$normVal] = $parentValues;
                            }
                        }
                    }
                }
            }

            // Also extract IOC values from indicator patterns
            if (!empty($parentObj['pattern']) && isset($parentObj['type']) && $parentObj['type'] === 'indicator') {
                $patternValues = $this->__extractValuesFromStixPattern($parentObj['pattern']);
                foreach ($patternValues as $val) {
                    $normVal = $this->__normaliseValueForLookup($val);
                    if ($normVal !== '' && !isset($valueLookup[$normVal])) {
                        $valueLookup[$normVal] = $parentValues;
                    }
                }
            }
        }

        return $valueLookup;
    }

    /**
     * Extract all meaningful values from a STIX SCO (observable) object.
     * Handles domain-name, ipv4-addr, ipv6-addr, url, file (name + hashes), x-uri, etc.
     *
     * @param array $sco The STIX SCO object
     * @return array List of string values
     */
    private function __extractScoValues(array $sco)
    {
        $values = [];

        // Direct value field (domain-name, ipv4-addr, ipv6-addr, url, x-uri, etc.)
        if (isset($sco['value']) && is_string($sco['value'])) {
            $values[] = $sco['value'];
        }

        // File name
        if (isset($sco['name']) && is_string($sco['name'])) {
            $values[] = $sco['name'];
        }

        // File hashes (MD5, SHA-1, SHA-256, SHA-512, etc.)
        if (isset($sco['hashes']) && is_array($sco['hashes'])) {
            foreach ($sco['hashes'] as $hashValue) {
                if (is_string($hashValue)) {
                    $values[] = $hashValue;
                }
            }
        }

        return $values;
    }

    /**
     * Extract IOC values from a STIX indicator pattern string.
     * Parses patterns like: [domain-name:value = 'example.com'] OR [file:hashes.MD5 = 'abc123']
     *
     * @param string $pattern STIX pattern string
     * @return array List of extracted values
     */
    private function __extractValuesFromStixPattern($pattern)
    {
        $values = [];
        // Match all single-quoted values in comparison expressions
        if (preg_match_all("/=\s*'([^']+)'/", $pattern, $matches)) {
            $values = $matches[1];
        }
        return $values;
    }

    /**
     * Normalise a value for lookup comparison (case-insensitive, trimmed).
     *
     * @param string $value
     * @return string
     */
    private function __normaliseValueForLookup($value)
    {
        return strtolower(trim($value));
    }

    /**
     * Apply attribute-level custom mapping to a single MISP attribute.
     * First tries the per-value lookup for 1-to-1 resolution; falls back to
     * first-match across all STIX objects if no lookup match is found.
     *
     * @param array $attribute MISP attribute (by reference)
     * @param array $valueLookup Per-value lookup table
     * @param array $attributeMapping stixKey => mispField mapping
     * @param array $stixObjects All STIX objects (for fallback)
     * @param callable $resolveKey Key resolver function
     */
    private function __applyAttributeLevelMapping(array &$attribute, array $valueLookup, array $attributeMapping, array $stixObjects, callable $resolveKey)
    {
        if (empty($attribute['value'])) {
            return;
        }

        $normVal = $this->__normaliseValueForLookup($attribute['value']);

        // Try lookup by exact normalised value
        if (isset($valueLookup[$normVal])) {
            foreach ($attributeMapping as $stixKey => $mispField) {
                if (isset($valueLookup[$normVal][$stixKey])) {
                    $attribute[$mispField] = $valueLookup[$normVal][$stixKey];
                }
            }
            return;
        }

        // For composite values (e.g. "filename|hash"), try each part
        if (strpos($attribute['value'], '|') !== false) {
            $parts = explode('|', $attribute['value']);
            foreach ($parts as $part) {
                $normPart = $this->__normaliseValueForLookup($part);
                if (isset($valueLookup[$normPart])) {
                    foreach ($attributeMapping as $stixKey => $mispField) {
                        if (isset($valueLookup[$normPart][$stixKey])) {
                            $attribute[$mispField] = $valueLookup[$normPart][$stixKey];
                        }
                    }
                    return;
                }
            }
        }

        // Fallback: search all STIX objects for first match (preserves old behaviour for edge cases)
        foreach ($attributeMapping as $stixKey => $mispField) {
            foreach ($stixObjects as $stixObj) {
                $value = $resolveKey($stixObj, $stixKey);
                if ($value !== null) {
                    $attribute[$mispField] = $value;
                    break;
                }
            }
        }
    }

    private function downloadStixFeed(array $feed, HttpSocket $HttpSocket = null, array $user, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];

        // Determine STIX version from feed settings
        $stixVersion = '2';
        if (!empty($feed['Feed']['settings']['stix_version'])) {
            $stixVersion = $feed['Feed']['settings']['stix_version'];
        }

        // Resolve the feed URL (handles directory → most recent file)
        $feedUrl = $this->__resolveStixFeedPath($feed);
        $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket);

        if (empty($data)) {
            $this->jobProgress($jobId, __('Feed %s: STIX data is empty.', $feedId));
            return true;
        }

        // Keep a copy of raw STIX data for custom mapping (before we unset it)
        $rawStixData = $data;

        $this->jobProgress($jobId, __('Feed %s: Converting STIX data to MISP format.', $feedId), 20);

        // Write STIX content to a temporary file for the converter
        $tmpFile = FileAccessTool::createTempFile();
        FileAccessTool::writeToFile($tmpFile, $data);
        unset($data);

        // Determine distribution settings
        $distribution = $feed['Feed']['distribution'];
        $sharingGroupId = $feed['Feed']['sharing_group_id'];

        $this->Event = ClassRegistry::init('Event');

        try {
            $decoded = $this->Event->convertStixToMisp(
                $stixVersion,
                $tmpFile,
                $distribution,
                $sharingGroupId,
                false, // forceContextualData
                true, // galaxiesAsTags
                0, // clusterDistribution
                null, // clusterSharingGroupId
                $user['Organisation']['uuid'],
                false // debug
            );
        } catch (Exception $e) {
            FileAccessTool::deleteFileIfExists($tmpFile);
            throw new Exception("STIX conversion failed for feed $feedId: " . $e->getMessage(), 0, $e);
        }

        FileAccessTool::deleteFileIfExists($tmpFile);

        if (empty($decoded['success'])) {
            $errorMsg = !empty($decoded['error']) ? $decoded['error'] : 'Unknown error during STIX conversion';
            throw new Exception("STIX conversion failed for feed $feedId: $errorMsg");
        }

        $this->jobProgress($jobId, __('Feed %s: Importing converted MISP data.', $feedId), 50);

        $convertedData = JsonTool::decodeArray($decoded['converted']);

        // Handle both single event and multiple events
        $events = [];
        if (isset($convertedData['Event'])) {
            $events[] = $convertedData;
        } elseif (isset($convertedData[0])) {
            foreach ($convertedData as $item) {
                if (isset($item['Event'])) {
                    $events[] = $item;
                } else {
                    $events[] = ['Event' => $item];
                }
            }
        } else {
            $events[] = ['Event' => $convertedData];
        }

        // Apply custom STIX field mappings if configured
        if (!empty($feed['Feed']['settings']['stix_custom_mapping'])) {
            $this->__applyStixCustomMapping($events, $rawStixData, $feed['Feed']['settings']['stix_custom_mapping']);
        }
        unset($rawStixData);

        $total = count($events);
        $successCount = 0;
        $failCount = 0;

        foreach ($events as $k => $event) {
            // Apply feed distribution settings
            if (5 != $feed['Feed']['distribution']) {
                $event['Event']['distribution'] = $feed['Feed']['distribution'];
                $event['Event']['sharing_group_id'] = $feed['Feed']['sharing_group_id'];
                if (!empty($event['Event']['Attribute'])) {
                    foreach ($event['Event']['Attribute'] as $attrKey => $attribute) {
                        $event['Event']['Attribute'][$attrKey]['distribution'] = 5;
                    }
                }
                if (!empty($event['Event']['Object'])) {
                    foreach ($event['Event']['Object'] as $objKey => $object) {
                        $event['Event']['Object'][$objKey]['distribution'] = 5;
                        if (!empty($object['Attribute'])) {
                            foreach ($object['Attribute'] as $oaKey => $oa) {
                                $event['Event']['Object'][$objKey]['Attribute'][$oaKey]['distribution'] = 5;
                            }
                        }
                    }
                }
            }

            // Apply feed tags
            if ($feed['Feed']['tag_id']) {
                if (!isset($event['Event']['Tag'])) {
                    $event['Event']['Tag'] = [];
                }
                $feedTag = $this->Tag->find('first', [
                    'conditions' => ['Tag.id' => $feed['Feed']['tag_id']],
                    'recursive' => -1,
                    'fields' => ['Tag.name', 'Tag.colour', 'Tag.exportable']
                ]);
                if (!empty($feedTag)) {
                    $event['Event']['Tag'][] = $feedTag['Tag'];
                }
            }

            // Check if event already exists
            $existingEvent = null;
            if (!empty($event['Event']['uuid'])) {
                $existingEvent = $this->Event->find('first', [
                    'conditions' => ['Event.uuid' => $event['Event']['uuid']],
                    'recursive' => -1,
                    'fields' => ['Event.uuid', 'Event.id', 'Event.timestamp']
                ]);
            }

            try {
                if (!empty($existingEvent)) {
                    if ($existingEvent['Event']['timestamp'] < ($event['Event']['timestamp'] ?? time())) {
                        $result = $this->Event->_edit($event, $user, $existingEvent['Event']['id']);
                    } else {
                        $result = true; // No change needed
                    }
                } else {
                    $result = $this->Event->_add($event, true, $user);
                }
                if ($result === true) {
                    $successCount++;
                } else {
                    $failCount++;
                    $this->log("Failed to save STIX-converted event from feed $feedId: " . json_encode($result), LOG_WARNING);
                }
            } catch (Exception $e) {
                $failCount++;
                $this->logException("Failed to save STIX-converted event from feed $feedId", $e);
            }

            if ($jobId && $k % 5 === 0) {
                $this->jobProgress($jobId, __('Feed %s: %s/%s events processed.', $feedId, $k + 1, $total), 50 + (($k + 1) / $total * 50));
            }
        }

        $this->jobProgress($jobId, __('Feed %s: %s events added/updated, %s failed.', $feedId, $successCount, $failCount));

        return true;
    }

    private function __cleanupFile($feed, $file)
    {
        if ($this->isFeedLocal($feed)) {
            if (isset($feed['Feed']['delete_local_file']) && $feed['Feed']['delete_local_file']) {
                FileAccessTool::deleteFileIfExists($feed['Feed']['url'] . $file);
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
            $disableCorrelation = false;
            if (!empty($feed['Feed']['settings'])) {
                $disableCorrelation = (bool) $feed['Feed']['settings']['disable_correlation'] ?? false;
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
                'user_id' => $user['id'],
                'disable_correlation' => $disableCorrelation,
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
                $modifiedValue = AttributeValidationTool::modifyBeforeValidation($dataPoint['type'], $dataPoint['value']);
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
            $data[$key]['distribution'] = 5;
            $data[$key]['sharing_group_id'] = 0;
            $data[$key]['to_ids'] = $feed['Feed']['override_ids'] ? 0 : $value['to_ids'];
            $uniqueValues[$value['value']] = true;
        }
        $chunks = array_chunk($data, 100);
        foreach ($chunks as $k => $chunk) {
            $this->Event->Attribute->saveMany($chunk, ['validate' => true, 'parentEvent' => $event]);
            $this->jobProgress($jobId, null, 50 + round(($k * 100 + 1) / count($data) * 50));
        }
        if (!empty($data) || !empty($attributesToDelete)) {
            unset($event['Event']['timestamp']);
            unset($event['Event']['attribute_count']);
            $this->Event->save($event);
        }
        if ($feed['Feed']['publish']) {
            $this->Event->publishRouter($event['Event']['id'], null, $user);
        }
        if ($feed['Feed']['tag_id'] || $feed['Feed']['tag_collection_id']) {
            if (!empty($feed['Feed']['tag_collection_id'])) {
                $this->TagCollection = ClassRegistry::init('TagCollection');
                $tagCollectionID = $feed['Feed']['tag_collection_id'];
                $tagCollection = $this->TagCollection->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'TagCollection.id' => $tagCollectionID,
                    ],
                    'contain' => [
                        'TagCollectionTag',
                    ]
                ]);
                foreach ($tagCollection['TagCollectionTag'] as $collectionTag) {
                    $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $collectionTag['tag_id']]);
                }
            } else {
                $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $feed['Feed']['tag_id']]);
            }
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
            } elseif ($scope == 'stix') {
                $params['conditions']['source_format'] = 'stix';
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

        $pipe = $redis->pipeline();
        foreach ($feeds as $feed) {
            $pipe->get('misp:feed_cache_timestamp:' . $feed['Feed']['id']);
        }
        $result = $redis->exec();
        foreach ($feeds as $k => $feed) {
            $feeds[$k]['Feed']['cache_timestamp'] = $result[$k];
        }
        return $feeds;
    }

    /**
     * @param array $feed
     * @param Redis $redis
     * @param int|false $jobId
     * @return bool
     */
    private function __cacheFeed($feed, $redis, $jobId = false)
    {
        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket();
        if ($feed['Feed']['source_format'] === 'misp') {
            $result = true;
            if (!$this->__cacheMISPFeedCache($feed, $redis, $HttpSocket, $jobId)) {
                $result = $this->__cacheMISPFeedTraditional($feed, $redis, $HttpSocket, $jobId);
            }
        } elseif ($feed['Feed']['source_format'] === 'stix') {
            $result = $this->__cacheStixFeed($feed, $redis, $HttpSocket, $jobId);
        } else {
            $result = $this->__cacheFreetextFeed($feed, $redis, $HttpSocket, $jobId);
        }

        if ($result) {
            $redis->set('misp:feed_cache_timestamp:' . $feed['Feed']['id'], time());
        }
        return $result;
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
            $values = $this->getFreetextFeed($feed, $HttpSocket, $feed['Feed']['source_format']);
        } catch (Exception $e) {
            $this->logException("Could not get freetext feed $feedId", $e);
            $this->jobProgress($jobId, __('Could not fetch freetext feed %s. See error log for more details.', $feedId));
            return false;
        }

        // Convert values to MD5 hashes
        $md5Values = array_map('md5', array_column($values, 'value'));

        $redis->del('misp:feed_cache:' . $feedId);
        foreach (array_chunk($md5Values, 5000) as $k => $chunk) {
            $pipe = $redis->pipeline();
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
        return true;
    }

    /**
     * Cache a STIX feed by converting it and extracting attribute values.
     *
     * @param array $feed
     * @param Redis $redis
     * @param HttpSocket|null $HttpSocket
     * @param int|false $jobId
     * @return bool
     */
    private function __cacheStixFeed(array $feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];

        $this->jobProgress($jobId, __('Feed %s: Fetching STIX data for caching.', $feedId));

        try {
            $feedUrl = $this->__resolveStixFeedPath($feed);
            $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket);
        } catch (Exception $e) {
            $this->logException("Could not get STIX feed $feedId for caching", $e);
            return false;
        }

        if (empty($data)) {
            return false;
        }

        $stixVersion = '2';
        if (!empty($feed['Feed']['settings']['stix_version'])) {
            $stixVersion = $feed['Feed']['settings']['stix_version'];
        }

        $tmpFile = FileAccessTool::createTempFile();
        FileAccessTool::writeToFile($tmpFile, $data);
        unset($data);

        $this->Event = ClassRegistry::init('Event');
        $this->Attribute = ClassRegistry::init('MispAttribute');

        try {
            $decoded = $this->Event->convertStixToMisp(
                $stixVersion,
                $tmpFile,
                0, // distribution (doesn't matter for caching)
                0, // sharingGroupId
                false, // forceContextualData
                true, // galaxiesAsTags
                0, // clusterDistribution
                null, // clusterSharingGroupId
                Configure::read('MISP.uuid') ?: 'no-uuid',
                false // debug
            );
        } catch (Exception $e) {
            FileAccessTool::deleteFileIfExists($tmpFile);
            $this->logException("STIX conversion failed for caching feed $feedId", $e);
            return false;
        }

        FileAccessTool::deleteFileIfExists($tmpFile);

        if (empty($decoded['success'])) {
            $this->log("STIX conversion failed for caching feed $feedId: " . ($decoded['error'] ?? 'Unknown error'), LOG_WARNING);
            return false;
        }

        $convertedData = JsonTool::decodeArray($decoded['converted']);

        // Collect events from conversion result
        $events = [];
        if (isset($convertedData['Event'])) {
            $events[] = $convertedData;
        } elseif (isset($convertedData[0])) {
            foreach ($convertedData as $item) {
                $events[] = isset($item['Event']) ? $item : ['Event' => $item];
            }
        } else {
            $events[] = ['Event' => $convertedData];
        }

        $redis->del('misp:feed_cache:' . $feedId);
        $compositeTypes = $this->Attribute->getCompositeTypes();

        foreach ($events as $event) {
            $eventData = $event['Event'] ?? $event;
            $eventUuid = $eventData['uuid'] ?? '';

            $attributeValues = [];
            if (!empty($eventData['Attribute'])) {
                foreach ($eventData['Attribute'] as $attribute) {
                    if (!in_array($attribute['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
                        if (in_array($attribute['type'], $compositeTypes, true)) {
                            $parts = explode('|', $attribute['value']);
                            if (in_array($attribute['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
                                unset($parts[1]);
                            }
                        } else {
                            $parts = [$attribute['value']];
                        }
                        foreach ($parts as $v) {
                            $attributeValues[] = $v;
                        }
                    }
                }
            }
            if (!empty($eventData['Object'])) {
                foreach ($eventData['Object'] as $object) {
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $attribute) {
                            if (!in_array($attribute['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
                                if (in_array($attribute['type'], $compositeTypes, true)) {
                                    $parts = explode('|', $attribute['value']);
                                    if (in_array($attribute['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
                                        unset($parts[1]);
                                    }
                                } else {
                                    $parts = [$attribute['value']];
                                }
                                foreach ($parts as $v) {
                                    $attributeValues[] = $v;
                                }
                            }
                        }
                    }
                }
            }

            if (!empty($attributeValues)) {
                $pipe = $redis->pipeline();
                foreach ($attributeValues as $v) {
                    $md5 = md5($v);
                    $redis->sAdd('misp:feed_cache:' . $feedId, $md5);
                    $redis->sAdd('misp:feed_cache:combined', $md5);
                    if (!empty($eventUuid)) {
                        $redis->sAdd('misp:feed_cache:event_uuid_lookup:' . $md5, $feedId . '/' . $eventUuid);
                    }
                }
                $pipe->exec();
            }
        }

        $this->jobProgress($jobId, __('Feed %s: STIX feed cached.', $feedId));
        return true;
    }

    /**
     * @param array $feed
     * @param Redis $redis
     * @param HttpSocket|null $HttpSocket
     * @param false $jobId
     * @return bool
     */
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
        $this->Attribute = ClassRegistry::init('MispAttribute');
        foreach ($manifest as $uuid => $event) {
            try {
                $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
            } catch (Exception $e) {
                $this->logException("Could not get and parse event '$uuid' for feed $feedId.", $e);
                return false;
            }

            if (!empty($event['Event']['Attribute'])) {
                $pipe = $redis->pipeline();
                foreach ($event['Event']['Attribute'] as $attribute) {
                    if (!in_array($attribute['type'], MispAttribute::NON_CORRELATING_TYPES, true)) {
                        if (in_array($attribute['type'], $this->Attribute->getCompositeTypes(), true)) {
                            $value = explode('|', $attribute['value']);
                            if (in_array($attribute['type'], MispAttribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
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

    /**
     * @param array $feed
     * @param Redis $redis
     * @param HttpSocket|null $HttpSocket
     * @param false $jobId
     * @return bool
     */
    private function __cacheMISPFeedCache($feed, $redis, HttpSocket $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['Feed']['id'];

        try {
            $cache = $this->getCache($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->logException("Could not get cache file for $feedId.", $e, LOG_NOTICE);
            return false;
        }

        $pipe = $redis->pipeline();
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

    public function compareFeeds($limited = false)
    {
        $redis = $this->setupRedis();
        if ($redis === false) {
            return array();
        }
        $fields = array('id', 'input_source', 'source_format', 'url', 'provider', 'name', 'default');
        $conditions = ['Feed.caching_enabled' => 1];
        if ($limited) {
            $conditions['Feed.lookup_visible'] = 1;
        }
        $feeds = $this->find('all', array(
            'recursive' => -1,
            'fields' => $fields,
            'conditions' => $conditions
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
        $servers = [];
        if (!$limited) {
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
        $temp_store = RandomTool::random_str(false, 12);
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

    public function getAllCachingEnabledFeeds($feedId, $intersectingOnly = false)
    {
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

    public function searchCaches($value, bool $limited = false)
    {
        $hits = array();
        $this->Server = ClassRegistry::init('Server');
        $redis = $this->setupRedis();
        $is_array = true;
        if (!is_array($value)) {
            $is_array = false;
            if (empty($value)) {
                // old behaviour allowed for empty values to return all data
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
                $conditions = ['caching_enabled' => 1];
                if ($limited) {
                    $conditions['lookup_visible'] = 1;
                }
                $feeds = $this->find('all', array(
                    'conditions' => $conditions,
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
            if (!$limited && ($v === false || $redis->sismember('misp:server_cache:combined', md5($v)))) {
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
    private function downloadAndParseEventFromFeed($feed, $eventUuid, HttpSocket $HttpSocket = null, $permissive = false, &$error_message = null)
    {
        if (!Validation::uuid($eventUuid)) {
            throw new InvalidArgumentException("Given event UUID '$eventUuid' is invalid.");
        }

        $path = $feed['Feed']['url'] . '/' . $eventUuid . '.json';
        $raw_data = $this->feedGetUri($feed, $path, $HttpSocket);

        try {
            $error_message = "Could not parse event JSON with UUID '$eventUuid' from feed";
            $data = JsonTool::decodeArray($raw_data);
            if (!empty($data['Event']['protected'])) {
                $path = $feed['Feed']['url'] . '/' . $eventUuid . '.asc';
                $sig = $this->feedGetUri($feed, $path, $HttpSocket);
                if (empty($sig)) {
                    $error_message = __('Signature file for protected event %s not found.', $eventUuid);
                    if (!$permissive) {
                        throw new NotFoundException($error_message);
                    }
                }
                $this->Event = ClassRegistry::init('Event');
                if (!$this->Event->CryptographicKey->validateAndCheckLocalProtectedEvent($raw_data, [], $sig, $data)) {
                    $error_message = __('Protected event %s signature validation failed.', $eventUuid);
                    if (!$permissive) {
                        throw new InvalidInputException($error_message);
                    }
                }
            }
            return $data;
        } catch (Exception $e) {
            throw new Exception($error_message, 0, $e);
        }
    }

    /**
     * @param array $feed
     * @param string $uri
     * @param HttpSocket|null $HttpSocket Null can be for local feed
     * @return string
     * @throws Exception
     */
    private function feedGetUri($feed, $uri, HttpSocket $HttpSocket = null)
    {
        if ($this->isFeedLocal($feed)) {
            $uri = mb_ereg_replace("/\:\/\//", '', $uri);
            if (file_exists($uri)) {
                return FileAccessTool::readFromFile($uri);
            } else {
                throw new Exception("Local file '$uri' doesn't exists.");
            }
        }

        return $this->feedGetUriRemote($feed, $uri, $HttpSocket)->body;
    }

    /**
     * @param array $feed
     * @param string $uri
     * @param HttpSocket $HttpSocket
     * @param string|null $etag
     * @return false|HttpSocketResponse
     * @throws HttpSocketHttpException
     */
    private function feedGetUriRemote(array $feed, $uri, HttpSocket $HttpSocket, $etag = null)
    {
        $request = $this->__createFeedRequest($feed['Feed']['headers']);
        if ($etag) {
            $request['header']['If-None-Match'] = $etag;
        }

        try {
            $response = $this->getFollowRedirect($HttpSocket, $uri, $request);
        } catch (Exception $e) {
            throw new Exception("Fetching the '$uri' failed with exception: {$e->getMessage()}", 0, $e);
        }

        if ($response->code != 200) { // intentionally !=
            throw new HttpSocketHttpException($response, $uri);
        }

        $contentType = $response->getHeader('content-type');
        if ($contentType === 'application/zip') {
            $zipFilePath = FileAccessTool::writeToTempFile($response->body);
            unset($response->body); // cleanup variable to reduce memory usage

            try {
                $response->body = $this->unzipFirstFile($zipFilePath);
            } catch (Exception $e) {
                throw new Exception("Fetching the '$uri' failed: {$e->getMessage()}");
            } finally {
                FileAccessTool::deleteFile($zipFilePath);
            }
        }

        return $response;
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
            $response = $HttpSocket->get($url, [], $request);
            if ($response->isRedirect()) {
                $HttpSocket = $this->__setupHttpSocket(); // Replace $HttpSocket with fresh instance
                $url = trim($response->getHeader('Location'), '=');
            } else {
                return $response;
            }
        }

        throw new Exception("Too many redirects when fetching $url.");
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
        $this->Log->saveOrFailSilently(array(
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
     * @param string $zipFile
     * @return string Uncompressed data
     * @throws Exception
     */
    private function unzipFirstFile($zipFile)
    {
        if (!class_exists('ZipArchive')) {
            throw new Exception('ZIP archive decompressing is not supported. ZIP extension is missing in PHP.');
        }

        $zip = new ZipArchive();
        $result = $zip->open($zipFile);
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
            $message = $errorCodes[$result] ?? 'error ' . $result;
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

        $destinationFile = FileAccessTool::createTempFile();
        $result = copy("zip://$zipFile#$filename", $destinationFile);
        if ($result === false) {
            throw new Exception("Remote server returns ZIP file, that contains '$filename' file, but this file cannot be extracted.");
        }

        return FileAccessTool::readAndDelete($destinationFile);
    }
}
