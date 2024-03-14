<?php

namespace App\Model\Table;

use App\Lib\Tools\AttributeValidationTool;
use App\Lib\Tools\ComplexTypeTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\JsonTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\RandomTool;
use App\Lib\Tools\RedisTool;
use App\Lib\Tools\TmpFileTool;
use App\Model\Entity\Attribute;
use App\Model\Entity\Feed;
use App\Model\Entity\User;
use App\Model\Table\AppTable;
use Cake\Core\Configure;
use Cake\Http\Client as HttpClient;
use Cake\Http\Exception\HttpException;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use Exception;
use InvalidArgumentException;
use ZipArchive;

class FeedsTable extends AppTable
{
    use LogExtendedTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'SharingGroups',
            [
                'foreignKey' => 'sharing_group_id',
                'className' => 'SharingGroups',
                'propertyName' => 'Organisation'
            ]
        );
        $this->belongsTo(
            'Tags',
            [
                'foreignKey' => 'tag_id',
                'className' => 'Tags',
                'propertyName' => 'Tag'
            ]
        );
        $this->belongsTo(
            'Orgc',
            [
                'foreignKey' => 'orgc_id',
                'className' => 'Organisations',
                'propertyName' => 'Orgc'
            ]
        );

        $this->addBehavior(
            'JsonFields',
            [
                'fields' => [
                    'settings' => ['default' => []],
                    'rules' => ['default' => []]
                ],
            ]
        );

        $this->setDisplayField('name');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence('url', 'name')
            ->notEmptyString('provider')
            ->add(
                'url',
                'custom',
                [
                    'rule' => function ($value, $context) {
                        if ($this->isFeedLocal($context['data'])) {
                            $path = mb_ereg_replace("/\:\/\//", '', $value);
                            if ($value['source_format'] == 'misp') {
                                if (!is_dir($path)) {
                                    return 'For MISP type local feeds, please specify the containing directory.';
                                }
                            } else {
                                if (!file_exists($path)) {
                                    return 'Invalid path or file not found. Make sure that the path points to an existing file that is readable and watch out for typos.';
                                }
                            }
                        } else {
                            if (!filter_var($context['data']['url'], FILTER_VALIDATE_URL)) {
                                return false;
                            }
                        }
                        return true;
                    },
                    'message' => 'Invalid URL/File Path.'
                ]
            )
            ->add(
                'input_source',
                'custom',
                [
                    'rule' => function ($value, $context) {
                        if (!empty($value['input_source'])) {
                            $localAllowed = empty(Configure::read('Security.disable_local_feed_access'));
                            $validOptions = ['network'];
                            if ($localAllowed) {
                                $validOptions[] = 'local';
                            }
                            if (!in_array($value['input_source'], $validOptions)) {
                                return __(
                                    'Invalid input source. The only valid options are %s. %s',
                                    implode(', ', $validOptions),
                                    (!$localAllowed && $value['input_source'] === 'local') ?
                                        __('Security.disable_local_feed_access is currently enabled, local feeds are thereby not allowed.') :
                                        ''
                                );
                            }
                        }
                        return true;
                    },
                    'message' => 'Invalid input source'
                ]
            )
            ->add(
                'event_id',
                'valid',
                [
                    'rule' => 'numeric',
                    'message' => 'Please enter a numeric event ID or leave this field blank.'
                ]
            );

        return $validator;
    }

    public function validateInputSource($fields)
    {
        if (!empty($this->data['input_source'])) {
            $localAllowed = empty(Configure::read('Security.disable_local_feed_access'));
            $validOptions = ['network'];
            if ($localAllowed) {
                $validOptions[] = 'local';
            }
            if (!in_array($this->data['input_source'], $validOptions)) {
                return __(
                    'Invalid input source. The only valid options are %s. %s',
                    implode(', ', $validOptions),
                    (!$localAllowed && $this->data['input_source'] === 'local') ?
                        __('Security.disable_local_feed_access is currently enabled, local feeds are thereby not allowed.') :
                        ''
                );
            }
        }
        return true;
    }

    public function urlOrExistingFilepath($value, $context)
    {
        if ($this->isFeedLocal($value)) {
            $path = mb_ereg_replace("/\:\/\//", '', $value['url']);
            if ($value['source_format'] == 'misp') {
                if (!is_dir($path)) {
                    return 'For MISP type local feeds, please specify the containing directory.';
                }
            } else {
                if (!file_exists($path)) {
                    return 'Invalid path or file not found. Make sure that the path points to an existing file that is readable and watch out for typos.';
                }
            }
        } else {
            if (!filter_var($value['url'], FILTER_VALIDATE_URL)) {
                return false;
            }
        }
        return true;
    }

    public function getFeedTypesOptions()
    {
        $result = [];
        foreach (Feed::FEED_TYPES as $key => $value) {
            $result[$key] = $value['name'];
        }
        return $result;
    }

    /**
     * Gets the event UUIDs from the feed by ID
     * Returns an array with the UUIDs of events that are new or that need updating.
     *
     * @param Feed $feed
     * @param HttpClient|null $HttpSocket
     * @return array
     * @throws Exception
     */
    public function getNewEventUuids($feed, HttpClient $HttpSocket = null)
    {
        $manifest = $this->isFeedLocal($feed) ? $this->downloadManifest($feed) : $this->getRemoteManifest($feed, $HttpSocket);
        $EventsTable = $this->fetchTable('Events');
        $events = $EventsTable->find(
            'all',
            [
                'conditions' => [
                    'uuid IN' => array_keys($manifest),
                ],
                'recursive' => -1,
                'fields' => ['uuid', 'timestamp']
            ]
        );
        $result = ['add' => [], 'edit' => []];
        foreach ($events as $event) {
            $eventUuid = $event['Event']['uuid'];
            if ($event['Event']['timestamp'] < $manifest[$eventUuid]['timestamp']) {
                $result['edit'][] = $eventUuid;
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
     * @param Feed $feed
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @return Generator<string>
     * @throws Exception
     */
    public function getCache(Feed $feed, HttpClient $HttpSocket = null)
    {
        $uri = $feed['url'] . '/hashes.csv';
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
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    private function downloadManifest($feed, HttpClient $HttpSocket = null)
    {
        $manifestUrl = $feed['url'] . '/manifest.json';
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
            FileAccessTool::deleteFileIfExists(Feed::CACHE_DIR . $fileName);
        }
    }

    /**
     * Get remote manifest for feed with etag checking.
     * @param Feed $feed
     * @param HttpClient $HttpSocket
     * @return array
     * @throws HttpException
     * @throws JsonException
     */
    private function getRemoteManifest(Feed $feed, HttpClient $HttpSocket)
    {
        $feedCache = Feed::CACHE_DIR . 'misp_feed_' . (int)$feed['id'] . '_manifest.cache.gz';
        $feedCacheEtag = Feed::CACHE_DIR . 'misp_feed_' . (int)$feed['id'] . '_manifest.etag';

        $etag = null;
        if (file_exists($feedCache) && file_exists($feedCacheEtag)) {
            $etag = file_get_contents($feedCacheEtag);
        }

        $manifestUrl = $feed['url'] . '/manifest.json';

        try {
            $response = $this->feedGetUriRemote($feed, $manifestUrl, $HttpSocket, $etag);
        } catch (HttpException $e) {
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
                FileAccessTool::writeCompressedFile($feedCache, $response->getBody());
                FileAccessTool::writeToFile($feedCacheEtag, $response->getHeader('etag')[0]);
            } catch (Exception $e) {
                FileAccessTool::deleteFileIfExists($feedCacheEtag);
                $this->logException("Could not save file `$feedCache` to cache.", $e, LOG_NOTICE);
            }
        } else {
            FileAccessTool::deleteFileIfExists($feedCacheEtag);
        }

        return $response->getJson();
    }

    /**
     * @param Feed $feed
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    public function getManifest(Feed $feed, HttpClient $HttpSocket = null)
    {
        $events = $this->isFeedLocal($feed) ? $this->downloadManifest($feed) : $this->getRemoteManifest($feed, $HttpSocket);
        $events = $this->__filterEventsIndex($events, $feed);
        return $events;
    }

    /**
     * Load remote file with cache support and etag checking.
     * @param Feed $feed
     * @param HttpClient $HttpSocket
     * @return string
     * @throws HttpException
     */
    private function getFreetextFeedRemote(Feed $feed, HttpClient $HttpSocket)
    {
        $feedCache = Feed::CACHE_DIR . 'misp_feed_' . (int)$feed['id'] . '.cache.gz';
        $feedCacheEtag = Feed::CACHE_DIR . 'misp_feed_' . (int)$feed['id'] . '.etag';

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
            $response = $this->feedGetUriRemote($feed, $feed['url'], $HttpSocket, $etag);
        } catch (HttpException $e) {
            if ($e->getCode() === 304) { // not modified
                try {
                    return FileAccessTool::readCompressedFile($feedCache);
                } catch (Exception $e) {
                    return $this->feedGetUriRemote($feed, $feed['url'], $HttpSocket); // cache file is not readable, fetch without etag
                }
            } else {
                throw $e;
            }
        }

        $content = $response->getBody()->getContents();

        try {
            FileAccessTool::writeCompressedFile($feedCache, $content, true);
            if ($response->getHeader('etag')) {
                FileAccessTool::writeToFile($feedCacheEtag, $response->getHeader('etag')[0]);
            }
        } catch (Exception $e) {
            FileAccessTool::deleteFileIfExists($feedCacheEtag);
            $this->logException("Could not save file `$feedCache` to cache.", $e, LOG_NOTICE);
        }

        return $content;
    }

    /**
     * @param Feed $feed
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @param string $type
     * @return array|bool
     * @throws Exception
     */
    public function getFreetextFeed($feed, HttpClient $HttpSocket = null, $type = 'freetext')
    {
        if ($this->isFeedLocal($feed)) {
            $feedUrl = $feed['url'];
            $data = $this->feedGetUri($feed, $feedUrl, $HttpSocket);
        } else {
            $data = $this->getFreetextFeedRemote($feed, $HttpSocket);
        }

        $complexTypeTool = new ComplexTypeTool();
        $WarninglistsTable = $this->fetchTable('Warninglists');
        $complexTypeTool->setTLDs($WarninglistsTable->fetchTLDLists());
        $complexTypeTool->setSecurityVendorDomains($WarninglistsTable->fetchSecurityVendorDomains());
        $settings = [];
        if (!empty($feed['settings']) && !is_array($feed['settings'])) {
            $feed['settings'] = json_decode($feed['settings'], true);
        }
        if (isset($feed['settings'][$type])) {
            $settings = $feed['settings'][$type];
        }
        if (isset($feed['settings']['common'])) {
            $settings = array_merge($settings, $feed['settings']['common']);
        }
        $resultArray = $complexTypeTool->checkComplexRouter($data, $type, $settings);
        $AttributesTable = $this->fetchTable('Attributes');
        $typeDefinitions = $AttributesTable->typeDefinitions;
        foreach ($resultArray as &$value) {
            $definition = $typeDefinitions[$value['default_type']];
            $value['category'] = $definition['default_category'];
            $value['to_ids'] = $definition['to_ids'];
        }
        return $resultArray;
    }

    public function getFreetextFeedCorrelations($data, $feedId)
    {
        $values = [];
        foreach ($data as $key => $value) {
            $values[] = $value['value'];
        }
        $AttributesTable = $this->fetchTable('Attributes');
        $redis = RedisTool::init();
        if ($redis !== false) {
            $feeds = $this->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['Feed.id !=' => $feedId],
                    'fields' => ['id', 'name', 'url', 'provider', 'source_format']
                ]
            );
            foreach ($feeds as $k => $v) {
                if (!$redis->exists('misp:feed_cache:' . $v['id'])) {
                    unset($feeds[$k]);
                }
            }
        } else {
            return [];
        }
        // Adding a 3rd parameter to a list find seems to allow grouping several results into a key. If we ran a normal list with value => event_id we'd only get exactly one entry for each value
        // The cost of this method is orders of magnitude lower than getting all id - event_id - value triplets and then doing a double loop comparison
        $correlations = $AttributesTable->find('list', ['conditions' => ['Attribute.value1' => $values, 'Attribute.deleted' => 0], 'fields' => ['Attribute.event_id', 'Attribute.event_id', 'Attribute.value1']]);
        $correlations2 = $AttributesTable->find('list', ['conditions' => ['Attribute.value2' => $values, 'Attribute.deleted' => 0], 'fields' => ['Attribute.event_id', 'Attribute.event_id', 'Attribute.value2']]);
        $correlations = array_merge_recursive($correlations, $correlations2);
        foreach ($data as $key => $value) {
            if (isset($correlations[$value['value']])) {
                $data[$key]['correlations'] = array_values($correlations[$value['value']]);
            }
            if ($redis) {
                foreach ($feeds as $k => $v) {
                    if ($redis->sismember('misp:feed_cache:' . $v['id'], md5($value['value']))) {
                        $data[$key]['feed_correlations'][] = [$v];
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
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return $attributes;
        }

        $cachePrefix = 'misp:' . strtolower($scope) . '_cache:';

        // Skip if redis cache for $scope is empty.
        if ($redis->sCard($cachePrefix . 'combined') === 0) {
            return $attributes;
        }

        $AttributesTable = $this->fetchTable('Attributes');
        $compositeTypes = $AttributesTable->getCompositeTypes();

        $pipe = $redis->pipeline();
        $hashTable = [];
        $redisResultToAttributePosition = [];

        foreach ($attributes as $k => $attribute) {
            if (in_array($attribute['type'], Attribute::NON_CORRELATING_TYPES, true)) {
                continue; // attribute type is not correlateable
            }
            if (!empty($attribute['disable_correlation'])) {
                continue; // attribute correlation is disabled
            }

            if (in_array($attribute['type'], $compositeTypes, true)) {
                list($value1, $value2) = explode('|', $attribute['value']);
                $parts = [$value1];

                if (!in_array($attribute['type'], Attribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
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
            $sources = array_map(
                function ($source) use ($scope, $allowedFieldsForAllUsers) {
                    return [$scope => array_intersect_key($source[$scope], $allowedFieldsForAllUsers)];
                },
                $sources
            );
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
            $params = [
                'recursive' => -1,
                'fields' => ['id', 'name', 'url', 'provider', 'source_format']
            ];
            if (!$user['Role']['perm_site_admin']) {
                $params['conditions'] = ['Feed.lookup_visible' => 1];
            }
            $sources = $this->find('all', $params);
        } else {
            $params = [
                'recursive' => -1,
                'fields' => ['id', 'name', 'url']
            ];
            if (!$user['Role']['perm_site_admin']) {
                $params['conditions'] = ['Server.caching_enabled' => 1];
            }
            $ServersTable = $this->fetchTable('Servers');
            $sources = $ServersTable->find('all', $params);
        }

        try {
            $redis = RedisTool::init();
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
     * @param Feed $feed
     * @param HttpClient|null $HttpSocket
     * @param array $user
     * @param int|false $jobId
     * @return array
     * @throws Exception
     */
    private function downloadFromFeed(array $actions, Feed $feed, HttpClient $HttpSocket = null, array $user, $jobId = false)
    {
        $total = count($actions['add']) + count($actions['edit']);
        $currentItem = 0;
        $results = [
            'add' => ['success' => [], 'fail' => []],
            'edit' => ['success' => [], 'fail' => []]
        ];
        $filterRules = $this->__prepareFilterRules($feed);

        foreach ($actions['add'] as $uuid) {
            try {
                $result = $this->__addEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
                if ($result === true) {
                    $results['add']['success'][] = $uuid;
                } else if ($result !== 'blocked') {
                    $results['add']['fail'][] = ['uuid' => $uuid, 'reason' => $result];
                    $this->log("Could not add event '$uuid' from feed {$feed['id']}: $result", LOG_WARNING);
                }
            } catch (Exception $e) {
                $this->logException("Could not add event '$uuid' from feed {$feed['id']}.", $e);
                $results['add']['fail'][] = ['uuid' => $uuid, 'reason' => $e->getMessage()];
            }

            $this->__cleanupFile($feed, '/' . $uuid . '.json');
            $this->jobProgress($jobId, null, 100 * (($currentItem + 1) / $total));
            $currentItem++;
        }

        foreach ($actions['edit'] as $uuid) {
            try {
                $result = $this->__updateEventFromFeed($HttpSocket, $feed, $uuid, $user, $filterRules);
                if ($result === true) {
                    $results['edit']['success'][] = $uuid;
                } else if ($result !== 'blocked') {
                    $results['edit']['fail'][] = ['uuid' => $uuid, 'reason' => $result];
                    $this->log("Could not edit event '$uuid' from feed {$feed['id']}: " . json_encode($result), LOG_WARNING);
                }
            } catch (Exception $e) {
                $this->logException("Could not edit event '$uuid' from feed {$feed['id']}.", $e);
                $results['edit']['fail'][] = ['uuid' => $uuid, 'reason' => $e->getMessage()];
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

        $result = [
            'header' => [
                'Accept' => ['application/json', 'text/plain', 'text/*'],
                'MISP-version' => $version,
                'MISP-uuid' => Configure::read('MISP.uuid'),
            ]
        ];

        $commit = $this->checkMISPCommit();
        if ($commit) {
            $result['header']['commit'] = $commit;
        }
        if (!empty($headers)) {
            $lines = explode("\n", $headers);
            foreach ($lines as $line) {
                if (!empty($line)) {
                    $kv = explode(':', $line);
                    if (!empty($kv[0]) && !empty($kv[1])) {
                        if (!in_array($kv[0], ['commit', 'MISP-version', 'MISP-uuid'])) {
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
        $fields = ['tags' => 'Tag', 'orgs' => 'Orgc'];
        $prefixes = ['OR', 'NOT'];
        foreach ($fields as $field => $fieldModel) {
            foreach ($prefixes as $prefix) {
                if (!empty($filterRules[$field][$prefix])) {
                    $found = false;
                    if (isset($event['Event'][$fieldModel]) && !empty($event['Event'][$fieldModel])) {
                        if (!isset($event['Event'][$fieldModel][0])) {
                            $event['Event'][$fieldModel] = [0 => $event['Event'][$fieldModel]];
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

    private function __filterEventsIndex(array $events, Feed $feed)
    {
        $filterRules = $this->__prepareFilterRules($feed);
        if (!$filterRules) {
            $filterRules = [];
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
        $AttributesTable = $this->fetchTable('Attributes');
        if (!empty($url_params['timestamp'])) {
            $timestamps = $AttributesTable->setTimestampConditions($url_params['timestamp'], [], '', true);
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
            $timestamps = $AttributesTable->setTimestampConditions($url_params['publish_timestamp'], [], '', true);
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
     * @param Feed $feed
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
        $EventsTable = $this->fetchTable('Events');
        $existingEvent = $EventsTable->find(
            'first',
            [
                'conditions' => ['uuid' => $event['Event']['uuid']],
                'recursive' => -1,
                'fields' => ['uuid', 'id', 'timestamp']
            ]
        );
        $result = [];
        if (!empty($existingEvent)) {
            $result['action'] = 'edit';
            if ($existingEvent['Event']['timestamp'] < $event['Event']['timestamp']) {
                $result['result'] = $EventsTable->_edit($event, $user);
            } else {
                $result['result'] = 'No change';
            }
        } else {
            $result['action'] = 'add';
            $result['result'] = $EventsTable->_add($event, true, $user);
        }
        return $result;
    }

    /**
     * @param array $event
     * @param Feed $feed
     * @param array $filterRules
     * @return array|string
     */
    private function __prepareEvent($event, Feed $feed, $filterRules)
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
        if (5 == $feed['distribution'] && isset($event['Event']['distribution'])) {
            // We inherit the distribution from the feed and should not rewrite the distributions.
            // MISP magically parses the Sharing Group info and creates the SG if it didn't exist.
        } else {
            // rewrite the distributions to the one configured by the Feed settings
            // overwrite Event distribution
            if (5 == $feed['distribution']) {
                // We said to inherit the distribution from the feed, but the feed does not contain distribution
                // rewrite the event to My org only distribution, and set all attributes to inherit the event distribution
                $event['Event']['distribution'] = 0;
                $event['Event']['sharing_group_id'] = 0;
            } else {
                $event['Event']['distribution'] = $feed['distribution'];
                $event['Event']['sharing_group_id'] = $feed['sharing_group_id'];
                if ($feed['sharing_group_id']) {
                    $sg = $this->SharingGroup->find(
                        'first',
                        [
                            'recursive' => -1,
                            'conditions' => ['SharingGroup.id' => $feed['sharing_group_id']]
                        ]
                    );
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
        if ($feed['tag_id']) {
            if (empty($feed['Tag']['name'])) {
                $feed_tag = $this->Tag->find(
                    'first',
                    [
                        'conditions' => [
                            'Tag.id' => $feed['tag_id']
                        ],
                        'recursive' => -1,
                        'fields' => ['Tag.name', 'Tag.colour', 'Tag.id']
                    ]
                );
                $feed['Tag'] = $feed_tag['Tag'];
            }
            if (!isset($event['Event']['Tag'])) {
                $event['Event']['Tag'] = [];
            }

            $feedTag = $this->Tag->find('first', ['conditions' => ['Tag.id' => $feed['tag_id']], 'recursive' => -1, 'fields' => ['Tag.name', 'Tag.colour', 'Tag.exportable']]);
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
        if (!$this->__checkIfEventBlockedByFilter($event, $filterRules)) {
            return 'blocked';
        }
        if (!empty($feed['settings'])) {
            if (!empty($feed['settings']['disable_correlation'])) {
                $event['Event']['disable_correlation'] = (bool) $feed['settings']['disable_correlation'];
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
        if (isset($feed['rules']) && !empty($feed['rules'])) {
            $filterRules = json_decode($feed['rules'], true);
            if ($filterRules === null) {
                throw new Exception('Could not parse feed filter rules JSON: ' . json_last_error_msg(), json_last_error());
            }
            $filterRules['url_params'] = !empty($filterRules['url_params']) ? $this->jsonDecode($filterRules['url_params']) : [];
        }
        return $filterRules;
    }

    private function __setupHttpSocket(Feed $feed)
    {
        $HttpTool = new HttpTool();
        $HttpTool->configFromFeed($feed->toArray());

        return $HttpTool;
    }

    /**
     * @param HttpClient|null $HttpSocket
     * @param Feed $feed
     * @param string $uuid
     * @param array $user
     * @param array|bool $filterRules
     * @return array|bool|string
     * @throws Exception
     */
    private function __addEventFromFeed(HttpClient $HttpSocket = null, $feed, $uuid, $user, $filterRules)
    {
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        $event = $this->__prepareEvent($event, $feed, $filterRules);
        if (is_array($event)) {
            $EventsTable = $this->fetchTable('Events');
            return $EventsTable->_add($event, true, $user);
        } else {
            return $event;
        }
    }

    /**
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @param Feed $feed
     * @param string $uuid
     * @param $user
     * @param array|bool $filterRules
     * @return mixed
     * @throws Exception
     */
    private function __updateEventFromFeed(HttpClient $HttpSocket = null, $feed, $uuid, $user, $filterRules)
    {
        $event = $this->downloadAndParseEventFromFeed($feed, $uuid, $HttpSocket);
        $event = $this->__prepareEvent($event, $feed, $filterRules);
        $EventsTable = $this->fetchTable('Events');
        return $EventsTable->_edit($event, $user, $uuid, $jobId = null);
    }

    public function addDefaultFeeds($newFeeds)
    {
        foreach ($newFeeds as $newFeed) {
            $existingFeed = $this->find('list', ['conditions' => ['Feed.url' => $newFeed['url']]]);
            $success = true;
            if (empty($existingFeed)) {
                $this->create();
                $feed = $this->newEntity(
                    [
                        'name' => $newFeed['name'],
                        'provider' => $newFeed['provider'],
                        'url' => $newFeed['url'],
                        'enabled' => $newFeed['enabled'],
                        'caching_enabled' => !empty($newFeed['caching_enabled']) ? $newFeed['caching_enabled'] : 0,
                        'distribution' => 3,
                        'sharing_group_id' => 0,
                        'tag_id' => 0,
                        'default' => true,
                    ]
                );
                $result = $this->save($feed) && $success;
            }
        }
        return $success;
    }

    /**
     * @param int $feedId
     * @param User $user
     * @param int|false $jobId
     * @return array|bool
     * @throws Exception
     */
    public function downloadFromFeedInitiator($feedId, $user, $jobId = false)
    {
        $feed = $this->find(
            'all',
            [
                'conditions' => ['Feeds.id' => $feedId],
                'recursive' => -1,
            ]
        )->first();
        if (empty($feed)) {
            throw new Exception("Feed with ID $feedId not found.");
        }

        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket($feed);
        if ($feed['source_format'] === 'misp') {
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
            $result = $this->downloadFromFeed($actions, $feed, $HttpSocket, $user->toArray(), $jobId);
            $this->__cleanupFile($feed, '/manifest.json');
        } else {
            $this->jobProgress($jobId, 'Fetching data.');
            try {
                $temp = $this->getFreetextFeed($feed, $HttpSocket, $feed['source_format']);
            } catch (Exception $e) {
                $this->logException("Could not get freetext feed $feedId", $e);
                $this->jobProgress($jobId, 'Could not fetch freetext feed. See error log for more details.');
                return false;
            }

            if (empty($temp)) {
                return true;
            }

            $data = [];
            foreach ($temp as $value) {
                $data[] = [
                    'category' => $value['category'],
                    'type' => $value['default_type'],
                    'value' => $value['value'],
                    'to_ids' => $value['to_ids']
                ];
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

    private function __cleanupFile($feed, $file)
    {
        if ($this->isFeedLocal($feed)) {
            if (isset($feed['delete_local_file']) && $feed['delete_local_file']) {
                FileAccessTool::deleteFileIfExists($feed['url'] . $file);
            }
        }
        return true;
    }

    /**
     * @param Feed $feed
     * @param array $data
     * @param User $user
     * @param int|bool $jobId
     * @return bool
     * @throws Exception
     */
    public function saveFreetextFeedData(Feed $feed, array $data, User $user, $jobId = false)
    {
        $EventsTable = $this->fetchTable('Events');

        if ($feed['fixed_event'] && $feed['event_id']) {
            $event = $EventsTable->find('all', ['conditions' => ['id' => $feed['event_id']], 'recursive' => -1])->first();
            if (empty($event)) {
                throw new Exception("The target event is no longer valid. Make sure that the target event {$feed['event_id']} exists.");
            }
        } else {
            $orgc_id = $user['org_id'];
            if (!empty($feed['orgc_id'])) {
                $orgc_id = $feed['orgc_id'];
            }
            $disableCorrelation = false;
            if (!empty($feed['settings'])) {
                if (!empty($feed['settings']['disable_correlation'])) {
                    $disableCorrelation = (bool) $feed['settings']['disable_correlation'];
                } else {
                    $disableCorrelation = false;
                }
            }
            $event = [
                'info' => $feed['name'] . ' feed',
                'analysis' => 2,
                'threat_level_id' => 4,
                'orgc_id' => $orgc_id,
                'org_id' => $user['org_id'],
                'date' => date('Y-m-d'),
                'distribution' => $feed['distribution'],
                'sharing_group_id' => $feed['sharing_group_id'],
                'user_id' => $user['id'],
                'disable_correlation' => $disableCorrelation,
            ];
            $eventEntity = $EventsTable->newEntity($event);
            $result = $EventsTable->save($eventEntity);
            if (!$result) {
                throw new Exception('Something went wrong while creating a new event.');
            }
            if (empty($eventEntity)) {
                throw new Exception("The newly created event is no longer valid. Make sure that the target event {$eventEntity->id} exists.");
            }
            if ($feed['fixed_event']) {
                $feed['event_id'] = $eventEntity['id'];
                if (!empty($feed['settings'])) {
                    $feed['settings'] = json_encode($feed['settings']);
                }
                $this->save($feed);
            }
        }
        if ($feed['fixed_event']) {
            $existsAttributesValueToId = $EventsTable->Attributes->find(
                'list',
                [
                    'conditions' => [
                        'Attribute.deleted' => 0,
                        'Attribute.event_id' => $eventEntity['id']
                    ],
                    'recursive' => -1,
                    'fields' => ['value', 'id']
                ]
            );

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
            if ($feed['delta_merge'] && !empty($existsAttributesValueToId)) {
                $attributesToDelete = $EventsTable->Attributes->find(
                    'all',
                    [
                        'conditions' => [
                            'Attribute.id' => array_values($existsAttributesValueToId)
                        ],
                        'recursive' => -1
                    ]
                );
                foreach ($attributesToDelete as $k => $attribute) {
                    $attributesToDelete[$k]['Attribute']['deleted'] = 1;
                    unset($attributesToDelete[$k]['Attribute']['timestamp']);
                }
                $EventsTable->Attributes->saveMany($attributesToDelete); // We need to trigger callback methods
                if (!empty($attributesToDelete)) {
                    $EventsTable->unpublishEvent($feed['event_id']);
                }
            }
        }
        if (empty($data) && empty($attributesToDelete)) {
            return true;
        }

        $uniqueValues = [];
        foreach ($data as $key => $value) {
            if (isset($uniqueValues[$value['value']])) {
                unset($data[$key]);
                continue;
            }
            $data[$key]['event_id'] = $eventEntity['id'];
            $data[$key]['distribution'] = 5;
            $data[$key]['sharing_group_id'] = 0;
            $data[$key]['to_ids'] = $feed['override_ids'] ? 0 : $value['to_ids'];
            $uniqueValues[$value['value']] = true;
        }
        $chunks = array_chunk($data, 100);
        foreach ($chunks as $k => $chunk) {
            $EventsTable->Attributes->saveMany($EventsTable->Attributes->newEntities($chunk), ['validate' => true, 'parentEvent' => $event]);
            $this->jobProgress($jobId, null, 50 + round(($k * 100 + 1) / count($data) * 50));
        }
        if (!empty($data) || !empty($attributesToDelete)) {
            unset($eventEntity['timestamp']);
            unset($eventEntity['attribute_count']);
            $EventsTable->save($eventEntity);
        }
        if ($feed['publish']) {
            $EventsTable->publishRouter($eventEntity['id'], null, $user);
        }
        if ($feed['tag_id']) {
            $EventsTable->EventTag->attachTagToEvent($eventEntity['id'], ['id' => $feed['tag_id']]);
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
        $params = [
            'conditions' => ['caching_enabled' => 1],
            'recursive' => -1,
            'fields' => ['source_format', 'input_source', 'url', 'id', 'settings', 'headers']
        ];
        $redis = RedisTool::init();
        if ($scope !== 'all') {
            if (is_numeric($scope)) {
                $params['conditions']['id'] = $scope;
            } elseif ($scope == 'freetext' || $scope == 'csv') {
                $params['conditions']['source_format'] = ['csv', 'freetext'];
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
        $feeds = $this->find('all', $params)->toArray();

        $results = ['successes' => 0, 'fails' => 0];
        foreach ($feeds as $k => $feed) {
            if ($this->__cacheFeed($feed, $redis, $jobId)) {
                $message = 'Feed ' . $feed['id'] . ' cached.';
                $results['successes']++;
            } else {
                $message = 'Failed to cache feed ' . $feed['id'] . '. See logs for more details.';
                $results['fails']++;
            }

            $this->jobProgress($jobId, $message, 100 * $k / count($feeds));
        }
        return $results;
    }

    /**
     * @param Feed $feed
     * @return Feed
     */
    public function attachFeedCacheTimestamps(Feed $feed)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return $feed;
        }

        $pipe = $redis->pipeline();
        $pipe->get('misp:feed_cache_timestamp:' . $feed['id']);
        $result = $redis->exec();
        $feed['cache_timestamp'] = $result[0];

        return $feed;
    }

    /**
     * @param Feed $feed
     * @param Redis $redis
     * @param int|false $jobId
     * @return bool
     */
    private function __cacheFeed($feed, $redis, $jobId = false)
    {
        $HttpSocket = $this->isFeedLocal($feed) ? null : $this->__setupHttpSocket($feed);
        if ($feed['source_format'] === 'misp') {
            $result = true;
            if (!$this->__cacheMISPFeedCache($feed, $redis, $HttpSocket, $jobId)) {
                $result = $this->__cacheMISPFeedTraditional($feed, $redis, $HttpSocket, $jobId);
            }
        } else {
            $result = $this->__cacheFreetextFeed($feed, $redis, $HttpSocket, $jobId);
        }

        if ($result) {
            $redis->set('misp:feed_cache_timestamp:' . $feed['id'], time());
        }
        return $result;
    }

    /**
     * @param Feed $feed
     * @param Redis $redis
     * @param HttpClient|null $HttpSocket
     * @param int|false $jobId
     * @return bool
     */
    private function __cacheFreetextFeed(Feed $feed, $redis, HttpClient $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['id'];

        $this->jobProgress($jobId, __("Feed %s: Fetching.", $feedId));

        try {
            $values = $this->getFreetextFeed($feed, $HttpSocket, $feed['source_format']);
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
     * @param Feed $feed
     * @param Redis $redis
     * @param HttpClient|null $HttpSocket
     * @param false $jobId
     * @return bool
     */
    private function __cacheMISPFeedTraditional($feed, $redis, HttpClient $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['id'];
        try {
            $manifest = $this->getManifest($feed, $HttpSocket);
        } catch (Exception $e) {
            $this->logException("Could not get manifest for feed $feedId.", $e);
            return false;
        }

        $redis->del('misp:feed_cache:' . $feedId);

        $k = 0;
        $AttributesTable = $this->fetchTable('Attributes');
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
                    if (!in_array($attribute['type'], Attribute::NON_CORRELATING_TYPES, true)) {
                        if (in_array($attribute['type'], $AttributesTable->getCompositeTypes(), true)) {
                            $value = explode('|', $attribute['value']);
                            if (in_array($attribute['type'], Attribute::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
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
     * @param Feed $feed
     * @param Redis $redis
     * @param HttpClient|null $HttpSocket
     * @param false $jobId
     * @return bool
     */
    private function __cacheMISPFeedCache($feed, $redis, HttpClient $HttpSocket = null, $jobId = false)
    {
        $feedId = $feed['id'];

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

    public function compareFeeds($id = false)
    {
        $redis = RedisTool::init();
        if ($redis === false) {
            return [];
        }
        $fields = ['id', 'input_source', 'source_format', 'url', 'provider', 'name', 'default'];
        $feeds = $this->find(
            'all',
            [
                'recursive' => -1,
                'fields' => $fields,
                'conditions' => ['Feed.caching_enabled' => 1]
            ]
        )->toArray();
        // we'll use this later for the intersect
        $fields[] = 'values';
        $fields = array_flip($fields);
        // Get all of the feed cache cardinalities for all feeds - if a feed is not cached remove it from the list
        foreach ($feeds as $k => $feed) {
            if (!$redis->exists('misp:feed_cache:' . $feed['id'])) {
                unset($feeds[$k]);
                continue;
            }
            $feeds[$k]['values'] = $redis->sCard('misp:feed_cache:' . $feed['id']);
        }
        $feeds = array_values($feeds);
        $ServersTable = $this->fetchTable('Servers');
        $servers = $ServersTable->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['id', 'url', 'name'],
                'contain' => ['RemoteOrg' => ['fields' => ['RemoteOrg.id', 'RemoteOrg.name']]],
                'conditions' => ['Server.caching_enabled' => 1]
            ]
        );
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
                $intersect = $redis->sInter('misp:feed_cache:' . $feed['id'], 'misp:feed_cache:' . $feed2['id']);
                $feeds[$k]['ComparedFeed'][] = array_merge(
                    array_intersect_key($feed2, $fields),
                    [
                        'overlap_count' => count($intersect),
                        'overlap_percentage' => round(100 * count($intersect) / $feeds[$k]['values']),
                    ]
                );
            }
            foreach ($servers as $k2 => $server) {
                $intersect = $redis->sInter('misp:feed_cache:' . $feed['id'], 'misp:server_cache:' . $server['Server']['id']);
                $feeds[$k]['ComparedFeed'][] = array_merge(
                    array_intersect_key($server['Server'], $fields),
                    [
                        'overlap_count' => count($intersect),
                        'overlap_percentage' => round(100 * count($intersect) / $feeds[$k]['values']),
                    ]
                );
            }
        }
        foreach ($servers as $k => $server) {
            foreach ($feeds as $k2 => $feed2) {
                $intersect = $redis->sInter('misp:server_cache:' . $server['Server']['id'], 'misp:feed_cache:' . $feed2['id']);
                $servers[$k]['Server']['ComparedFeed'][] = array_merge(
                    array_intersect_key($feed2, $fields),
                    [
                        'overlap_count' => count($intersect),
                        'overlap_percentage' => round(100 * count($intersect) / $servers[$k]['Server']['values']),
                    ]
                );
            }
            foreach ($servers as $k2 => $server2) {
                if ($k == $k2) {
                    continue;
                }
                $intersect = $redis->sInter('misp:server_cache:' . $server['Server']['id'], 'misp:server_cache:' . $server2['Server']['id']);
                $servers[$k]['Server']['ComparedFeed'][] = array_merge(
                    array_intersect_key($server2['Server'], $fields),
                    [
                        'overlap_count' => count($intersect),
                        'overlap_percentage' => round(100 * count($intersect) / $servers[$k]['Server']['values']),
                    ]
                );
            }
        }
        foreach ($servers as $k => $server) {
            $server = $server['Server'];
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
            $feeds = [$feeds];
        }
        $results = ['successes' => 0, 'fails' => 0];
        if (empty($feeds)) {
            return $results;
        }
        $existingFeeds = $this->find('all', []);
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
                if ($existingFeed['url'] == $feed['Feed']['url']) {
                    $found = true;
                }
            }
            if (!$found) {
                $feed['Feed']['tag_id'] = 0;
                if (isset($feed['Tag'])) {
                    $tag_id = $this->Tags->captureTag($feed['Tag'], $user);
                    if ($tag_id) {
                        $feed['Feed']['tag_id'] = $tag_id;
                    }
                }

                $feedEntity = $this->newEntity($feed['Feed']);

                if (!$this->save($feedEntity)) {
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
        $user = ['Role' => ['perm_tag_editor' => 1, 'perm_site_admin' => 1]];
        $json = file_get_contents(APP . '../libraries/feed-metadata/defaults.json');
        $this->importFeeds($json, $user, true);
        return true;
    }

    public function setEnableFeedCachingDefaults()
    {
        $feeds = $this->find(
            'all',
            [
                'conditions' => [
                    'Feed.enabled' => 1
                ],
                'recursive' => -1
            ]
        );
        if (empty($feeds)) {
            return true;
        }
        foreach ($feeds as $feed) {
            $feed['caching_enabled'] = 1;
            $this->save($feed);
        }
        return true;
    }

    public function getFeedCoverage($id, $source_scope = 'feed', $dataset = 'all')
    {
        $redis = RedisTool::init();
        if ($redis === false) {
            return 'Could not reach Redis.';
        }
        $ServersTable = $this->fetchTable('Servers');
        $feed_conditions = ['Feeds.caching_enabled' => 1];
        $server_conditions = ['Servers.caching_enabled' => 1];
        if ($source_scope === 'feed') {
            $feed_conditions['NOT'] = ['Feeds.id' => $id];
        } else {
            $server_conditions['NOT'] = ['Servers.id' => $id];
        }
        if ($dataset !== 'all') {
            if (empty($dataset)) {
                $feed_conditions['OR'] = ['Feeds.id' => -1];
            } else {
                $feed_conditions['OR'] = ['Feeds.id' => $dataset];
            }
            if (empty($dataset['Server'])) {
                $server_conditions['OR'] = ['Servers.id' => -1];
            } else {
                $server_conditions['OR'] = ['Servers.id' => $dataset['Server']];
            }
        }
        $other_feeds = $this->find(
            'list',
            [
                'recursive' => -1,
                'conditions' => $feed_conditions,
                'fields' => ['Feeds.id', 'Feeds.id']
            ]
        );
        $other_servers = $ServersTable->find(
            'list',
            [
                'recursive' => -1,
                'conditions' => $server_conditions,
                'fields' => ['Servers.id', 'Servers.id']
            ]
        );
        $feed_element_count = $redis->scard('misp:feed_cache:' . $id);
        $temp_store = (new RandomTool())->random_str(false, 12);
        $params = ['misp:feed_temp:' . $temp_store];
        foreach ($other_feeds as $other_feed) {
            $params[] = 'misp:feed_cache:' . $other_feed;
        }
        foreach ($other_servers as $other_server) {
            $params[] = 'misp:server_cache:' . $other_server;
        }
        if (count($params) != 1 && $feed_element_count > 0) {
            call_user_func_array([$redis, 'sunionstore'], $params);
            call_user_func_array([$redis, 'sinterstore'], ['misp:feed_temp:' . $temp_store . '_intersect', 'misp:feed_cache:' . $id, 'misp:feed_temp:' . $temp_store]);
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
        $redis = RedisTool::init();
        $cardinality = $redis->sCard('misp:feed_cache:' . $feedId);
        return $cardinality;
    }

    public function getAllCachingEnabledFeeds($feedId, $intersectingOnly = false)
    {
        if ($intersectingOnly) {
            $redis = RedisTool::init();
        }
        $result = $this->find(
            'all',
            [
                'conditions' => [
                    'Feed.id !=' => $feedId,
                    'caching_enabled' => 1
                ],
                'recursive' => -1,
                'fields' => ['Feed.id', 'Feed.name', 'Feed.url']
            ]
        );
        $ServersTable = $this->fetchTable('Servers');
        $result['Server'] = $ServersTable->find(
            'all',
            [
                'conditions' => [
                    'caching_enabled' => 1
                ],
                'recursive' => -1,
                'fields' => ['Server.id', 'Server.name', 'Server.url']
            ]
        );
        $scopes = ['Feed', 'Server'];
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
        $hits = [];
        $ServersTable = $this->fetchTable('Servers');
        $redis = RedisTool::init();
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
                $feeds = $this->find(
                    'all',
                    [
                        'conditions' => [
                            'caching_enabled' => 1
                        ],
                        'recursive' => -1,
                        'fields' => ['Feed.id', 'Feed.name', 'Feed.url', 'Feed.source_format']
                    ]
                );
                foreach ($feeds as $feed) {
                    if (($v === false) || $redis->sismember('misp:feed_cache:' . $feed['id'], md5($v))) {
                        if ($feed['source_format'] === 'misp') {
                            $uuid = $redis->smembers('misp:feed_cache:event_uuid_lookup:' . md5($v));
                            foreach ($uuid as $k => $url) {
                                $uuid[$k] = explode('/', $url)[1];
                            }
                            $feed['uuid'] = $uuid;
                            if (!empty($feed['uuid'])) {
                                foreach ($feed['uuid'] as $uuid) {
                                    $feed['direct_urls'][] = [
                                        'url' => sprintf(
                                            '%s/feeds/previewEvent/%s/%s',
                                            Configure::read('MISP.baseurl'),
                                            h($feed['id']),
                                            h($uuid)
                                        ),
                                        'name' => __('Event %s', $uuid)
                                    ];
                                }
                            }
                            $feed['type'] = 'MISP Feed';
                        } else {
                            $feed['type'] = 'Feed';
                            if (!empty($v)) {
                                $feed['direct_urls'][] = [
                                    'url' => sprintf(
                                        '%s/feeds/previewIndex/%s',
                                        Configure::read('MISP.baseurl'),
                                        h($feed['id'])
                                    ),
                                    'name' => __('Feed %s', $feed['id'])
                                ];
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
                $servers = $ServersTable->find(
                    'all',
                    [
                        'conditions' => [
                            'caching_enabled' => 1
                        ],
                        'recursive' => -1,
                        'fields' => ['Server.id', 'Server.name', 'Server.url']
                    ]
                );
                foreach ($servers as $server) {
                    if ($v === false || $redis->sismember('misp:server_cache:' . $server['Server']['id'], md5($v))) {
                        $uuid = $redis->smembers('misp:server_cache:event_uuid_lookup:' . md5($v));
                        if (!empty($uuid)) {
                            foreach ($uuid as $k => $url) {
                                $uuid[$k] = explode('/', $url)[1];
                                $server['Server']['direct_urls'][] = [
                                    'url' => sprintf(
                                        '%s/servers/previewEvent/%s/%s',
                                        Configure::read('MISP.baseurl'),
                                        h($server['Server']['id']),
                                        h($uuid[$k])
                                    ),
                                    'name' => __('Event %s', h($uuid[$k]))
                                ];
                            }
                        }
                        $server['Server']['uuid'] = $uuid;
                        $server['Server']['type'] = 'MISP Server';
                        if ($is_array) {
                            $hits[$v][] = ['Feed' => $server['Server']];
                        } else {
                            $hits[] = ['Feed' => $server['Server']];
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
     * @param Feed $feed
     * @param string $eventUuid
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @return array
     * @throws Exception
     */
    private function downloadAndParseEventFromFeed($feed, $eventUuid, HttpClient $HttpSocket = null)
    {
        if (!Validation::uuid($eventUuid)) {
            throw new InvalidArgumentException("Given event UUID '$eventUuid' is invalid.");
        }

        $path = $feed['url'] . '/' . $eventUuid . '.json';
        $data = $this->feedGetUri($feed, $path, $HttpSocket);

        try {
            return JsonTool::decodeArray($data);
        } catch (Exception $e) {
            throw new Exception("Could not parse event JSON with UUID '$eventUuid' from feed", 0, $e);
        }
    }

    /**
     * @param Feed $feed
     * @param string $uri
     * @param HttpClient|null $HttpSocket Null can be for local feed
     * @return string
     * @throws Exception
     */
    private function feedGetUri($feed, $uri, HttpClient $HttpSocket = null)
    {
        if ($this->isFeedLocal($feed)) {
            $uri = mb_ereg_replace("/\:\/\//", '', $uri);
            if (file_exists($uri)) {
                return FileAccessTool::readFromFile($uri);
            } else {
                throw new Exception("Local file '$uri' doesn't exists.");
            }
        }

        return $this->feedGetUriRemote($feed, $uri, $HttpSocket)->getBody();
    }

    /**
     * @param Feed $feed
     * @param string $uri
     * @param HttpClient $HttpSocket
     * @param string|null $etag
     * @return false|HttpClientResponse
     * @throws HttpException
     */
    private function feedGetUriRemote(Feed $feed, $uri, HttpClient $HttpSocket, $etag = null)
    {
        $request = $this->__createFeedRequest($feed['headers']);
        if ($etag) {
            $request['header']['If-None-Match'] = $etag;
        }

        try {
            $response = $this->getFollowRedirect($HttpSocket, $uri, $request, $feed);
        } catch (Exception $e) {
            throw new Exception("Fetching the '$uri' failed with exception: {$e->getMessage()}", 0, $e);
        }

        if ($response->getStatusCode() != 200) { // intentionally !=
            throw new HttpException($response, $uri);
        }

        $contentType = $response->getHeader('content-type');
        if ($contentType === 'application/zip') {
            $zipFilePath = FileAccessTool::writeToTempFile($response->body);

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
     * It should be possible to use 'redirect' $request attribute, but because HttpClient contains bug that require
     * certificate for first domain even when redirect to another domain, we need to use own solution.
     *
     * @param HttpClient $HttpSocket
     * @param string $url
     * @param array $request
     * @param Feed $feed
     * @param int $iterations
     * @return false|HttpClientResponse
     * @throws Exception
     */
    private function getFollowRedirect(HttpClient $HttpSocket, $url, $request, $feed = null, $iterations = 5)
    {
        for ($i = 0; $i < $iterations; $i++) {
            $response = $HttpSocket->get($url, [], $request);
            if ($response->isRedirect()) {
                $HttpSocket = $this->__setupHttpSocket($feed); // Replace $HttpSocket with fresh instance
                $url = trim($response->getHeader('Location')[0], '=');
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
        return isset($feed['input_source']) && $feed['input_source'] === 'local';
    }

    /**
     * @param int|null $jobId
     * @param string|null $message
     * @param int|null $progress
     */
    private function jobProgress($jobId = null, $message = null, $progress = null)
    {
        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');
            $JobsTable->saveProgress($jobId, $message, $progress);
        }
    }

    /**
     * remove all events tied to a feed. Returns int on success, error message
     * as string on failure
     */
    public function cleanupFeedEvents($user_id, $id)
    {
        $feed = $this->find(
            'all',
            [
                'conditions' => ['Feed.id' => $id],
                'recursive' => -1
            ]
        )->first();
        if (empty($feed)) {
            return __('Invalid feed id.');
        }
        if (!in_array($feed['source_format'], ['csv', 'freetext'])) {
            return __('Feed has to be either a CSV or a freetext feed for the purging to work.');
        }
        $UsersTable = $this->fetchTable('Users');
        $user = $UsersTable->getAuthUser($user_id);
        if (empty($user)) {
            return __('Invalid user id.');
        }
        $conditions = ['info' => $feed['name'] . ' feed'];
        $EventsTable = $this->fetchTable('Events');
        $events = $EventsTable->find(
            'list',
            [
                'conditions' => $conditions,
                'fields' => ['id', 'id']
            ]
        )->toArray();
        $count = count($events);
        foreach ($events as $event_id) {
            $EventsTable->delete($event_id);
        }
        $LogsTable = $this->fetchTable('Logs');
        $LogsTable->saveOrFailSilently(
            [
                'org' => 'SYSTEM',
                'model' => 'Feed',
                'model_id' => $id,
                'email' => $user['email'],
                'action' => 'purge_events',
                'title' => __('Events related to feed %s purged.', $id),
                'change' => null,
            ]
        );
        $feed['fixed_event'] = 1;
        $feed['event_id'] = 0;

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

        $destinationFile = FileAccessTool::createTempFile();
        $result = copy("zip://$zipFile#$filename", $destinationFile);
        if ($result === false) {
            throw new Exception("Remote server returns ZIP file, that contains '$filename' file, but this file cannot be extracted.");
        }

        return FileAccessTool::readAndDelete($destinationFile);
    }
}
