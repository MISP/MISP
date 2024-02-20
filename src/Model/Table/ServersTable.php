<?php

namespace App\Model\Table;

use App\Http\Exception\HttpSocketHttpException;
use App\Http\Exception\HttpSocketJsonException;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\BetterSecurity;
use App\Lib\Tools\EncryptedValue;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\GitTool;
use App\Lib\Tools\GpgTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\JsonTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\ProcessTool;
use App\Lib\Tools\RedisTool;
use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\Event;
use App\Model\Entity\Job;
use App\Model\Entity\SystemSetting;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Chronos\Chronos;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Utility\Hash;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use Closure;
use DirectoryIterator;
use Exception;
use InvalidArgumentException;
use RegexIterator;
use SplFileInfo;

class ServersTable extends AppTable
{
    use LogExtendedTrait;

    public const MYSQL_RECOMMENDED_SETTINGS = [
        'innodb_buffer_pool_size' => [
            'default' => '134217728',
            'recommended' => '2147483648',
            'explanation' => 'The InnoDB buffer pool is the memory area where caches table and index data reside. It is the most important MySQL setting, in a dedicated server it should be around 3/4 of all the available RAM. In a shared server it should be around 1/2 of the available RAM.',
        ],
        'innodb_dedicated_server' => [
            'default' => '0',
            'recommended' => '',
            'explanation' => 'Set to `1` if the database is running in a dedicated server. The database engine will examine the available memory and dynamically set `innodb_buffer_pool_size`, `innodb_log_file_size`, `innodb_log_files_in_group` and `innodb_flush_method`. It is particularly useful in cloud enviroments that can be auto-scaled.',
        ],
        'innodb_log_file_size' => [
            'default' => '100663296',
            'recommended' => '629145600',
            'explanation' => 'This parameter determines the fixed size for MySQLs redo logs. Tuning this value affects the crash recovery time and also overall system performance.',
        ],
        'innodb_log_files_in_group' => [
            'default' => '2',
            'recommended' => '2',
            'explanation' => 'Defines the number of log files in the log group.',
        ],
        'innodb_change_buffering' => [
            'default' => 'none',
            'recommended' => 'none',
            'explanation' => 'Whether InnoDB performs change buffering, an optimization that delays write operations to secondary indexes so that the I/O operations can be performed sequentially, enabling it causes extremely long shutdown times for upgrades.',
        ],
        'innodb_io_capacity' => [
            'default' => '200',
            'recommended' => '1000',
            'explanation' => 'Defines the number of I/O operations per second (IOPS) available to InnoDB background tasks, such as flushing pages from the buffer pool and merging data from the change buffer.',
        ],
        'innodb_io_capacity_max' => [
            'default' => '2000',
            'recommended' => '2000',
            'explanation' => 'If flushing activity falls behind, InnoDB can flush more aggressively, at a higher rate of I/O operations per second (IOPS) than defined by the `innodb_io_capacity variable`.',
        ],
        'innodb_stats_persistent' => [
            'default' => 'ON',
            'recommended' => 'ON',
            'explanation' => 'Specifies whether InnoDB index statistics are persisted to disk. Otherwise, statistics may be recalculated frequently which can lead to variations in query execution plans.',
        ],
        'innodb_read_io_threads' => [
            'default' => '4',
            'recommended' => '16',
            'explanation' => 'The number of I/O threads for read operations in InnoDB.',
        ],
        'innodb_write_io_threads' => [
            'default' => '4',
            'recommended' => '4',
            'explanation' => 'The number of I/O threads for write operations in InnoDB.',
        ],
    ];

    public const VALID_EVENT_INDEX_FILTERS = ['searchall', 'searchpublished', 'searchorg', 'searchtag', 'searcheventid', 'searchdate', 'searcheventinfo', 'searchthreatlevel', 'searchdistribution', 'searchanalysis', 'searchattribute'];

    protected $serverSettings = [];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('EncryptedFields', ['fields' => ['authkey']]);
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => [
                    'push_rules' => [
                        'default' => ["tags" => ["OR" => [], "NOT" => []], "orgs" => ["OR" => [], "NOT" => []]]
                    ],
                    'pull_rules' => [
                        'default' => ["tags" => ["OR" => [], "NOT" => []], "orgs" => ["OR" => [], "NOT" => []], "type_attributes" => ["NOT" => []], "type_objects" => ["NOT" => []], "url_params" => ""]
                    ]
                ],
            ]
        );

        $this->belongsTo(
            'Organisations',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation',
            ]
        );
        $this->belongsTo(
            'RemoteOrg',
            [
                'className' => 'Organisations',
                'foreignKey' => 'remote_org_id',
                'propertyName' => 'RemoteOrg',
            ]
        );
        $this->hasMany(
            'SharingGroupServers',
            [
                'foreignKey' => 'server_id',
                'dependent' => true,
            ]
        );
        $this->hasMany(
            'Users',
            [
                'className' => 'Users',
                'foreignKey' => 'server_id',
                'dependent' => true,
            ]
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->requirePresence(['name'], 'create')
            ->add(
                'url',
                [
                    'validateURL' => [
                        'rule' => function ($value) {
                            return $this->testURL($value);
                        }
                    ]
                ]
            )
            ->add(
                'authkey',
                [
                    'validateAuthkey' => [
                        'rule' => function ($value) {
                            return $this->validateAuthkey($value);
                        }
                    ]
                ]
            )
            ->add(
                'org_id',
                [
                    'validateOrgId' => [
                        'rule' => function ($value) {
                            return $this->valueIsID($value);
                        },
                        'allowEmpty' => false,
                        'required' => true,
                    ]
                ]
            )
            ->boolean('push')
            ->allowEmptyString('push')
            ->boolean('pull')
            ->allowEmptyString('pull')
            ->boolean('push_sightings')
            ->allowEmptyString('push_sightings')
            ->integer('lastpushedid')
            ->allowEmptyString('lastpushedid')
            ->integer('lastpulledid')
            ->allowEmptyString('lastpulledid');

        return $validator;
    }

    public function beforeSave(EventInterface $event, EntityInterface $server, ArrayObject $options)
    {
        if (!empty($server['url'])) {
            $server['url'] = rtrim($server['url'], '/');
        }
        if (empty($server['id'])) {
            $max_prio = $this->find(
                'all',
                [
                    'recursive' => -1,
                    'order' => ['priority' => 'DESC'],
                    'fields' => ['priority']
                ]
            )->first();
            if (empty($max_prio)) {
                $max_prio = 0;
            } else {
                $max_prio = $max_prio['priority'];
            }
            $server['priority'] = $max_prio + 1;
        }
        // Encrypt authkey if plain key provided and encryption is enabled
        if (!empty($server['authkey']) && strlen($server['authkey']) === 40) {
            $server['authkey'] = EncryptedValue::encryptIfEnabled($server['authkey']);
        }

        try {
            // Clean caches when remote server setting changed
            $cacheKeys = [
                "misp:event_index:{$server->id}",
                "misp:fetched_sightings:{$server->id}",
                "misp:empty_events:{$server->id}",
            ];
            RedisTool::unlink(RedisTool::init(), $cacheKeys);
        } catch (Exception $e) {
            // ignore
        }

        return true;
    }

    /**
     * @param int|string $technique 'full', 'update', remote event ID or remote event UUID
     * @param ServerSyncTool $serverSync
     * @param bool $force
     * @return array Event UUIDSs or IDs
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    private function __getEventIdListBasedOnPullTechnique($technique, ServerSyncTool $serverSync, $force = false)
    {
        if ("full" === $technique) {
            // get a list of the event_ids on the server
            $eventIds = $this->getEventIdsFromServer($serverSync, false, false, $force);
            // reverse array of events, to first get the old ones, and then the new ones
            return array_reverse($eventIds);
        } elseif ("update" === $technique) {
            $eventIds = $this->getEventIdsFromServer($serverSync, false, true, $force);
            $EventsTable = $this->fetchTable('Events');
            $localEventUuids = $EventsTable->find(
                'column',
                [
                    'fields' => ['Event.uuid'],
                ]
            );
            return array_intersect($eventIds, $localEventUuids);
        } elseif (is_numeric($technique)) {
            return [intval($technique)];
        } elseif (Validation::uuid($technique)) {
            return [$technique];
        }
        throw new InvalidArgumentException("Invalid pull technique `$technique`.");
    }

    /**
     * @param array $event
     * @param array $server
     * @param array $user
     * @param array $pullRules
     * @return bool Return true if event was emptied by pull rules
     */
    private function __updatePulledEventBeforeInsert(array &$event, array $server, array $user, array $pullRules)
    {
        $pullRulesEmptiedEvent = false;
        // we have an Event array
        // The event came from a pull, so it should be locked.
        $event['Event']['locked'] = true;
        if (!isset($event['Event']['distribution'])) { // version 1
            $event['Event']['distribution'] = '1';
        }
        // Distribution
        if (empty(Configure::read('MISP.host_org_id')) || !$server['internal'] ||  Configure::read('MISP.host_org_id') != $server['org_id']) {
            switch ($event['Event']['distribution']) {
                case 1:
                    // if community only, downgrade to org only after pull
                    $event['Event']['distribution'] = '0';
                    break;
                case 2:
                    // if connected communities downgrade to community only
                    $event['Event']['distribution'] = '1';
                    break;
            }
            // We remove local tags obtained via pull
            if (isset($event['Event']['Tag'])) {
                foreach ($event['Event']['Tag'] as $key => $a) {
                    if ($a['local']) {
                        unset($event['Event']['Tag'][$key]);
                    }
                }
            }

            $filterOnTypeEnabled = !empty(Configure::read('MISP.enable_synchronisation_filtering_on_type'));
            $attributeTypeFilteringEnabled = $filterOnTypeEnabled && !empty($pullRules['type_attributes']['NOT']);

            if (isset($event['Event']['Attribute'])) {
                $originalCount = count($event['Event']['Attribute']);
                foreach ($event['Event']['Attribute'] as $key => $attribute) {
                    if ($attributeTypeFilteringEnabled && in_array($attribute['type'], $pullRules['type_attributes']['NOT'], true)) {
                        unset($event['Event']['Attribute'][$key]);
                        continue;
                    }
                    switch ($attribute['distribution']) {
                        case '1':
                            $event['Event']['Attribute'][$key]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['Attribute'][$key]['distribution'] = '1';
                            break;
                    }
                    // We remove local tags obtained via pull
                    if (isset($attribute['Tag'])) {
                        foreach ($attribute['Tag'] as $k => $v) {
                            if ($v['local']) {
                                unset($event['Event']['Attribute'][$key]['Tag'][$k]);
                            }
                        }
                    }
                }
                if ($attributeTypeFilteringEnabled && $originalCount > 0 && empty($event['Event']['Attribute'])) {
                    $pullRulesEmptiedEvent = true;
                }
            }

            if (isset($event['Event']['Object'])) {
                $originalObjectCount = count($event['Event']['Object']);
                foreach ($event['Event']['Object'] as $i => $object) {
                    if (
                        $filterOnTypeEnabled &&
                        !empty($pullRules['type_objects']['NOT']) &&
                        in_array($object['template_uuid'], $pullRules['type_objects']['NOT'], true)
                    ) {
                        unset($event['Event']['Object'][$i]);
                        continue;
                    }
                    switch ($object['distribution']) {
                        case '1':
                            $event['Event']['Object'][$i]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['Object'][$i]['distribution'] = '1';
                            break;
                    }
                    if (isset($object['Attribute'])) {
                        $originalAttributeCount = count($object['Attribute']);
                        foreach ($object['Attribute'] as $j => $a) {
                            if ($attributeTypeFilteringEnabled && in_array($a['type'], $pullRules['type_attributes']['NOT'], true)) {
                                unset($event['Event']['Object'][$i]['Attribute'][$j]);
                                continue;
                            }
                            switch ($a['distribution']) {
                                case '1':
                                    $event['Event']['Object'][$i]['Attribute'][$j]['distribution'] = '0';
                                    break;
                                case '2':
                                    $event['Event']['Object'][$i]['Attribute'][$j]['distribution'] = '1';
                                    break;
                            }
                            // We remove local tags obtained via pull
                            if (isset($a['Tag'])) {
                                foreach ($a['Tag'] as $k => $v) {
                                    if ($v['local']) {
                                        unset($event['Event']['Object'][$i]['Attribute'][$j]['Tag'][$k]);
                                    }
                                }
                            }
                        }
                        if ($attributeTypeFilteringEnabled && $originalAttributeCount > 0 && empty($event['Event']['Object'][$i]['Attribute'])) {
                            unset($event['Event']['Object'][$i]); // Object is empty, get rid of it
                        }
                    }
                }
                if ($filterOnTypeEnabled && $originalObjectCount > 0 && empty($event['Event']['Object'])) {
                    $pullRulesEmptiedEvent = true;
                }
            }
            if (isset($event['Event']['EventReport'])) {
                foreach ($event['Event']['EventReport'] as $key => $r) {
                    switch ($r['distribution']) {
                        case '1':
                            $event['Event']['EventReport'][$key]['distribution'] = '0';
                            break;
                        case '2':
                            $event['Event']['EventReport'][$key]['distribution'] = '1';
                            break;
                    }
                }
            }
        }

        // Distribution, set reporter of the event, being the admin that initiated the pull
        $event['Event']['user_id'] = $user['id'];

        return $pullRulesEmptiedEvent;
    }

    /**
     * @param array $event
     * @return bool True if event is not empty
     */
    private function __checkIfEventSaveAble(array $event)
    {
        if (!empty($event['Event']['Attribute'])) {
            foreach ($event['Event']['Attribute'] as $attribute) {
                if (empty($attribute['deleted'])) {
                    return true;
                }
            }
        }
        if (!empty($event['Event']['Object'])) {
            foreach ($event['Event']['Object'] as $object) {
                if (!empty($object['deleted'])) {
                    continue;
                }
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        if (empty($attribute['deleted'])) {
                            return true;
                        }
                    }
                }
            }
        }
        if (!empty($event['Event']['EventReport'])) {
            foreach ($event['Event']['EventReport'] as $report) {
                if (empty($report['deleted'])) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param array $event
     * @param int|string $eventId
     * @param array $successes
     * @param array $fails
     * @param EventsTable $EventsTable
     * @param array $server
     * @param array $user
     * @param int $jobId
     * @param bool $force
     * @param Response $response
     * @return false|void
     * @throws Exception
     */
    private function __checkIfPulledEventExistsAndAddOrUpdate($event, $eventId, &$successes, &$fails, EventsTable $EventsTable, $server, $user, $jobId, $force, $response)
    {
        $force = $force ?? false;

        // check if the event already exist (using the uuid)
        $existingEvent = $EventsTable->find(
            'all',
            [
                'conditions' => ['uuid' => $event['Event']['uuid']],
                'recursive' => -1,
                'fields' => ['id', 'locked', 'protected'],
                'contain' => ['CryptographicKeys']
            ]
        )->first();
        $passAlong = $server['id'];
        if (!$existingEvent) {
            // add data for newly imported events
            if (isset($event['Event']['protected']) && $event['Event']['protected']) {
                if (!$EventsTable->CryptographicKeys->validateProtectedEvent($response->body, $user, $response->getHeader('x-pgp-signature'), $event)) {
                    $fails[$eventId] = __('Event failed the validation checks. The remote instance claims that the event can be signed with a valid key which is sus.');
                    return false;
                }
            }
            $result = $EventsTable->_add($event, true, $user, $server['org_id'], $passAlong, true, $jobId);
            if ($result) {
                $successes[] = $eventId;
                if ($this->pubToZmq('event')) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->event_save(['Event' => $eventId, 'Server' => $server['id']], 'add_from_connected_server');
                }
            } else {
                $fails[$eventId] = __('Failed (partially?) because of validation errors: ') . json_encode($EventsTable->validationErrors);
            }
        } else {
            if (!$existingEvent['Event']['locked'] && !$server['internal']) {
                $fails[$eventId] = __('Blocked an edit to an event that was created locally. This can happen if a synchronised event that was created on this instance was modified by an administrator on the remote side.');
            } else {
                if ($existingEvent['Event']['protected']) {
                    if (!$EventsTable->CryptographicKeys->validateProtectedEvent($response->body, $user, $response->getHeader('x-pgp-signature'), $existingEvent)) {
                        $fails[$eventId] = __('Event failed the validation checks. The remote instance claims that the event can be signed with a valid key which is sus.');
                    }
                }
                $result = $EventsTable->_edit($event, $user, $existingEvent['Event']['id'], $jobId, $passAlong, $force);
                if ($result === true) {
                    $successes[] = $eventId;
                    if ($this->pubToZmq('event')) {
                        $pubSubTool = $this->getPubSubTool();
                        $pubSubTool->event_save(['Event' => $eventId, 'Server' => $server['id']], 'edit_from_connected_server');
                    }
                } elseif (isset($result['error'])) {
                    $fails[$eventId] = $result['error'];
                } else {
                    $fails[$eventId] = json_encode($result);
                }
            }
        }
    }

    /**
     * @param int|string $eventId Event ID or UUID
     * @param array $successes
     * @param array $fails
     * @param EventsTable $EventsTable
     * @param ServerSyncTool $serverSync
     * @param array $user
     * @param int $jobId
     * @param bool $force
     * @return bool
     */
    private function __pullEvent($eventId, array &$successes, array &$fails, EventsTable $EventsTable, ServerSyncTool $serverSync, $user, $jobId, $force = false)
    {
        $params = [
            'deleted' => [0, 1],
            'excludeGalaxy' => 1,
            'includeEventCorrelations' => 0, // we don't need remote correlations
            'includeFeedCorrelations' => 0,
            'includeWarninglistHits' => 0, // we don't need remote warninglist hits
        ];
        if (empty($serverSync->server()['internal'])) {
            $params['excludeLocalTags'] = 1;
        }
        try {
            $response = $serverSync->fetchEvent($eventId, $params);
            $event = $response->getJson();
        } catch (Exception $e) {
            $this->logException("Failed to download the event $eventId from remote server {$serverSync->serverId()} '{$serverSync->serverName()}'", $e);
            $fails[$eventId] = __('failed downloading the event');
            return false;
        }

        $pullRulesEmptiedEvent = $this->__updatePulledEventBeforeInsert($event, $serverSync->server(), $user, $serverSync->pullRules());

        if (!$this->__checkIfEventSaveAble($event)) {
            if (!$pullRulesEmptiedEvent) { // The event is empty because of the filtering rule. This is not considered a failure
                $fails[$eventId] = __('Empty event detected.');
                $this->addEmptyEvent($serverSync->serverId(), $event);
            }
            return false;
        }
        $this->__checkIfPulledEventExistsAndAddOrUpdate($event, $eventId, $successes, $fails, $EventsTable, $serverSync->server(), $user, $jobId, $force, $response);
        return true;
    }

    /**
     * @param array $user
     * @param string $technique
     * @param array $server
     * @param int|false $jobId
     * @param bool $force
     * @return array|string
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws JsonException
     */
    public function pull(array $user, $technique, array $server, $jobId = false, $force = false)
    {
        if ($jobId) {
            Configure::write('CurrentUserId', $user['id']);
            $JobsTable = $this->fetchTable('Jobs');
            $email = "Scheduled job";
        } else {
            $email = $user['email'];
        }

        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
        try {
            $server['version'] = $serverSync->info()['version'];
        } catch (Exception $e) {
            $this->logException("Could not get remote server `{$server['name']}` version.", $e);
            if ($e instanceof HttpSocketHttpException && $e->getCode() === 403) {
                $message = __('Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server. Another reason could be an incorrect sync server setting.');
            } else {
                $message = $e->getMessage();
            }
            $title = 'Failed pull from ' . $server['url'] . ' initiated by ' . $email;
            $this->loadLog()->createLogEntry($user, 'error', 'Server', $server['id'], $title, $message);
            return $message;
        }

        $pulledClusters = 0;
        if (!empty($server['pull_galaxy_clusters'])) {
            $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            if ($jobId) {
                $JobsTable->saveProgress($jobId, $technique === 'pull_relevant_clusters' ? __('Pulling relevant galaxy clusters.') : __('Pulling galaxy clusters.'));
            }
            $pulledClusters = $GalaxyClustersTable->pullGalaxyClusters($user, $serverSync, $technique);
            if ($technique === 'pull_relevant_clusters') {
                if ($jobId) {
                    $JobsTable->saveStatus($jobId, true, 'Pulling complete.');
                }
                return [[], [], 0, 0, $pulledClusters];
            }
            if ($jobId) {
                $JobsTable->saveProgress($jobId, 'Pulling events.', 10);
            }
        }

        try {
            $eventIds = $this->__getEventIdListBasedOnPullTechnique($technique, $serverSync, $force);
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server `{$server['name']}`.", $e);
            if ($e instanceof HttpSocketHttpException && $e->getCode() === 403) {
                $message = __('Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server. Another reason could be an incorrect sync server setting.');
            } else {
                $message = $e->getMessage();
            }
            $title = 'Failed pull from ' . $server['url'] . ' initiated by ' . $email;
            $this->loadLog()->createLogEntry($user, 'error', 'Server', $server['id'], $title, $message);
            return $message;
        }

        /** @var EventsTable $EventTable */
        $EventsTable = $this->fetchTable('Events');
        $successes = [];
        $fails = [];
        // now process the $eventIds to pull each of the events sequentially
        if (!empty($eventIds)) {
            // download each event
            if ($jobId) {
                $JobsTable->saveProgress($jobId, __n('Pulling {0} event.', 'Pulling {1} events.', count($eventIds), count($eventIds)));
            }
            foreach ($eventIds as $k => $eventId) {
                $this->__pullEvent($eventId, $successes, $fails, $EventsTable, $serverSync, $user, $jobId, $force);
                if ($jobId && $k % 10 === 0) {
                    $JobsTable->saveProgress($jobId, null, 10 + 40 * (($k + 1) / count($eventIds)));
                }
            }
            foreach ($fails as $eventid => $message) {
                $this->loadLog()->createLogEntry($user, 'pull', 'Server', $server['id'], "Failed to pull event #$eventid.", 'Reason: ' . $message);
            }
        }
        if ($jobId) {
            $JobsTable->saveProgress($jobId, 'Pulling proposals.', 50);
        }
        $pulledProposals = $pulledSightings = 0;
        if ($technique === 'full' || $technique === 'update') {
            $pulledProposals = $EventsTable->ShadowAttributes->pullProposals($user, $serverSync);

            if ($jobId) {
                $JobsTable->saveProgress($jobId, 'Pulling sightings.', 75);
            }
            $pulledSightings = $EventsTable->Sightings->pullSightings($user, $serverSync);
        }
        if ($jobId) {
            $JobsTable->saveStatus($jobId, true, 'Pull completed.');
        }

        $change = sprintf(
            '%s events, %s proposals, %s sightings and %s galaxy clusters pulled or updated. %s events failed or didn\'t need an update.',
            count($successes),
            $pulledProposals,
            $pulledSightings,
            $pulledClusters,
            count($fails)
        );
        $this->loadLog()->createLogEntry($user, 'pull', 'Server', $server['id'], 'Pull from ' . $server['url'] . ' initiated by ' . $email, $change);
        return [$successes, $fails, $pulledProposals, $pulledSightings, $pulledClusters];
    }

    public function filterRuleToParameter($filter_rules)
    {
        $final = [];
        if (empty($filter_rules)) {
            return $final;
        }
        $url_params = [];
        foreach ($filter_rules as $field => $rules) {
            $temp = [];
            if ($field === 'url_params') {
                $url_params = empty($rules) ? [] : $this->jsonDecode($rules);
            } else {
                foreach ($rules as $operator => $elements) {
                    foreach ($elements as $k => $element) {
                        if ($operator === 'NOT') {
                            $element = '!' . $element;
                        }
                        if (!empty($element)) {
                            $temp[] = $element;
                        }
                    }
                }
                if (!empty($temp)) {
                    $final[substr($field, 0, strlen($field) - 1)] = $temp;
                }
            }
        }
        if (!empty($url_params)) {
            $final = array_merge_recursive($final, $url_params);
        }
        return $final;
    }

    /**
     * fetchCustomClusterIdsFromServer Fetch custom-published remote clusters' UUIDs and versions
     *
     * @param ServerSyncTool $serverSync
     * @param array $conditions
     * @return array The list of clusters
     * @throws JsonException|HttpSocketHttpException|HttpSocketJsonException
     */
    private function fetchCustomClusterIdsFromServer(ServerSyncTool $serverSync, array $conditions = [])
    {
        $filterRules = [
            'published' => 1,
            'minimal' => 1,
            'custom' => 1,
        ];
        $filterRules = array_merge($filterRules, $conditions);
        $clusterArray = $serverSync->galaxyClusterSearch($filterRules)->getJson();
        if (isset($clusterArray['response'])) {
            $clusterArray = $clusterArray['response'];
        }
        return $clusterArray;
    }

    /**
     * Get a list of cluster IDs that are present on the remote server and returns clusters that should be pulled
     *
     * @param ServerSyncTool $serverSync
     * @param bool $onlyUpdateLocalCluster If set to true, only cluster present locally will be returned
     * @param array $eligibleClusters Array of cluster present locally that could potentially be updated. Linked to $onlyUpdateLocalCluster
     * @param array $conditions Conditions to be sent to the remote server while fetching accessible clusters IDs
     * @return array List of cluster UUIDs to be pulled
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws JsonException
     */
    public function getElligibleClusterIdsFromServerForPull(ServerSyncTool $serverSync, $onlyUpdateLocalCluster = true, array $eligibleClusters = [], array $conditions = [])
    {
        $this->log("Fetching eligible clusters from server #{$serverSync->serverId()} for pull: " . JsonTool::encode($conditions), LOG_INFO);

        if ($onlyUpdateLocalCluster && empty($eligibleClusters)) {
            return []; // no clusters for update
        }

        $clusterArray = $this->fetchCustomClusterIdsFromServer($serverSync, $conditions = $conditions);
        if (empty($clusterArray)) {
            return []; // empty remote clusters
        }

        /** @var GalaxyClusterBlocklistsTable $GalaxyClusterBlocklistsTable */
        $GalaxyClusterBlocklistsTable = $this->fetchTable('GalaxyClusterBlocklists');

        if (!$onlyUpdateLocalCluster) {
            /** @var GalaxyClustersTable $GalaxyClustersTable */
            $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            // Do not fetch clusters with the same or newer version that already exists on local instance
            $eligibleClusters = $GalaxyClustersTable->find(
                'list',
                [
                    'conditions' => ['GalaxyCluster.uuid' => array_column(array_column($clusterArray, 'GalaxyCluster'), 'uuid')],
                    'fields' => ['GalaxyCluster.uuid', 'GalaxyCluster.version'],
                ]
            );
        }

        $clustersForPull = [];
        foreach ($clusterArray as $cluster) {
            $clusterUuid = $cluster['GalaxyCluster']['uuid'];

            if ($GalaxyClusterBlocklistsTable->checkIfBlocked($clusterUuid)) {
                continue; // skip blocked clusters
            }

            if (isset($eligibleClusters[$clusterUuid])) {
                $localVersion = $eligibleClusters[$clusterUuid];
                if ($localVersion < $cluster['GalaxyCluster']['version']) {
                    $clustersForPull[] = $clusterUuid;
                }
            } elseif (!$onlyUpdateLocalCluster) {
                $clustersForPull[] = $clusterUuid;
            }
        }
        return $clustersForPull;
    }

    /**
     * Get an array of cluster_ids that are present on the remote server and returns clusters that should be pushed.
     * @param ServerSyncTool $serverSync
     * @param array $localClusters
     * @param array $conditions
     * @return array
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws JsonException
     */
    private function getElligibleClusterIdsFromServerForPush(ServerSyncTool $serverSync, array $localClusters = [], array $conditions = [])
    {
        $this->log("Fetching eligible clusters from server #{$serverSync->serverId()} for push: " . JsonTool::encode($conditions), LOG_INFO);
        $clusterArray = $this->fetchCustomClusterIdsFromServer($serverSync, $conditions = $conditions);
        $keyedClusterArray = Hash::combine($clusterArray, '{n}.GalaxyCluster.uuid', '{n}.GalaxyCluster.version');
        if (!empty($localClusters)) {
            foreach ($localClusters as $k => $localCluster) {
                if (isset($keyedClusterArray[$localCluster['GalaxyCluster']['uuid']])) {
                    $remoteVersion = $keyedClusterArray[$localCluster['GalaxyCluster']['uuid']];
                    if ($localCluster['GalaxyCluster']['version'] <= $remoteVersion) {
                        unset($localClusters[$k]);
                    }
                }
            }
        }
        return $localClusters;
    }

    /**
     * @param ServerSyncTool $serverSync
     * @param bool $ignoreFilterRules Ignore defined server pull rules
     * @return array
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws JsonException
     * @throws RedisException
     */
    public function getEventIndexFromServer(ServerSyncTool $serverSync, $ignoreFilterRules = false)
    {
        if (!$ignoreFilterRules) {
            $filterRules = $this->filterRuleToParameter($serverSync->server()['pull_rules']);
            if (!empty($filterRules['org']) && !$serverSync->isSupported(ServerSyncTool::FEATURE_ORG_RULE)) {
                $filterRules['org'] = implode('|', $filterRules['org']);
            }
        } else {
            $filterRules = [];
        }
        $filterRules['minimal'] = 1;
        $filterRules['published'] = 1;

        // Fetch event index from cache if exists and is not modified
        $redis = RedisTool::init();
        $indexFromCache = $redis->get("misp:event_index:{$serverSync->serverId()}");
        if ($indexFromCache) {
            list($etag, $eventIndex) = RedisTool::deserialize(RedisTool::decompress($indexFromCache));
        } else {
            $etag = '""';  // Provide empty ETag, so MISP will compute ETag for returned data
        }

        $response = $serverSync->eventIndex($filterRules, $etag);

        if ($response->getStatusCode() === 304 && $indexFromCache) {
            return $eventIndex;
        }

        $eventIndex = $response->getJson();

        // correct $eventArray if just one event, probably this response returns old MISP
        if (isset($eventIndex['id'])) {
            $eventIndex = [$eventIndex];
        }

        // Save to cache for 24 hours if ETag provided
        $etag = null;
        if (count($response->getHeader('etag'))) {
            $etag = $response->getHeader('etag')[0];
        }

        if ($etag) {
            $data = RedisTool::compress(RedisTool::serialize([$etag, $eventIndex]));
            $redis->setex("misp:event_index:{$serverSync->serverId()}", 3600 * 24, $data);
        } elseif ($indexFromCache) {
            RedisTool::unlink($redis, "misp:event_index:{$serverSync->serverId()}");
        }

        return $eventIndex;
    }

    /**
     * @param array $events
     * @return void
     */
    private function removeOlderEvents(array &$events)
    {
        if (empty($events)) {
            return;
        }

        $conditions = (count($events) > 10000) ? [] : ['uuid IN' => array_column($events, 'uuid')];
        $EventsTable = $this->fetchTable('Events');
        $localEvents = $EventsTable->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => $conditions,
                'fields' => ['Events.uuid', 'Events.timestamp', 'Events.locked'],
            ]
        )->toArray();
        $localEvents = array_column($localEvents, null, 'uuid');
        foreach ($events as $k => $event) {
            $uuid = $event['uuid'];
            if (isset($localEvents[$uuid]) && ($localEvents[$uuid]['timestamp'] >= $event['timestamp'] || !$localEvents[$uuid]['locked'])) {
                unset($events[$k]);
            }
        }
    }

    /**
     * @param int $serverId
     * @param array $event
     * @return void
     * @throws RedisException
     */
    private function addEmptyEvent($serverId, array $event)
    {
        $emptyEventKey = "{$event['Event']['uuid']}:{$event['Event']['timestamp']}";
        $redis = RedisTool::init();
        $redis->sAdd("misp:empty_events:$serverId", $emptyEventKey);
        $redis->expire("misp:empty_events:$serverId", 24 * 3600);
    }

    /**
     * Remove from $events array events, that was already fetched before and was empty.
     * @param int $serverId
     * @param array $events
     * @return void
     */
    private function removeEmptyEvents($serverId, array &$events)
    {
        try {
            $emptyEvents = RedisTool::init()->sMembers("misp:empty_events:$serverId");
        } catch (Exception $e) {
            return;
        }
        if (empty($emptyEvents)) {
            return;
        }
        $emptyEvents = array_flip($emptyEvents);
        foreach ($events as $k => $event) {
            if (isset($emptyEvents["{$event['uuid']}:{$event['timestamp']}"])) {
                unset($events[$k]);
            }
        }
    }

    /**
     * Get an array of event UUIDs that are present on the remote server.
     *
     * @param ServerSyncTool $serverSync
     * @param bool $all
     * @param bool $ignoreFilterRules Ignore defined server pull rules
     * @param bool $force If true, returns all events regardless their update timestamp
     * @return array Array of event UUIDs.
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     * @throws InvalidArgumentException
     */
    private function getEventIdsFromServer(ServerSyncTool $serverSync, $all = false, $ignoreFilterRules = false, $force = false)
    {
        $eventArray = $this->getEventIndexFromServer($serverSync, $ignoreFilterRules);

        if ($all) {
            return array_column($eventArray, 'uuid');
        }

        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
            $EventBlocklistsTable = $this->fetchTable('EventBlocklists');
            $EventBlocklistsTable->removeBlockedEvents($eventArray);
        }

        if (Configure::read('MISP.enableOrgBlocklisting') !== false) {
            $OrgBlocklistsTable = $this->fetchTable('OrgBlocklists');
            $OrgBlocklistsTable->removeBlockedEvents($eventArray);
        }

        foreach ($eventArray as $k => $event) {
            if (1 != $event['published']) {
                unset($eventArray[$k]); // do not keep non-published events
            }
        }
        if (!$force) {
            $this->removeOlderEvents($eventArray);
            $this->removeEmptyEvents($serverSync->serverId(), $eventArray);
        }
        return array_column($eventArray, 'uuid');
    }

    public function serverEventsOverlap()
    {
        $servers = $this->find(
            'all',
            [
                'conditions' => ['Server.pull' => 1],
                'order' => ['Server.id ASC'],
                'recursive' => -1,
            ]
        )->toArray();

        if (count($servers) < 2) {
            return [$servers, []];
        }

        $serverUuids = [];
        foreach ($servers as &$server) {
            try {
                $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
                $uuids = array_column($this->getEventIndexFromServer($serverSync, true), 'uuid');
                $serverUuids[$server['id']] = array_flip($uuids);
                $server['events_count'] = count($uuids);
            } catch (Exception $e) {
                $this->logException("Could not get event UUIDs for server {$server['id']}", $e);
            }
        }
        unset($server);

        $compared = [];
        foreach ($servers as $server) {
            if (!isset($serverUuids[$server['id']])) {
                continue;
            }

            foreach ($servers as $server2) {
                if ($server['id'] == $server2['id']) {
                    continue;
                }
                if (!isset($serverUuids[$server2['id']])) {
                    continue;
                }

                $intersect = count(array_intersect_key($serverUuids[$server['id']], $serverUuids[$server2['id']]));
                $percentage = round(100 * $intersect / $server['events_count']);
                $compared[$server['id']][$server2['id']] = [
                    'percentage' => $percentage,
                    'events' => $intersect,
                ];
            }
        }
        return [$servers, $compared];
    }

    /**
     * @param int $id Server ID
     * @param string|int $technique Can be 'full', 'incremental' or event ID
     * @param int|false $jobId
     * @param HttpSocket $HttpSocket
     * @param array $user
     * @return array|bool
     * @throws Exception
     */
    public function push($id, $technique, $jobId, $HttpSocket, array $user)
    {
        $jobId = $jobId ?? false;

        $technique = $technique ?? 'full';

        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');
        }
        $server = $this->get($id);
        if (!$server) {
            throw new NotFoundException('Server not found');
        }
        $serverSync = new ServerSyncTool($server->toArray(), $this->setupSyncRequest($server->toArray()));

        $EventsTable = $this->fetchTable('Events');
        $url = $server['url'];
        $push = $this->checkVersionCompatibility($server->toArray(), $user, $serverSync);
        if (is_array($push) && !$push['canPush'] && !$push['canSight']) {
            $push = 'Remote instance is outdated or no permission to push.';
        }
        if (!is_array($push)) {
            $message = __('Push to server {0} failed. Reason: {1}', $id, $push);
            $LogsTable = $this->fetchTable('Logs');
            $LogsTable->saveOrFailSilently(
                [
                    'org' => $user['Organisation']['name'],
                    'model' => 'Server',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'error',
                    'user_id' => $user['id'],
                    'title' => 'Failed: Push to ' . $url . ' initiated by ' . $user['email'],
                    'change' => $message
                ]
            );
            if ($jobId) {
                $JobsTable->saveStatus($jobId, false, $message);
            }
            return $push;
        }

        // sync events if user is capable and server is configured for push
        if ($push['canPush'] && $server['push']) {
            $successes = [];
            if ("full" == $technique) {
                $eventid_conditions_key = 'Events.id >';
                $eventid_conditions_value = 0;
            } elseif ("incremental" == $technique) {
                $eventid_conditions_key = 'Events.id >';
                $eventid_conditions_value = $server['lastpushedid'];
            } elseif (intval($technique) !== 0) {
                $eventid_conditions_key = 'Events.id';
                $eventid_conditions_value = intval($technique);
            } else {
                throw new InvalidArgumentException("Technique parameter must be 'full', 'incremental' or event ID.");
            }

            // sync custom galaxy clusters if user is capable
            if ($push['canEditGalaxyCluster'] && $server['push_galaxy_clusters'] && "full" == $technique) {
                $clustersSuccesses = $this->syncGalaxyClusters($serverSync, $server->toArray(), $user, $technique = 'full');
            } else {
                $clustersSuccesses = [];
            }
            $successes = array_merge($successes, $clustersSuccesses);

            $sgs = $EventsTable->SharingGroup->find(
                'all',
                [
                    'recursive' => -1,
                    'contain' => ['Organisations', 'SharingGroupOrgs' => ['Organisations'], 'SharingGroupServers']
                ]
            );
            $sgIds = [];
            foreach ($sgs as $sg) {
                if ($EventsTable->SharingGroup->checkIfServerInSG($sg, $server)) {
                    $sgIds[] = $sg['id'];
                }
            }
            if (empty($sgIds)) {
                $sgIds = [-1];
            }
            $eventReportQuery = 'EXISTS (SELECT id, deleted FROM event_reports WHERE event_reports.event_id = Events.id and event_reports.deleted = 0)';
            $findParams = [
                'conditions' => [
                    $eventid_conditions_key => $eventid_conditions_value,
                    'Events.published' => 1,
                    'OR' => [
                        [
                            ['Events.attribute_count >' => 0],
                            [$eventReportQuery]
                        ],
                        [
                            'AND' => [
                                ['Events.distribution >' => 0],
                                ['Events.distribution <' => 4],
                            ],
                        ],
                        [
                            'AND' => [
                                'Events.distribution' => 4,
                                'Events.sharing_group_id IN' => $sgIds
                            ],
                        ]
                    ]
                ], // array of conditions
                'recursive' => -1, //int
                'contain' => ['EventTags' => ['fields' => ['EventTags.tag_id', 'EventTags.event_id']]],
                'fields' => ['Events.id', 'Events.timestamp', 'Events.sighting_timestamp', 'Events.uuid', 'Events.orgc_id'], // array of field names
            ];
            $eventIds = $EventsTable->find('all', $findParams)->toArray();
            $eventUUIDsFiltered = $this->getEventIdsForPush($server->toArray(), $serverSync, $eventIds);
            if (!empty($eventUUIDsFiltered)) {
                $eventCount = count($eventUUIDsFiltered);
                // now process the $eventIds to push each of the events sequentially
                $fails = [];
                foreach ($eventUUIDsFiltered as $k => $eventUuid) {
                    $params = [];
                    if (!empty($server['push_rules'])) {
                        if (!empty($server['push_rules']['tags']['NOT'])) {
                            $params['blockedAttributeTags'] = $server['push_rules']['tags']['NOT'];
                        }
                    }
                    $params = array_merge(
                        $params,
                        [
                            'event_uuid' => $eventUuid,
                            'includeAttachments' => true,
                            'includeAllTags' => true,
                            'deleted' => [0, 1],
                            'excludeGalaxy' => 1
                        ]
                    );
                    if (empty($server['push_sightings'])) {
                        $params['noSightings'] = 1;
                    }
                    $event = $EventsTable->fetchEvent($user, $params);
                    $event = $event[0];
                    $event['locked'] = 1;

                    // Check if remote server supports galaxy cluster push, is set to push and if event will be pushed to
                    // server
                    $pushGalaxyClustersForEvent = $push['canEditGalaxyCluster'] &&
                        $server['push_galaxy_clusters'] &&
                        "full" !== $technique &&
                        $EventsTable->shouldBePushedToServer($event, $server->toArray());

                    if ($pushGalaxyClustersForEvent) {
                        $this->syncGalaxyClusters($serverSync, $this->data, $user, $technique = $event['id'], $event = $event);
                    }

                    $result = $EventsTable->uploadEventToServer($event, $server->toArray(), $serverSync);
                    if ('Success' === $result) {
                        $successes[] = $event['id'];
                    } else {
                        $fails[$event['id']] = $result;
                    }
                    if ($jobId && $k % 10 == 0) {
                        $JobsTable->saveProgress($jobId, null, 100 * $k / $eventCount);
                    }
                }
                if (count($fails) > 0) {
                    // there are fails, take the lowest fail
                    $lastpushedid = min(array_keys($fails));
                } else {
                    // no fails, take the highest success
                    $lastpushedid = max($successes);
                }
                // increment lastid based on the highest ID seen
                // Save the entire Server data instead of just a single field, so that the logger can be fed with the extra fields.
                $server['lastpushedid'] = $lastpushedid;
                $this->save($server);
            }
            $this->syncProposals($HttpSocket, $server->toArray(), null, null, $EventsTable);
        }

        if ($push['canPush'] || $push['canSight']) {
            $SightingsTable = $this->fetchTable('Sightings');
            $sightingSuccesses = $SightingsTable->pushSightings($user, $serverSync);
        } else {
            $sightingSuccesses = [];
        }

        if (!isset($successes)) {
            $successes = $sightingSuccesses;
        } else {
            $successes = array_merge($successes, $sightingSuccesses);
        }
        if (!isset($fails)) {
            $fails = [];
        }

        $LogsTable = $this->fetchTable('Logs');
        $LogsTable->saveOrFailSilently(
            [
                'org' => $user['Organisation']['name'],
                'model' => 'Server',
                'model_id' => $id,
                'email' => $user['email'],
                'action' => 'push',
                'user_id' => $user['id'],
                'title' => 'Push to ' . $url . ' initiated by ' . $user['email'],
                'change' => count($successes) . ' events pushed or updated. ' . count($fails) . ' events failed or didn\'t need an update.'
            ]
        );
        if ($jobId) {
            $JobsTable->saveStatus($jobId, true, __('Push to server {0} complete.', $id));
        } else {
            return [$successes, $fails];
        }
        return true;
    }

    /**
     * @param array $server
     * @param ServerSyncTool $serverSync
     * @param array $events
     * @return array|false
     */
    private function getEventIdsForPush(array $server, ServerSyncTool $serverSync, array $events)
    {
        $request = [];
        foreach ($events as $event) {
            if (empty($this->eventFilterPushableServers($event, [$server]))) {
                continue;
            }
            $request[] = [
                'Event' => [
                    'uuid' => $event['uuid'],
                    'timestamp' => $event['timestamp'],
                ]

            ];
        }

        if (empty($request)) {
            return [];
        }

        try {
            return $serverSync->filterEventIdsForPush($request)->getJson();
        } catch (Exception $e) {
            $this->logException("Could not filter events for push when pushing to server {$serverSync->serverId()}", $e);
            return false;
        }
    }

    /**
     * syncGalaxyClusters Push eligible clusters depending on the provided technique
     *
     * @param  ServerSyncTool $serverSync
     * @param  array $server
     * @param  array $user
     * @param  string|int $technique Either the 'full' string or the event id
     * @param  array|bool  $event
     * @return array List of successfully pushed clusters
     */
    public function syncGalaxyClusters(ServerSyncTool $serverSync, array $server, array $user, $technique = 'full', $event = false)
    {
        if (!$server['push_galaxy_clusters']) {
            return []; // pushing clusters is not enabled
        }

        $this->log("Starting $technique clusters sync with server #{$serverSync->serverId()}", LOG_INFO);

        $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');

        if ($technique === 'full') {
            $clusters = $GalaxyClustersTable->getElligibleClustersToPush($user, $conditions = [], $full = true);
        } else {
            if ($event === false) {
                throw new InvalidArgumentException('The event from which the cluster should be taken must be provided.');
            }
            $tagNames = $this->User->Event->extractAllTagNames($event);
            if (empty($tagNames)) {
                return [];
            }
            // Filter out tag names that are not in custom galaxy cluster format
            $customGalaxyClusterTags = array_filter(
                $tagNames,
                function ($tagName) {
                    return $this->User->Event->EventTag->Tag->isCustomGalaxyClusterTag($tagName);
                }
            );
            if (empty($customGalaxyClusterTags)) {
                return [];
            }
            $clusters = $GalaxyClustersTable->getElligibleClustersToPush($user, $conditions = ['GalaxyCluster.tag_name' => $customGalaxyClusterTags], $full = true);
        }
        if (empty($clusters)) {
            return []; // no local clusters eligible for push
        }
        $localClusterUUIDs = Hash::extract($clusters, '{n}.GalaxyCluster.uuid');
        try {
            $clustersToPush = $this->getElligibleClusterIdsFromServerForPush($serverSync, $localClusters = $clusters, $conditions = ['uuid' => $localClusterUUIDs]);
        } catch (Exception $e) {
            $this->logException("Could not get eligible cluster IDs from server #{$server['id']} for push.", $e);
            return [];
        }
        $successes = [];
        foreach ($clustersToPush as $cluster) {
            $result = $GalaxyClustersTable->uploadClusterToServer($cluster, $server, $serverSync, $user);
            if ($result === 'Success') {
                $successes[] = __('GalaxyCluster {0}', $cluster['GalaxyCluster']['uuid']);
            }
        }
        return $successes;
    }

    public function syncProposals($HttpSocket, array $server, $sa_id, $event_id, $EventsTable)
    {
        $sa_id = $sa_id ?? null;
        $event_id = $event_id ?? null;

        $ShadowAttributesTable = $this->fetchTable('ShadowAttributes');

        $HttpSocket = new HttpTool();
        $HttpSocket->configFromServer($server);

        if ($sa_id == null) {
            if ($event_id == null) {
                // event_id is null when we are doing a push
                $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
                try {
                    $ids = $this->getEventIdsFromServer($serverSync, true, true);
                } catch (Exception $e) {
                    $this->logException("Could not fetch event IDs from server {$server['name']}", $e);
                    return false;
                }
                $conditions = ['uuid IN' => $ids];
            } else {
                $conditions = ['id' => $event_id];
                // event_id is not null when we are doing a publish
            }

            if (empty($ids)) {
                return true;
            }

            $events = $EventsTable->find(
                'all',
                [
                    'conditions' => $conditions,
                    'recursive' => 1,
                    'contain' => 'ShadowAttributes',
                    'fields' => ['uuid']
                ]
            )->toArray();

            $fails = 0;
            $success = 0;
            $error_message = "";
            foreach ($events as $k => &$event) {
                if (!empty($event['ShadowAttribute'])) {
                    foreach ($event['ShadowAttribute'] as &$sa) {
                        $sa['data'] = $ShadowAttributesTable->base64EncodeAttachment($sa);
                        unset($sa['id']);
                        unset($sa['value1']);
                        unset($sa['value2']);
                    }

                    $data = json_encode($event['ShadowAttribute']);
                    $request = $this->setupSyncRequest($server);
                    $uri = $server['url'] . '/events/pushProposals/' . $event['Event']['uuid'];
                    $response = $HttpSocket->post($uri, $data, $request);
                    if ($response->getStatusCode() === 200) {
                        $result = $response->getJson();
                        if ($result['success']) {
                            $success += intval($result['counter']);
                        } else {
                            $fails++;
                            if ($error_message == "") {
                                $result['message'];
                            } else {
                                $error_message .= " --- " . $result['message'];
                            }
                        }
                    } else {
                        $fails++;
                    }
                }
            }
        } else {
            // connect to checkuuid($uuid)
            $request = $this->setupSyncRequest($server);
            $uri = $server['url'] . '/events/checkuuid/' . $sa_id;
            $response = $HttpSocket->get($uri, '', $request);
            if ($response->getStatusCode() !== 200) {
                return false;
            }
        }
        return true;
    }

    /**
     * @return array
     */
    public function getCurrentServerSettings()
    {
        $serverSettings = $this->serverSettings;
        $moduleTypes = ['Enrichment', 'Import', 'Export', 'Action', 'Cortex'];
        return $this->readModuleSettings($serverSettings, $moduleTypes);
    }

    /**
     * @param array $serverSettings
     * @param array $moduleTypes
     * @return array
     */
    private function readModuleSettings(array $serverSettings, array $moduleTypes)
    {
        $ModulesTable = $this->fetchTable('Modules');
        foreach ($moduleTypes as $moduleType) {
            if (Configure::read('Plugin.' . $moduleType . '_services_enable')) {
                $results = $ModulesTable->getModuleSettings($moduleType);
                foreach ($results as $module => $data) {
                    foreach ($data as $result) {
                        $setting = ['level' => 1, 'errorMessage' => ''];
                        if ($result['type'] === 'boolean') {
                            $setting['test'] = 'testBool';
                            $setting['type'] = 'boolean';
                            $setting['description'] = __('Enable or disable the {0} module.', $module);
                            if (!empty($result['description'])) {
                                $setting['description'] = sprintf(
                                    "[%s%s%s] %s",
                                    '<span class="bold">',
                                    $setting['description'],
                                    '</span>',
                                    $result['description']
                                );
                            }
                            $setting['value'] = false;
                        } elseif ($result['type'] === 'orgs') {
                            $setting['description'] = __('Restrict the {0} module to the given organisation.', $module);
                            $setting['value'] = 0;
                            $setting['test'] = 'testLocalOrg';
                            $setting['type'] = 'numeric';
                            $setting['optionsSource'] = function () {
                                return $this->loadLocalOrganisations();
                            };
                        } else {
                            $setting['test'] = isset($result['test']) ? $result['test'] : 'testForEmpty';
                            $setting['type'] = isset($result['type']) ? $result['type'] : 'string';
                            $setting['description'] = isset($result['description']) ? $result['description'] : __('Set this required module specific setting.');
                            $setting['value'] = isset($result['value']) ? $result['value'] : '';
                        }
                        $serverSettings['Plugin'][$moduleType . '_' . $module . '_' .  $result['name']] = $setting;
                    }
                }
            }
            if (Configure::read('Plugin.Workflow_enable')) {
                $WorkflowsTable = $this->fetchTable('Workflows');
                $triggerModules = $WorkflowsTable->getModulesByType('trigger');
                foreach ($triggerModules as $triggerModule) {
                    $setting = [
                        'level' => 1,
                        'description' => __('Enable/disable the `{0}` trigger', $triggerModule['id']),
                        'value' => false,
                        'test' => 'testBool',
                        'type' => 'boolean'
                    ];
                    $serverSettings['Plugin']['Workflow_triggers_' . $triggerModule['id']] = $setting;
                }
            }
        }
        return $serverSettings;
    }

    private function __serverSettingsRead($serverSettings, $currentSettings)
    {
        foreach ($serverSettings as $branchKey => &$branchValue) {
            if (isset($branchValue['branch'])) {
                foreach ($branchValue as $leafKey => &$leafValue) {
                    if ($leafKey !== 'branch' && $leafValue['level'] == 3 && !isset($currentSettings[$branchKey][$leafKey])) {
                        continue;
                    }
                    $setting = null;
                    if (isset($currentSettings[$branchKey][$leafKey])) {
                        $setting = $currentSettings[$branchKey][$leafKey];
                    }
                    if ($leafKey !== 'branch') {
                        $leafValue = $this->__evaluateLeaf($leafValue, $leafKey, $setting);
                        if ($branchKey == 'Plugin') {
                            $pluginData = explode('_', $leafKey);
                            $leafValue['subGroup'] = $pluginData[0];
                        }
                        if (strpos($branchKey, 'Secur') === 0) {
                            $leafValue['tab'] = 'Security';
                        } else {
                            $leafValue['tab'] = $branchKey;
                        }
                        $finalSettingsUnsorted[$branchKey . '.' . $leafKey] = $leafValue;
                    }
                }
            } else {
                $setting = null;
                if (isset($currentSettings[$branchKey])) {
                    $setting = $currentSettings[$branchKey];
                }
                $branchValue = $this->__evaluateLeaf($branchValue, $branchKey, $setting);
                $branchValue['tab'] = 'misc';
                $finalSettingsUnsorted[$branchKey] = $branchValue;
            }
        }
        return $finalSettingsUnsorted;
    }

    private function __sortFinalSettings($finalSettingsUnsorted)
    {
        $finalSettings = [];
        for ($i = 0; $i < 4; $i++) {
            foreach ($finalSettingsUnsorted as $k => $s) {
                $s['setting'] = $k;
                if ($s['level'] == $i) {
                    $finalSettings[] = $s;
                }
            }
        }
        return $finalSettings;
    }

    public function serverSettingsRead($unsorted = false)
    {
        $settingTabMergeRules = [
            'GnuPG' => 'Encryption',
            'SMIME' => 'Encryption',
            'misc' => 'Security',
            'Security' => 'Security',
            'Session' => 'Security',
            'LinOTPAuth' => 'Security',
            'SimpleBackgroundJobs' => 'SimpleBackgroundJobs'
        ];

        $serverSettings = $this->getCurrentServerSettings();
        $currentSettings = Configure::read();
        $finalSettingsUnsorted = $this->__serverSettingsRead($serverSettings, $currentSettings);
        foreach ($finalSettingsUnsorted as $key => $temp) {
            if (isset($settingTabMergeRules[$temp['tab']])) {
                $finalSettingsUnsorted[$key]['tab'] = $settingTabMergeRules[$temp['tab']];
            }
        }
        if ($unsorted) {
            return $finalSettingsUnsorted;
        }
        return $this->__sortFinalSettings($finalSettingsUnsorted);
    }

    public function serverSettingReadSingle($settingObject, $settingName, $leafKey)
    {
        $setting = Configure::read($settingName);
        $result = $this->__evaluateLeaf($settingObject, $leafKey, $setting);
        $result['setting'] = $settingName;
        return $result;
    }

    /**
     * @param array $leafValue
     * @param string $leafKey
     * @param mixed $setting
     * @return array
     */
    private function __evaluateLeaf(array $leafValue, $leafKey, $setting)
    {
        if (isset($setting)) {
            if ($setting instanceof EncryptedValue) {
                try {
                    $setting = $setting->decrypt();
                } catch (Exception $e) {
                    $leafValue['errorMessage'] = 'Could not decrypt.';
                    return $leafValue;
                }
            }
            if (!empty($leafValue['test'])) {
                if ($leafValue['test'] instanceof Closure) {
                    $result = $leafValue['test']($setting);
                } else {
                    $result = $this->{$leafValue['test']}($setting, empty($leafValue['errorMessage']) ? false : $leafValue['errorMessage']);
                }
                if ($result !== true) {
                    $leafValue['error'] = 1;
                    if ($result !== false) {
                        $leafValue['errorMessage'] = $result;
                    }
                }
            }
            if (isset($leafValue['optionsSource'])) {
                $leafValue['options'] = $leafValue['optionsSource']();
            }
            if (!isset($leafValue['error']) && isset($leafValue['options']) && !isset($leafValue['options'][$setting])) {
                $leafValue['error'] = 1;
                $validValues = implode(', ', array_keys($leafValue['options']));
                $leafValue['errorMessage'] = __('Invalid setting `{0}`, valid values are: {1}', $setting, $validValues);
            }

            if ($setting !== '') {
                $leafValue['value'] = $setting;
            }
        } else {
            if ($leafKey !== 'branch' && (!isset($leafValue['null']) || !$leafValue['null'])) {
                $leafValue['error'] = 1;
                $leafValue['errorMessage'] = __('Value not set.');
            }
        }
        return $leafValue;
    }

    public function loadAvailableLanguages()
    {
        $dirs = glob(APP . 'Locale/*', GLOB_ONLYDIR);
        $languages = ['eng' => 'eng'];
        foreach ($dirs as $dir) {
            $dir = str_replace(APP . 'Locale' . DS, '', $dir);
            $languages[$dir] = $dir;
        }
        return $languages;
    }

    public function testLanguage($value)
    {
        $languages = $this->loadAvailableLanguages();
        if (!isset($languages[$value])) {
            return __('Invalid language.');
        }
        return true;
    }

    public function loadTagCollections()
    {
        $TagCollectionsTable = $this->fetchTable('TagCollections');
        $user = ['Role' => ['perm_site_admin' => 1]];
        $tagCollections = $TagCollectionsTable->fetchTagCollection($user);
        $options = [0 => 'None'];
        foreach ($tagCollections as $tagCollection) {
            $options[intval($tagCollection['TagCollection']['id'])] = $tagCollection['TagCollection']['name'];
        }
        return $options;
    }

    private function loadLocalOrganisations($strict = false)
    {
        static $localOrgs;

        if ($localOrgs === null) {
            $localOrgs = $this->Organisation->find(
                'list',
                [
                    'conditions' => ['local' => 1],
                    'recursive' => -1,
                    'fields' => ['Organisation.id', 'Organisation.name']
                ]
            );
        }

        if (!$strict) {
            return array_replace([0 => __('No organisation selected.')], $localOrgs);
        }

        return $localOrgs;
    }

    public function testTagCollections($value)
    {
        $tag_collections = $this->loadTagCollections();
        if (!isset($tag_collections[intval($value)])) {
            return __('Invalid tag_collection.');
        }
        return true;
    }

    public function testForNumeric($value)
    {
        if (!is_numeric($value)) {
            return __('This setting has to be a number.');
        }
        return true;
    }

    public function testForPositiveInteger($value)
    {
        if ((is_int($value) && $value >= 0) || ctype_digit($value)) {
            return true;
        }
        return __('The value has to be a whole number greater or equal 0.');
    }

    public function testForCookieTimeout($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < Configure::read('Session.timeout') && $value !== 0) {
            return __('The cookie timeout is currently lower than the session timeout. This will invalidate the cookie before the session expires.');
        }
        return true;
    }

    public function testUuid($value)
    {
        if (empty($value) || !preg_match('/^\{?[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\}?$/', $value)) {
            return 'Invalid UUID.';
        }
        return true;
    }

    public function testForSessionDefaults($value)
    {
        if (empty($value) || !in_array($value, ['php', 'database', 'cake', 'cache'])) {
            return 'Please choose a valid session handler. Recommended values: php or database. Alternate options are cake (cakephp file based sessions) and cache.';
        } else {
            return true;
        }
    }

    public function testForCorrelationEngine($value)
    {
        $options = Configure::read('MISP.correlation_engine.options');
        if (!empty($value) && !in_array($value, array_keys($options))) {
            return __('Please select a valid option from the list of available engines: ', implode(', ', array_keys($options)));
        } else {
            return true;
        }
    }

    public function testLocalOrg($value)
    {
        if ($value == 0) {
            return true; // `No organisation selected` option
        }

        return $this->testLocalOrgStrict($value);
    }

    public function testLocalOrgStrict($value)
    {
        if ($value == 0) {
            return 'No organisation selected';
        }
        $local_orgs = $this->loadLocalOrganisations(true);
        if (in_array($value, array_keys($local_orgs))) {
            return true;
        }
        return 'Invalid organisation';
    }

    public function testForEmpty($value)
    {
        $value = trim($value);
        if ($value === '') {
            return 'Value not set.';
        }
        return true;
    }

    public function testForPath($value)
    {
        if ($value === '') {
            return true;
        }
        if (preg_match('@^\/?(([a-z0-9_.]+[a-z0-9_.\-.\:]*[a-z0-9_.\-.\:]|[a-z0-9_.])+\/?)+$@i', $value)) {
            return true;
        }
        return 'Invalid characters in the path.';
    }

    public function beforeHookBinExec($setting, $value)
    {
        return $this->testForBinExec($value);
    }

    public function testForBinExec($value)
    {
        if (substr($value, 0, 7) === "phar://") {
            return 'Phar protocol not allowed.';
        }
        if ($value === '') {
            return true;
        }
        if (is_executable($value)) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $type = finfo_file($finfo, $value);
            finfo_close($finfo);
            if ($type === "application/x-executable" || $type === "application/x-pie-executable" || $type === "application/x-sharedlib") {
                return true;
            } else {
                return 'Binary file not executable. It is of type: ' . $type;
            }
        } else {
            return 'Binary file not executable.';
        }
    }

    public function testForWritableDir($value)
    {
        if (substr($value, 0, 7) === "phar://") {
            return 'Phar protocol not allowed.';
        }
        if (substr($value, 0, 5) === "s3://") {
            return true;
        }
        if (!is_dir($value)) {
            return 'Not a valid directory.';
        }
        if (!is_writeable($value)) {
            return 'Not a writable directory.';
        }
        return true;
    }

    public function testDebug($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if ($this->testForNumeric($value) !== true) {
            return 'This setting has to be a number between 0 and 2, with 0 disabling debug mode.';
        }
        if ($value === 0) {
            return true;
        }
        return 'This setting has to be set to 0 on production systems. Ignore this warning if this is not the case.';
    }

    public function testDebugAdmin($value)
    {
        if ($this->testBool($value) !== true) {
            return 'This setting has to be either true or false.';
        }
        if (!$value) {
            return true;
        }
        return 'Enabling debug is not recommended. Turn this on temporarily if you need to see a stack trace to debug an issue, but make sure this is not left on.';
    }

    public function testDate($date)
    {
        if ($this->testForEmpty($date) !== true) {
            return $this->testForEmpty($date);
        }
        if (!strtotime($date)) {
            return 'The date that you have entered is invalid. Expected: yyyy-mm-dd';
        }
        return true;
    }

    public function getHost()
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
        } else {
            $headers = $_SERVER;
        }

        if (array_key_exists('X-Forwarded-Host', $headers)) {
            $host = $headers['X-Forwarded-Host'];
        } else {
            $host = $_SERVER['HTTP_HOST'];
        }
        return $host;
    }

    public function getProto()
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
        } else {
            $headers = $_SERVER;
        }

        if (array_key_exists('X-Forwarded-Proto', $headers)) {
            $proto = $headers['X-Forwarded-Proto'];
        } else {
            $proto = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443) === true ? 'HTTPS' : 'HTTP';
        }
        return $proto;
    }

    public function validateURL($check)
    {
        $check = array_values($check);
        $check = $check[0];
        return $this->testURL($check);
    }

    public function testBaseURL($value)
    {
        // only run this check via the GUI, via the CLI it won't work
        if (php_sapi_name() == 'cli') {
            if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
                return 'Invalid baseurl, please make sure that the protocol is set.';
            }
            return true;
        }
        if (empty($value)) {
            return true;
        }
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        $regex = "/^(?<proto>https?):\/\/(?<host>([\w,\-,\.]+))(?::(?<port>[0-9]+))?(?<base>\/[a-z0-9_\-\.]+)?$/i";
        if (
            !preg_match($regex, $value, $matches) ||
            strtolower($matches['proto']) != strtolower($this->getProto()) ||
            (
                strtolower($matches['host']) != strtolower($this->getHost()) &&
                strtolower($matches['host']) . ':' . $matches['port'] != strtolower($this->getHost())
            )
        ) {
            return 'Invalid baseurl, it has to be in the "https://FQDN" format.';
        }
        return true;
    }

    public function testURL($value)
    {
        // only run this check via the GUI, via the CLI it won't work
        if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
            return 'Invalid baseurl, please make sure that the protocol is set.';
        }
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        return true;
    }

    public function testDisableEmail($value)
    {
        if (isset($value) && $value) {
            return 'E-mailing is blocked.';
        }
        return true;
    }

    public function testDisableCache($value)
    {
        if (isset($value) && $value) {
            return 'Export caches are disabled.';
        }
        return true;
    }

    public function testLive($value)
    {
        if ($this->testBool($value) !== true) {
            return $this->testBool($value);
        }
        if (!$value) {
            return 'MISP disabled.';
        }
        return true;
    }

    public function testBool($value, $errorMessage = false)
    {
        if ($value !== true && $value !== false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return __('Value is not a boolean, make sure that you convert \'true\' to true for example.');
        }
        return true;
    }

    public function testBoolTrue($value, $errorMessage = false)
    {
        if ($this->testBool($value, $errorMessage) !== true) {
            return $this->testBool($value, $errorMessage);
        }
        if ($value === false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return 'It is highly recommended that this setting is enabled. Make sure you understand the impact of having this setting turned off.';
        } else {
            return true;
        }
    }

    public function testBoolFalse($value, $errorMessage = false)
    {
        if ($this->testBool($value, $errorMessage) !== true) {
            return $this->testBool($value, $errorMessage);
        }
        if ($value !== false) {
            if ($errorMessage) {
                return $errorMessage;
            }
            return 'It is highly recommended that this setting is disabled. Make sure you understand the impact of having this setting turned on.';
        } else {
            return true;
        }
    }

    public function testParanoidSkipDb($value)
    {
        if (!empty(Configure::read('MISP.log_paranoid')) && empty($value)) {
            return 'Perhaps consider skipping the database when using paranoid mode. A great number of entries will be added to your log database otherwise that will lead to performance degradation.';
        }
        return true;
    }

    public function testSalt($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (strlen($value) < 32) {
            return 'The salt has to be an at least 32 byte long string.';
        }
        if ($value == "Rooraenietu8Eeyo<Qu2eeNfterd-dd+") {
            return 'This is the default salt shipped with the application and is therefore unsecure.';
        }
        return true;
    }

    public function testForTermsFile($value)
    {
        return $this->__testForFile($value, APP . 'files' . DS . 'terms');
    }

    public function testForCABundle($value)
    {
        $file = new SplFileInfo($value);
        if (!$file->isFile()) {
            return __('Invalid file path or file not accessible.');
        }
        if ($file->getExtension() !== 'pem') {
            return __('File has to be in .pem format.');
        }
        return true;
    }

    public function testForStyleFile($value)
    {
        if (empty($value)) {
            return true;
        }
        return $this->__testForFile($value, APP . 'webroot' . DS . 'css');
    }

    public function testForCustomImage($value)
    {
        return $this->__testForFile($value, APP . 'webroot' . DS . 'img' . DS . 'custom');
    }

    public function testPasswordLength($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 0) {
            return 'Length cannot be negative, set a positive integer or 0 (to choose the default option).';
        }
        return true;
    }

    public function testForPortNumber($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 21 || $value > 65535) {
            return 'Make sure that you pick a valid port number.';
        }
        return true;
    }

    public function testForZMQPortNumber($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 49152 || $value > 65535) {
            return 'It is recommended that you pick a port number in the dynamic range (49152-65535). However, if you have a valid reason to use a different port, ignore this message.';
        }
        return true;
    }

    public function testPasswordRegex($value)
    {
        if (!empty($value) && @preg_match($value, 'test') === false) {
            return 'Invalid regex.';
        }
        return true;
    }

    public function testPasswordResetText($value)
    {
        if (strpos($value, '$password') === false || strpos($value, '$username') === false || strpos($value, '$misp') === false) {
            return 'The text served to the users must include the following replacement strings: "$username", "$password", "$misp"';
        }
        return true;
    }

    public function testForGPGBinary($value)
    {
        if (empty($value)) {
            $value = $this->serverSettings['GnuPG']['binary']['value'];
        }
        if (file_exists($value)) {
            return true;
        }
        return 'Could not find the GnuPG executable at the defined location.';
    }

    public function testForRPZDuration($value)
    {
        if (($this->testForNumeric($value) !== true && preg_match('/^[0-9]*[mhdw]$/i', $value)) || $value >= 0) {
            return true;
        } else {
            return 'Negative seconds found. The following formats are accepted: seconds (positive integer), or duration (positive integer) followed by a letter denoting scale (such as m, h, d, w for minutes, hours, days, weeks)';
        }
    }

    public function testForRPZBehaviour($value)
    {
        $numeric = $this->testForNumeric($value);
        if ($numeric !== true) {
            return $numeric;
        }
        if ($value < 0 || $value > 5) {
            return 'Invalid setting, valid range is 0-5 (0 = DROP, 1 = NXDOMAIN, 2 = NODATA, 3 = walled garden, 4 = PASSTHRU, 5 = TCP-only.';
        }
        return true;
    }

    public function sightingsBeforeHook($setting, $value)
    {
        if ($value == true) {
            $this->updateDatabase('addSightings');
        }
        return true;
    }

    public function email_otpBeforeHook($setting, $value)
    {
        if ($value && !empty(Configure::read('MISP.disable_emailing'))) {
            return __('Emailing is currently disabled. Enabling OTP without e-mailing being configured would lock all users out.');
        }
        return true;
    }

    public function otpBeforeHook($setting, $value)
    {
        if ($value && (!class_exists('\OTPHP\TOTP') || !class_exists('\BaconQrCode\Writer'))) {
            return __('The TOTP and QR code generation libraries are not installed. Enabling OTP without those libraries installed would lock all users out.');
        }
        if ($value && Configure::read('LinOTPAuth.enabled')) {
            return __('The TOTP and LinOTPAuth should not be used at the same time.');
        }
        return true;
    }

    public function testForRPZSerial($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!preg_match('/^((\$date(\d*)|\$time|\d*))$/', $value)) {
            return 'Invalid format.';
        }
        return true;
    }

    public function testForRPZNS($value)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!preg_match('/^\w+(\.\w+)*(\.?) \w+(\.\w+)*$/', $value)) {
            return 'Invalid format.';
        }
        return true;
    }

    public function zmqAfterHook($setting, $value)
    {
        // If we are trying to change the enable setting to false, we don't need to test anything, just kill the server and return true.
        if ($setting === 'Plugin.ZeroMQ_enable') {
            if ($value == false || $value == 0) {
                $this->getPubSubTool()->killService();
                return true;
            }
        } elseif (!Configure::read('Plugin.ZeroMQ_enable')) {
            // If we are changing any other ZeroMQ settings but the feature is disabled, don't reload the service
            return true;
        }
        $this->getPubSubTool()->reloadServer();
        return true;
    }

    public function disableCacheAfterHook($setting, $value)
    {
        if ($value) {
            // delete all cache files
            foreach (Event::exportTypes() as $type => $settings) {
                $files = new DirectoryIterator(APP . 'tmp/cached_exports/' . $type);
                // No caches created for this type of export, move on
                if ($files == null) {
                    continue;
                }
                foreach ($files as $file) {
                    if ($file->getExtension() === $settings['extension']) {
                        unlink($file->getPathname());
                    }
                }
            }
        }
        return true;
    }

    public function correlationAfterHook($setting, $value)
    {
        if (!Configure::read('BackgroundJobs.enabled')) {
            $AttributesTable = $this->fetchTable('Attributes');
            if ($value) {
                $AttributesTable->purgeCorrelations();
            } else {
                $AttributesTable->generateCorrelation();
            }
        } else {
            if ($value) {
                $jobType = 'jobPurgeCorrelation';
                $jobTypeText = 'purge correlations';
            } else {
                $jobType = 'jobGenerateCorrelation';
                $jobTypeText = 'generate correlation';
            }

            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                'SYSTEM',
                Job::WORKER_PRIO,
                $jobTypeText,
                'All attributes',
                'Job created.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    $jobType,
                    $jobId
                ],
                true,
                $jobId
            );
        }
        return true;
    }

    public function ipLogBeforeHook($setting, $value)
    {
        if ($setting == 'MISP.log_client_ip') {
            if ($value == true) {
                $this->updateDatabase('addIPLogging');
            }
        }
        return true;
    }

    public function customAuthBeforeHook($setting, $value)
    {
        if (!empty($value)) {
            $this->updateDatabase('addCustomAuth');
        }
        $this->cleanCacheFiles();
        return true;
    }

    // never come here directly, always go through a secondary check like testForTermsFile in order to also pass along the expected file path
    private function __testForFile($value, $path)
    {
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        if (!$this->checkFilename($value)) {
            return 'Invalid filename.';
        }
        $file = $path . DS . $value;
        if (!file_exists($file)) {
            return 'Could not find the specified file. Make sure that it is uploaded into the following directory: ' . $path;
        }
        return true;
    }

    private function __serverSettingNormaliseValue($data, $value)
    {
        if (!empty($data['type'])) {
            if ($data['type'] === 'boolean') {
                $value = (bool)$value;
            } elseif ($data['type'] === 'numeric') {
                $value = (int)$value;
            }
        }
        return $value;
    }

    /**
     * @param string $settingName
     * @return array|false False if setting doesn't exists
     */
    public function getSettingData($settingName, $withOptions = true)
    {
        // This is just hack to reset opcache, so for next request cache will be reloaded.
        $this->opcacheResetConfig();

        if (strpos($settingName, 'Plugin.Enrichment') !== false || strpos($settingName, 'Plugin.Import') !== false || strpos($settingName, 'Plugin.Export') !== false || strpos($settingName, 'Plugin.Cortex') !== false || strpos($settingName, 'Plugin.Action') !== false || strpos($settingName, 'Plugin.Workflow') !== false) {
            $serverSettings = $this->getCurrentServerSettings();
        } else {
            $serverSettings = $this->serverSettings;
        }

        $setting = $serverSettings;
        $parts = explode('.', $settingName);
        foreach ($parts as $part) {
            if (isset($setting[$part])) {
                $setting = $setting[$part];
            } else {
                return false;
            }
        }

        if (isset($setting['level'])) {
            $setting['name'] = $settingName;
            if ($withOptions && isset($setting['optionsSource'])) {
                $setting['options'] = $setting['optionsSource']();
            }
        }

        return $setting;
    }

    /**
     * @param array|string $user
     * @param array $setting
     * @param mixed $value
     * @param bool $forceSave
     * @return mixed|string|true|null
     * @throws Exception
     */
    public function serverSettingsEditValue($user, array $setting, $value, $forceSave = false)
    {
        if (isset($setting['beforeHook'])) {
            $beforeResult = $this->{$setting['beforeHook']}($setting['name'], $value);
            if ($beforeResult !== true) {
                $change = 'There was an issue witch changing ' . $setting['name'] . ' to ' . $value  . '. The error message returned is: ' . $beforeResult . 'No changes were made.';
                $this->loadLog()->createLogEntry($user, 'serverSettingsEdit', 'Server', 0, 'Server setting issue', $change);
                return $beforeResult;
            }
        }
        if ($value !== null) {
            $value = trim($value);
            if ($setting['type'] === 'boolean') {
                $value = (bool)$value;
            } else if ($setting['type'] === 'numeric') {
                $value = (int)$value;
            }
            if (isset($setting['test'])) {
                if ($setting['test'] instanceof Closure) {
                    $testResult = $setting['test']($value);
                } else {
                    $testResult = $this->{$setting['test']}($value);
                }
            } else {
                $testResult = true;  # No test defined for this setting: cannot fail
            }
        } else if (isset($setting['null']) && $setting['null']) {
            $testResult = true;
        } else {
            $testResult = __('Value could not be null.');
        }

        if (!$forceSave && $testResult !== true) {
            if ($testResult === false) {
                $errorMessage = $setting['errorMessage'];
            } else {
                $errorMessage = $testResult;
            }
            return $errorMessage;
        }
        $oldValue = Configure::read($setting['name']);
        $fileOnly = isset($setting['cli_only']) && $setting['cli_only'];
        $settingSaveResult = $this->serverSettingsSaveValue($setting['name'], $value, $fileOnly);
        if ($settingSaveResult) {
            if (SystemSetting::isSensitive($setting['name'])) {
                $change = [$setting['name'] => ['*****', '*****']];
            } else {
                $change = [$setting['name'] => [$oldValue, $value]];
            }
            $this->loadLog()->createLogEntry($user, 'serverSettingsEdit', 'Server', 0, 'Server setting changed', $change);

            // execute after hook
            if (isset($setting['afterHook'])) {
                if ($setting['afterHook'] instanceof Closure) {
                    $afterResult = $setting['afterHook']($setting['name'], $value, $oldValue);
                } else {
                    $afterResult = $this->{$setting['afterHook']}($setting['name'], $value, $oldValue);
                }
                if ($afterResult !== true) {
                    $change = 'There was an issue after setting a new setting. The error message returned is: ' . $afterResult;
                    $this->loadLog()->createLogEntry($user, 'serverSettingsEdit', 'Server', 0, 'Server setting issue', $change);
                    return $afterResult;
                }
            }
            return true;
        }
        return __('Something went wrong. MISP tried to save a malformed config file or you dont have permission to write to config file. Setting change reverted.');
    }

    /**
     * @param string $setting
     * @param mixed $value
     * @param bool $fileOnly If true, always store value in config file even when `MISP.system_setting_db` is enabled
     * @return bool
     * @throws Exception
     */
    public function serverSettingsSaveValue($setting, $value, $fileOnly = false)
    {
        if (!$fileOnly && Configure::read('MISP.system_setting_db')) {
            /** @var SystemSetting $systemSetting */
            $SystemSettingsTable = $this->fetchTable('SystemSettings');
            return $SystemSettingsTable->setSetting($setting, $value);
        }

        $configFilePath = APP . 'Config' . DS . 'config.php';
        if (!is_writable($configFilePath)) {
            return false; // config file is not writeable
        }

        // validate if current config.php is intact:
        $current = FileAccessTool::readFromFile($configFilePath);
        if (strlen(trim($current)) < 20) {
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', 0, 'Error: Tried to modify server settings but current config is broken.');
            return false;
        }
        $safeConfigChanges = empty(Configure::read('MISP.server_settings_skip_backup_rotate'));
        if ($safeConfigChanges) {
            $backupFilePath = APP . 'Config' . DS . 'config.backup.php';
            // Create current config file backup
            if (!copy($configFilePath, $backupFilePath)) {
                throw new Exception("Could not create config backup `$backupFilePath`.");
            }
        }

        $settingObject = $this->getSettingData($setting, false);
        if ($settingObject) {
            $value = $this->__serverSettingNormaliseValue($settingObject, $value);
        }

        /** @var array $config */
        require $configFilePath;
        if (!isset($config)) {
            throw new Exception("Could not load config file `$configFilePath`.");
        }
        $config = Hash::insert($config, $setting, $value);

        $settingsToSave = [
            'debug', 'MISP', 'GnuPG', 'SMIME', 'Proxy', 'SecureAuth',
            'Security', 'Session', 'site_admin_debug', 'Plugin', 'CertAuth',
            'ApacheShibbAuth', 'ApacheSecureAuth', 'OidcAuth', 'AadAuth',
            'SimpleBackgroundJobs', 'LinOTPAuth'
        ];
        $settingsArray = [];
        foreach ($settingsToSave as $setting) {
            if (Hash::check($config, $setting)) {
                $settingsArray[$setting] = Hash::get($config, $setting);
            }
        }
        $settingsString = var_export($settingsArray, true);
        $settingsString = '<?php' . "\n" . '$config = ' . $settingsString . ';';

        if ($safeConfigChanges) {
            $previous_file_perm = substr(sprintf('%o', fileperms($configFilePath)), -4);
            try {
                $tmpFile = FileAccessTool::writeToTempFile($settingsString);
            } catch (Exception $e) {
                $this->logException('Could not create temp config file.', $e);
                $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', 0, 'Error: Could not create temp config file.');
                return false;
            }
            if (!rename($tmpFile, $configFilePath)) {
                FileAccessTool::deleteFile($tmpFile);
                throw new Exception("Could not rename `$tmpFile` to config file `$configFilePath`.");
            }
            $this->opcacheResetConfig();
            chmod($configFilePath, octdec($previous_file_perm));
            $config_saved = FileAccessTool::readFromFile($configFilePath);
            // if the saved config file is empty, restore the backup.
            if (strlen($config_saved) < 20) {
                rename($backupFilePath, $configFilePath);
                $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', 0, 'Error: Something went wrong saving the config file, reverted to backup file.');
                return false;
            } else {
                FileAccessTool::deleteFile($backupFilePath);
            }
        } else {
            FileAccessTool::writeToFile($configFilePath, $settingsString);
            $this->opcacheResetConfig();
        }
        return true;
    }

    public function getFileRules()
    {
        return [
            'orgs' => [
                'name' => __('Organisation logos'),
                'description' => __('The logo used by an organisation on the event index, event view, discussions, proposals, etc. Make sure that the filename is in the org.png format, where org is the case-sensitive organisation name.'),
                'expected' => [],
                'valid_format' => __('48x48 pixel .png files'),
                'path' => APP . 'webroot' . DS . 'img' . DS . 'orgs',
                'regex' => '.*\.(png|PNG)$',
                'regex_error' => __('Filename must be in the following format: *.png'),
                'files' => [],
            ],
            'img' => [
                'name' => __('Additional image files'),
                'description' => __('Image files uploaded into this directory can be used for various purposes, such as for the login page logos'),
                'expected' => [
                    'MISP.footer_logo' => Configure::read('MISP.footer_logo'),
                    'MISP.home_logo' => Configure::read('MISP.home_logo'),
                    'MISP.welcome_logo' => Configure::read('MISP.welcome_logo'),
                    'MISP.welcome_logo2' => Configure::read('MISP.welcome_logo2'),
                ],
                'valid_format' => __('PNG or SVG file'),
                'path' => APP . 'webroot' . DS . 'img' . DS . 'custom',
                'regex' => '.*\.(png|svg)$',
                'regex_error' => __('Filename must be in the following format: *.png or *.svg'),
                'files' => [],
            ],
        ];
    }

    public function grabFiles()
    {
        $validItems = $this->getFileRules();
        foreach ($validItems as $k => $item) {
            $dir = new DirectoryIterator($item['path']);

            $files = new RegexIterator($dir, $item['regex']);
            foreach ($files as $file) {
                $f = new SplFileInfo($item['path'] . DS . $file);
                $validItems[$k]['files'][] = [
                    'filename' => $file,
                    'filesize' => $f->getSize(),
                    'read' => $f->isReadable(),
                    'write' => $f->isWritable(),
                    'execute' => $f->isExecutable(),
                ];
            }
        }
        return $validItems;
    }

    /**
     * @param array $server
     * @param bool $withPostTest
     * @return array
     * @throws JsonException
     */
    public function runConnectionTest(array $server, $withPostTest = true)
    {
        try {
            $clientCertificate = HttpTool::getServerClientCertificateInfo($server);
            if ($clientCertificate) {
                $clientCertificate['valid_from'] = $clientCertificate['valid_from'] ? $clientCertificate['valid_from']->format('c') : __('Not defined');
                $clientCertificate['valid_to'] = $clientCertificate['valid_to'] ? $clientCertificate['valid_to']->format('c') : __('Not defined');
                $clientCertificate['public_key_size'] = $clientCertificate['public_key_size'] ?: __('Unknown');
                $clientCertificate['public_key_type'] = $clientCertificate['public_key_type'] ?: __('Unknown');
            }
        } catch (Exception $e) {
            $clientCertificate = ['error' => $e->getMessage()];
        }

        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));

        try {
            $info = $serverSync->info();
            $response = [
                'status' => 1,
                'info' => $info,
                'client_certificate' => $clientCertificate,
            ];

            $connectionMeta = $serverSync->connectionMetaData();
            if (isset($connectionMeta['crypto']['protocol'])) {
                $response['tls_version'] = $connectionMeta['crypto']['protocol'];
            }
            if (isset($connectionMeta['crypto']['cipher_name'])) {
                $response['tls_cipher'] = $connectionMeta['crypto']['cipher_name'];
            }

            if ($withPostTest) {
                $response['post'] = $serverSync->isSupported(ServerSyncTool::FEATURE_POST_TEST) ? $this->runPOSTtest($serverSync) : null;
            }

            return $response;
        } catch (HttpSocketHttpException $e) {
            $response = $e->getResponse();
            if ($e->getCode() === 403) {
                return ['status' => 4, 'client_certificate' => $clientCertificate];
            } else if ($e->getCode() === 405) {
                try {
                    $responseText = $e->getResponse()->getJson()['message'];
                    if ($responseText === 'Your user account is expecting a password change, please log in via the web interface and change it before proceeding.') {
                        return ['status' => 5, 'client_certificate' => $clientCertificate];
                    } elseif ($responseText === 'You have not accepted the terms of use yet, please log in via the web interface and accept them.') {
                        return ['status' => 6, 'client_certificate' => $clientCertificate];
                    }
                } catch (Exception $e) {
                    // pass
                }
            }
        } catch (HttpSocketJsonException $e) {
            $response = $e->getResponse();
        } catch (Exception $e) {
            $logTitle = 'Error: Connection test failed. Reason: ' .  $e->getMessage();
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['id'], $logTitle);
            return ['status' => 2, 'client_certificate' => $clientCertificate];
        }

        $logTitle = 'Error: Connection test failed. Returned data is in the change field.';
        $this->loadLog()->createLogEntry(
            'SYSTEM',
            'error',
            'Server',
            $server['id'],
            $logTitle,
            [
                'response' => ['', $response->getStringBody()],
                'response-code' => ['', $response->getStatusCode()],
            ]
        );
        return ['status' => 3, 'client_certificate' => $clientCertificate];
    }

    /**
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    private function runPOSTtest(ServerSyncTool $serverSync)
    {
        $testFile = file_get_contents(APP . '../tests/Files/test_payload.txt');
        if (!$testFile) {
            throw new Exception("Could not load payload for POST test.");
        }

        try {
            $response = $serverSync->postTest($testFile);
            $contentEncoding = $response->getHeader('Content-Encoding');
            $rawBody = $response->body;
            $response = $response->getJson();
        } catch (Exception $e) {
            $this->logException("Invalid response for remote server {$serverSync->server()['name']} POST test.", $e);
            $title = 'Error: POST connection test failed. Reason: ' . $e->getMessage();
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $serverSync->serverId(), $title);
            return ['status' => 8];
        }
        if (!isset($response['body']['testString']) || $response['body']['testString'] !== $testFile) {
            if (!empty($response['body']['testString'])) {
                $responseString = $response['body']['testString'];
            } else if (!empty($rawBody)) {
                $responseString = $rawBody;
            } else {
                $responseString = __('Response was empty.');
            }

            $title = 'Error: POST connection test failed due to the message body not containing the expected data. Response: ' . PHP_EOL . PHP_EOL . $responseString;
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $serverSync->serverId(), $title);
            return ['status' => 9, 'content-encoding' => $contentEncoding];
        }
        $headers = ['Accept', 'Content-type'];
        foreach ($headers as $header) {
            if (!isset($response['headers'][$header]) || $response['headers'][$header] !== 'application/json') {
                $responseHeader = isset($response['headers'][$header]) ? $response['headers'][$header] : 'Header was not set.';
                $title = 'Error: POST connection test failed due to a header ' . $header . ' not matching the expected value. Expected: "application/json", received "' . $responseHeader . '"';
                $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $serverSync->serverId(), $title);
                return ['status' => 10, 'content-encoding' => $contentEncoding];
            }
        }
        return ['status' => 1, 'content-encoding' => $contentEncoding];
    }

    /**
     * @param array $server
     * @param array $user
     * @param ServerSyncTool|null $serverSync
     * @return array|string
     * @throws JsonException
     */
    public function checkVersionCompatibility(array $server, $user = [], ServerSyncTool $serverSync = null)
    {
        // for event publishing when we don't have a user.
        if (empty($user)) {
            $user = 'SYSTEM';
        }

        $serverSync = $serverSync ? $serverSync : new ServerSyncTool($server, $this->setupSyncRequest($server));

        try {
            $remoteVersion = $serverSync->info();
        } catch (Exception $e) {
            $this->logException("Connection to the server {$server['id']} has failed", $e);

            if ($e instanceof HttpSocketHttpException) {
                $title = 'Error: Connection to the server has failed. Returned response code: ' . $e->getCode();
            } else {
                $title = 'Error: Connection to the server has failed. The returned exception\'s error message was: ' . $e->getMessage();
            }
            $this->loadLog()->createLogEntry($user, 'error', 'Server', $server['id'], $title);
            return $title;
        }

        $canPush = isset($remoteVersion['perm_sync']) ? $remoteVersion['perm_sync'] : false;
        $canSight = isset($remoteVersion['perm_sighting']) ? $remoteVersion['perm_sighting'] : false;
        $canEditGalaxyCluster = isset($remoteVersion['perm_galaxy_editor']) ? $remoteVersion['perm_galaxy_editor'] : false;
        $remoteVersionString = $remoteVersion['version'];
        $remoteVersion = explode('.', $remoteVersion['version']);
        if (!isset($remoteVersion[0])) {
            $message = __('Error: Server didn\'t send the expected response. This may be because the remote server version is outdated.');
            $this->loadLog()->createLogEntry($user, 'error', 'Server', $server['id'], $message);
            return $message;
        }
        $localVersion = $this->checkMISPVersion();
        $protectedMode = version_compare($remoteVersionString, '2.4.156') >= 0;
        $response = false;
        $success = false;
        $issueLevel = "warning";
        if ($localVersion['major'] > $remoteVersion[0]) {
            $response = "Sync to Server ('{$server['id']}') aborted. The remote instance's MISP version is behind by a major version.";
        }
        if ($response === false && $localVersion['major'] < $remoteVersion[0]) {
            $response = "Sync to Server ('{$server['id']}') aborted. The remote instance is at least a full major version ahead - make sure you update your MISP instance!";
        }
        if ($response === false && $localVersion['minor'] > $remoteVersion[1]) {
            $response = "Sync to Server ('{$server['id']}') aborted. The remote instance's MISP version is behind by a minor version.";
        }
        if ($response === false && $localVersion['minor'] < $remoteVersion[1]) {
            $response = "Sync to Server ('{$server['id']}') aborted. The remote instance is at least a full minor version ahead - make sure you update your MISP instance!";
        }

        // if we haven't set a message yet, we're good to go. We are only behind by a hotfix version
        if ($response === false) {
            $success = true;
        } else {
            $issueLevel = "error";
        }
        if ($response === false && $localVersion['hotfix'] > $remoteVersion[2]) {
            $response = "Sync to Server ('{$server['id']}') initiated, but the remote instance is a few hotfixes behind.";
        }
        if ($response === false && $localVersion['hotfix'] < $remoteVersion[2]) {
            $response = "Sync to Server ('{$server['id']}') initiated, but the remote instance is a few hotfixes ahead. Make sure you keep your instance up to date!";
        }
        if (empty($response) && $remoteVersion[2] < 111) {
            $response = "Sync to Server ('{$server['id']}') initiated, but version 2.4.111 is required in order to be able to pull proposals from the remote side.";
        }

        if ($response !== false) {
            $this->loadLog()->createLogEntry($user, $issueLevel, 'Server', $server['id'], ucfirst($issueLevel) . ': ' . $response);
        }
        return [
            'success' => $success,
            'response' => $response,
            'canPush' => $canPush,
            'canSight' => $canSight,
            'canEditGalaxyCluster' => $canEditGalaxyCluster,
            'version' => $remoteVersion,
            'protectedMode' => $protectedMode,
        ];
    }

    public function captureServer($server, $user)
    {
        if (isset($server[0])) {
            $server = $server[0];
        }
        if ($server['url'] == Configure::read('MISP.baseurl')) {
            return 0;
        }
        $existingServer = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['url' => $server['url']]
            ]
        )->disableHydration()->first();
        // unlike with other capture methods, if we find a server that we don't know
        // we don't want to save it.
        if (empty($existingServer)) {
            return false;
        }
        return $existingServer['id'];
    }

    public function dbSpaceUsage()
    {
        $inMb = function ($value) {
            return round($value / 1024 / 1024, 2) . " MB";
        };

        $result = [];
        if ($this->isMysql()) {
            $sql = sprintf(
                'select TABLE_NAME, DATA_LENGTH, INDEX_LENGTH, DATA_FREE from information_schema.tables where table_schema = %s group by TABLE_NAME, DATA_LENGTH, INDEX_LENGTH, DATA_FREE;',
                "'" . $this->getDataSource()->config['database'] . "'"
            );
            $sqlResult = $this->query($sql);

            foreach ($sqlResult as $temp) {
                $result[$temp['tables']['TABLE_NAME']] = [
                    'table' => $temp['tables']['TABLE_NAME'],
                    'used' => $inMb($temp['tables']['DATA_LENGTH'] + $temp['tables']['INDEX_LENGTH']),
                    'reclaimable' => $inMb($temp['tables']['DATA_FREE']),
                    'data_in_bytes' => (int) $temp['tables']['DATA_LENGTH'],
                    'index_in_bytes' => (int) $temp['tables']['INDEX_LENGTH'],
                    'reclaimable_in_bytes' => (int) $temp['tables']['DATA_FREE'],
                ];
            }
        } else {
            $sql = sprintf(
                'select TABLE_NAME as table, pg_total_relation_size(%s||%s||TABLE_NAME) as used from information_schema.tables where table_schema = %s group by TABLE_NAME;',
                "'" . $this->getDataSource()->config['database'] . "'",
                "'.'",
                "'" . $this->getDataSource()->config['database'] . "'"
            );
            $sqlResult = $this->query($sql);
            foreach ($sqlResult as $temp) {
                foreach ($temp[0] as $k => $v) {
                    if ($k == "table") {
                        continue;
                    }
                    $temp[0][$k] = $inMb($v);
                }
                $temp[0]['reclaimable'] = '0 MB';
                $result[] = $temp[0];
            }
        }
        return $result;
    }

    public function redisInfo()
    {
        $output = [
            'extensionVersion' => phpversion('redis'),
            'connection' => false,
        ];

        try {
            $redis = RedisTool::init();
            $output['connection'] = true;
            $output = array_merge($output, $redis->info());
        } catch (Exception $e) {
            $output['connection_error'] = $e->getMessage();
        }

        return $output;
    }

    public function dbSchemaDiagnostic()
    {
        $AdminSettingsTable = $this->fetchTable('AdminSettings');
        $actualDbVersion = $AdminSettingsTable->getSetting('db_version');
        $dataSource = $this->getDataSource()->config['datasource'];
        $schemaDiagnostic = [
            'dataSource' => $dataSource,
            'actual_db_version' => $actualDbVersion,
            'checked_table_column' => [],
            'diagnostic' => [],
            'diagnostic_index' => [],
            'expected_db_version' => '?',
            'error' => '',
            'update_locked' => $this->isUpdateLocked(),
            'remaining_lock_time' => $this->getLockRemainingTime(),
            'update_fail_number_reached' => $this->UpdateFailNumberReached(),
            'indexes' => []
        ];
        if ($this->isMysql()) {
            $dbActualSchema = $this->getActualDBSchema();
            $dbExpectedSchema = $this->getExpectedDBSchema();
            if ($dbExpectedSchema !== false) {
                $db_schema_comparison = $this->compareDBSchema($dbActualSchema['schema'], $dbExpectedSchema['schema']);
                $db_indexes_comparison = $this->compareDBIndexes($dbActualSchema['indexes'], $dbExpectedSchema['indexes'], $dbExpectedSchema);
                $schemaDiagnostic['checked_table_column'] = $dbActualSchema['column'];
                $schemaDiagnostic['diagnostic'] = $db_schema_comparison;
                $schemaDiagnostic['diagnostic_index'] = $db_indexes_comparison;
                $schemaDiagnostic['expected_db_version'] = $dbExpectedSchema['db_version'];
                foreach ($dbActualSchema['schema'] as $tableName => $tableMetas) {
                    foreach ($tableMetas as $tableMeta) {
                        $schemaDiagnostic['columnPerTable'][$tableName][] = $tableMeta['column_name'];
                    }
                }
                $schemaDiagnostic['indexes'] = $dbActualSchema['indexes'];
            } else {
                $schemaDiagnostic['error'] = 'Diagnostic not available as the expected schema file could not be loaded';
            }
        } else {
            $schemaDiagnostic['error'] = sprintf('Diagnostic not available for DataSource `%s`', $dataSource);
        }
        if (!empty($schemaDiagnostic['diagnostic'])) {
            foreach ($schemaDiagnostic['diagnostic'] as $table => &$fields) {
                foreach ($fields as &$field) {
                    $field = $this->__attachRecoveryQuery($field, $table);
                }
            }
        }
        return $schemaDiagnostic;
    }

    /*
     * Get RDBMS configuration values
     */
    public function dbConfiguration(): array
    {
        if ($this->isMysql()) {
            $configuration = [];

            $dbVariables = $this->query("SHOW VARIABLES;");
            $settings = array_keys(self::MYSQL_RECOMMENDED_SETTINGS);

            foreach ($dbVariables as $dbVariable) {
                // different rdbms have different casing
                if (isset($dbVariable['SESSION_VARIABLES'])) {
                    $dbVariable = $dbVariable['SESSION_VARIABLES'];
                } elseif (isset($dbVariable['session_variables'])) {
                    $dbVariable = $dbVariable['session_variables'];
                } else {
                    continue;
                }

                if (in_array($dbVariable['Variable_name'], $settings)) {
                    $configuration[] = [
                        'name' => $dbVariable['Variable_name'],
                        'value' => $dbVariable['Value'],
                        'default' => self::MYSQL_RECOMMENDED_SETTINGS[$dbVariable['Variable_name']]['default'],
                        'recommended' => self::MYSQL_RECOMMENDED_SETTINGS[$dbVariable['Variable_name']]['recommended'],
                        'explanation' => self::MYSQL_RECOMMENDED_SETTINGS[$dbVariable['Variable_name']]['explanation'],
                    ];
                }
            }

            return $configuration;
        } else {
            return [];
        }
    }

    /*
     * Work in progress, still needs DEFAULT in the schema for it to work correctly
     * Currently only works for missing_column and column_different
     * Only currently supported field types are: int, tinyint, varchar, text
     */
    private function __attachRecoveryQuery($field, $table)
    {
        if (isset($field['error_type'])) {
            $length = false;
            if (in_array($field['error_type'], ['missing_column', 'column_different'])) {
                preg_match('/([a-z]+)(?:\((?<dw>[0-9,]+)\))?\s*([a-z]+)?/i', $field['expected']['column_type'], $displayWidthMatches);
                if (isset($displayWidthMatches['dw'])) {
                    $length = $displayWidthMatches[2];
                } elseif ($field['expected']['data_type'] === 'int') {
                    $length = 11;
                } elseif ($field['expected']['data_type'] === 'tinyint') {
                    $length = 1;
                } elseif ($field['expected']['data_type'] === 'varchar') {
                    $length = $field['expected']['character_maximum_length'];
                } elseif ($field['expected']['data_type'] === 'text') {
                    $length = null;
                }
            }
            if ($length !== false) {
                switch ($field['error_type']) {
                    case 'missing_column':
                        $field['sql'] = sprintf(
                            'ALTER TABLE `%s` ADD COLUMN `%s` %s%s %s %s %s %s %s;',
                            $table,
                            $field['column_name'],
                            $field['expected']['data_type'],
                            $length !== null ? sprintf('(%d)', $length) : '',
                            strpos($field['expected']['column_type'], 'unsigned') !== false ? 'UNSIGNED' : '',
                            isset($field['expected']['column_default']) ? 'DEFAULT "' . $field['expected']['column_default'] . '"' : '',
                            $field['expected']['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                            empty($field['expected']['collation_name']) ? '' : 'COLLATE ' . $field['expected']['collation_name'],
                            empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                        );
                        break;
                    case 'column_different':
                        $field['sql'] = sprintf(
                            'ALTER TABLE `%s` MODIFY COLUMN `%s` %s%s %s %s %s %s %s;',
                            $table,
                            $field['column_name'],
                            $field['expected']['data_type'],
                            $length !== null ? sprintf('(%d)', $length) : '',
                            strpos($field['expected']['column_type'], 'unsigned') !== false ? 'UNSIGNED' : '',
                            isset($field['expected']['column_default']) ? 'DEFAULT "' . $field['expected']['column_default'] . '"' : '',
                            $field['expected']['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                            empty($field['expected']['collation_name']) ? '' : 'COLLATE ' . $field['expected']['collation_name'],
                            empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                        );
                        break;
                }
            } elseif ($field['error_type'] == 'missing_table') {
                $allFields = [];
                foreach ($field['expected_table'] as $expectedField) {
                    $length = false;
                    if ($expectedField['data_type'] === 'int') {
                        $length = 11;
                    } elseif ($expectedField['data_type'] === 'tinyint') {
                        $length = 1;
                    } elseif ($expectedField['data_type'] === 'varchar') {
                        $length = $expectedField['character_maximum_length'];
                    } elseif ($expectedField['data_type'] === 'text') {
                        $length = null;
                    }
                    $fieldSql = sprintf(
                        '`%s` %s%s %s %s %s %s %s',
                        $expectedField['column_name'],
                        $expectedField['data_type'],
                        $length !== null ? sprintf('(%d)', $length) : '',
                        strpos($expectedField['column_type'], 'unsigned') !== false ? 'UNSIGNED' : '',
                        isset($expectedField['column_default']) ? 'DEFAULT "' . $expectedField['column_default'] . '"' : '',
                        $expectedField['is_nullable'] === 'NO' ? 'NOT NULL' : 'NULL',
                        empty($expectedField['collation_name']) ? '' : 'COLLATE ' . $expectedField['collation_name'],
                        empty($field['expected']['extra']) ? '' : $field['expected']['extra']
                    );
                    $allFields[] = $fieldSql;
                }
                $field['sql'] = __("% The command below is a suggestion and might be incorrect. Please ask if you are not sure what you are doing.") . "</br></br>" . sprintf(
                    "CREATE TABLE IF NOT EXISTS `%s` ( %s ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;",
                    $table,
                    implode(', ', $allFields)
                );
            }
        }
        return $field;
    }

    public function getExpectedDBSchema()
    {
        try {
            return FileAccessTool::readJsonFromFile(ROOT . DS . 'db_schema.json');
        } catch (Exception $e) {
            return false;
        }
    }

    // TODO: Use CakePHP 3.X's Schema System
    /*
        $db = ConnectionManager::get('default');

        // Create a schema collection.
        $collection = $db->schemaCollection();

        // Get the table names
        $tables = $collection->listTables();

        // Get a single table (instance of Schema\TableSchema)
        $tableSchema = $collection->describe('posts');

    */
    public function getActualDBSchema(
        $tableColumnNames = [
            'column_name',
            'is_nullable',
            'data_type',
            'character_maximum_length',
            'numeric_precision',
            // 'datetime_precision',    -- Only available on MySQL 5.6+
            'collation_name',
            'column_type',
            'column_default',
            'extra',
        ]
    ) {
        $dbActualSchema = [];
        $dbActualIndexes = [];
        if ($this->isMysql()) {
            $sqlGetTable = sprintf('SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = %s ORDER BY TABLE_NAME;', "'" . $this->getDataSource()->config['database'] . "'");
            $sqlResult = $this->query($sqlGetTable);
            $tables = Hash::extract($sqlResult, '{n}.tables.TABLE_NAME');
            foreach ($tables as $table) {
                $sqlSchema = sprintf(
                    "SELECT %s
                    FROM information_schema.columns
                    WHERE table_schema = '%s' AND TABLE_NAME = '%s'",
                    implode(',', $tableColumnNames),
                    $this->getDataSource()->config['database'],
                    $table
                );
                $sqlResult = $this->query($sqlSchema)->toArray();
                $sqlResult = array_column($sqlResult, 'columns');
                foreach ($sqlResult as $column_schema) {
                    $column_schema = array_change_key_case($column_schema, CASE_LOWER);
                    $dbActualSchema[$table][] = $column_schema;
                }
                $dbActualIndexes[$table] = $this->getDatabaseIndexes($this->getDataSource()->config['database'], $table);
            }
        } else {
            return ['Database/Postgres' => ['description' => __('Can\'t check database schema for Postgres database type')]];
        }
        return ['schema' => $dbActualSchema, 'column' => $tableColumnNames, 'indexes' => $dbActualIndexes];
    }

    private function compareDBSchema($dbActualSchema, $dbExpectedSchema)
    {
        // Column that should be ignored while performing the comparison
        $allowedlistFields = [
            'users' => ['external_auth_required', 'external_auth_key'],
        ];
        $nonCriticalColumnElements = ['collation_name'];
        $dbDiff = [];
        // perform schema comparison for tables
        foreach ($dbExpectedSchema as $tableName => $columns) {
            if (!array_key_exists($tableName, $dbActualSchema)) {
                $dbDiff[$tableName][] = [
                    'description' => __('Table `{0}` does not exist', $tableName),
                    'error_type' => 'missing_table',
                    'expected_table' => $columns,
                    'column_name' => $tableName,
                    'is_critical' => true
                ];
            } else {
                // perform schema comparison for table's columns
                $expectedColumnKeys = [];
                $keyedExpectedColumn = [];
                foreach ($columns as $column) {
                    $expectedColumnKeys[] = $column['column_name'];
                    $keyedExpectedColumn[$column['column_name']] = $column;
                }
                $existingColumnKeys = [];
                $keyedActualColumn = [];
                foreach ($dbActualSchema[$tableName] as $column) {
                    $existingColumnKeys[] = $column['column_name'];
                    $keyedActualColumn[$column['column_name']] = $column;
                }

                $additionalKeysInActualSchema = array_diff($existingColumnKeys, $expectedColumnKeys);
                foreach ($additionalKeysInActualSchema as $additionalKeys) {
                    if (isset($allowedlistFields[$tableName]) && in_array($additionalKeys, $allowedlistFields[$tableName])) {
                        continue; // column is allowedlisted
                    }
                    $dbDiff[$tableName][] = [
                        'description' => __('Column `{0}` exists but should not', $additionalKeys),
                        'error_type' => 'additional_column',
                        'column_name' => $additionalKeys,
                        'is_critical' => false
                    ];
                }
                foreach ($keyedExpectedColumn as $columnName => $column) {
                    if (isset($allowedlistFields[$tableName]) && in_array($columnName, $allowedlistFields[$tableName])) {
                        continue; // column is allowedlisted
                    }
                    if (isset($keyedActualColumn[$columnName])) {
                        $colDiff = array_diff_assoc($column, $keyedActualColumn[$columnName]);
                        if (count($colDiff) > 0) {
                            $colElementDiffs = array_keys(array_diff_assoc($column, $keyedActualColumn[$columnName]));
                            $isCritical = false;
                            foreach ($colElementDiffs as $colElementDiff) {
                                if (!in_array($colElementDiff, $nonCriticalColumnElements)) {
                                    if ($colElementDiff == 'column_default') {
                                        $expectedValue = $column['column_default'];
                                        $actualValue = $keyedActualColumn[$columnName]['column_default'];
                                        if (preg_match(sprintf('@(\'|")+%s(\1)+@', $expectedValue), $actualValue) || (empty($expectedValue) && $actualValue === 'NULL')) { // some version of mysql quote the default value
                                            continue;
                                        } else {
                                            $isCritical = true;
                                            break;
                                        }
                                    } else {
                                        $isCritical = true;
                                        break;
                                    }
                                }
                            }
                            $dbDiff[$tableName][] = [
                                'description' => __('Column `{0}` is different', $columnName),
                                'column_name' => $column['column_name'],
                                'error_type' => 'column_different',
                                'actual' => $keyedActualColumn[$columnName],
                                'expected' => $column,
                                'is_critical' => $isCritical
                            ];
                        }
                    } else {
                        $dbDiff[$tableName][] = [
                            'description' => __('Column `{0}` does not exist but should', $columnName),
                            'column_name' => $columnName,
                            'error_type' => 'missing_column',
                            'actual' => [],
                            'expected' => $column,
                            'is_critical' => true
                        ];
                    }
                }
            }
        }
        foreach (array_diff(array_keys($dbActualSchema), array_keys($dbExpectedSchema)) as $additionalTable) {
            $dbDiff[$additionalTable][] = [
                'description' => __('Table `{0}` is an additional table', $additionalTable),
                'column_name' => $additionalTable,
                'error_type' => 'additional_table',
                'is_critical' => false
            ];
        }
        return $dbDiff;
    }

    /**
     * Returns `true` if given column for given table contains just unique values.
     *
     * @param string $tableName
     * @param string $columnName
     * @return bool
     */
    private function checkIfColumnContainsJustUniqueValues($tableName, $columnName)
    {
        $db = $this->getDataSource();
        $duplicates = $this->query(
            sprintf(
                'SELECT %s, COUNT(*) c FROM %s GROUP BY %s HAVING c > 1;',
                $db->name($columnName),
                $db->name($tableName),
                $db->name($columnName)
            )
        );
        return empty($duplicates);
    }

    private function generateSqlDropIndexQuery($tableName, $columnName)
    {
        return sprintf(
            'DROP INDEX `%s` ON %s;',
            $columnName,
            $tableName
        );
    }

    private function generateSqlIndexQuery(array $dbExpectedSchema, $tableName, $columnName, $shouldBeUnique = false, $defaultIndexKeylength = 255)
    {
        $columnData = Hash::extract($dbExpectedSchema['schema'][$tableName], "{n}[column_name=$columnName]");
        if (empty($columnData)) {
            throw new Exception("Index in db_schema.json is defined for `$tableName.$columnName`, but this column is not defined.");
        }

        $columnData = $columnData[0];
        if ($columnData['data_type'] === 'varchar') {
            $keyLength = sprintf('(%s)', $columnData['character_maximum_length'] < $defaultIndexKeylength ? $columnData['character_maximum_length'] : $defaultIndexKeylength);
        } elseif ($columnData['data_type'] === 'text') {
            $keyLength = sprintf('(%s)', $defaultIndexKeylength);
        } else {
            $keyLength = '';
        }
        return sprintf(
            'CREATE%s INDEX `%s` ON `%s` (`%s`%s);',
            $shouldBeUnique ? ' UNIQUE' : '',
            $columnName,
            $tableName,
            $columnName,
            $keyLength
        );
    }

    /**
     * @throws Exception
     */
    private function compareDBIndexes(array $actualIndex, array $expectedIndex, array $dbExpectedSchema)
    {
        $indexDiff = [];
        foreach ($expectedIndex as $tableName => $indexes) {
            if (!array_key_exists($tableName, $actualIndex)) {
                continue; // If table does not exist, it is covered by the schema diagnostic
            }
            $tableIndexDiff = array_diff(array_keys($indexes), array_keys($actualIndex[$tableName])); // check for missing indexes
            foreach ($tableIndexDiff as $columnDiff) {
                $shouldBeUnique = $indexes[$columnDiff];

                $message = __('Column `{0}` should be indexed', $columnDiff);
                $indexDiff[$tableName][$columnDiff] = [
                    'message' => $message,
                    'sql' => $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $columnDiff, $shouldBeUnique),
                ];
            }
            $tableIndexDiff = array_diff(array_keys($actualIndex[$tableName]), array_keys($indexes)); // check for additional indexes
            foreach ($tableIndexDiff as $columnDiff) {
                $message = __('Column `{0}` is indexed but should not', $columnDiff);
                $indexDiff[$tableName][$columnDiff] = [
                    'message' => $message,
                    'sql' => $this->generateSqlDropIndexQuery($tableName, $columnDiff),
                ];
            }
            foreach ($indexes as $column => $unique) {
                if (isset($actualIndex[$tableName][$column]) && $actualIndex[$tableName][$column] != $unique) {
                    if ($actualIndex[$tableName][$column]) {
                        $sql = $this->generateSqlDropIndexQuery($tableName, $column);
                        $sql .= '<br>' . $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $column, false);

                        $message = __('Column `{0}` has unique index, but should be non unique', $column);
                        $indexDiff[$tableName][$column] = [
                            'message' => $message,
                            'sql' => $sql,
                        ];
                    } else {
                        $sql = $this->generateSqlDropIndexQuery($tableName, $column);
                        $sql .= '<br>' . $this->generateSqlIndexQuery($dbExpectedSchema, $tableName, $column, true);

                        $message = __('Column `{0}` should be unique index', $column);
                        $indexDiff[$tableName][$column] = [
                            'message' => $message,
                            'sql' => $sql,
                        ];
                    }
                }
            }
        }
        return $indexDiff;
    }

    /**
     * Returns indexes for given schema and table in array, where key is column name and value is `true` if
     * index is index is unique, `false` otherwise.
     *
     * @param string $database
     * @param string $table
     * @return array
     */
    private function getDatabaseIndexes($database, $table)
    {
        $sqlTableIndex = sprintf(
            "SELECT DISTINCT TABLE_NAME, COLUMN_NAME, NON_UNIQUE FROM information_schema.statistics WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s' ORDER BY COLUMN_NAME;",
            $database,
            $table
        );
        $sqlTableIndexResult = $this->query($sqlTableIndex);
        $output = [];
        foreach ($sqlTableIndexResult as $index) {
            $output[$index['statistics']['COLUMN_NAME']] = $index['statistics']['NON_UNIQUE'] == 0;
        }
        return $output;
    }

    public function writeableDirsDiagnostics(&$diagnostic_errors)
    {
        $writeableDirs = [
            '/tmp' => 0,
            APP . 'tmp' => 0,
            APP . 'files' => 0,
            APP . 'files' . DS . 'scripts' . DS . 'tmp' => 0,
            APP . 'tmp' . DS . 'csv_all' => 0,
            APP . 'tmp' . DS . 'csv_sig' => 0,
            APP . 'tmp' . DS . 'md5' => 0,
            APP . 'tmp' . DS . 'sha1' => 0,
            APP . 'tmp' . DS . 'snort' => 0,
            APP . 'tmp' . DS . 'suricata' => 0,
            APP . 'tmp' . DS . 'text' => 0,
            APP . 'tmp' . DS . 'xml' => 0,
            APP . 'tmp' . DS . 'files' => 0,
            APP . 'tmp' . DS . 'logs' => 0,
            APP . 'tmp' . DS . 'bro' => 0,
        ];

        $attachmentDir = Configure::read('MISP.attachments_dir');
        if ($attachmentDir && !isset($writeableDirs[$attachmentDir])) {
            $writeableDirs[$attachmentDir] = 0;
        }

        $tmpDir = Configure::read('MISP.tmpdir');
        if ($tmpDir && !isset($writeableDirs[$tmpDir])) {
            $writeableDirs[$tmpDir] = 0;
        }

        foreach ($writeableDirs as $path => &$error) {
            if (!file_exists($path)) {
                // Try to create directory if not exists
                if (!mkdir($path, 0700, true)) {
                    $error = 1;
                }
            }
            if (!is_writable($path)) {
                $error = 2;
            }
            if ($error !== 0) {
                $diagnostic_errors++;
            }
        }
        return $writeableDirs;
    }

    public function writeableFilesDiagnostics(&$diagnostic_errors)
    {
        $writeableFiles = [
            APP . 'Config' . DS . 'config.php' => 0,
            ROOT .  DS . '.git' . DS . 'ORIG_HEAD' => 0,
        ];
        foreach ($writeableFiles as $path => &$error) {
            if (!file_exists($path)) {
                $error = 1;
                continue;
            }
            if (!is_writeable($path)) {
                $error = 2;
                $diagnostic_errors++;
            }
        }
        return $writeableFiles;
    }

    public function readableFilesDiagnostics(&$diagnostic_errors)
    {
        $readableFiles = [
            APP . 'files' . DS . 'scripts' . DS . 'stixtest.py' => 0
        ];
        foreach ($readableFiles as $path => &$error) {
            if (!is_readable($path)) {
                $error = 1;
                continue;
            }
        }
        return $readableFiles;
    }

    public function yaraDiagnostics(&$diagnostic_errors)
    {
        $scriptFile = APP . 'files' . DS . 'scripts' . DS . 'yaratest.py';
        try {
            $scriptResult = ProcessTool::execute([ProcessTool::pythonBin(), $scriptFile]);
            $scriptResult = JsonTool::decode($scriptResult);
        } catch (Exception $exception) {
            $this->logException('Failed to run yara diagnostics.', $exception);
            return [
                'operational' => 0,
                'plyara' => 0,
                'test_run' => false
            ];
        }
        return ['operational' => $scriptResult['success'], 'plyara' => $scriptResult['plyara'], 'test_run' => true];
    }

    public function stixDiagnostics(&$diagnostic_errors)
    {
        $expected = ['stix' => '>1.2.0.11', 'cybox' => '>2.1.0.21', 'mixbox' => '>1.0.5', 'maec' => '>4.1.0.17', 'stix2' => '>3.0.0', 'pymisp' => '>2.4.120'];
        // check if the STIX and Cybox libraries are working using the test script stixtest.py
        $scriptFile = APP . 'files' . DS . 'scripts' . DS . 'stixtest.py';
        try {
            $scriptResult = ProcessTool::execute([ProcessTool::pythonBin(), $scriptFile]);
        } catch (Exception $exception) {
            $this->logException('Failed to run STIX diagnostics.', $exception);
            return [
                'operational' => 0,
                'invalid_version' => false,
                'test_run' => false
            ];
        }

        try {
            $scriptResult = JsonTool::decode($scriptResult);
        } catch (Exception $e) {
            $this->logException('Invalid JSON returned from stixtest', $e);
            return [
                'operational' => -1,
                'invalid_version' => false,
                'stix' => ['expected' => $expected['stix']],
                'cybox' => ['expected' => $expected['cybox']],
                'mixbox' => ['expected' => $expected['mixbox']],
                'maec' => ['expected' => $expected['maec']],
                'stix2' => ['expected' => $expected['stix2']],
                'pymisp' => ['expected' => $expected['pymisp']]
            ];
        }
        $scriptResult['operational'] = $scriptResult['success'];
        if ($scriptResult['operational'] == 0) {
            $diagnostic_errors++;
        }
        $result = [
            'operational' => $scriptResult['operational'],
            'invalid_version' => false,
            'test_run' => true
        ];
        foreach ($expected as $package => $expectedVersion) {
            $result[$package]['version'] = $scriptResult[$package];
            $result[$package]['expected'] = $expectedVersion;
            if ($expectedVersion[0] === '>') {
                $result[$package]['status'] = version_compare($result[$package]['version'], trim($expectedVersion, '>')) >= 0 ? 1 : 0;
            } else {
                $result[$package]['status'] = $result[$package]['version'] === $expectedVersion ? 1 : 0;
            }
            if ($result[$package]['status'] == 0) {
                $diagnostic_errors++;
                $result['invalid_version'] = true;
            }
        }
        return $result;
    }

    /**
     * @param int $diagnostic_errors
     * @return array
     */
    public function gpgDiagnostics(&$diagnostic_errors)
    {
        $output = ['status' => 0, 'version' => null];
        if (Configure::read('GnuPG.email') && Configure::read('GnuPG.homedir')) {
            try {
                $gpg = GpgTool::initializeGpg();
            } catch (Exception $e) {
                $this->logException("Error during initializing GPG.", $e, LOG_NOTICE);
                $output['status'] = 2;
            }
            if ($output['status'] === 0) {
                try {
                    $output['version'] = $gpg->getVersion();
                } catch (Exception $e) {
                    // ignore
                }

                try {
                    $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
                } catch (Exception $e) {
                    $this->logException("Error during adding GPG signing key.", $e, LOG_NOTICE);
                    $output['status'] = 3;
                }
            }
            if ($output['status'] === 0) {
                try {
                    $gpg->sign('test', \Crypt_GPG::SIGN_MODE_CLEAR);
                } catch (Exception $e) {
                    $this->logException("Error during GPG signing.", $e, LOG_NOTICE);
                    $output['status'] = 4;
                }
            }
        } else {
            $output['status'] = 1;
        }
        if ($output['status'] !== 0) {
            $diagnostic_errors++;
        }
        return $output;
    }

    public function zmqDiagnostics(&$diagnostic_errors)
    {
        if (!Configure::read('Plugin.ZeroMQ_enable')) {
            return 1;
        }
        $pubSubTool = $this->getPubSubTool();
        try {
            $isInstalled = $pubSubTool->checkIfPythonLibInstalled();
        } catch (Exception $e) {
            $this->logException('ZMQ is not properly installed.', $e, LOG_NOTICE);
            $diagnostic_errors++;
            return 2;
        }

        if (!$isInstalled) {
            $diagnostic_errors++;
            return 2;
        }
        if ($pubSubTool->checkIfRunning()) {
            return 0;
        }
        $diagnostic_errors++;
        return 3;
    }

    public function moduleDiagnostics(&$diagnostic_errors, $type = 'Enrichment')
    {
        $ModulesTable = $this->fetchTable('Modules');
        $diagnostic_errors++;
        if (Configure::read('Plugin.' . $type . '_services_enable')) {
            try {
                $result = $ModulesTable->getModules($type, true);
            } catch (Exception $e) {
                return $e->getMessage();
            }
            if (empty($result)) {
                return 2;
            }
            $diagnostic_errors--;
            return 0;
        }
        return 1;
    }

    public function proxyDiagnostics(&$diagnostic_errors)
    {
        $proxyStatus = 0;
        $proxy = Configure::read('Proxy');
        if (!empty($proxy['host'])) {
            try {
                $HttpSocket = $this->setupHttpSocket(null);
                $proxyResponse = $HttpSocket->get('https://www.github.com/');
            } catch (Exception $e) {
                $proxyStatus = 2;
            }
            if (empty($proxyResponse) || $proxyResponse->code > 399) {
                $proxyStatus = 2;
            }
        } else {
            $proxyStatus = 1;
        }
        if ($proxyStatus > 1) {
            $diagnostic_errors++;
        }
        return $proxyStatus;
    }

    public function sessionDiagnostics(&$diagnostic_errors = 0)
    {
        $sessionCount = null;
        $sessionHandler = null;

        switch (Configure::read('Session.defaults')) {
            case 'php':
                $sessionHandler = 'php_' .  ini_get('session.save_handler');
                switch ($sessionHandler) {
                    case 'php_files':
                        $diagnostic_errors++;
                        $errorCode = 2;
                        break;
                    case 'php_redis':
                        $errorCode = 0;
                        break;
                    default:
                        $diagnostic_errors++;
                        $errorCode = 8;
                        break;
                }
                break;
            case 'database':
                $sessionHandler = 'database';
                $sql = 'SELECT COUNT(id) AS session_count FROM cake_sessions WHERE expires < ' . time() . ';';
                $sqlResult = $this->query($sql);
                if (isset($sqlResult[0][0])) {
                    $sessionCount = $sqlResult[0][0]['session_count'];
                    $errorCode = 0;
                } else {
                    $errorCode = 9;
                }
                if ($sessionCount > 1000) {
                    $diagnostic_errors++;
                    $errorCode = 1;
                }
                break;
            default:
                $diagnostic_errors++;
                $errorCode =  8;
                break;
        }

        return [
            'handler' => $sessionHandler,
            'expired_count' => $sessionCount,
            'error_code' => $errorCode
        ];
    }

    /**
     * @param int $workerIssueCount
     * @return array
     * @throws ProcessException
     */
    public function workerDiagnostics(&$workerIssueCount)
    {
        $worker_array = [
            'cache' => ['ok' => false],
            'default' => ['ok' => false],
            'email' => ['ok' => false],
            'prio' => ['ok' => false],
            'update' => ['ok' => false]
        ];

        try {
            $workers = $this->getWorkers();
        } catch (Exception $e) {
            // TODO: [3.x-MIGRATION] check exception logging in 3.x
            // $this->logException('Could not get list of workers.', $e);
            return $worker_array;
        }

        $currentUser = ProcessTool::whoami();
        $procAccessible = file_exists('/proc');
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                throw new Exception('Non numeric PID found.');
            }
            $entry = $worker['type'] === 'regular' ? $worker['queue'] : $worker['type'];
            $correctUser = ($currentUser === $worker['user']);
            if ($procAccessible) {
                $alive = $correctUser && file_exists("/proc/$pid");
            } else {
                $alive = 'N/A';
            }
            $ok = true;
            if (!$alive || !$correctUser) {
                $ok = false;
                $workerIssueCount++;
            }
            $worker_array[$entry]['workers'][] = [
                'pid' => $pid,
                'user' => $worker['user'],
                'alive' => $alive,
                'correct_user' => $correctUser,
                'ok' => $ok
            ];
        }
        foreach ($worker_array as $k => $queue) {
            if (isset($queue['workers'])) {
                foreach ($queue['workers'] as $worker) {
                    if ($worker['ok']) {
                        $worker_array[$k]['ok'] = true; // If at least one worker is up, the queue can be considered working
                    }
                }
            }

            $worker_array[$k]['jobCount'] = BackgroundJobsTool::getInstance()->getQueueSize($k);

            if (!isset($queue['workers'])) {
                $workerIssueCount++;
                $worker_array[$k]['ok'] = false;
            }
        }
        $worker_array['proc_accessible'] = $procAccessible;
        $worker_array['controls'] = 1;
        if (Configure::check('MISP.manage_workers')) {
            $worker_array['controls'] = Configure::read('MISP.manage_workers');
        }

        if (Configure::read('BackgroundJobs.enabled')) {
            try {
                $worker_array['supervisord_status'] = BackgroundJobsTool::getInstance()->getSupervisorStatus();
            } catch (Exception $exception) {
                $this->logException('Error getting supervisor status.', $exception);
                $worker_array['supervisord_status'] = false;
            }
        }

        return $worker_array;
    }

    public function backgroundJobsDiagnostics(&$diagnostic_errors)
    {
        $backgroundJobsStatus = $this->getBackgroundJobsTool()->getStatus();

        if ($backgroundJobsStatus > 0) {
            $diagnostic_errors++;
        }
        return $backgroundJobsStatus;
    }

    public function retrieveCurrentSettings($branch, $subString)
    {
        $settings = [];
        foreach ($this->serverSettings[$branch] as $settingName => $setting) {
            if (strpos($settingName, $subString) !== false) {
                $settings[$settingName] = $setting['value'];
                if (Configure::read('Plugin.' . $settingName)) {
                    $settings[$settingName] = Configure::read('Plugin.' . $settingName);
                }
                if (isset($setting['options'])) {
                    $settings[$settingName] = $setting['options'][$settings[$settingName]];
                }
            }
        }
        return $settings;
    }

    /**
     * Return PHP setting in basic unit (bytes).
     * @param string $setting
     * @return string|int|null
     */
    public function getIniSetting($setting)
    {
        $value = ini_get($setting);
        if ($value === '') {
            return null;
        }

        switch ($setting) {
            case 'memory_limit':
            case 'upload_max_filesize':
            case 'post_max_size':
                return (int)preg_replace_callback(
                    '/(-?\d+)(.?)/',
                    function ($m) {
                        return $m[1] * pow(1024, strpos('BKMG', $m[2]));
                    },
                    strtoupper($value)
                );
            case 'max_execution_time':
                return (int)$value;
            default:
                return $value;
        }
    }

    public function killWorker($pid, $user)
    {
        if (!is_numeric($pid)) {
            throw new MethodNotAllowedException('Non numeric PID found!');
        }
        $workers = $this->getBackgroundJobsTool()->getWorkers();
        foreach ($workers as $worker) {
            if ($worker['pid'] == $pid) {
                if (substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0 ? true : false) {
                    shell_exec('kill ' . $pid . ' > /dev/null 2>&1 &');
                    $this->__logRemoveWorker($user, $pid, $worker['queue'], false);
                } else {
                    $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
                }
                break;
            }
        }
    }

    public function killAllWorkers($user = false, $force = false)
    {
        $workers = $this->getBackgroundJobsTool()->getWorkers();
        $killed = [];
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                continue;
            }
            if (substr_count(trim(shell_exec('ps -p ' . $pid)), PHP_EOL) > 0) {
                shell_exec('kill ' . ($force ? ' -9 ' : '') . $pid . ' > /dev/null 2>&1 &');
                $this->__logRemoveWorker($user, $pid, $worker['queue'], false);
            } else {
                $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
            }
        }
        return $killed;
    }

    public function workerRemoveDead($user = false)
    {
        $workers = $this->getBackgroundJobsTool()->getWorkers();
        $killed = [];
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                throw new MethodNotAllowedException('Non numeric PID found!');
            }
            $pidTest = file_exists('/proc/' . addslashes($pid));
            if (!$pidTest) {
                $this->__logRemoveWorker($user, $pid, $worker['queue'], true);
                if (empty($killed[$worker['queue']])) {
                    $killed[$worker['queue']] = 1;
                } else {
                    $killed[$worker['queue']] += 1;
                }
            }
        }
        return $killed;
    }

    private function __logRemoveWorker($user, $pid, $queue, $dead = false)
    {
        $LogsTable = $this->fetchTable('Logs');
        if (empty($user)) {
            $user = [
                'id' => 0,
                'Organisation' => [
                    'name' => 'SYSTEM'
                ],
                'email' => 'SYSTEM'
            ];
        }
        $type = $dead ? 'dead' : 'kill';
        $text = [
            'dead' => [
                'action' => 'remove_dead_workers',
                'title' => __('Removing a dead worker.'),
                'change' => sprintf(__('Removing dead worker data. Worker was of type {0} with pid {1}'), $queue, $pid)
            ],
            'kill' => [
                'action' => 'stop_worker',
                'title' => __('Stopping a worker.'),
                'change' => sprintf(__('Stopping a worker. Worker was of type {0} with pid {1}'), $queue, $pid)
            ]
        ];
        $LogsTable->saveOrFailSilently(
            [
                'org' => $user['Organisation']['name'],
                'model' => 'User',
                'model_id' => $user['id'],
                'email' => $user['email'],
                'action' => $text[$type]['action'],
                'user_id' => $user['id'],
                'title' => $text[$type]['title'],
                'change' => $text[$type]['change']
            ]
        );
    }

    /**
     * Returns an array with the events
     * @param array $server
     * @param $user - not used
     * @param array $passedArgs
     * @return array
     * @throws Exception
     */
    public function previewIndex(array $server, $user, array $passedArgs)
    {
        $validArgs = array_merge(['sort', 'direction', 'page', 'limit'], $this->validEventIndexFilters);
        $urlParams = '';
        foreach ($validArgs as $v) {
            if (isset($passedArgs[$v])) {
                $urlParams .= '/' . $v . ':' . $passedArgs[$v];
            }
        }

        $relativeUri = '/events/index' . $urlParams;
        $response = $this->serverGetRequest($server, $relativeUri);
        $events = $response->getJson();
        $totalCount = $response->getHeader('X-Result-Count') ?: 0;

        foreach ($events as $k => $event) {
            if (!isset($event['Orgc'])) {
                $event['Orgc']['name'] = $event['orgc'];
            }
            if (!isset($event['Org'])) {
                $event['Org']['name'] = $event['org'];
            }
            if (!isset($event['EventTag'])) {
                $event['EventTag'] = [];
            }
            $events[$k] = ['Event' => $event];
        }

        return [$events, $totalCount];
    }

    /**
     * Returns an array with the event.
     * @param array $server
     * @param int $eventId
     * @return array
     * @throws Exception
     */
    public function previewEvent(array $server, $eventId)
    {
        $relativeUri = '/events/' . $eventId;
        $response = $this->serverGetRequest($server, $relativeUri);
        $event = $response->getJson();

        if (!isset($event['Event']['Orgc'])) {
            $event['Event']['Orgc']['name'] = $event['Event']['orgc'];
        }
        if (isset($event['Event']['Orgc'][0])) {
            $event['Event']['Orgc'] = $event['Event']['Orgc'][0];
        }
        if (!isset($event['Event']['Org'])) {
            $event['Event']['Org']['name'] = $event['Event']['org'];
        }
        if (isset($event['Event']['Org'][0])) {
            $event['Event']['Org'] = $event['Event']['Org'][0];
        }
        if (!isset($event['Event']['EventTag'])) {
            $event['Event']['EventTag'] = [];
        }

        return $event;
    }

    // Loops through all servers and checks which servers' push rules don't conflict with the given event.
    // returns the server objects that would allow the event to be pushed
    public function eventFilterPushableServers($event, $servers)
    {
        $eventTags = [];
        $validServers = [];
        foreach ($event['EventTag'] as $tag) {
            $eventTags[] = $tag['tag_id'];
        }
        foreach ($servers as $server) {
            if (!empty($server['push_rules']['tags']['OR'])) {
                $intersection = array_intersect($server['push_rules']['tags']['OR'], $eventTags);
                if (empty($intersection)) {
                    continue;
                }
            }
            if (!empty($server['push_rules']['tags']['NOT'])) {
                $intersection = array_intersect($server['push_rules']['tags']['NOT'], $eventTags);
                if (!empty($intersection)) {
                    continue;
                }
            }
            if (!empty($server['push_rules']['orgs']['OR'])) {
                if (!in_array($event['orgc_id'], $server['push_rules']['orgs']['OR'])) {
                    continue;
                }
            }
            if (!empty($server['push_rules']['orgs']['NOT'])) {
                if (in_array($event['orgc_id'], $server['push_rules']['orgs']['NOT'])) {
                    continue;
                }
            }
            $validServers[] = $server;
        }
        return $validServers;
    }

    /**
     * Check installed PHP extensions and their versions.
     * @return array
     * @throws JsonException
     */
    public function extensionDiagnostics()
    {
        try {
            $composer = FileAccessTool::readJsonFromFile(APP . DS . 'composer.json');
            $extensions = [];
            $dependencies = [];
            foreach ($composer['require'] as $require => $foo) {
                if (substr($require, 0, 4) === 'ext-') {
                    $extensions[substr($require, 4)] = true;
                } else if (mb_strpos($require, '/') !== false) {  // external dependencies have namespaces, so a /
                    $dependencies[$require] = true;
                }
            }
            foreach ($composer['suggest'] as $suggest => $reason) {
                if (substr($suggest, 0, 4) === 'ext-') {
                    $extensions[substr($suggest, 4)] = $reason;
                } else if (mb_strpos($suggest, '/') !== false) {  // external dependencies have namespaces, so a /
                    $dependencies[$suggest] = $reason;
                }
            }
        } catch (Exception $e) {
            $this->logException('Could not load extensions from composer.json', $e, LOG_NOTICE);
            $extensions = ['redis' => '', 'gd' => '', 'ssdeep' => '', 'zip' => '', 'intl' => '']; // Default extensions
        }

        // check PHP extensions
        $results = ['cli' => false];
        foreach ($extensions as $extension => $reason) {
            $results['extensions'][$extension] = [
                'web_version' => phpversion($extension),
                'web_version_outdated' => false,
                'cli_version' => false,
                'cli_version_outdated' => false,
                'required' => $reason === true,
                'info' => $reason === true ? null : $reason,
            ];
        }
        if (is_readable(APP . DS . 'files' . DS . 'scripts' . DS . 'selftest.php')) {
            try {
                $execResult = ProcessTool::execute(['php', APP . DS . 'files' . DS . 'scripts' . DS . 'selftest.php', json_encode(array_keys($extensions))]);
            } catch (Exception $e) {
                // pass
            }
            if (!empty($execResult)) {
                $execResult = JsonTool::decodeArray($execResult);
                $results['cli']['phpversion'] = $execResult['phpversion'];
                foreach ($execResult['extensions'] as $extension => $loaded) {
                    $results['extensions'][$extension]['cli_version'] = $loaded;
                }
            }
        }

        // version check
        $minimalVersions = [
            'redis' => '2.2.8', // because of sAddArray method
        ];
        foreach ($minimalVersions as $extension => $version) {
            if (!isset($results['extensions'][$extension])) {
                continue;
            }
            $results['extensions'][$extension]['required_version'] = $version;
            foreach (['web', 'cli'] as $type) {
                if ($results['extensions'][$extension][$type . '_version']) {
                    $outdated = version_compare($results['extensions'][$extension][$type . '_version'], $version, '<');
                    $results['extensions'][$extension][$type . '_version_outdated'] = $outdated;
                }
            }
        }

        // check PHP dependencies, installed in the Vendor directory, just check presence of the folder
        if (class_exists('\Composer\InstalledVersions')) {
            foreach ($dependencies as $dependency => $reason) {
                try {
                    $version = \Composer\InstalledVersions::getVersion($dependency);
                } catch (Exception $e) {
                    $version = false;
                }
                $results['dependencies'][$dependency] = [
                    'version' => $version,
                    'version_outdated' => false,
                    'required' => $reason === true,
                    'info' => $reason === true ? null : $reason,
                ];
            }
        }

        return $results;
    }

    public function databaseEncodingDiagnostics(&$diagnostic_errors)
    {
        if (!isset($this->getDataSource()->config['encoding']) || strtolower($this->getDataSource()->config['encoding']) != 'utf8') {
            $diagnostic_errors++;
            return false;
        }
        return true;
    }

    /**
     * @param string $newest
     * @return array
     * @throws JsonException
     */
    private function checkVersion($newest)
    {
        $version_array = $this->checkMISPVersion();
        $current = implode('.', $version_array);

        $upToDate = version_compare($current, substr($newest, 1));
        if ($newest === null && (Configure::read('MISP.online_version_check') || !Configure::check('MISP.online_version_check'))) {
            $upToDate = 'error';
        } elseif ($newest === null && (!Configure::read('MISP.online_version_check') && Configure::check('MISP.online_version_check'))) {
            $upToDate = 'disabled';
        } elseif ($upToDate === 0) {
            $upToDate = 'same';
        } else {
            $upToDate = $upToDate === -1 ? 'older' : 'newer';
        }
        return ['current' => 'v' . $current, 'newest' => $newest, 'upToDate' => $upToDate];
    }

    /**
     * Fetch latest MISP version from GitHub
     * @return array|false
     * @throws JsonException
     */
    private function checkRemoteVersion($HttpSocket)
    {
        try {
            $tags = GitTool::getLatestTags($HttpSocket);
        } catch (Exception $e) {
            $this->logException('Could not retrieve latest tags from GitHub', $e, LOG_NOTICE);
            return false;
        }
        // find the latest version tag in the v[major].[minor].[hotfix] format
        foreach ($tags as $tag) {
            if (preg_match('/^v[0-9]+\.[0-9]+\.[0-9]+$/', $tag['name'])) {
                return $this->checkVersion($tag['name']);
            }
        }
        return false;
    }

    /**
     * @param bool $checkVersion
     * @return array
     * @throws JsonException
     */
    public function getCurrentGitStatus($checkVersion = false)
    {
        $latestCommit = false;

        if (Configure::read('MISP.online_version_check') || !Configure::check('MISP.online_version_check')) {
            $HttpSocket = $this->setupHttpSocket(null, null, 3);
            try {
                $latestCommit = GitTool::getLatestCommit($HttpSocket);
            } catch (Exception $e) {
                $this->logException('Could not retrieve version from GitHub', $e, LOG_NOTICE);
            }
        }

        $output = [
            'commit' => $this->checkMIPSCommit(),
            'branch' => $this->getCurrentBranch(),
            'latestCommit' => $latestCommit,
        ];
        if ($checkVersion) {
            $output['version'] = $latestCommit ? $this->checkRemoteVersion($HttpSocket) : $this->checkVersion(null);
        }
        return $output;
    }

    public function getCurrentBranch()
    {
        try {
            return GitTool::currentBranch();
        } catch (Exception $e) {
            $this->logException('Could not retrieve current Git branch', $e, LOG_NOTICE);
            return false;
        }
    }

    /**
     * Check if MISP update is possible.
     * @return bool
     */
    public function isUpdatePossible()
    {
        return $this->getCurrentBranch() !== false && is_writable(APP);
    }

    public function checkoutMain()
    {
        $mainBranch = '2.4';
        return exec('git checkout ' . $mainBranch);
    }

    public function getSubmodulesGitStatus()
    {
        try {
            $submodules = GitTool::submoduleStatus();
        } catch (Exception $e) {
            $this->logException('Could not fetch git submodules status', $e, LOG_NOTICE);
            return [];
        }
        $status = [];
        foreach ($submodules as $submodule) {
            if ($this->_isAcceptedSubmodule($submodule['name'])) {
                $status[$submodule['name']] = $this->getSubmoduleGitStatus($submodule['name'], $submodule['commit']);
            }
        }
        return $status;
    }

    private function _isAcceptedSubmodule($submodule)
    {
        $accepted_submodules_names = [
            'PyMISP',
            'app/files/misp-galaxy',
            'app/files/taxonomies',
            'app/files/misp-objects',
            'app/files/noticelists',
            'app/files/warninglists',
            'app/files/misp-decaying-models',
            'app/files/scripts/cti-python-stix2',
            'app/files/scripts/misp-opendata',
            'app/files/scripts/python-maec',
            'app/files/scripts/python-stix',
        ];
        return in_array($submodule, $accepted_submodules_names, true);
    }

    /**
     * @param string $submoduleName
     * @param string $superprojectSubmoduleCommitId
     * @return array
     * @throws Exception
     */
    private function getSubmoduleGitStatus($submoduleName, $superprojectSubmoduleCommitId)
    {
        $path = APP . '../' . $submoduleName;
        $submoduleName = (strpos($submoduleName, '/') >= 0 ? explode('/', $submoduleName) : $submoduleName);
        $submoduleName = end($submoduleName);

        $submoduleCurrentCommitId = GitTool::currentCommit($path);

        $currentTimestamp = GitTool::commitTimestamp($submoduleCurrentCommitId, $path);
        if ($submoduleCurrentCommitId !== $superprojectSubmoduleCommitId) {
            $remoteTimestamp = GitTool::commitTimestamp($superprojectSubmoduleCommitId, $path);
        } else {
            $remoteTimestamp = $currentTimestamp;
        }

        $status = [
            'moduleName' => $submoduleName,
            'current' => $submoduleCurrentCommitId,
            'currentTimestamp' => $currentTimestamp,
            'remote' => $superprojectSubmoduleCommitId,
            'remoteTimestamp' => $remoteTimestamp,
            'upToDate' => 'error',
            'isReadable' => is_readable($path) && is_readable($path . '/.git'),
        ];

        if (!empty($status['remote'])) {
            if ($status['remote'] === $status['current']) {
                $status['upToDate'] = 'same';
            } else if ($status['currentTimestamp'] < $status['remoteTimestamp']) {
                $status['upToDate'] = 'older';
            } else {
                $status['upToDate'] = 'younger';
            }
        }

        if ($status['isReadable'] && !empty($status['remoteTimestamp']) && !empty($status['currentTimestamp'])) {
            $date1 = new Chronos("@{$status['remoteTimestamp']}");
            $date2 = new Chronos("@{$status['currentTimestamp']}");
            $status['timeDiff'] = $date1->diff($date2);
        } else {
            $status['upToDate'] = 'error';
        }

        return $status;
    }

    public function updateSubmodule($user, $submodule_name = false)
    {
        $path = APP . '../';
        if ($submodule_name == false) {
            $command = sprintf('cd %s; git submodule update --init --recursive 2>&1', $path);
            exec($command, $output, $return_code);
            $output = implode("\n", $output);
            $res = ['status' => ($return_code == 0 ? true : false), 'output' => $output];
            if ($return_code == 0) { // update all DB
                $res = array_merge($res, $this->updateDatabaseAfterPullRouter($submodule_name, $user));
            }
        } else if ($this->_isAcceptedSubmodule($submodule_name)) {
            $command = sprintf('cd %s; git submodule update --init --recursive -- %s 2>&1', $path, $submodule_name);
            exec($command, $output, $return_code);
            $output = implode("\n", $output);
            $res = ['status' => ($return_code == 0 ? true : false), 'output' => $output];
            if ($return_code == 0) { // update DB if necessary
                $res = array_merge($res, $this->updateDatabaseAfterPullRouter($submodule_name, $user));
            }
        } else {
            $res = ['status' => false, 'output' => __('Invalid submodule.'), 'job_sent' => false, 'sync_result' => __('unknown')];
        }
        return $res;
    }

    public function updateDatabaseAfterPullRouter($submodule_name, $user)
    {
        if (Configure::read('BackgroundJobs.enabled')) {
            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $user,
                Job::WORKER_PRIO,
                'update_after_pull',
                __('Updating: ' . $submodule_name),
                'Update the database after PULLing the submodule(s).'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'updateAfterPull',
                    $submodule_name,
                    $jobId,
                    $user['id']
                ],
                true,
                $jobId
            );

            return ['job_sent' => true, 'sync_result' => __('unknown')];
        } else {
            $result = $this->updateAfterPull($submodule_name, $user['id']);
            return ['job_sent' => false, 'sync_result' => $result];
        }
    }

    public function updateAfterPull($submodule_name, $userId)
    {
        $user = $this->User->getAuthUser($userId);
        $result = [];
        if ($user['Role']['perm_site_admin']) {
            $updateAll = empty($submodule_name);
            if ($submodule_name == 'app/files/misp-galaxy' || $updateAll) {
                $GalaxiesTable = $this->fetchTable('Galaxies');
                $result[] = ($GalaxiesTable->update() ? 'Update `' . h($submodule_name) . '` Successful.' : 'Update `' . h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/misp-objects' || $updateAll) {
                $ObjectTemplatesTable = $this->fetchTable('ObjectTemplates');
                $result[] = ($ObjectTemplatesTable->update($user, false, false) ? 'Update `' . h($submodule_name) . '` Successful.' : 'Update `' . h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/noticelists' || $updateAll) {
                $NoticelistsTable = $this->fetchTable('Noticelists');
                $result[] = ($NoticelistsTable->update() ? 'Update `' . h($submodule_name) . '` Successful.' : 'Update `' . h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/taxonomies' || $updateAll) {
                $TaxonomiesTable = $this->fetchTable('Taxonomies');
                $result[] = ($TaxonomiesTable->update() ? 'Update `' . h($submodule_name) . '` Successful.' : 'Update `' . h($submodule_name) . '` failed.') . PHP_EOL;
            }
            if ($submodule_name == 'app/files/warninglists' || $updateAll) {
                $WarninglistsTable = $this->fetchTable('Warninglists');
                $result[] = ($WarninglistsTable->update() ? 'Update `' . h($submodule_name) . '` Successful.' : 'Update `' . h($submodule_name) . '` failed.') . PHP_EOL;
            }
        }
        return implode('\n', $result);
    }

    public function update(array $status, &$raw = [], array $settings = [])
    {
        $final = '';
        $workingDirectoryPrefix = 'cd $(git rev-parse --show-toplevel) && ';
        $cleanup_commands = [
            // (>^-^)> [hacky]
            $workingDirectoryPrefix . 'git checkout app/composer.json 2>&1'
        ];
        foreach ($cleanup_commands as $cleanup_command) {
            $final .= $cleanup_command . "\n\n";
            $returnCode = false;
            exec($cleanup_command, $output, $returnCode);
            $raw[] = [
                'input' => $cleanup_command,
                'output' => $output,
                'status' => $returnCode,
            ];
            $final .= implode("\n", $output) . "\n\n";
        }
        if (!empty($settings['branch'])) {
            $branchname = false;
            preg_match('/^[a-z0-9\_]+/i', $settings['branch'], $branchname);
            if (!empty($branchname)) {
                $branchname = $branchname[0];
                $checkout_command = $workingDirectoryPrefix . 'git checkout ' . escapeshellarg($branchname) . ' 2>&1';
                exec($checkout_command, $output, $returnCode);
                $raw[] = [
                    'input' => $checkout_command,
                    'output' => $output,
                    'status' => $returnCode,
                ];
                $status = $this->getCurrentGitStatus();
            }
        }
        $command1 = $workingDirectoryPrefix . 'git pull origin ' . escapeshellarg($status['branch']) . ' 2>&1';
        $commandSync = $workingDirectoryPrefix . 'git submodule sync 2>&1';
        $command2 = $workingDirectoryPrefix . 'git submodule update --init --recursive 2>&1';
        $final .= $command1 . "\n\n";
        $returnCode = false;
        exec($command1, $output, $returnCode);
        $raw[] = [
            'input' => $command1,
            'output' => $output,
            'status' => $returnCode,
        ];
        $final .= implode("\n", $output) . "\n\n=================================\n\n";

        $output = [];
        $final .= $commandSync . "\n\n";
        $returnCode = false;
        exec($commandSync, $output, $returnCode);
        $raw[] = [
            'input' => $commandSync,
            'output' => $output,
            'status' => $returnCode,
        ];
        $final .= implode("\n", $output) . "\n\n=================================\n\n";

        $output = [];
        $final .= $command2 . "\n\n";
        $returnCode = false;
        exec($command2, $output, $returnCode);
        $raw[] = [
            'input' => $command2,
            'output' => $output,
            'status' => $returnCode,
        ];
        $final .= implode("\n", $output);
        return $final;
    }

    public function fetchServer($id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = ['Servers.id' => $id];
        if (!is_numeric($id)) {
            $conditions = [
                'OR' => [
                    'LOWER(Servers.name)' => strtolower($id),
                    'LOWER(Servers.url)' => strtolower($id)
                ]
            ];
        }
        $server = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1
            ]
        )->disableHydration()->first();
        return (empty($server)) ? false : $server;
    }

    public function restartWorkers($user = false)
    {
        if (Configure::read('BackgroundJobs.enabled')) {
            $this->workerRemoveDead($user);
            $prepend = '';
            shell_exec($prepend . APP . 'Console' . DS . 'worker' . DS . 'start.sh > /dev/null 2>&1 &');
        }
        return true;
    }

    public function restartDeadWorkers($user = false)
    {
        if (Configure::read('BackgroundJobs.enabled')) {
            $killed = $this->workerRemoveDead($user);
            foreach ($killed as $queue => $count) {
                for ($i = 0; $i < $count; $i++) {
                    $this->startWorker($queue);
                }
            }
        }
        return true;
    }

    public function restartWorker($pid)
    {
        if (Configure::read('BackgroundJobs.Enabled')) {
            $workers = $this->getBackgroundJobsTool()->getWorkers();
            $pid = intval($pid);
            if (!isset($workers[$pid])) {
                return __('Invalid worker.');
            }
            $currentWorker = $workers[$pid];
            $this->killWorker($pid, false);
            $this->startWorker($currentWorker['queue']);
            return true;
        }
        return __('Background workers not enabled.');
    }

    public function startWorker($queue)
    {
        $validTypes = ['default', 'email', 'cache', 'prio', 'update'];
        if (!in_array($queue, $validTypes)) {
            return __('Invalid worker type.');
        }

        $this->getBackgroundJobsTool()->startWorker($queue);

        return true;
    }

    public function cacheServerInitiator($user, $id = 'all', $jobId = false)
    {
        $redis = RedisTool::init();
        if ($redis === false) {
            return 'Redis not reachable.';
        }
        $params = [
            'conditions' => ['caching_enabled' => 1],
        ];
        if ($id !== 'all') {
            $params['conditions']['id'] = $id;
        } else {
            $redis->del('misp:server_cache:combined');
            $redis->del($redis->keys('misp:server_cache:event_uuid_lookup:*'));
        }
        $servers = $this->find('all', $params);
        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');
            $job = $JobsTable->get($jobId);
            if (!$job) {
                $jobId = false;
            }
        }
        foreach ($servers as $k => $server) {
            $this->__cacheInstance($server->toArray(), $redis, $jobId);
            if ($jobId) {
                $job->progress = 100 * $k / $servers->count();
                $job->message =  'Server ' . $server['id'] . ' cached.';
                $JobsTable->save($job);
            }
        }
        return true;
    }

    /**
     * @param array $server
     * @param Redis $redis
     * @param int|false $jobId
     * @return bool
     * @throws JsonException
     */
    private function __cacheInstance($server, $redis, $jobId = false)
    {
        $serverId = $server['id'];
        $i = 0;
        $chunk_size = 50000;
        $redis->del('misp:server_cache:' . $serverId);

        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
        while (true) {
            $i++;
            $rules = [
                'returnFormat' => 'cache',
                'includeEventUuid' => 1,
                'page' => $i,
                'limit' => $chunk_size,
            ];
            try {
                $data = $serverSync->attributeSearch($rules)->getStringBody();
            } catch (Exception $e) {
                $this->logException("Could not fetch cached attribute from server {$serverSync->serverId()}.", $e);
                break;
            }

            $data = trim($data);
            if (empty($data)) {
                break;
            }

            $data = explode(PHP_EOL, $data);
            $pipe = $redis->pipeline();
            foreach ($data as $entry) {
                list($value, $uuid) = explode(',', $entry);
                if (!empty($value)) {
                    $redis->sAdd('misp:server_cache:' . $serverId, $value);
                    $redis->sAdd('misp:server_cache:combined', $value);
                    $redis->sAdd('misp:server_cache:event_uuid_lookup:' . $value, $serverId . '/' . $uuid);
                }
            }
            $pipe->exec();
            if ($jobId) {
                $JobsTable = $this->fetchTable('Jobs');
                $JobsTable->saveProgress($jobId, 'Server ' . $server['id'] . ': ' . ((($i - 1) * $chunk_size) + count($data)) . ' attributes cached.');
            }
        }
        $redis->set('misp:server_cache_timestamp:' . $serverId, time());
        return true;
    }

    /**
     * @param array $servers
     * @return array
     */
    public function attachServerCacheTimestamps(array $servers)
    {
        $redis = RedisTool::init();
        if ($redis === false) {
            return $servers;
        }
        $redis->pipeline();
        foreach ($servers as $server) {
            $redis->get('misp:server_cache_timestamp:' . $server['id']);
        }
        $results = $redis->exec();
        foreach ($servers as $k => $v) {
            $servers[$k]['cache_timestamp'] = $results[$k];
        }
        return $servers;
    }

    public function updateJSON()
    {
        $results = [];
        foreach (['Galaxies', 'Noticelists', 'Warninglists', 'Taxonomies', 'ObjectTemplates', 'ObjectRelationships'] as $target) {
            $Table = $this->fetchTable($target);
            $result = $Table->update();
            $results[$target] = $result === false ? false : true;
        }
        return $results;
    }

    public function resetRemoteAuthKey($id)
    {
        $server = $this->get($id);
        if (empty($server)) {
            return __('Invalid server');
        }
        $serverSync = new ServerSyncTool($server->toArray(), $this->setupSyncRequest($server->toArray()));

        try {
            $response = $serverSync->resetAuthKey();
        } catch (Exception $e) {
            $message = 'Could not reset the remote authentication key.';
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $id, 'Error: ' . $message);
            return $message;
        }
        if ($response->isOk()) {
            try {
                $response = $response->getJson();
            } catch (Exception $e) {
                $message = 'Invalid response received from the remote instance.';
                $this->logException($message, $e);
                $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $id, 'Error: ' . $message);
                return $message;
            }
            if (!empty($response['message'])) {
                $authkey = $response['message'];
            }
            if (substr($authkey, 0, 17) === 'Authkey updated: ') {
                $authkey = substr($authkey, 17, 57);
            }
            $server['authkey'] = $authkey;
            $this->save($server);
            return true;
        } else {
            return __('Could not reset the remote authentication key.');
        }
    }

    public function reprioritise($id = false, $direction = 'up')
    {
        $servers = $this->find(
            'all',
            [
                'recursive' => -1,
                'order' => ['Server.priority ASC', 'Server.id ASC']
            ]
        );
        $success = true;
        if ($id) {
            foreach ($servers as $k => $server) {
                if ($server['id'] && $server['id'] == $id) {
                    if (
                        !($k === 0 && $direction === 'up') &&
                        !(empty($servers[$k + 1]) && $direction === 'down')
                    ) {
                        $temp = $servers[$k];
                        $destination = $direction === 'up' ? $k - 1 : $k + 1;
                        $servers[$k] = $servers[$destination];
                        $servers[$destination] = $temp;
                    } else {
                        $success = false;
                    }
                }
            }
        }
        foreach ($servers as $k => $server) {
            $server['priority'] = $k + 1;
            $result = $this->save($server);
            $success = $success && $result;
        }
        return $success;
    }

    /**
     * @param array $server
     * @param string $relativeUri
     * @return HttpSocketResponseExtended
     * @throws Exception
     */
    private function serverGetRequest(array $server, $relativeUri)
    {
        $HttpSocket = $this->setupHttpSocket($server);
        $request = $this->setupSyncRequest($server);

        $uri = $server['url'] . $relativeUri;
        $response = $HttpSocket->get($uri, [], $request);
        if ($response->code == 404) { // intentional !=
            throw new NotFoundException(__("Fetching the '{0}' failed with HTTP error 404: Not Found", $uri));
        } else if ($response->code == 405) { // intentional !=
            $responseText = json_decode($response->body, true);
            if ($responseText !== null) {
                throw new Exception(__("Fetching the '{0}' failed with HTTP error {1}: {2}", $uri, $response->code, $responseText['message']));
            }
        }

        if ($response->code != 200) { // intentional !=
            throw new Exception(__("Fetching the '{0}' failed with HTTP error {1}: {2}", $uri, $response->code, $response->reasonPhrase));
        }

        return $response;
    }

    /**
     * @param int $id
     * @return array|null
     * @throws JsonException
     */
    public function getRemoteUser($id)
    {
        $server = $this->find(
            'all',
            [
                'conditions' => ['Server.id' => $id],
                'recursive' => -1
            ]
        )->first();
        if (empty($server)) {
            return null; // server not found
        }

        $serverSync = new ServerSyncTool($server->toArray(), $this->setupSyncRequest($server));

        try {
            $response = $serverSync->userInfo();
            $user = $response->getJson();

            $results = [
                __('User') => $user['User']['email'],
                __('Role name') => $user['Role']['name'] ?? __('Unknown, outdated instance'),
                __('Sync flag') => isset($user['Role']['perm_sync']) ? ($user['Role']['perm_sync'] ? __('Yes') : __('No')) : __('Unknown, outdated instance'),
            ];
            if ($response->getHeader('X-Auth-Key-Expiration')) {
                $date = new Chronos($response->getHeader('X-Auth-Key-Expiration'));
                $results[__('Auth key expiration')] = $date->format('Y-m-d H:i:s');
            }
            return $results;
        } catch (HttpSocketHttpException $e) {
            $this->logException('Could not fetch remote user account.', $e);
            return ['error' => $e->getCode()];
        } catch (Exception $e) {
            $this->logException('Could not fetch remote user account.', $e);
            $message = __('Could not fetch remote user account.');
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $id, 'Error: ' . $message);
            return ['error' => $message];
        }
    }

    public function __isset($name)
    {
        if ($name === 'serverSettings' || $name === 'command_line_functions') {
            return true;
        }
        return parent::__isset($name);
    }

    /**
     * @return int Number of orphans removed.
     */
    public function removeOrphanedCorrelations()
    {
        $CorrelationsTable = $this->fetchTable('Correlations');
        $orphansLeft = $CorrelationsTable->find(
            'all',
            [
                'contain' => ['Attribute'],
                'conditions' => [
                    'Attribute.id IS NULL'
                ],
                'fields' => ['Correlation.id', 'Correlation.attribute_id'],
            ]
        )->toArray();
        if (empty($orphansLeft)) {
            return 0;
        }
        $orphansRight = $CorrelationsTable->find(
            'column',
            [
                'conditions' => [
                    '1_attribute_id IN' => array_column($orphansLeft, 'attribute_id'),
                ],
                'fields' => ['Correlation.id'],
            ]
        );
        $orphans = array_merge(
            array_column($orphansLeft, 'id'),
            $orphansRight
        );
        if (!empty($orphans)) {
            $CorrelationsTable->deleteAll(
                [
                    'id' => $orphans
                ],
                false
            );
        }
        return count($orphans);
    }

    public function queryAvailableSyncFilteringRules(array $server)
    {
        $syncFilteringRules = [
            'error' => '',
            'data' => []
        ];

        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));

        try {
            $syncFilteringRules['data'] = $serverSync->getAvailableSyncFilteringRules()->getJson();
        } catch (Exception $e) {
            $syncFilteringRules['error'] = __('Connection failed. Error returned: {0}', $e->getMessage());
            return $syncFilteringRules;
        }

        return $syncFilteringRules;
    }

    public function getAvailableSyncFilteringRules(array $user)
    {
        $TagsTable = $this->fetchTable('Tags');
        $organisations = [];
        if ($user['Role']['perm_sharing_group'] || !Configure::read('Security.hide_organisation_index_from_users')) {
            $organisations = $this->Organisation->find(
                'column',
                [
                    'fields' => ['name'],
                ]
            );
        }
        $tags = $TagsTable->find(
            'column',
            [
                'fields' => ['name'],
            ]
        );
        return [
            'organisations' => $organisations,
            'tags' => $tags,
        ];
    }

    /**
     * @param string|null $old Old (or current) encryption key.
     * @param string|null $new New encryption key. If empty, encrypted values will be decrypted.
     * @throws Exception
     */
    public function reencryptAuthKeys($old, $new)
    {
        $servers = $this->find(
            'list',
            [
                'fields' => ['Server.id', 'Server.authkey'],
            ]
        );
        $toSave = [];
        foreach ($servers as $id => $authkey) {
            if (EncryptedValue::isEncrypted($authkey)) {
                try {
                    $authkey = BetterSecurity::decrypt(substr($authkey, 2), $old);
                } catch (Exception $e) {
                    throw new Exception("Could not decrypt auth key for server #$id", 0, $e);
                }
            }
            if (!empty($new)) {
                $authkey = EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($authkey, $new);
            }
            $toSave[] = [
                'Server' => [
                    'id' => $id,
                    'authkey' => $authkey,
                ]

            ];
        }
        if (empty($toSave)) {
            return true;
        }
        return $this->saveMany($toSave, ['validate' => false, 'fields' => ['authkey']]);
    }

    /**
     * @param string $encryptionKey
     * @return bool
     * @throws Exception
     */
    public function isEncryptionKeyValid($encryptionKey)
    {
        $servers = $this->find(
            'list',
            [
                'fields' => ['Server.id', 'Server.authkey'],
            ]
        );
        foreach ($servers as $id => $authkey) {
            if (EncryptedValue::isEncrypted($authkey)) {
                try {
                    BetterSecurity::decrypt(substr($authkey, 2), $encryptionKey);
                } catch (Exception $e) {
                    throw new Exception("Could not decrypt auth key for server #$id", 0, $e);
                }
            }
        }
        return true;
    }

    /**
     * Return all Attribute and Object types
     */
    public function getAllTypes(): array
    {
        $allTypes = [];
        $AttributesTable = $this->fetchTable('Attributes');
        $ObjectTemplatesTable = $this->fetchTable('ObjectTemplates');
        $objects = $ObjectTemplatesTable->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['uuid', 'name'],
                'group' => ['uuid', 'name'],
            ]
        )->toArray();
        $allTypes = [
            'attribute' => array_unique(Hash::extract(Hash::extract($AttributesTable->categoryDefinitions, '{s}.types'), '{n}.{n}')),
            'object' => Hash::map(
                $objects,
                '{n}.ObjectTemplate',
                function ($item) {
                    return ['id' => $item['uuid'], 'name' => sprintf('%s (%s)', $item['name'], $item['uuid'])];
                }
            )
        ];
        return $allTypes;
    }

    /**
     * Invalidate config.php from php opcode cache
     */
    private function opcacheResetConfig()
    {
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate(APP . 'Config' . DS . 'config.php', true);
        }
    }

    /**
     * Get workers
     *
     * @return array
     */
    private function getWorkers(): array
    {
        $worker_array = [];
        $workers = $this->getBackgroundJobsTool()->getWorkers();

        foreach ($workers as $worker) {
            $worker_array[$worker->pid()] = [
                'queue' => $worker->queue(),
                'type' => 'regular',
                'user' => $worker->user()
            ];
        }

        return $worker_array;
    }
}
