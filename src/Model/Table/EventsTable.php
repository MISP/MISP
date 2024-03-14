<?php

namespace App\Model\Table;

use App\Http\Exception\HttpSocketHttpException;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\ComplexTypeTool;
use App\Lib\Tools\CustomPaginationTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\JSONConverterTool;
use App\Lib\Tools\JsonTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\{ProcessTool, ProcessException};
use App\Lib\Tools\SendEmailTemplate;
use App\Lib\Tools\ServerSyncTool;
use App\Lib\Tools\TmpFileTool;
use App\Lib\Tools\TrendingTool;
use App\Model\Entity\Analysis;
use App\Model\Entity\AttachmentScan;
use App\Model\Entity\Attribute;
use App\Model\Entity\Distribution;
use App\Model\Entity\Event;
use App\Model\Entity\Job;
use App\Model\Entity\ThreatLevel;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\ORM\RulesChecker;
use Cake\Utility\Hash;
use Cake\Utility\Inflector;
use Cake\Utility\Text;
use Cake\Utility\Xml;
use Cake\Validation\Validation;
use Cake\Validation\Validator;
use Exception;
use InvalidArgumentException;

class EventsTable extends AppTable
{
    use LogExtendedTrait;

    private $assetCache = [];

    /** @var array|null */
    private $eventBlockRule;

    private $__beforeSaveData = null;

    public $possibleOptions = [
        'eventid',
        'idList',
        'tags',
        'from',
        'to',
        'last',
        'to_ids',
        'includeAllTags', // include also non exportable tags, default `false`
        'includeAttachments',
        'event_uuid',
        'distribution',
        'sharing_group_id',
        'disableSiteAdmin',
        'metadata',
        'enforceWarninglist', // return just attributes that contains no warnings
        'sgReferenceOnly', // do not fetch additional information about sharing groups
        'flatten',
        'blockedAttributeTags',
        'eventsExtendingUuid',
        'extended',
        'extensionList',
        'excludeGalaxy',
        // 'includeCustomGalaxyCluster', // not used
        'includeRelatedTags',
        'excludeLocalTags',
        'includeDecayScore',
        'includeScoresOnEvent',
        'includeSightingdb',
        'includeFeedCorrelations',
        'includeServerCorrelations',
        'includeWarninglistHits',
        'includeGranularCorrelations',
        'noEventReports', // do not include event report in event data
        'noShadowAttributes', // do not fetch proposals,
        'limit',
        'page',
        'order',
        'protected',
        'published',
        'orgc_id',
    ];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'User',
            [
                'className' => 'Users',
                'foreignKey' => 'user_id'
            ]
        );
        $this->belongsTo(
            'ThreatLevel',
            [
                'className' => 'ThreatLevels',
                'foreignKey' => 'threat_level_id'
            ]
        );
        $this->belongsTo(
            'Org',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id'
            ]
        );
        $this->belongsTo(
            'Orgc',
            [
                'className' => 'Organisations',
                'foreignKey' => 'orgc_id'
            ]
        );
        $this->belongsTo(
            'SharingGroup',
            [
                'className' => 'SharingGroups',
                'foreignKey' => 'sharing_group_id'
            ]
        );

        $this->hasMany(
            'Attributes',
            [
                'dependent' => true,
                'propertyName' => 'Attribute'
            ]
        );
        $this->hasMany(
            'ShadowAttributes',
            [
                'dependent' => true,
                'propertyName' => 'ShadowAttribute'
            ]
        );
        $this->hasMany(
            'Objects',
            [
                'dependent' => true,
                'propertyName' => 'Object',
            ]
        );
        $this->hasMany(
            'EventTags',
            [
                'dependent' => true,
                'propertyName' => 'EventTag',
            ]
        );
        $this->hasMany(
            'Sightings',
            [
                'dependent' => true,
                'propertyName' => 'Sighting',
            ]
        );
        $this->hasMany(
            'EventReports',
            [
                'dependent' => true,
                'propertyName' => 'EventReport',
            ]
        );
        $this->hasMany(
            'CryptographicKeys',
            [
                'dependent' => true,
                'propertyName' => 'CryptographicKey',
                'foreignKey' => 'parent_id',
                'conditions' => [
                    'parent_type' => 'Events'
                ],
            ]
        );
        $this->setDisplayField('info');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['org_id', 'orgc_id', 'date', 'threat_level_id', 'distribution', 'analysis', 'info'])
            ->add('org_id', 'numeric')
            ->add('orgc_id', 'numeric')
            ->add(
                'date',
                'date',
                [
                    'rule' => 'date',
                    'message' => __('Expected date format: YYYY-MM-DD')
                ]
            )
            ->add(
                'threat_level_id',
                'inList',
                [
                    'rule' => ['inList', ThreatLevel::ALL],
                    'message' => __('Options: ' . implode(', ', ThreatLevel::DESCRIPTIONS))
                ]
            )
            ->add(
                'distribution',
                'inList',
                [
                    'rule' => ['inList', Distribution::ALL],
                    'message' => 'Options: ' . implode(', ', Distribution::DESCRIPTIONS)
                ]
            )
            ->add(
                'sharing_group_id',
                'sharingGroupRequired',
                [
                    'rule' => function ($value, $context) {
                        return !($context['data']['distribution'] == Distribution::SHARING_GROUP && empty($value));
                    },
                    'message' => 'If the distribution is set to "Sharing Group", a sharing group has to be selected.',
                ]
            )
            ->add(
                'analysis',
                'inList',
                [
                    'rule' => ['inList', Analysis::ALL],
                    'message' => 'Options: ' . implode(', ', Analysis::DESCRIPTIONS)
                ]
            )
            ->notEmptyString('info')
            ->numeric('user_id')
            ->boolean('published')
            ->allowEmptyString('extends_uuid')
            ->add(
                'uuid',
                'uuid',
                [
                    'rule' => 'uuid',
                    'message' => 'Please provide a valid RFC 4122 UUID'
                ]
            )
            ->add(
                'extends_uuid',
                'uuid',
                [
                    'rule' => 'uuid',
                    'message' => 'Please provide a valid RFC 4122 UUID'
                ]
            );

        return $validator;
    }

    public function validationUpdate(Validator $validator): Validator
    {
        return $this->validationDefault($validator);
    }

    public function validationPublish(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['published', 'timestamp'])
            ->numeric('timestamp')
            ->boolean('published');

        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['uuid']));
        return $rules;
    }

    public function beforeDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        // blocklist the event UUID if the feature is enabled
        if (Configure::read('MISP.enableEventBlocklisting') !== false && empty($this->skipBlocklist)) {
            $EventBlocklistsTable = $this->fetchTable('EventBlocklists');
            $orgc = $this->Orgc->find('all', ['conditions' => ['Orgc.id' => $entity['orgc_id']], 'recursive' => -1, 'fields' => ['Orgc.name']]);
            $EventBlocklistsTable->create();
            $blocklistEntry = $EventBlocklistsTable->newEntity(
                [
                    'event_uuid' => $entity['uuid'],
                    'event_info' => $entity['info'],
                    'event_orgc' => $orgc['Orgc']['name'],
                    'comment' => __('Automatically blocked by deleting event'),
                ]
            );
            $EventBlocklistsTable->save($blocklistEntry);
        }

        if (!empty($entity['id'])) {
            if ($this->pubToZmq('event')) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->event_save(['Event' => $entity], 'delete');
            }
            if (Configure::read('Plugin.Kafka_enable')) {
                $kafkaEventTopic = Configure::read('Plugin.Kafka_event_notifications_topic');
                if (Configure::read('Plugin.Kafka_event_notifications_enable') && !empty($kafkaEventTopic)) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaEventTopic, ['Event' => $entity], 'delete');
                }
                $kafkaPubTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (!empty($entity['published']) && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaPubTopic)) {
                    $hostOrg = $this->Org->find('all', ['conditions' => ['name' => Configure::read('MISP.org')], 'fields' => ['id']])->first();
                    if (!empty($hostOrg)) {
                        $user = ['org_id' => $hostOrg['Org']['id'], 'Role' => ['perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 0], 'Organisation' => $hostOrg['Org']];
                        $params = ['eventid' => $entity['id']];
                        if (Configure::read('Plugin.Kafka_include_attachments')) {
                            $params['includeAttachments'] = 1;
                        }
                        $fullEvent = $this->fetchEvent($user, $params);
                        if (!empty($fullEvent)) {
                            $kafkaPubTool = $this->getKafkaPubTool();
                            $kafkaPubTool->publishJson($kafkaPubTopic, $fullEvent[0], 'delete');
                        }
                    }
                }
            }
        }

        try {
            $this->loadAttachmentTool()->deleteAll($entity->id);
        } catch (Exception $e) {
            $this->logException('Delete of event file directory failed.', $e);
            throw new InternalErrorException('Delete of event file directory failed. Please report to administrator.');
        }
        $this->CryptographicKey->deleteAll(['CryptographicKey.parent_type' => 'Event', 'CryptographicKey.parent_id' => $entity->id]);
    }

    public function beforeMarshal(EventInterface $appEvent, ArrayObject $event, ArrayObject $options)
    {
        // analysis - setting correct vars
        if (isset($event['analysis'])) {
            switch ($event['analysis']) {
                case 'Initial':
                    $event['analysis'] = Analysis::INITIAL;
                    break;
                case 'Ongoing':
                    $event['analysis'] = Analysis::ONGOING;
                    break;
                case 'Completed':
                    $event['analysis'] = Analysis::COMPLETED;
                    break;
            }
        } else {
            $event['analysis'] = 0;
        }

        if (!isset($event['threat_level_id'])) {
            $event['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ?: 4;
        }

        // generate UUID if it doesn't exist
        if (!empty($event['uuid'])) {
            $event['uuid'] = strtolower($event['uuid']);
        }

        // Convert event ID to uuid if needed
        if (!empty($event['extends_uuid'])) {
            if (is_numeric($event['extends_uuid'])) {
                $extended_event = $this->find(
                    'all',
                    [
                        'recursive' => -1,
                        'conditions' => ['id' => $event['extends_uuid']],
                        'fields' => ['uuid']
                    ]
                )->first();
                if (empty($extended_event)) {
                    $event['extends_uuid'] = '';
                    $this->invalidate('extends_uuid', 'Invalid event ID provided.');
                } else {
                    $event['extends_uuid'] = $extended_event['Event']['uuid'];
                }
            } else {
                $event['extends_uuid'] = strtolower($event['extends_uuid']);
            }
        }

        // generate timestamp if it doesn't exist
        if (empty($event['timestamp'])) {
            $event['timestamp'] = time();
        }

        if (isset($event['publish_timestamp']) && empty($event['publish_timestamp'])) {
            $event['publish_timestamp'] = 0;
        }

        if (empty($event['date'])) {
            $event['date'] = date('Y-m-d');
        }

        if (!isset($event['distribution']) || $event['distribution'] != 4) {
            $event['sharing_group_id'] = 0;
        }
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->uuid === null) {
            $entity->uuid = Text::uuid();
        }

        $this->__beforeSaveData = $entity;

        $trigger_id = 'event-before-save';
        if ($this->isTriggerCallable($trigger_id)) {
            $event = $this->data;
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => 'add',
                'id' => 0,
                'message' => __('The workflow `%s` prevented the saving of event (%s)', $trigger_id, $event['uuid']),
            ];
            $triggerData = $event;
            $workflowSuccess = $this->executeTrigger($trigger_id, $triggerData, $workflowErrors, $logging);
            if (!$workflowSuccess) {
                return false;
            }
        }

        return true;
    }

    public function afterSave(EventInterface $cakeEvent, EntityInterface $event, ArrayObject $options)
    {
        if (!Configure::read('MISP.completely_disable_correlation') && !$event->isNew()) {
            if (
                empty($this->__beforeSaveData) ||
                (
                    isset($this->__beforeSaveData['distribution']) &&
                    $event['distribution'] != $this->__beforeSaveData['distribution']
                ) ||
                (
                    isset($this->__beforeSaveData['sharing_group_id']) &&
                    $event['sharing_group_id'] != $this->__beforeSaveData['sharing_group_id']
                )
            ) {
                $this->Attributes->Correlation->updateContainedCorrelations($event, 'event');
            }
        }
        $this->__beforeSaveData = null;
        if (empty($event['unpublishAction']) && empty($event['skip_zmq']) && $this->pubToZmq('event')) {
            $pubSubTool = $this->getPubSubTool();
            $eventForZmq = $this->quickFetchEvent($event['id']);
            if (!empty($event)) {
                $pubSubTool->event_save($eventForZmq, $event->isNew() ? 'add' : 'edit');
            }
        }
        if (empty($event['unpublishAction']) && empty($event['skip_kafka'])) {
            $this->publishKafkaNotification('event', $this->quickFetchEvent($event['id']), $event->isNew() ? 'add' : 'edit');
        }
        if ($this->isTriggerCallable('event-after-save')) {
            $event = $this->quickFetchEvent($event['id']);
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => $event->isNew() ? 'add' : 'edit',
                'id' => $event['id'],
            ];
            $triggerData = $event;
            $this->executeTrigger('event-after-save', $triggerData, $workflowErrors, $logging);
        }
    }

    public function attachTagsToEvents(array $events)
    {
        $tagsToFetch = [];
        foreach ($events as $event) {
            foreach ($event['EventTag'] as $et) {
                $tagsToFetch[$et['tag_id']] = $et['tag_id'];
            }
        }
        if (empty($tagsToFetch)) {
            return $events;
        }
        $tags = $this->EventTag->Tag->find(
            'all',
            [
                'conditions' => ['Tag.id' => $tagsToFetch],
                'recursive' => -1,
                'fields' => ['id', 'name', 'colour', 'is_galaxy'], // fetch just necessary columns
                'order' => false
            ]
        );
        $tags = array_column(array_column($tags, 'Tag'), null, 'id');
        foreach ($events as &$event) {
            foreach ($event['EventTag'] as &$et) {
                $et['Tag'] = $tags[$et['tag_id']];
            }
        }
        return $events;
    }

    /**
     * @param int $event_id
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function touch($event_id)
    {
        return $this->unpublishEvent($event_id);
    }

    public function attachTagsToEventAndTouch($event_id, array $options, array $user)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $relationship = $options['relationship_type'];
        $touchEvent = false;
        $success = false;
        $capturedTags = [];
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->captureTagWithCache(
                [
                    'name' => $tag_name,
                ],
                $user,
                $capturedTags
            );
            $tag = [
                'id' => $tag_id,
                'local' => $local,
                'relationship_type' => $relationship,
            ];
            $attachSuccess = $this->EventTag->attachTagToEvent($event_id, $tag, $nothingToChange);
            $success = $success || $attachSuccess;
            $touchEvent = $touchEvent || !$nothingToChange;
        }
        if ($touchEvent) {
            return $this->touch($event_id);
        }
        return $success;
    }

    public function detachTagsFromEventAndTouch($event_id, array $options)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $touchEvent = false;
        $success = false;
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->EventTag->Tag->lookupTagIdFromName($tag_name);
            if ($tag_id == -1) {
                $success = $success || true;
                continue;
            }
            $detachSuccess = $this->EventTag->detachTagFromEvent($event_id, $tag_id, $local, $nothingToChange);
            $success = $success || $detachSuccess;
            $touchEvent = $touchEvent || !$nothingToChange;
        }
        if ($touchEvent) {
            return $this->touch($event_id);
        }
        return $success;
    }

    /**
     * Gets the logged in user + an array of events, attaches the correlation count to each
     * @param array $user
     * @param array $events
     * @return array
     */
    public function attachCorrelationCountToEvents(array $user, array $events)
    {
        $sgids = $this->SharingGroup->authorizedIds($user);
        foreach ($events as &$event) {
            $event['correlation_count'] = $this->getRelatedEventCount($user, $event['id'], $sgids);
        }
        return $events;
    }

    public function attachSightingsCountToEvents(array $user, array $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $this->Sighting->virtualFields['count'] = 'count(Sighting.id)';
        $sightings = $this->Sighting->find(
            'list',
            [
                'fields' => ['Sighting.event_id', 'Sighting.count'],
                'conditions' => ['event_id' => $eventIds],
                'group' => ['event_id']
            ]
        );
        foreach ($events as $key => $event) {
            $events[$key]['Event']['sightings_count'] = isset($sightings[$event['id']]) ? $sightings[$event['id']] : 0;
        }
        return $events;
    }

    public function attachProposalsCountToEvents($user, $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $proposals = $this->ShadowAttribute->find(
            'all',
            [
                'fields' => ['ShadowAttributes.event_id', 'count(distinct(ShadowAttributes.id)) as count'],
                'conditions' => ['event_id' => $eventIds, 'deleted' => 0],
                'recursive' => -1,
                'group' => ['event_id']
            ]
        );
        $proposals = Hash::combine($proposals, '{n}.ShadowAttributes.event_id', '{n}.0.count');
        foreach ($events as $key => $event) {
            $events[$key]['Event']['proposals_count'] = isset($proposals[$event['id']]) ? $proposals[$event['id']] : 0;
        }
        return $events;
    }

    public function attachDiscussionsCountToEvents($user, $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $ThreadsTable = $this->fetchTable('Threads');
        $threads = $ThreadsTable->find(
            'list',
            [
                'conditions' => ['Thread.event_id' => $eventIds],
                'fields' => ['Thread.event_id', 'Thread.id']
            ]
        );
        $posts = $ThreadsTable->Post->find(
            'all',
            [
                'conditions' => ['Post.thread_id' => $threads],
                'recursive' => -1,
                'fields' => ['Count(id) AS post_count', 'thread_id', 'max(date_modified) as last_post'],
                'group' => ['Post.thread_id']
            ]
        );
        $event_threads = [];
        foreach ($posts as $k => $v) {
            foreach ($threads as $k2 => $v2) {
                if ($v2 == $v['Post']['thread_id']) {
                    $event_threads[$k2] = [
                        'post_count' => $v[0]['post_count'],
                        'last_post' => strtotime($v[0]['last_post'])
                    ];
                }
            }
        }
        foreach ($events as $k => $v) {
            $events[$k]['Event']['post_count'] = !empty($event_threads[$events[$k]['Event']['id']]) ? $event_threads[$events[$k]['Event']['id']]['post_count'] : 0;
            $events[$k]['Event']['last_post'] = !empty($event_threads[$events[$k]['Event']['id']]) ? $event_threads[$events[$k]['Event']['id']]['last_post'] : 0;
        }
        return $events;
    }

    public function getRelatedEventCount(array $user, $eventId, $sgids)
    {
        if (!isset($sgids) || empty($sgids)) {
            $sgids = [-1];
        }
        return count($this->Attributes->Correlation->getRelatedEventIds($user, $eventId, $sgids));
    }

    private function getRelatedEvents($user, $eventId, $sgids)
    {
        if (!isset($sgids) || empty($sgids)) {
            $sgids = [-1];
        }
        $relatedEventIds = $this->Attributes->Correlations->getRelatedEventIds($user, $eventId, $sgids);
        if (empty($relatedEventIds)) {
            return [];
        }
        // now look up the event data for these attributes
        $relatedEvents =  $this->find(
            'all',
            [
                'conditions' => [
                    'id IN' => $relatedEventIds
                ],
                'recursive' => -1,
                'order' => 'date DESC',
                'fields' => [
                    'id', 'date', 'threat_level_id', 'info', 'published', 'uuid', 'analysis', 'timestamp', 'distribution', 'org_id', 'orgc_id'
                ],
                'contain' => [
                    'Org' => [
                        'fields' => ['id', 'name', 'uuid']
                    ],
                    'Orgc' => [
                        'fields' => ['id', 'name', 'uuid']
                    ]
                ]
            ]
        );
        $fieldsToRearrange = ['Org', 'Orgc'];
        foreach ($relatedEvents as $k => $relatedEvent) {
            foreach ($fieldsToRearrange as $field) {
                if (isset($relatedEvent[$field])) {
                    $relatedEvents[$k]['Event'][$field] = $relatedEvent[$field];
                    unset($relatedEvents[$k][$field]);
                }
            }
        }
        return $relatedEvents;
    }

    /**
     * Get related attributes for event
     * @param array $user
     * @param int|array $eventIds Event IDs
     * @return array
     */
    public function getRelatedAttributes(array $user, $eventIds)
    {
        $CorrelationsTable = $this->fetchTable('Correlations');

        $sgids = $this->SharingGroup->authorizedIds($user);
        $relatedAttributes = $CorrelationsTable->getAttributesRelatedToEvent($user, $eventIds, $sgids);
        return $relatedAttributes;
    }

    /**
     * Clean up an Event Array that was received by an XML request.
     * The structure needs to be changed a little bit to be compatible with what CakePHP expects
     *
     * This function receives the reference of the variable, so no return is required as it directly
     * modifies the original data.
     */
    private function cleanupEventArrayFromXML(&$data)
    {
        $objects = ['Attribute', 'ShadowAttribute', 'Object'];
        foreach ($objects as $object) {
            // Workaround for different structure in XML/array than what CakePHP expects
            if (isset($data['Event'][$object]) && is_array($data['Event'][$object]) && count($data['Event'][$object])) {
                if (!is_numeric(implode('', array_keys($data['Event'][$object])))) {
                    // single attribute
                    $data['Event'][$object] = [0 => $data['Event'][$object]];
                }
                $data['Event'][$object] = array_values($data['Event'][$object]);
            }
        }
        $objects = ['Org', 'Orgc', 'SharingGroup'];
        foreach ($objects as $object) {
            if (isset($data['Event'][$object][0])) {
                $data['Event'][$object] = $data['Event'][$object][0];
            }
        }
        return $data;
    }

    /**
     * Returns list of server that event will be pushed.
     * @param array $event
     * @return array
     */
    public function listServerToPush(array $event)
    {
        $elevatedUser = [
            'Role' => [
                'perm_site_admin' => 1,
                'perm_sync' => 1,
                'perm_audit' => 0,
            ],
            'org_id' => $event['orgc_id']
        ];
        // Fetch event with details
        $event = $this->fetchEvent($elevatedUser, ['eventid' => $event['id'], 'metadata' => true]);
        $event = $event[0];

        $ServersTable = $this->fetchTable('Servers');
        $servers = $ServersTable->find(
            'all',
            [
                'conditions' => ['Server.push' => true],
                'recursive' => -1,
                'contain' => ['RemoteOrg', 'Organisation'],
                'order' => ['Server.priority ASC', 'Server.id ASC'],
            ]
        );

        $output = [];
        foreach ($servers as $server) {
            $isEventPushableToServer = $this->shouldBePushedToServer($event, $server, $reason);
            if ($isEventPushableToServer) {
                $result = true;
            } else {
                if ($reason === Event::NO_PUSH_DISTRIBUTION) {
                    $result = 'The distribution level of this event blocks it from being pushed.';
                } elseif ($reason === Event::NO_PUSH_SERVER_RULES) {
                    $result = 'The server rules blocks it from being pushed.';
                } else {
                    $result = $reason;
                }
            }
            $output[$server['Server']['name']] = $result;
        }
        return $output;
    }

    /**
     * Check if event can be pushed to remote server.
     *
     * @param array $event
     * @param array $server
     * @param string $reason If method returns false, this variable contains reason why event should not be pushed
     * @return bool
     */
    public function shouldBePushedToServer(array $event, array $server, &$reason)
    {
        if (!isset($server['Server']['internal'])) {
            throw new InvalidArgumentException('Invalid Server array provided.');
        }

        // This check is probably redundant, because it should be checked in also in `checkDistributionForPush`
        // But keep it here just for sure
        if (!$server['Server']['internal'] && $event['distribution'] < Distribution::CONNECTED_COMMUNITIES) {
            $reason = Event::NO_PUSH_DISTRIBUTION;
            return false;
        }

        $ServersTable = $this->fetchTable('Servers');

        if (empty($ServersTable->eventFilterPushableServers($event, [$server]))) {
            $reason = Event::NO_PUSH_SERVER_RULES;
            return false;
        }

        if (!$this->checkDistributionForPush($event, $server)) {
            $reason = Event::NO_PUSH_DISTRIBUTION;
            return false;
        }

        return true;
    }

    /**
     * @param array $event
     * @param array $server
     * @param ServerSyncTool $serverSync
     * @return false|string
     * @throws HttpSocketJsonException
     * @throws JsonException
     * @throws Exception
     */
    public function uploadEventToServer(array $event, array $server, ServerSyncTool $serverSync)
    {
        $ServersTable = $this->fetchTable('Servers');

        if (empty($ServersTable->eventFilterPushableServers($event, [$server]))) {
            return 'The server rules blocks it from being pushed.';
        }
        if (!$this->checkDistributionForPush($event, $server, 'Event')) {
            return 'The distribution level of this event blocks it from being pushed.';
        }

        $push = $ServersTable->checkVersionCompatibility($server, false, $serverSync);
        if (empty($push['canPush'])) {
            return 'The remote user is not a sync user - the upload of the event has been blocked.';
        }
        if (!empty($server['Server']['unpublish_event'])) {
            $event['published'] = 0;
        }
        try {
            // TODO: Replace by __updateEventForSync method in future
            $event = $this->__prepareForPushToServer($event, $server);
            if (is_numeric($event)) {
                throw new Exception("This should never happen.");
            }

            $serverSync->pushEvent($event)->getJson();
        } catch (\Crypt_GPG_KeyNotFoundException $e) {
            $errorMessage = sprintf(
                'Could not push event %s to remote server #%s. Reason: %s',
                $event['uuid'],
                $server['Server']['id'],
                $e->getMessage()
            );
            $this->logException($errorMessage, $e);
            $this->__logUploadResult($server, $event, $errorMessage);
            return false;
        } catch (Exception $e) {
            $errorMessage = $e->getMessage();
            if ($e instanceof HttpSocketHttpException && $e->getCode() === 403) {
                // Do not log errors that are expected
                $errorJson = $e->getResponse()->getJson();
                if (isset($errorJson['errors'])) {
                    $errorMessage = $errorJson['errors'];
                    if ($errorMessage === 'Event could not be saved: Event in the request not newer than the local copy.') {
                        return $errorMessage;
                    }
                }
            }
            $this->logException("Could not push event '{$event['uuid']}' to remote server #{$server['id']}", $e);
            $this->__logUploadResult($server, $event, $errorMessage);
            return false;
        }
        return 'Success';
    }

    private function __prepareForPushToServer($event, $server)
    {
        $serverId = $server['id'];
        if ($event['distribution'] == 4) {
            if (empty($event['SharingGroup']['roaming']) && empty($server['internal'])) {
                $serverFound = false;
                if (!empty($event['SharingGroup']['SharingGroupServer'])) {
                    foreach ($event['SharingGroup']['SharingGroupServer'] as $sgs) {
                        if ($sgs['server_id'] == $server['id']) {
                            $serverFound = true;
                        }
                    }
                }
                if (!$serverFound) {
                    $this->log("Error when pushing event {$event['uuid']} to remote server {$serverId}: server not found in sharing group.");
                    return 403;
                }
            }
            $orgFound = false;
            if (!empty($event['SharingGroup']['SharingGroupOrg'])) {
                foreach ($event['SharingGroup']['SharingGroupOrg'] as $org) {
                    if (isset($org['Organisation']) && $org['Organisation']['uuid'] === $server['RemoteOrg']['uuid']) {
                        $orgFound = true;
                    }
                }
            }
            if (!$orgFound) {
                $this->log("Error when pushing event {$event['uuid']} to remote server {$serverId}: org not found in sharing group.");
                return 403;
            }
        }
        $ServersTable = $this->fetchTable('Servers');
        $server = $ServersTable->eventFilterPushableServers($event, [$server]);
        if (empty($server)) {
            $this->log("Error when pushing event {$event['uuid']} to remote server {$serverId}: event doesn't match sever push rules.");
            return 403;
        }
        $server = $server[0];
        if ($this->checkDistributionForPush($event, $server, 'Event')) {
            $event = $this->__updateEventForSync($event, $server);
        } else {
            $this->log("Error when pushing event {$event['uuid']} to remote server {$serverId}: event doesn't match distribution.");
            return 403;
        }
        return $event;
    }

    private function __rearrangeEventStructureForSync($event)
    {
        // rearrange things to be compatible with the Xml::fromArray()
        $objectsToRearrange = [
            'Attribute',
            'Object',
            'Orgc',
            'SharingGroup',
            'EventTag',
            'Org',
            'ShadowAttribute',
            'EventReport',
            'CryptographicKey',
            'ThreatLevel',
            'Galaxy'
        ];
        foreach ($objectsToRearrange as $o) {
            if (isset($event[$o])) {
                $event[$o] = $event[$o];
                unset($event[$o]);
            }
        }
        // cleanup the array from things we do not want to expose
        foreach (['Org', 'org_id', 'orgc_id', 'proposal_email_lock', 'org', 'orgc'] as $field) {
            unset($event[$field]);
        }
        return ['Event' => $event];
    }

    // since we fetch the event and filter on tags after / server, we need to cull all of the non exportable tags
    public function __removeNonExportableTags($data, $dataType, $server = [])
    {
        if (isset($data[$dataType . 'Tag'])) {
            if (!empty($data[$dataType . 'Tag'])) {
                foreach ($data[$dataType . 'Tag'] as $k => $tag) {
                    if (!$tag['Tag']['exportable'] || (!empty($tag['local']) && empty($server['internal']))) {
                        unset($data[$dataType . 'Tag'][$k]);
                    } else {
                        unset($tag['org_id']);
                        $data['Tag'][] = $tag['Tag'];
                    }
                }
            }
            unset($data[$dataType . 'Tag']);
        }
        return $data;
    }

    private function __prepareAttributesForSync($data, $server, $pushRules)
    {
        // prepare attribute for sync
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $key => $attribute) {
                if (!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type')) && in_array($attribute['type'], $pushRules['type_attributes']['NOT'])) {
                    unset($data['Attribute'][$key]);
                    continue;
                }
                $data['Attribute'][$key] = $this->__updateAttributeForSync($attribute, $server);
                if (empty($data['Attribute'][$key])) {
                    unset($data['Attribute'][$key]);
                } else {
                    $data['Attribute'][$key] = $this->__removeNonExportableTags($data['Attribute'][$key], 'Attribute', $server);
                }
            }
            $data['Attribute'] = array_values($data['Attribute']);
        }
        return $data;
    }

    private function __prepareObjectsForSync($data, $server, $pushRules)
    {
        // prepare Object for sync
        if (!empty($data['Object'])) {
            foreach ($data['Object'] as $key => $object) {
                if (!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type')) && in_array($object['template_uuid'], $pushRules['type_objects']['NOT'])) {
                    unset($data['Object'][$key]);
                    continue;
                }
                $data['Object'][$key] = $this->__updateObjectForSync($object, $server);
                if (empty($data['Object'][$key])) {
                    unset($data['Object'][$key]);
                } else {
                    $data['Object'][$key] = $this->__prepareAttributesForSync($data['Object'][$key], $server, $pushRules);
                }
            }
            $data['Object'] = array_values($data['Object']);
        }
        return $data;
    }

    private function __prepareEventReportForSync($data, $server)
    {
        if (!empty($data['EventReport'])) {
            foreach ($data['EventReport'] as $key => $report) {
                $data['EventReport'][$key] = $this->__updateEventReportForSync($report, $server);
                if (empty($data['EventReport'][$key])) {
                    unset($data['EventReport'][$key]);
                }
            }
            $data['EventReport'] = array_values($data['EventReport']);
        }
        if (isset($data['EventReport']) && empty($data['EventReport'])) {
            unset($data['EventReport']);
        }
        return $data;
    }

    private function __updateEventForSync($event, $server)
    {
        $event = $this->__rearrangeEventStructureForSync($event);
        $event = $this->__removeNonExportableTags($event, 'Event', $server);
        // Add the local server to the list of instances in the SG
        if (isset($event['SharingGroup']) && isset($event['SharingGroup']['SharingGroupServer'])) {
            foreach ($event['SharingGroup']['SharingGroupServer'] as &$s) {
                if ($s['server_id'] == 0) {
                    $s = [
                        'id' => 0,
                        'url' => $this->__getAnnounceBaseurl(),
                        'name' => $this->__getAnnounceBaseurl()
                    ];
                }
            }
        }

        $event = $this->__prepareAttributesForSync($event, $server, $server['push_rules']);
        $event = $this->__prepareObjectsForSync($event, $server, $server['push_rules']);
        $event = $this->__prepareEventReportForSync($event, $server, $server['push_rules']);

        // Downgrade the event from connected communities to community only
        if (!$server['internal'] && $event['Event']['distribution'] == 2) {
            $event['distribution'] = 1;
        }

        return $event;
    }

    private function __updateObjectForSync($object, $server)
    {
        if (!$server['Server']['internal'] && $object['distribution'] < 2) {
            return false;
        }
        // Downgrade the object from connected communities to community only
        if (!$server['Server']['internal'] && $object['distribution'] == 2) {
            $object['distribution'] = 1;
        }
        // If the object has a sharing group attached, make sure it can be transferred
        if ($object['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(['Object' => $object], $server, 'Object') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (isset($object['SharingGroup']['SharingGroupServer'])) {
                foreach ($object['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = [
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        ];
                    }
                }
            }
        }
        return $object;
    }

    public function __getAnnounceBaseurl()
    {
        $baseurl = '';
        if (!empty(Configure::read('MISP.external_baseurl'))) {
            $baseurl = Configure::read('MISP.external_baseurl');
        } else if (!empty(Configure::read('MISP.baseurl'))) {
            $baseurl = Configure::read('MISP.baseurl');
        }
        return $baseurl;
    }

    private function __updateAttributeForSync($attribute, $server)
    {
        // do not keep attributes that are private, nor cluster
        if (!$server['Server']['internal'] && $attribute['distribution'] < 2) {
            return false;
        }
        // Downgrade the attribute from connected communities to community only
        if (!$server['Server']['internal'] && $attribute['distribution'] == 2) {
            $attribute['distribution'] = 1;
        }

        // If the attribute has a sharing group attached, make sure it can be transferred
        if ($attribute['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(['Attribute' => $attribute], $server, 'Attribute') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (!empty($attribute['SharingGroup']['SharingGroupServer'])) {
                foreach ($attribute['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = [
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        ];
                    }
                }
            }
        }
        // also add the encoded attachment
        if ($this->Attributes->typeIsAttachment($attribute['type'])) {
            $attribute['data'] = $this->Attributes->base64EncodeAttachment($attribute);
        }
        // Passing the attribute ID together with the attribute could cause the deletion of attributes after a publish/push
        // Basically, if the attribute count differed between two instances, and the instance with the lower attribute
        // count pushed, the old attributes with the same ID got overwritten. Unsetting the ID before pushing it
        // solves the issue and a new attribute is always created.
        unset($attribute['id']);
        // remove value1 and value2 from the output
        unset($attribute['value1']);
        unset($attribute['value2']);
        return $attribute;
    }

    private function __updateEventReportForSync($report, $server)
    {
        if (!$server['Server']['internal'] && $report['distribution'] < 2) {
            return false;
        }
        // check if remote version support event reports
        $eventReportSupportedByRemote = false;
        $uri = $server['Server']['url'] . '/eventReports/add';
        $HttpSocket = $this->setupHttpSocket($server, null);
        $request = $this->setupSyncRequest($server);
        try {
            $response = $HttpSocket->get($uri, false, $request);
            if ($response->isOk()) {
                $apiDescription = json_decode($response->body, true);
                $eventReportSupportedByRemote = !empty($apiDescription['description']);
            }
        } catch (Exception $e) {
            $LogsTable = $this->fetchTable('Logs');
            $message = __('Remote version does not support event report.');
            $LogsTable->createLogEntry('SYSTEM', '__updateEventReportForSync', 'Server', $server['id'], $message);
        }

        if (!$eventReportSupportedByRemote) {
            return [];
        }

        // Downgrade the object from connected communities to community only
        if (!$server['Server']['internal'] && $report['distribution'] == 2) {
            $report['distribution'] = 1;
        }
        // If the object has a sharing group attached, make sure it can be transferred
        if ($report['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(['EventReport' => $report], $server, 'EventReport') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (isset($report['SharingGroup']['SharingGroupServer'])) {
                foreach ($report['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = [
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        ];
                    }
                }
            }
        }
        return $report;
    }

    /**
     * Download event metadata from remote server.
     *
     * @param int $eventId
     * @param array $server
     * @param bool $minimal Return just minimal event response
     * @return array|null Null when event doesn't exists on remote server
     * @throws Exception
     */
    public function downloadEventMetadataFromServer($eventId, $server, $minimal = false)
    {
        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
        $data = $serverSync->eventIndex(['eventid' => $eventId, 'minimal' => $minimal ? '1' : '0'])->getJson();
        if (empty($data)) {
            return null;
        }
        // Old format used by old MISP version
        if (isset($data['id'])) {
            return $data;
        }
        return $data[0];
    }

    /**
     * @param array $event
     * @return bool
     */
    public function quickDelete(array $event)
    {
        $event = $this->get((int)$event['id']);

        $ThreadsTable = $this->fetchTable('Threads');
        $thread = $ThreadsTable->get($event->id);
        $thread_id = !empty($thread) ? (int)$thread['id'] : false;
        $relations = [
            [
                'table' => 'attributes',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'shadow_attributes',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'event_tags',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'attribute_tags',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'threads',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'sightings',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'event_delegations',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'objects',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'object_references',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ],
            [
                'table' => 'event_reports',
                'foreign_key' => 'event_id',
                'value' => $event->id
            ]
        ];
        if ($thread_id) {
            $relations[] =  [
                'table' => 'posts',
                'foreign_key' => 'thread_id',
                'value' => $thread_id
            ];
        }
        if (!Configure::read('MISP.completely_disable_correlation')) {
            $correlationTableName = $this->Attributes->Correlation->getTableName();
            array_push(
                $relations,
                [
                    'table' => $correlationTableName,
                    'foreign_key' => 'event_id',
                    'value' => $event->id
                ],
                [
                    'table' => $correlationTableName,
                    'foreign_key' => '1_event_id',
                    'value' => $event->id
                ]
            );
        }

        $db = $this->getDataSource();
        $db->begin();
        $connection = $db->getConnection();
        foreach ($relations as $relation) {
            $query = $connection->prepare('DELETE FROM ' . $db->name($relation['table']) . ' WHERE ' . $db->name($relation['foreign_key']) . ' = :value');
            $query->bindValue(':value', $relation['value'], \PDO::PARAM_INT);
            $query->execute();
        }
        if (!$db->commit()) {
            return false;
        }
        $this->set($event);
        return $this->delete($event, false);
    }

    public function createEventConditions($user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $unpublishedPrivate = Configure::read('MISP.unpublishedprivate');
            $conditions['AND']['OR'] = [
                'Events.org_id' => $user['org_id'],
                [
                    'AND' => [
                        'Events.distribution >' => 0,
                        'Events.distribution <' => 4,
                        $unpublishedPrivate ? ['Events.published' => 1] : [],
                    ],
                ],
                [
                    'AND' => [
                        'Events.sharing_group_id' => $sgids,
                        'Events.distribution' => 4,
                        $unpublishedPrivate ? ['Events.published' => 1] : [],
                    ]
                ]
            ];
        }
        return $conditions;
    }

    public function set_filter_wildcard(&$params, $conditions, $options)
    {
        $tempConditions = [];
        $tempConditions[] = ['Events.info LIKE' => $params['wildcard']];
        $attributeParams = ['value1', 'value2', 'comment'];
        foreach ($attributeParams as $attributeParam) {
            $subQueryOptions = [
                'conditions' => ['Attributes.' . $attributeParam . ' LIKE' => $params['wildcard']],
                'fields' => ['event_id']
            ];
            $tempConditions[] = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'id');
        }
        $tagScopes = ['Event', 'Attribute'];
        $AttributeTagsTable = $this->fetchTable('AttributeTags');
        $tagIds = $AttributeTagsTable->Tag->find(
            'column',
            [
                'recursive' => -1,
                'conditions' => ['Tag.name LIKE' => $params['wildcard']],
                'fields' => ['Tag.id']
            ]
        );
        if (!empty($tagIds)) {
            foreach ($tagScopes as $tagScope) {
                $subQueryOptions = [
                    'conditions' => [
                        'tag_id' => $tagIds,
                    ],
                    'fields' => ['event_id']
                ];
                $tempConditions[] = $this->subQueryGenerator($this->{$tagScope . 'Tag'}, $subQueryOptions, 'id');
            }
        }
        return $tempConditions;
    }

    public function set_filter_wildcard_attributes(&$params, $conditions, $options)
    {
        $tempConditions = [];
        $tempConditions[] = ['Events.info LIKE' => $params['wildcard']];
        $attributeParams = ['value1', 'value2', 'comment'];
        foreach ($attributeParams as $attributeParam) {
            $tempConditions[] = ['Attributes.' . $attributeParam . ' LIKE' => $params['wildcard']];
        }
        $tagIds = $this->Attributes->AttributeTags->Tags->find(
            'column',
            [
                'recursive' => -1,
                'conditions' => ['Tag.name LIKE' => $params['wildcard']],
                'fields' => ['Tag.id']
            ]
        );
        if (!empty($tagIds)) {
            $subQueryOptions = [
                'conditions' => [
                    'tag_id' => $tagIds,
                ],
                'fields' => ['event_id']
            ];
            $tempConditions[] = $this->subQueryGenerator($this->EventTag, $subQueryOptions, 'Attributes.event_id');
            $subQueryOptions = [
                'conditions' => [
                    'tag_id' => $tagIds,
                ],
                'fields' => ['attribute_id']
            ];
            $tempConditions[] = $this->subQueryGenerator($this->Attributes->AttributeTag, $subQueryOptions, 'Attributes.id');
        }
        return $tempConditions;
    }

    /**
     * @param array $user
     * @param array $params
     * @param int $result_count
     * @return array Event IDs, when `include_attribute_count` is enabled, then it is Event ID => Attribute count
     */
    public function filterEventIds($user, &$params = [], &$result_count = 0)
    {
        $conditions = $this->createEventConditions($user);
        if (isset($params['wildcard'])) {
            $temp = [];
            $options = [
                'filter' => 'wildcard',
                'scope' => 'Event',
                'pop' => false,
                'context' => 'Event'
            ];
            $conditions['AND'][] = ['OR' => $this->set_filter_wildcard($params, $temp, $options)];
        } else {
            $simple_params = [
                'Event' => [
                    'eventid' => ['function' => 'set_filter_eventid', 'pop' => true],
                    'eventinfo' => ['function' => 'set_filter_eventinfo'],
                    'ignore' => ['function' => 'set_filter_ignore'],
                    'tags' => ['function' => 'set_filter_tags'],
                    'event_tags' => ['function' => 'set_filter_tags', 'pop' => true],
                    'from' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'to' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'date' => ['function' => 'set_filter_date', 'pop' => true],
                    'last' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'timestamp' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'event_timestamp' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'publish_timestamp' => ['function' => 'set_filter_timestamp', 'pop' => true],
                    'org' => ['function' => 'set_filter_org', 'pop' => true],
                    'orgc_id' => ['function' => 'set_filter_orgc_id', 'pop' => true],
                    'uuid' => ['function' => 'set_filter_uuid', 'pop' => true],
                    'published' => ['function' => 'set_filter_published', 'pop' => true],
                    'threat_level_id' => ['function' => 'set_filter_threat_level_id', 'pop' => true],
                    'sharinggroup' => ['function' => 'set_filter_sharing_group']
                ],
                'Object' => [
                    'object_name' => ['function' => 'set_filter_object_name'],
                    'object_template_uuid' => ['function' => 'set_filter_object_template_uuid'],
                    'object_template_version' => ['function' => 'set_filter_object_template_version'],
                    'deleted' => ['function' => 'set_filter_deleted']
                ],
                'Attribute' => [
                    'value' => ['function' => 'set_filter_value'],
                    'category' => ['function' => 'set_filter_simple_attribute'],
                    'type' => ['function' => 'set_filter_type'],
                    'object_relation' => ['function' => 'set_filter_simple_attribute'],
                    'tags' => ['function' => 'set_filter_tags', 'pop' => true],
                    'ignore' => ['function' => 'set_filter_ignore'],
                    'deleted' => ['function' => 'set_filter_deleted'],
                    'to_ids' => ['function' => 'set_filter_to_ids'],
                    'comment' => ['function' => 'set_filter_comment'],
                    'sharinggroup' => ['function' => 'set_filter_sharing_group']
                ]
            ];
            foreach ($params as $param => $paramData) {
                foreach ($simple_params as $scope => $simple_param_scoped) {
                    if (isset($simple_param_scoped[$param]) && $paramData !== false) {
                        $options = [
                            'filter' => $param,
                            'scope' => $scope,
                            'pop' => !empty($simple_param_scoped[$param]['pop']),
                            'context' => 'Event'
                        ];
                        if ($scope === 'Event') {
                            $conditions = $this->{$simple_param_scoped[$param]['function']}($params, $conditions, $options);
                        } else {
                            $temp = [];
                            $temp = $this->{$simple_param_scoped[$param]['function']}($params, $temp, $options);
                            if (!empty($temp)) {
                                $subQueryOptions = [
                                    'conditions' => $temp,
                                    'fields' => [
                                        'event_id'
                                    ]
                                ];
                                $subQuery = $this->subQueryGenerator($this->{$scope}, $subQueryOptions, 'id');
                                if ($param === 'value') {
                                    $subQuery[0] = explode('WHERE', $subQuery[0]);
                                    $subQuery[0][0] .= ' USE INDEX (value1, value2) ';
                                    $subQuery[0] = implode('WHERE', $subQuery[0]);
                                }
                                $conditions['AND'][] = $subQuery;
                            }
                        }
                    }
                }
            }
        }
        $find_params = [
            'conditions' => $conditions,
            'recursive' => -1,
        ];
        if (isset($params['order'])) {
            $find_params['order'] = $this->findOrder(
                $params['order'],
                'Event',
                ['id', 'info', 'analysis', 'threat_level_id', 'distribution', 'timestamp', 'publish_timestamp']
            );
        }
        if (isset($params['limit'])) {
            // Get the count (but not the actual data) of results for paginators
            $result_count = $this->find('count', $find_params);
            $find_params['limit'] = $params['limit'];
            if (isset($params['page'])) {
                $find_params['page'] = $params['page'];
            }
        }
        if (!empty($params['include_attribute_count'])) {
            $find_params['fields'] = ['id', 'Events.attribute_count'];
            $results = $this->find('list', $find_params);
        } else {
            $find_params['fields'] = ['id'];
            $results = $this->find('column', $find_params);
        }
        if (!isset($params['limit'])) {
            $result_count = $results->count();
        }
        return $results;
    }

    public function fetchSimpleEventIds(array $user, $params = [])
    {
        $conditions = $this->createEventConditions($user);
        $conditions['AND'][] = $params['conditions'];
        $results = $this->find(
            'column',
            [
                'conditions' => $conditions,
                'fields' => ['id']
            ]
        );
        return $results;
    }

    /**
     * @param array $user
     * @param string|int $id Event ID or UUID
     * @param array $params
     * @return array|null
     */
    public function fetchSimpleEvent(array $user, $id, array $params = [])
    {
        $conditions = $this->createEventConditions($user);

        if (is_numeric($id)) {
            $conditions['AND'][]['Events.id'] = $id;
        } else if (Validation::uuid($id)) {
            $conditions['AND'][]['Events.uuid'] = $id;
        } else {
            return null;
        }
        if (isset($params['conditions'])) {
            $conditions['AND'][] = $params['conditions'];
        }
        $params['conditions'] = $conditions;
        $params['recursive'] = -1;
        return $this->find('all', $params)->first();
    }

    /**
     * @param array $user
     * @param array $params
     * @param bool $includeOrgc
     * @return array
     */
    public function fetchSimpleEvents(array $user, array $params, $includeOrgc = false)
    {
        $conditions = $this->createEventConditions($user);
        $conditions['AND'][] = $params['conditions'];
        $params = [
            'conditions' => $conditions,
            'recursive' => -1
        ];
        if ($includeOrgc) {
            $params['contain'] = ['Orgc.name'];
        }
        return $this->find('all', $params);
    }

    public function fetchEventIds($user, $options)
    {
        // restricting to non-private or same org if the user is not a site-admin.
        $conditions = $this->createEventConditions($user);
        $paramMapping = [
            'from' => 'Events.date >=',
            'to' => 'Events.date <=',
            'last' => 'Events.publish_timestamp >=',
            'timestamp' => 'Events.timestamp >=',
            'publish_timestamp' => 'Events.publish_timestamp >=',
            'eventIdList' => 'id',
        ];
        foreach ($paramMapping as $paramName => $paramLookup) {
            if (isset($options[$paramName])) {
                $conditions['AND'][] = [$paramLookup => $options[$paramName]];
            }
        }
        if (isset($options['list'])) {
            $params = [
                'conditions' => $conditions,
                'fields' => ['id'],
            ];
            $results = $this->find('column', $params);
        } else {
            $params = [
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => ['id', 'Events.org_id', 'Events.distribution', 'Events.sharing_group_id'],
            ];
            $results = $this->find('all', $params);
        }
        return $results;
    }

    /*
     * Unlike the other fetchers, this one foregoes any ACL checks.
     * the objective is simple: Fetch the given event with all related objects needed for the ZMQ output,
     * standardising on this function for fetching the event to be passed to the pubsub handler
     */
    public function quickFetchEvent($id)
    {
        $event = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Events.id' => $id],
                'contain' => [
                    'Orgc' => [
                        'fields' => ['Orgc.id', 'Orgc.uuid', 'Orgc.name']
                    ],
                    'EventTags' => [
                        'Tags' => ['fields' => ['Tags.id', 'Tags.name', 'Tags.colour', 'Tags.exportable']]
                    ]
                ]
            ]
        )->first();
        return $event;
    }

    //Once the data about the user is gathered from the appropriate sources, fetchEvent is called from the controller or background process.
    // Possible options:
    // eventid: single event ID
    // idList: array with event IDs
    // tags: string with the usual tag syntax
    // from: date string (YYYY-MM-DD)
    // to: date string (YYYY-MM-DD)
    // includeAllTags: true will include the tags that are marked as non-exportable
    // includeAttachments: true will attach the attachments to the attributes in the data field
    public function fetchEvent($user, $options = [], $useCache = false)
    {
        if (!isset($user['org_id'])) {
            throw new InvalidArgumentException('There was an error with the user account (missing `org_id` field).');
        }
        if (isset($options['id'])) {
            $options['eventid'] = $options['id'];
        }
        if (!isset($options['excludeLocalTags']) && !empty($user['Role']['perm_sync']) && empty($user['Role']['perm_site_admin'])) {
            $options['excludeLocalTags'] = 1;
        }
        if (!isset($options['includeEventCorrelations'])) {
            $options['includeEventCorrelations'] = true;
        }
        if (!isset($options['fetchFullClusters'])) {
            $options['fetchFullClusters'] = true;
        }
        if (!isset($options['fetchFullClusterRelationship'])) {
            $options['fetchFullClusterRelationship'] = false;
        }
        foreach ($this->possibleOptions as $opt) {
            if (!isset($options[$opt])) {
                $options[$opt] = false;
            }
        }
        $conditions = $this->createEventConditions($user);
        if ($options['eventid']) {
            $conditions['AND'][] = ["Events.id" => $options['eventid']];
        }
        if ($options['eventsExtendingUuid']) {
            if (!is_array($options['eventsExtendingUuid'])) {
                $options['eventsExtendingUuid'] = [$options['eventsExtendingUuid']];
            }
            foreach ($options['eventsExtendingUuid'] as $extendedEvent) {
                $extendedUuids = [];
                if (!Validation::uuid($extendedEvent)) {
                    $eventUuid = $this->find(
                        'all',
                        [
                            'recursive' => -1,
                            'conditions' => ['id' => $extendedEvent],
                            'fields' => ['uuid']
                        ]
                    )->first();
                    if (!empty($eventUuid)) {
                        $extendedUuids[] = $eventUuid['Event']['uuid'];
                    }
                } else {
                    $extendedUuids[] = $extendedEvent;
                }
            }
            if (!empty($extendedUuids)) {
                $conditions['AND'][] = ['Events.extends_uuid' => $extendedUuids];
            } else {
                // We've set as a search pattern any event that extends an event and didn't find anything
                // valid, make sure we don't get everything thrown in our face that the user can see.
                $conditions['AND'][] = ['id' => -1];
            }
        }
        $isSiteAdmin = $user['Role']['perm_site_admin'];
        if (isset($options['disableSiteAdmin']) && $options['disableSiteAdmin']) {
            $isSiteAdmin = false;
        }
        $conditionsAttributes = [];
        $conditionsObjects = [];
        $conditionsEventReport = [];

        $flatten = (bool)$options['flatten'];

        // restricting to non-private or same org if the user is not a site-admin.
        $sgids = $this->SharingGroup->authorizedIds($user);
        if (!$isSiteAdmin) {
            // if delegations are enabled, check if there is an event that the current user might see because of the request itself
            if (Configure::read('MISP.delegation')) {
                $delegatedEventIDs = $this->__cachedelegatedEventIDs($user, $useCache);
                $conditions['AND']['OR']['id'] = $delegatedEventIDs;
            }
            $attributeCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Attributes.event_id)';
            $objectCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Object.event_id)';
            $eventReportCondSelect = '(SELECT events.org_id FROM events WHERE events.id = EventReport.event_id)';
            if (!$this->isMysql()) {
                $schemaName = $this->getDataSource()->config['schema'];
                $attributeCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Attribute"."event_id")', $schemaName, $schemaName, $schemaName);
                $objectCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Object"."event_id")', $schemaName, $schemaName, $schemaName);
                $eventReportCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "EventReport"."event_id")', $schemaName, $schemaName, $schemaName);
            }
            $conditionsAttributes['AND'][0]['OR'] = [
                [
                    'AND' => [
                        'Attributes.distribution >' => 0,
                        'Attributes.distribution !=' => 4,
                    ]

                ],
                [
                    'AND' => [
                        'Attributes.distribution' => 4,
                        'Attributes.sharing_group_id' => $sgids,
                    ]

                ],
                $attributeCondSelect => $user['org_id']
            ];

            $conditionsObjects['AND'][0]['OR'] = [
                [
                    'AND' => [
                        'Object.distribution >' => 0,
                        'Object.distribution !=' => 4,
                    ]

                ],
                [
                    'AND' => [
                        'Object.distribution' => 4,
                        'Object.sharing_group_id' => $sgids,
                    ]

                ],
                $objectCondSelect => $user['org_id']
            ];

            $conditionsEventReport['AND'][0]['OR'] = [
                [
                    'AND' => [
                        'EventReport.distribution >' => 0,
                        'EventReport.distribution !=' => 4,
                    ]

                ],
                [
                    'AND' => [
                        'EventReport.distribution' => 4,
                        'EventReport.sharing_group_id' => $sgids,
                    ]

                ],
                $eventReportCondSelect => $user['org_id']
            ];
        }
        if ($options['distribution']) {
            $conditions['AND'][] = ['Events.distribution' => $options['distribution']];
            $conditionsAttributes['AND'][] = ['Attributes.distribution' => $options['distribution']];
            $conditionsObjects['AND'][] = ['Object.distribution' => $options['distribution']];
            $conditionsEventReport['AND'][] = ['EventReport.distribution' => $options['distribution']];
        }
        if ($options['sharing_group_id']) {
            $conditions['AND'][] = ['Events.sharing_group_id' => $options['sharing_group_id']];
            $conditionsAttributes['AND'][] = ['Attributes.sharing_group_id' => $options['sharing_group_id']];
            $conditionsObjects['AND'][] = ['Object.sharing_group_id' => $options['sharing_group_id']];
            $conditionsEventReport['AND'][] = ['EventReport.sharing_group_id' => $options['sharing_group_id']];
        }
        if ($options['from']) {
            $conditions['AND'][] = ['Events.date >=' => $options['from']];
        }
        if ($options['to']) {
            $conditions['AND'][] = ['Events.date <=' => $options['to']];
        }
        if ($options['last']) {
            $conditions['AND'][] = ['Events.publish_timestamp >=' => $options['last']];
        }
        if ($options['event_uuid']) {
            $conditions['AND'][] = ['Events.uuid' => $options['event_uuid']];
        }
        if ($options['protected']) {
            $conditions['AND'][] = ['Events.protected' => $options['protected']];
        }
        if ($options['published']) {
            $conditions['AND'][] = ['Events.published' => $options['published']];
        }
        if ($options['orgc_id']) {
            $conditions['AND'][] = ['Events.orgc_id' => $options['orgc_id']];
        }
        if (!empty($options['includeRelatedTags'])) {
            $options['includeGranularCorrelations'] = 1;
        }
        if (isset($options['ignore']) && empty($options['ignore'])) {
            $conditions['AND'][] = ['Events.published' => 1];
            $conditionsAttributes['AND'][] = ['Attributes.to_ids' => 1];
        }
        $softDeletables = ['Attributes', 'Objects', 'EventReports'];
        if (isset($options['deleted'])) {
            if (!is_array($options['deleted'])) {
                $options['deleted'] = [$options['deleted']];
            }
            foreach ($options['deleted'] as $deleted_key => $deleted_value) {
                if ($deleted_value === 'only') {
                    $deleted_value = 1;
                }
                $options['deleted'][$deleted_key] = (int)$deleted_value;
            }
            if (!$user['Role']['perm_sync']) {
                foreach ($softDeletables as $softDeletable) {
                    if (in_array(0, $options['deleted'])) {
                        $deletion_subconditions = [
                            sprintf('%s.deleted', $softDeletable) => 0
                        ];
                    } else {
                        $deletion_subconditions = [
                            '1=0'
                        ];
                    }
                    ${'conditions' . $softDeletable}['AND'][] = [
                        'OR' => [
                            'AND' => [
                                sprintf('(SELECT events.org_id FROM events WHERE events.id = %s.event_id)', $softDeletable) => $user['org_id'],
                                "$softDeletable.deleted IN" => $options['deleted'],
                            ],
                            $deletion_subconditions
                        ]
                    ];
                }
            } else {
                // MySQL couldn't optimise query, so it is better just skip this condition
                $both = in_array(0, $options['deleted']) && in_array(1, $options['deleted']);
                if (!$both) {
                    foreach ($softDeletables as $softDeletable) {
                        ${'conditions' . $softDeletable}['AND'][] = [
                            "$softDeletable.deleted IN" => $options['deleted'],
                        ];
                    }
                }
            }
        } else {
            foreach ($softDeletables as $softDeletable) {
                ${'conditions' . $softDeletable}['AND'][$softDeletable . '.deleted'] = 0;
            }
        }
        $proposal_conditions = ['OR' => ['ShadowAttributes.deleted' => 0]];
        if (isset($options['deleted_proposals'])) {
            if ($isSiteAdmin) {
                $proposal_conditions = ['OR' => ['ShadowAttributes.deleted' => 1]];
            } else {
                $proposal_conditions['OR'][] = ['(SELECT events.org_id FROM events WHERE events.id = ShadowAttributes.event_id)' => $user['org_id']];
            }
        }
        if ($options['idList'] && !$options['tags']) {
            $conditions['AND'][] = ['Events.id IN' => $options['idList']];
        }
        // If we sent any tags along, load the associated tag names for each attribute
        if ($options['tags']) {
            $temp = $this->__generateCachedTagFilters($options['tags']);
            foreach ($temp as $rules) {
                $conditions['AND'][] = $rules;
            }
        }
        if (!empty($options['to_ids']) || $options['to_ids'] === 0) {
            $conditionsAttributes['AND'][] = ['Attributes.to_ids' => $options['to_ids']];
        }

        // removing this for now, we export the to_ids == 0 attributes too, since there is a to_ids field indicating it in the .xml
        // $conditionsAttributes['AND'] = array('Attributes.to_ids =' => 1);
        // Same idea for the published. Just adjust the tools to check for this
        // $conditions['AND'][] = array('Events.published =' => 1);

        // do not expose all the data ...
        $fields = ['Events.id', 'Events.orgc_id', 'Events.org_id', 'Events.date', 'Events.threat_level_id', 'Events.info', 'Events.published', 'Events.uuid', 'Events.attribute_count', 'Events.analysis', 'Events.timestamp', 'Events.distribution', 'Events.proposal_email_lock', 'Events.user_id', 'Events.locked', 'Events.publish_timestamp', 'Events.sharing_group_id', 'Events.disable_correlation', 'Events.extends_uuid', 'Events.protected'];
        $fieldsAtt = ['Attributes.id', 'Attributes.type', 'Attributes.category', 'Attributes.value1', 'Attributes.value2', 'Attributes.to_ids', 'Attributes.uuid', 'Attributes.event_id', 'Attributes.distribution', 'Attributes.timestamp', 'Attributes.comment', 'Attributes.sharing_group_id', 'Attributes.deleted', 'Attributes.disable_correlation', 'Attributes.object_id', 'Attributes.object_relation', 'Attributes.first_seen', 'Attributes.last_seen'];
        $fieldsShadowAtt = ['ShadowAttributes.id', 'ShadowAttributes.type', 'ShadowAttributes.category', 'ShadowAttributes.value1', 'ShadowAttributes.value2', 'ShadowAttributes.to_ids', 'ShadowAttributes.uuid', 'ShadowAttributes.event_uuid', 'ShadowAttributes.event_id', 'ShadowAttributes.old_id', 'ShadowAttributes.comment', 'ShadowAttributes.org_id', 'ShadowAttributes.proposal_to_delete', 'ShadowAttributes.timestamp', 'ShadowAttributes.first_seen', 'ShadowAttributes.last_seen'];
        $fieldsOrg = ['id', 'name', 'uuid', 'local'];
        $params = [
            'conditions' => $conditions,
            // 'recursive' => 0,
            'fields' => $fields,
            'contain' => [
                'ThreatLevel' => [
                    'fields' => ['ThreatLevel.name']
                ],
                'Attributes' => [
                    'fields' => $fieldsAtt,
                    'conditions' => $conditionsAttributes,
                ],
                'Objects' => [
                    'conditions' => $conditionsObjects,
                ],
                'ShadowAttributes' => [
                    'fields' => $fieldsShadowAtt,
                    'conditions' => $proposal_conditions,
                    'Org' => ['fields' => $fieldsOrg],
                ],
                'EventTags' => [
                    'Tags'
                ],
                'EventReports' => [
                    'conditions' => $conditionsEventReport,
                ],
                'CryptographicKeys' => []
            ]
        ];
        if (!empty($options['excludeLocalTags'])) {
            $params['contain']['EventTags']['conditions'] = [
                'EventTag.local' => 0
            ];
        }
        if ($flatten) {
            unset($params['contain']['Objects']);
        }
        if ($options['noEventReports']) {
            unset($params['contain']['EventReports']);
        }
        if ($options['noShadowAttributes']) {
            unset($params['contain']['ShadowAttributes']);
        }
        if ($options['metadata']) {
            unset($params['contain']['Attributes']);
            unset($params['contain']['ShadowAttributes']);
            unset($params['contain']['Objects']);
            unset($params['contain']['EventReports']);
        }
        if (!empty($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        if (!empty($options['page'])) {
            $params['page'] = $options['page'];
        }
        if (!empty($options['order'])) {
            $params['order'] = $this->findOrder(
                $options['order'],
                'Event',
                ['id', 'info', 'analysis', 'threat_level_id', 'distribution', 'timestamp', 'publish_timestamp']
            );
        }
        $results = $this->find('all', $params)->toArray();
        if (empty($results)) {
            return [];
        }

        $sharingGroupReferenceOnly = (bool)$options['sgReferenceOnly'];
        $sharingGroupData = $sharingGroupReferenceOnly ? [] : $this->__cacheSharingGroupData($user, $useCache);

        // Initialize classes that will be necessary during event fetching
        if ((!empty($options['includeDecayScore']) || !empty($options['includeScoresOnEvent']))) {
            $DecayingModelsTable = $this->fetchTable('DecayingModels');
        }
        if (
            $options['includeServerCorrelations'] &&
            (!$isSiteAdmin && $user['org_id'] != Configure::read('MISP.host_org_id') && !Configure::read('MISP.show_server_correlations_for_all_users', false))
        ) {
            $options['includeServerCorrelations'] = false; // not permission to see server correlations
        }
        if (($options['includeFeedCorrelations'] || $options['includeServerCorrelations'])) {
            $FeedsTable = $this->fetchTable('Feeds');
        }
        if (($options['enforceWarninglist'] || $options['includeWarninglistHits']) && !isset($WarninglistsTable)) {
            $WarninglistsTable = $this->fetchTable('Warninglists');
        }
        // Precache current user email
        $userEmails = empty($user['id']) ? [] : [$user['id'] => $user['email']];

        if (!$options['includeAllTags']) {
            $justExportableTags = true;
        } else {
            $justExportableTags = false;
        }

        $overrideLimit = !empty($options['overrideLimit']);

        if (!empty($options['allow_proposal_blocking']) && !Configure::read('MISP.proposals_block_attributes')) {
            $options['allow_proposal_blocking'] = false; // proposal blocking is not enabled
        }

        if (!$options['metadata']) {
            $this->__attachAttributeTags($results, $options['excludeLocalTags']);
        }

        if (!$options['metadata'] && !$flatten) {
            $this->__attachReferences($results);
        }

        foreach ($results as &$event) {
            /*
            // REMOVING THIS FOR NOW - users should see data they own, even if they're not in the sharing group.
            if ($event['distribution'] == 4 && !in_array($event['sharing_group_id'], $sgids)) {
                $LogsTable = $this->fetchTable('Logs');
                $LogsTable->create();
                $LogsTable->saveOrFailSilently(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Event',
                    'model_id' => $event['id'],
                    'email' => $user['email'],
                    'action' => 'fetchEvent',
                    'user_id' => $user['id'],
                    'title' => 'User was able to fetch the event but not the sharing_group it belongs to',
                    'change' => ''
                ));
                unset($results[$eventKey]); // Current user cannot access sharing_group associated to this event
                continue;
            }
            */
            if ($options['includeWarninglistHits'] || $options['enforceWarninglist']) {
                $eventWarnings = $WarninglistsTable->attachWarninglistToAttributes($event['Attribute']);
                $WarninglistsTable->attachWarninglistToAttributes($event['ShadowAttribute']);
                $event['warnings'] = $eventWarnings;
            }
            $event = $event->toArray();
            $this->__attachTags($event, $justExportableTags);
            $this->__attachGalaxies($event, $user, $options['excludeGalaxy'], $options['fetchFullClusters'], $options['fetchFullClusterRelationship']);
            $event = $this->Orgc->attachOrgs($event, $fieldsOrg);
            if (!$sharingGroupReferenceOnly && $event['sharing_group_id']) {
                if (isset($sharingGroupData[$event['sharing_group_id']])) {
                    $event['SharingGroup'] = $sharingGroupData[$event['sharing_group_id']];
                }
            }

            // Include information about event creator user email. This information is included for:
            // - users from event creator org
            // - site admins
            // In export, this information will be included in `event_creator_email` field for auditors of event creator org and site admins.
            $sameOrg = $event['orgc_id'] === $user['org_id'];
            if ($sameOrg || $user['Role']['perm_site_admin']) {
                if (!isset($userEmails[$event['user_id']])) {
                    $userEmails[$event['user_id']] = $this->User->get($event['user_id'])->email;
                }

                $userEmail = $userEmails[$event['user_id']];
                if ($sameOrg && $user['Role']['perm_audit'] || $user['Role']['perm_site_admin']) {
                    $event['event_creator_email'] = $userEmail;
                }
                $event['User']['email'] = $userEmail;
            }
            // Let's find all the related events and attach it to the event itself
            if ($options['includeEventCorrelations']) {
                $event['RelatedEvent'] = $this->getRelatedEvents($user, $event['id'], $sgids);
            }
            // Let's also find all the relations for the attributes - this won't be in the xml export though
            if (!empty($options['includeGranularCorrelations'])) {
                $event['RelatedAttribute'] = $this->getRelatedAttributes($user, $event['id']);
                if (!empty($options['includeRelatedTags'])) {
                    $event = $this->includeRelatedTags($event, $options);
                }
                //$event['RelatedShadowAttribute'] = $this->getRelatedAttributes($user, $event['id'], true);
            }
            if (!empty($options['includeScoresOnEvent'])) {
                // $event = $DecayingModelsTable->attachBaseScoresToEvent($user, $event);
                $event = $DecayingModelsTable->attachScoresToEvent($user, $event);
            }
            $shadowAttributeByOldId = [];
            if (!empty($event['ShadowAttribute'])) {
                if ($isSiteAdmin && $options['includeFeedCorrelations']) {
                    $event['ShadowAttribute'] = $FeedsTable->attachFeedCorrelations($event['ShadowAttribute'], $user, $event, $overrideLimit);
                }
                if ($options['includeServerCorrelations']) {
                    $event['ShadowAttribute'] = $FeedsTable->attachFeedCorrelations($event['ShadowAttribute'], $user, $event, $overrideLimit, 'Server');
                }

                if ($options['includeAttachments']) {
                    foreach ($event['ShadowAttribute'] as &$sa) {
                        if ($this->ShadowAttribute->typeIsAttachment($sa['type'])) {
                            $encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa);
                            $sa['data'] = $encodedFile;
                        }
                    }
                    unset($sa);
                }

                foreach ($event['ShadowAttribute'] as $sa) {
                    $shadowAttributeByOldId[$sa['old_id']][] = $sa;
                }
                // Assign just shadow attributes that are linked to event (that means they have old_id set to `0`)
                $event['ShadowAttribute'] = $shadowAttributeByOldId[0] ?? [];
            }
            if (!empty($event['Attribute'])) {
                if ($options['includeFeedCorrelations']) {
                    $event['Attribute'] = $FeedsTable->attachFeedCorrelations($event['Attribute'], $user, $event, $overrideLimit);
                }
                if ($options['includeServerCorrelations']) {
                    $event['Attribute'] = $FeedsTable->attachFeedCorrelations($event['Attribute'], $user, $event, $overrideLimit, 'Server');
                }
                $event = $this->__filterBlockedAttributesByTags($event, $options, $user);
                if (!$sharingGroupReferenceOnly) {
                    $event['Attribute'] = $this->__attachSharingGroups($event['Attribute'], $sharingGroupData);
                }

                if (!empty($options['includeGranularCorrelations'])) {
                    $event['Attribute'] = $this->Attributes->Correlation->attachCorrelationExclusion($event['Attribute']);
                }

                // move all object attributes to a temporary container
                $tempObjectAttributeContainer = [];
                foreach ($event['Attribute'] as $key => &$attribute) {
                    if ($options['enforceWarninglist'] && !empty($attribute['warnings'])) {
                        unset($event['Attribute'][$key]);
                        continue;
                    }
                    if ($attribute['category'] === 'Financial fraud') {
                        $attribute = $this->Attributes->attachValidationWarnings($attribute);
                    }
                    if ($options['includeAttachments'] && $this->Attributes->typeIsAttachment($attribute['type'])) {
                        $encodedFile = $this->Attributes->base64EncodeAttachment($attribute);
                        $attribute['data'] = $encodedFile;
                    }
                    if (!empty($options['includeDecayScore'])) {
                        if (isset($event['EventTag'])) { // include EventTags for score computation
                            $attribute['EventTag'] = $event['EventTag'];
                        }
                        $attribute = $DecayingModelsTable->attachScoresToAttribute($user, $attribute);
                        if (isset($event['EventTag'])) { // remove included EventTags
                            unset($attribute['EventTag']);
                        }
                    }
                    // If a shadowattribute can be linked to an attribute, link it to it
                    // This is to differentiate between proposals that were made to an attribute for modification and between proposals for new attributes
                    $attribute['ShadowAttribute'] = $shadowAttributeByOldId[$attribute['id']] ?? [];
                    if (!empty($options['allow_proposal_blocking'])) {
                        foreach ($attribute['ShadowAttribute'] as $sa) {
                            if ($sa['proposal_to_delete'] || $sa['to_ids'] == 0) {
                                unset($event['Attribute'][$key]);
                                continue 2;
                            }
                        }
                    }
                    if (!$flatten && $attribute['object_id'] != 0) {
                        $tempObjectAttributeContainer[$attribute['object_id']][] = $attribute;
                        unset($event['Attribute'][$key]);
                    }
                }
                $event['Attribute'] = array_values($event['Attribute']);
            }
            if (!empty($event['Object'])) {
                if (!$sharingGroupReferenceOnly) {
                    $event['Object'] = $this->__attachSharingGroups($event['Object'], $sharingGroupData);
                }
                foreach ($event['Object'] as &$objectValue) {
                    if (isset($tempObjectAttributeContainer[$objectValue['id']])) {
                        $objectValue['Attribute'] = $tempObjectAttributeContainer[$objectValue['id']];
                    }
                }
                unset($tempObjectAttributeContainer);
            }
            if (!$sharingGroupReferenceOnly && !empty($event['EventReport'])) {
                $event['EventReport'] = $this->__attachSharingGroups($event['EventReport'], $sharingGroupData);
            }
            if (empty($options['metadata']) && empty($options['noSightings'])) {
                $event['Sighting'] = $this->Sightings->attachToEvent($event, $user);
            }
            if ($options['includeSightingdb']) {
                $SightingdbsTable = $this->fetchTable('Sightingdbs');
                $event = $SightingdbsTable->attachToEvent($event, $user);
            }
        }
        if ($options['extended']) {
            foreach ($results as $k => $result) {
                $results[$k] = $this->__mergeExtensions($user, $result, $options);
            }
        }
        if ($options['extensionList']) {
            foreach ($results as $k => $result) {
                $results[$k] = $this->__fetchEventsExtendingEvent($user, $result, $options);
            }
        }
        return $results;
    }

    /**
     * Attach galaxy clusters to event and attributes.
     * @param array $event
     * @param array $user
     * @param bool $excludeGalaxy
     * @param bool $fetchFullCluster
     */
    private function __attachGalaxies(array &$event, array $user, $excludeGalaxy, $fetchFullCluster, $fetchFullRelationship = false)
    {
        $galaxyTags = [];
        $event['Galaxy'] = [];
        if (!$excludeGalaxy && isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                if ($eventTag['Tag']['is_galaxy']) {
                    $galaxyTags[$eventTag['Tag']['id']] = $eventTag['Tag']['name'];
                }
            }
        }
        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                $attribute['Galaxy'] = [];
                if (!$excludeGalaxy && isset($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $attributeTag) {
                        if ($attributeTag['Tag']['is_galaxy']) {
                            $galaxyTags[$attributeTag['Tag']['id']] = $attributeTag['Tag']['name'];
                        }
                    }
                }
            }
        }

        if ($excludeGalaxy || empty($galaxyTags)) {
            return;
        }

        $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
        $clusters = $GalaxyClustersTable->getClustersByTags($galaxyTags, $user, true, $fetchFullCluster, $fetchFullRelationship);

        if (empty($clusters)) {
            return;
        }

        $clustersByTagIds = array_column(array_column($clusters, 'GalaxyCluster'), null, 'tag_id');
        unset($clusters);
        if (isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                if (!$eventTag['Tag']['is_galaxy']) {
                    continue;
                }
                $tagId = $eventTag['Tag']['id'];
                if (isset($clustersByTagIds[$tagId])) {
                    $cluster = $clustersByTagIds[$tagId];
                    $galaxyId = $cluster['Galaxy']['id'];
                    $cluster['event_tag_id'] = $eventTag['id'];
                    $cluster['local'] = $eventTag['local'] ?? false;
                    $cluster['relationship_type'] = !empty($eventTag['relationship_type']) ? $eventTag['relationship_type'] : false;
                    if (isset($event['Galaxy'][$galaxyId])) {
                        unset($cluster['Galaxy']);
                        $event['Galaxy'][$galaxyId]['GalaxyCluster'][] = $cluster;
                    } else {
                        $event['Galaxy'][$galaxyId] = $cluster['Galaxy'];
                        unset($cluster['Galaxy']);
                        $event['Galaxy'][$galaxyId]['GalaxyCluster'] = [$cluster];
                    }
                }
            }
            $event['Galaxy'] = array_values($event['Galaxy']);
        }
        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                if (isset($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $attributeTag) {
                        if (isset($attributeTag['Tag']['is_galaxy']) && !$attributeTag['Tag']['is_galaxy']) {
                            continue;
                        }
                        $tagId = $attributeTag['Tag']['id'];
                        if (isset($clustersByTagIds[$tagId])) {
                            $cluster = $clustersByTagIds[$tagId];
                            $galaxyId = $cluster['Galaxy']['id'];
                            $cluster['attribute_tag_id'] = $attributeTag['id'];
                            $cluster['local'] = $attributeTag['local'] ?? false;
                            $cluster['relationship_type'] = !empty($attributeTag['relationship_type']) ? $attributeTag['relationship_type'] : false;
                            if (isset($attribute['Galaxy'][$galaxyId])) {
                                unset($cluster['Galaxy']);
                                $attribute['Galaxy'][$galaxyId]['GalaxyCluster'][] = $cluster;
                            } else {
                                $attribute['Galaxy'][$galaxyId] = $cluster['Galaxy'];
                                unset($cluster['Galaxy']);
                                $attribute['Galaxy'][$galaxyId]['GalaxyCluster'] = [$cluster];
                            }
                        }
                    }
                    $attribute['Galaxy'] = array_values($attribute['Galaxy']);
                }
            }
        }
    }

    private function __cacheRelatedEventTags($eventTagCache, array $relatedAttribute, $excludeLocalTags)
    {
        if (!isset($eventTagCache[$relatedAttribute['id']])) {
            $params = [
                'contain' => [
                    'Tag' => [
                        'fields' => [
                            'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.numerical_value'
                        ]
                    ]
                ],
                'recursive' => -1,
                'conditions' => [
                    'EventTag.event_id' => $relatedAttribute['id']
                ]
            ];
            if ($excludeLocalTags) {
                $params['conditions']['EventTag.local'] = 0;
            }
            $eventTags = $this->EventTag->find('all', $params);
            $eventTagCache[$relatedAttribute['id']] = [];
            foreach ($eventTags as $et) {
                if (!isset($eventTagCache[$relatedAttribute['id']][$et['Tag']['id']])) {
                    $eventTagCache[$relatedAttribute['id']][$et['Tag']['id']] = $et['Tag'];
                }
            }
        }
        return $eventTagCache;
    }

    private function includeRelatedTags(array $event, array $options)
    {
        $eventTagCache = [];
        $excludeLocalTags = !empty($options['excludeLocalTags']);
        foreach ($event['RelatedAttribute'] as $attributeId => $relatedAttributes) {
            $tags = [];
            foreach ($relatedAttributes as $relatedAttribute) {
                $eventTagCache = $this->__cacheRelatedEventTags($eventTagCache, $relatedAttribute, $excludeLocalTags);
                foreach ($eventTagCache[$relatedAttribute['id']] as $tagId => $tag) {
                    $tags[$tagId] = $tag;
                }
                $params = [
                    'contain' => [
                        'Tag' => [
                            'fields' => [
                                'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.numerical_value'
                            ]
                        ]
                    ],
                    'recursive' => -1,
                    'conditions' => [
                        'AttributeTags.attribute_id' => $relatedAttribute['attribute_id']
                    ]
                ];
                if ($excludeLocalTags) {
                    $params['conditions']['AttributeTags.local'] = 0;
                }
                $attributeTags = $this->Attributes->AttributeTags->find('all', $params);
                foreach ($attributeTags as $at) {
                    $tags[$at['Tag']['id']] = $at['Tag'];
                }
            }
            if (!empty($tags)) {
                $attributePos = false;
                foreach ($event['Attribute'] as $k => $attribute) {
                    if ($attribute['id'] == $attributeId) {
                        $attributePos = $k;
                        break;
                    }
                }
                $event['Attribute'][$attributePos]['RelatedTags'] = array_values($tags);
            }
        }
        return $event;
    }

    /**
     * @param array $user
     * @param array $event
     * @param array $options
     * @return array
     * @throws Exception
     */
    private function __fetchEventsExtendingEvent(array $user, array $event, array $options)
    {
        $extensions = $this->fetchEvent(
            $user,
            [
                'eventsExtendingUuid' => $event['uuid'],
                'sgReferenceOnly' => $options['sgReferenceOnly'],
                'metadata' => 1
            ]
        );
        $extensionList = [];
        foreach ($extensions as $extension) {
            $extensionList[] = [
                'id' => $extension['Event']['id'],
                'uuid' => $extension['Event']['uuid'],
                'info' => $extension['Event']['info'],
                'Orgc' => [
                    'id' => $extension['Orgc']['id'],
                    'uuid' => $extension['Orgc']['uuid'],
                    'name' => $extension['Orgc']['name']
                ]
            ];
        }
        $event['ExtendedBy'] = $extensionList;
        return $event;
    }

    /**
     * @param array $user
     * @param array $event
     * @param array $options
     * @return array
     * @throws Exception
     */
    private function __mergeExtensions(array $user, array $event, array $options)
    {
        $extensions = $this->fetchEvent(
            $user,
            [
                'eventsExtendingUuid' => $event['uuid'],
                'includeEventCorrelations' => $options['includeEventCorrelations'],
                'includeWarninglistHits' => $options['includeWarninglistHits'],
                'noShadowAttributes' => $options['noShadowAttributes'],
                'noEventReports' => $options['noEventReports'],
                'noSightings' => isset($options['noSightings']) ? $options['noSightings'] : null,
                'sgReferenceOnly' => $options['sgReferenceOnly'],
            ]
        );
        foreach ($extensions as $extensionEvent) {
            $eventMeta = [
                'id' => $extensionEvent['Event']['id'],
                'info' => $extensionEvent['Event']['info'],
                'orgc_id' => $extensionEvent['Event']['orgc_id'],
                'user_id' => $extensionEvent['Event']['user_id'],
                'Orgc' => [
                    'id' => $extensionEvent['Orgc']['id'],
                    'name' => $extensionEvent['Orgc']['name'],
                    'uuid' => $extensionEvent['Orgc']['uuid'],
                ],
            ];
            $event['extensionEvents'][$eventMeta['id']] = $eventMeta;
            $thingsToMerge = ['Attribute', 'Object', 'ShadowAttribute', 'Galaxy'];
            foreach ($thingsToMerge as $thingToMerge) {
                if (!isset($event[$thingToMerge])) {
                    $event[$thingToMerge] = [];
                }
                if (!isset($extensionEvent[$thingToMerge])) {
                    $extensionEvent[$thingToMerge] = [];
                }
                $event[$thingToMerge] = array_merge($event[$thingToMerge], $extensionEvent[$thingToMerge]);
            }
            // Merge event reports if requested
            if (!$options['noEventReports'] && isset($event['EventReport'])) {
                $event['EventReport'] = array_merge($event['EventReport'], $extensionEvent['EventReport']);
            }
            // Merge just tags that are not already in main event
            foreach ($extensionEvent['EventTag'] as $eventTag) {
                foreach ($event['EventTag'] as $eT) {
                    if ($eT['Tag']['id'] == $eventTag['Tag']['id']) {
                        continue 2; // tag already exists, skip
                    }
                }
                $event['EventTag'][] = $eventTag;
            }
            if ($options['includeEventCorrelations']) {
                // Merge just related events that are not already in main event
                foreach ($extensionEvent['RelatedEvent'] as $relatedEvent) {
                    foreach ($event['RelatedEvent'] as $rE) {
                        if ($rE['Event']['id'] == $relatedEvent['Event']['id']) {
                            continue 2; // event already exists, skip
                        }
                    }
                    $event['RelatedEvent'][] = $relatedEvent;
                }
            }
            if ($options['includeWarninglistHits']) {
                // Merge just event warninglist that are not already in main event
                foreach ($extensionEvent['warnings'] as $warninglistId => $warning) {
                    if (!isset($event['warnings'][$warninglistId])) {
                        $event['warnings'][$warninglistId] = $warning;
                    }
                }
            }
        }
        return $event;
    }

    private function __attachSharingGroups($data, $sharingGroupData)
    {
        foreach ($data as $k => $v) {
            if ($v['distribution'] == 4) {
                if (isset($sharingGroupData[$v['sharing_group_id']])) {
                    $data[$k]['SharingGroup'] = $sharingGroupData[$v['sharing_group_id']];
                } else {
                    unset($data[$k]); // current user could not fetch the sharing_group
                }
            }
        }
        return $data;
    }

    // Filter the attributes within an event based on the tag filter block rules
    private function __filterBlockedAttributesByTags($event, $options, $user)
    {
        if (!empty($options['blockedAttributeTags'])) {
            foreach ($options['blockedAttributeTags'] as $key => $blockedTag) {
                if (!is_numeric($blockedTag)) {
                    $options['blockedAttributeTags'][$key] = $this->EventTag->Tag->lookupTagIdFromName($blockedTag);
                } else {
                    $options['blockedAttributeTags'][$key] = $blockedTag;
                }
            }
        }
        if (!empty($user['Server']['push_rules'])) {
            $push_rules = json_decode($user['Server']['push_rules'], true);
            if (!empty($push_rules['tags']['NOT'])) {
                if (empty($options['blockedAttributeTags'])) {
                    $options['blockedAttributeTags'] = [];
                }
                $options['blockedAttributeTags'] = array_merge($options['blockedAttributeTags'], $push_rules['tags']['NOT']);
            }
        }
        if (!empty($options['blockedAttributeTags'])) {
            if (!empty($event['Attribute'])) {
                $event['Attribute'] = $this->__filterBlockedAttributesFromContainer($event['Attribute'], $options['blockedAttributeTags']);
            }
        }
        return $event;
    }

    // accepts an attribute array and a list of blocked tags. Returns the attribute array with the blocked attributes cleaned out.
    private function __filterBlockedAttributesFromContainer($container, $blockedTags)
    {
        foreach ($container as $key => $attribute) {
            if (!empty($attribute['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $at) {
                    if (in_array($at['tag_id'], $blockedTags)) {
                        unset($container[$key]);
                    }
                }
            }
        }
        $container = array_values($container);
        return $container;
    }

    public function set_filter_sharing_group(&$params, $conditions, $options)
    {
        if (!empty($params['sharinggroup'])) {
            $params['sharinggroup'] = $this->convert_filters($params['sharinggroup']);
            if ($options['scope'] === 'Attribute') {
                $conditions = $this->generic_add_filter($conditions, $params['sharinggroup'], ['Events.sharing_group_id', 'Attributes.sharing_group_id']);
            } else {
                $conditions = $this->generic_add_filter($conditions, $params['sharinggroup'], 'Events.sharing_group_id');
            }
        }
        return $conditions;
    }

    public function set_filter_orgc_id(&$params, $conditions, $options)
    {
        if (!empty($params['orgc_id'])) {
            $orgFilter = ['OR' => $params['orgc_id']];
            $conditions = $this->generic_add_filter($conditions, $orgFilter, 'Events.orgc_id');
        }
        return $conditions;
    }

    public function set_filter_org(&$params, $conditions, $options)
    {
        if (!empty($params['org'])) {
            $params['org'] = $this->convert_filters($params['org']);
            if (!empty($params['org']['OR'])) {
                foreach ($params['org']['OR'] as $k => $org) {
                    if (!is_numeric($org)) {
                        $existingOrg = $this->Orgc->find(
                            'all',
                            [
                                'recursive' => -1,
                                'conditions' => [
                                    'OR' => [
                                        'Orgc.name' => $org,
                                        'Orgc.uuid' => $org
                                    ]
                                ],
                                'fields' => ['Orgc.id']
                            ]
                        )->first();
                        if (empty($existingOrg)) {
                            $params['org']['OR'][$k] = -1;
                        } else {
                            $params['org']['OR'][$k] = $existingOrg['Orgc']['id'];
                        }
                    }
                }
            }
            if (!empty($params['org']['NOT'])) {
                $temp = [];
                foreach ($params['org']['NOT'] as $org) {
                    if (!is_numeric($org)) {
                        $existingOrg = $this->Orgc->find(
                            'all',
                            [
                                'recursive' => -1,
                                'conditions' => [
                                    'OR' => [
                                        'Orgc.name' => $org,
                                        'Orgc.uuid' => $org
                                    ]
                                ],
                                'fields' => ['Orgc.id']
                            ]
                        )->first();
                        if (!empty($existingOrg)) {
                            $temp[] = $existingOrg['Orgc']['id'];
                        }
                    } else {
                        $temp[] = $org;
                    }
                }
                if (!empty($temp)) {
                    $params['org']['NOT'] = $temp;
                } else {
                    unset($params['org']['NOT']);
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params['org'], 'Events.orgc_id');
        }
        return $conditions;
    }

    public function set_filter_eventid(&$params, $conditions, $options)
    {
        if (!empty($params['eventid']) && $params['eventid'] !== 'all') {
            $params['eventid'] = $this->convert_filters($params['eventid']);
            $keys = [
                'uuid' => 'uuid',
                'id' => 'id'
            ];
            $id_params = [];
            foreach ($params['eventid'] as $operand => $list) {
                foreach ($list as $id) {
                    if ($operand === 'OR') {
                        $id_params['AND']['OR'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    } else if ($operand === 'AND') {
                        $id_params['AND']['AND'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    } else {
                        $id_params['AND']['NOT'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    }
                }
            }
            $conditions['AND'][] = $id_params;
        }
        return $conditions;
    }

    public function set_filter_eventinfo(&$params, $conditions, $options)
    {
        if (!empty($params['eventinfo'])) {
            $params['eventinfo'] = $this->convert_filters($params['eventinfo']);
            $conditions = $this->generic_add_filter($conditions, $params['eventinfo'], 'Events.info');
        }
        return $conditions;
    }

    public function set_filter_uuid(&$params, $conditions, $options)
    {
        if ($options['scope'] === 'Event') {
            if (!empty($params['uuid'])) {
                $params['uuid'] = $this->convert_filters($params['uuid']);
                if (!empty($params['uuid']['OR'])) {
                    $subQueryOptions = [
                        'conditions' => ['Attributes.uuid' => $params['uuid']['OR']],
                        'fields' => ['event_id']
                    ];
                    $attributeSubquery = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'id');
                    $conditions['AND'][] = [
                        'OR' => [
                            'uuid' => $params['uuid']['OR'],
                            $attributeSubquery
                        ]
                    ];
                }
                if (!empty($params['uuid']['NOT'])) {
                    $subQueryOptions = [
                        'conditions' => ['Attributes.uuid' => $params['uuid']['NOT']],
                        'fields' => ['event_id']
                    ];
                    $attributeSubquery = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'id');
                    $conditions['AND'][] = [
                        'NOT' => [
                            'uuid' => $params['uuid']['NOT'],
                            $attributeSubquery
                        ]
                    ];
                }
            }
        } else {
            $conditions = $this->{$options['scope']}->set_filter_uuid($params, $conditions, $options);
        }
        return $conditions;
    }

    public function set_filter_mixed_id(&$params, $conditions, $options)
    {
        if (!empty($params['mixed_id'])) {
            $params['mixed_id'] = $this->convert_filters($params['mixed_id']);
            if (!empty($options['scope']) && $options['scope'] === 'Event') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'uuid');
            }
            if (!empty($options['scope']) && $options['scope'] === 'Attribute') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'Attributes.uuid');
            }
        }
        return $conditions;
    }

    public function set_filter_deleted(&$params, $conditions, $options)
    {
        if (!empty($params['deleted'])) {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            if ($params['deleted']) {
                $conditions = $this->generic_add_filter($conditions, $params['deleted'], $scope . '.deleted');
            }
        }
        return $conditions;
    }

    public function set_filter_to_ids(&$params, $conditions, $options)
    {
        if (isset($params['to_ids'])) {
            if ($params['to_ids'] === 'exclude') {
                $params['to_ids'] = 0;
            }
            $conditions['AND']['Attributes.to_ids'] = $params['to_ids'];
        }
        return $conditions;
    }

    public function set_filter_ignore(&$params, $conditions, $options)
    {
        if (empty($params['ignore'])) {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            if ($scope === 'Attribute') {
                $conditions['AND']['Attributes.to_ids'] = 1;
            } else {
                $conditions['AND']['Events.published'] = 1;
            }
        }
        return $conditions;
    }

    public function set_filter_published(&$params, $conditions, $options)
    {
        if (isset($params['published']) && $params['published'] !== [true, false]) {
            $conditions['AND']['Events.published'] = $params['published'];
        }
        return $conditions;
    }

    public function set_filter_threat_level_id(&$params, $conditions, $options)
    {
        if (isset($params['threat_level_id'])) {
            $conditions['AND']['Events.threat_level_id'] = $params['threat_level_id'];
        }
        return $conditions;
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        if (!empty($params['tags']) || !empty($params['event_tags'])) {
            $conditions = $this->Attributes->set_filter_tags($params, $conditions, $options);
        }
        return $conditions;
    }

    public function set_filter_type(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            if (!empty(Configure::read('MISP.attribute_filters_block_only'))) {
                if ($options['context'] === 'Event' && !empty($params[$options['filter']]['OR'])) {
                    unset($params[$options['filter']]['OR']);
                }
            }
            if (!empty($params[$options['filter']])) {
                foreach (['OR', 'NOT'] as $operator) {
                    if (
                        !empty($params[$options['filter']][$operator]) &&
                        (
                            in_array('email-src', $params[$options['filter']][$operator]) ||
                            in_array('email-dst', $params[$options['filter']][$operator])
                        ) && (
                            !in_array('email', $params[$options['filter']][$operator])
                        )
                    ) {
                        $params[$options['filter']][$operator][] = 'email';
                    }
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attributes.' . $options['filter']);
        }
        return $conditions;
    }


    public function set_filter_simple_attribute(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            if (!empty(Configure::read('MISP.attribute_filters_block_only'))) {
                if ($options['context'] === 'Event' && !empty($params[$options['filter']]['OR'])) {
                    unset($params[$options['filter']]['OR']);
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attributes.' . $options['filter']);
        }
        return $conditions;
    }

    public function set_filter_attribute_id(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attributes.' . $options['filter']);
        }
        return $conditions;
    }

    /**
     * @param string $value
     * @return string
     */
    private static function compressIpv6($value)
    {
        if (strpos($value, ':') && $converted = inet_pton($value)) {
            return inet_ntop($converted);
        }
        return $value;
    }

    public function set_filter_value(&$params, $conditions, $options)
    {
        if (!empty($params['value'])) {
            $params[$options['filter']] = $this->convert_filters($params['value']);
            foreach (['OR', 'AND', 'NOT'] as $operand) {
                if (!empty($params[$options['filter']][$operand])) {
                    foreach ($params[$options['filter']][$operand] as $k => $v) {
                        if ($operand === 'NOT') {
                            $v = mb_substr($v, 1);
                        }
                        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            $v = $this->compressIpv6($v);
                        }
                        $params[$options['filter']][$operand][$k] = $operand === 'NOT' ? '!' . $v : $v;
                    }
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params['value'], ['Attributes.value1', 'Attributes.value2']);
        }

        return $conditions;
    }

    public function set_filter_object_name(&$params, $conditions, $options)
    {
        if (!empty($params['object_name'])) {
            $params['object_name'] = $this->convert_filters($params['object_name']);
            $conditions = $this->generic_add_filter($conditions, $params['object_name'], 'Object.name');
        }
        return $conditions;
    }

    public function set_filter_object_template_uuid(&$params, $conditions, $options)
    {
        if (!empty($params['object_template_uuid'])) {
            $params['object_template_uuid'] = $this->convert_filters($params['object_template_uuid']);
            $conditions = $this->generic_add_filter($conditions, $params['object_template_uuid'], 'Object.template_uuid');
        }
        return $conditions;
    }

    public function set_filter_object_template_version(&$params, $conditions, $options)
    {
        if (!empty($params['object_template_version'])) {
            $params['object_template_version'] = $this->convert_filters($params['object_template_version']);
            $conditions = $this->generic_add_filter($conditions, $params['object_template_version'], 'Object.template_version');
        }
        return $conditions;
    }

    public function set_filter_comment(&$params, $conditions, $options)
    {
        if (!empty($params['comment'])) {
            $params['comment'] = $this->convert_filters($params['comment']);
            $conditions = $this->generic_add_filter($conditions, $params['comment'], 'Attributes.comment');
        }
        return $conditions;
    }

    public function set_filter_seen(&$params, $conditions, $options)
    {
        $f = $options['scope'] . '.' . $options['filter'];
        $conditions = $this->Attributes->setTimestampSeenConditions($params[$options['filter']], $conditions, $f);
        return $conditions;
    }

    /**
     * @param array $params
     * @param array $conditions
     * @param array $options
     * @return array
     */
    public function set_filter_timestamp(&$params, $conditions, $options)
    {
        if ($options['filter'] === 'from') {
            if (is_numeric($params['from'])) {
                $conditions['AND']['Events.date >='] = date('Y-m-d', $params['from']);
            } else {
                $conditions['AND']['Events.date >='] = $params['from'];
            }
        } elseif ($options['filter'] === 'to') {
            if (is_numeric($params['to'])) {
                $conditions['AND']['Events.date <='] = date('Y-m-d', $params['to']);
            } else {
                $conditions['AND']['Events.date <='] = $params['to'];
            }
        } else {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            $filters = [
                'timestamp' => [
                    $scope . '.timestamp'
                ],
                'publish_timestamp' => [
                    'Events.publish_timestamp'
                ],
                'last' => [
                    'Events.publish_timestamp'
                ],
                'event_timestamp' => [
                    'Events.timestamp'
                ],
                'attribute_timestamp' => [
                    'Attributes.timestamp'
                ],
            ];
            foreach ($filters[$options['filter']] as $f) {
                $conditions = $this->Attributes->setTimestampConditions($params[$options['filter']], $conditions, $f);
                if (!empty($options['pop'])) {
                    unset($params[$options['filter']]);
                }
            }
        }
        return $conditions;
    }

    public function set_filter_date(&$params, $conditions, $options)
    {
        $timestamp = $this->Attributes->setTimestampConditions($params[$options['filter']], $conditions, 'Events.date', true);
        if (!is_array($timestamp)) {
            $conditions['AND']['Events.date >='] = date('Y-m-d', $timestamp);
        } else {
            $conditions['AND']['Events.date >='] = date('Y-m-d', $timestamp[0]);
            $conditions['AND']['Events.date <='] = date('Y-m-d', $timestamp[1]);
        }
        return $conditions;
    }

    public function sendAlertEmailRouter($id, $user, $oldpublish = null)
    {
        if (Configure::read('MISP.block_old_event_alert')) {
            $oldest = time() - (Configure::read('MISP.block_old_event_alert_age') * 86400);
            $oldest_date = time() - (Configure::read('MISP.block_old_event_alert_by_date') * 86400);
            $event = $this->find(
                'all',
                [
                    'conditions' => ['id' => $id],
                    'recursive' => -1,
                    'fields' => ['Events.timestamp', 'Events.date']
                ]
            )->first();
            if (empty($event)) {
                return false;
            }
            if (!empty(Configure::read('MISP.block_old_event_alert_age')) && is_numeric(Configure::read('MISP.block_old_event_alert_age'))) {
                if (intval($event['timestamp']) < $oldest) {
                    return true;
                }
            }
            if (!empty(Configure::read('MISP.block_old_event_alert_by_date')) && is_numeric(Configure::read('MISP.block_old_event_alert_by_date'))) {
                if (strtotime($event['date']) < $oldest_date) {
                    return true;
                }
            }
        }
        if (Configure::read('MISP.block_event_alert') && Configure::read('MISP.block_event_alert_tag') && !empty(Configure::read('MISP.block_event_alert_tag'))) {
            $noAlertTag = Configure::read('MISP.block_event_alert_tag');
            $tagLen = strlen($noAlertTag);
            $event = $this->fetchEvent($user, ['eventid' => $id, 'includeAllTags' => true]);
            if (empty($event)) {
                return false;
            }
            foreach ($event[0]['EventTag'] as $k => $tag) {
                if (strcasecmp($noAlertTag, $tag['Tag']['name']) == 0) {
                    return true;
                }
            }
        }
        if (Configure::read('MISP.disable_emailing')) {
            $LogsTable = $this->fetchTable('Logs');
            $LogsTable->saveOrFailSilently(
                [
                    'org' => 'SYSTEM',
                    'model' => 'Event',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'publish',
                    'title' => 'E-mail alerts not sent out during publishing. Reason: Emailing is currently disabled on this instance.',
                    'change' => null,
                ]
            );
            return true;
        }
        $banStatus = $this->getEventRepublishBanStatus($id);
        $banStatusUser = $this->User->checkNotificationBanStatus($user);
        if ($banStatus['active'] || $banStatusUser['active']) {
            $logMessage = $banStatus['active'] ? $banStatus['message'] : $banStatusUser['message'];
            $banError = $banStatus['error'] || $banStatusUser['error'];
            $LogsTable = $this->fetchTable('Logs');
            $LogsTable->saveOrFailSilently(
                [
                    'org' => 'SYSTEM',
                    'model' => 'Event',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'publish',
                    'title' => __('E-mail alerts not sent out during publishing'),
                    'change' => $logMessage,
                ]
            );
            return !$banError;
        }
        if (Configure::read('MISP.background_jobs')) {
            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob($user, Job::WORKER_EMAIL, 'publish_alert_email', "Event: $id", 'Sending...');

            $args = [
                'alertemail',
                $user['id'],
                $jobId,
                $id,
            ];
            if ($oldpublish !== null) {
                $args[] = $oldpublish;
            }

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::EMAIL_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                $args,
                true,
                $jobId
            );

            return true;
        } else {
            return $this->sendAlertEmail($id, $user, $oldpublish);
        }
    }

    /**
     * @param int $id
     * @param array $senderUser Not used anymore.
     * @param int|null $oldpublish Timestamp of old publishing.
     * @param int|null $jobId
     * @return bool
     * @throws Exception
     */
    public function sendAlertEmail($id, array $senderUser, $oldpublish = null, $jobId = null)
    {
        $event = $this->find(
            'all',
            [
                'conditions' => ['id' => $id],
                'recursive' => -1,
            ]
        )->first();
        if (empty($event)) {
            throw new NotFoundException('Invalid Events.');
        }

        // Initialise the Job class if we have a background process ID
        // This will keep updating the process's progress bar
        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');
        }

        $NotificationLogsTable = $this->fetchTable('NotificationLogs');
        if (!$NotificationLogsTable->check($event['orgc_id'], 'publish')) {
            if ($jobId) {
                $JobsTable->saveStatus($jobId, true, __('Mails blocked by org alert threshold.'));
            }
            return true;
        }
        $userConditions = ['autoalert' => 1];
        $usersWithAccess = $this->User->getUsersWithAccess(
            $owners = [
                $event['orgc_id'],
                $event['org_id']
            ],
            $event['distribution'],
            $event['sharing_group_id'],
            $userConditions
        );

        $userCount = count($usersWithAccess);
        $metadataOnly = Configure::read('MISP.event_alert_metadata_only') || Configure::read('MISP.publish_alerts_summary_only');
        foreach ($usersWithAccess as $k => $user) {
            // Fetch event for user that will receive alert e-mail to respect all ACLs
            $eventForUser = $this->fetchEvent(
                $user,
                [
                    'eventid' => $id,
                    'includeAllTags' => true,
                    'includeEventCorrelations' => true,
                    'noEventReports' => true,
                    'noSightings' => true,
                    'metadata' => $metadataOnly,
                ]
            );
            if (empty($eventForUser)) {
                $JobsTable->saveProgress($jobId, null, $k / $userCount * 100);
                $this->loadLog()->createLogEntry($senderUser, 'alert', 'User', $user['id'], __('Something went wrong with alerting user #%s about event #%s. Sending was blocked due to insufficient access to the given Events.'));
                continue;
            }
            $eventForUser = $eventForUser[0];
            if ($this->User->UserSetting->checkPublishFilter($user, $eventForUser)) {
                $body = $this->prepareAlertEmail($eventForUser, $user, $oldpublish);
                $this->User->sendEmail(['User' => $user], $body, false, null);
            }
            if ($jobId) {
                $JobsTable->saveProgress($jobId, null, $k / $userCount * 100);
            }
        }

        if ($jobId) {
            $JobsTable->saveStatus($jobId, true, __('Mails sent.'));
        }
        return true;
    }

    /**
     * @param array $event
     * @param array $user E-mail receiver
     * @param int|null $oldpublish Timestamp of previous publishing.
     * @return SendEmailTemplate
     * @throws CakeException
     */
    public function prepareAlertEmail(array $event, array $user, $oldpublish = null)
    {
        if (Configure::read('MISP.extended_alert_subject')) {
            $subject = preg_replace("/\r|\n/", "", $event['info']);
            if (mb_strlen($subject) > 58) {
                $subject = mb_substr($subject, 0, 55) . '... - ';
            } else {
                $subject .= " - ";
            }
        } else {
            $subject = '';
        }

        if (Configure::read('MISP.threatlevel_in_email_subject') === false) {
            $threatLevel = '';
        } else {
            $threatLevel = $event['ThreatLevel']['name'] . " - ";
        }

        $subjMarkingString = $this->getEmailSubjectMarkForEvent($event);
        $subject = "[" . Configure::read('MISP.org') . " MISP] Event {$event['id']} - $subject$threatLevel" . strtoupper($subjMarkingString);

        $template = new SendEmailTemplate('alert');
        $template->set('event', $event);
        $template->set('user', $user);
        $template->set('oldPublishTimestamp', $oldpublish);
        $template->set('baseurl', $this->__getAnnounceBaseurl());
        $template->set('distributionLevels', $this->distributionLevels);
        $template->set('analysisLevels', $this->analysisLevels);
        $template->set('tlp', $subjMarkingString);
        $template->subject($subject);
        $template->referenceId("event-alert|{$event['id']}");

        $unsubscribeLink = $this->__getAnnounceBaseurl() . '/users/unsubscribe/' . $this->User->unsubscribeCode($user);
        $template->set('unsubscribe', $unsubscribeLink);
        $template->listUnsubscribe($unsubscribeLink);
        return $template;
    }

    /**
     * @param int $id Event ID
     * @param string $message Message that user want to send to event creator
     * @param bool $creator_only Should be contacted just event creator or all user from org owning given event?
     * @param array $user User that wanna know more
     * @return bool True if all e-mails was send correctly.
     * @throws Exception
     */
    public function sendContactEmail($id, $message, $creator_only, array $user)
    {
        // fetch the event as user that requested more information. So if creators will reply to that email, no data
        // that requestor could not access would be leaked.
        $event = $this->fetchEvent(
            $user,
            [
                'eventid' => $id,
                'includeAllTags' => true,
                'includeEventCorrelations' => true,
            ]
        );
        if (empty($event)) {
            throw new NotFoundException('Invalid Events.');
        }
        $event = $event[0];

        if (!$creator_only) {
            // Insert extra field here: alertOrg or something, then foreach all the org members
            // limit this array to users with contactalerts turned on!
            $orgMembers = [];
            $this->User->recursive = 0;
            $temp = $this->User->find(
                'all',
                [
                    'fields' => ['email', 'gpgkey', 'certif_public', 'contactalert', 'id', 'org_id', 'disabled'],
                    'conditions' => ['disabled' => 0, 'User.org_id' => $event['orgc_id']],
                    'recursive' => -1
                ]
            );
            foreach ($temp as $tempElement) {
                if ($tempElement['User']['contactalert'] || $tempElement['User']['id'] == $event['user_id']) {
                    array_push($orgMembers, $tempElement);
                }
            }
        } else {
            $temp = $this->User->find(
                'all',
                [
                    'conditions' => [
                        'User.id' => $event['user_id'],
                        'User.disabled' => 0,
                        'User.org_id' => $event['orgc_id'],
                    ],
                    'fields' => ['User.email', 'User.gpgkey', 'User.certif_public', 'User.id', 'User.disabled'],
                    'recursive' => -1
                ]
            )->first();
            if (!empty($temp)) {
                $orgMembers = [$temp];
            }
        }
        if (empty($orgMembers)) {
            return false;
        }
        $tplColorString = $this->getEmailSubjectMarkForEvent($event);
        $subject = "[" . Configure::read('MISP.org') . " MISP] Need info about event $id - " . strtoupper($tplColorString);
        $result = true;
        foreach ($orgMembers as $eventReporter) {
            $requestor = !empty($user['User']) ? $user : ['User' => $user];
            $reporterForEmailTemplate = !empty($eventReporter['User']) ? $eventReporter['User'] : $eventReporter;
            $body = $this->prepareContactAlertEmail($requestor, $reporterForEmailTemplate, $message, $event);
            $result = $this->User->sendEmail($eventReporter, $body, false, $subject, ['User' => $user]) && $result;
        }
        return $result;
    }

    /**
     * @param array $user
     * @param array $eventReporter
     * @param string $message
     * @param array $event
     * @return SendEmailTemplate
     */
    private function prepareContactAlertEmail(array $user, array $eventReporter, $message, array $event)
    {
        $template = new SendEmailTemplate('alert_contact');
        $template->set('event', $event);
        $template->set('requestor', $user);
        $template->set('message', $message);
        $template->set('user', $eventReporter);
        $template->set('baseurl', $this->__getAnnounceBaseurl());
        $template->set('distributionLevels', $this->distributionLevels);
        $template->set('analysisLevels', $this->analysisLevels);
        $template->set('contactAlert', true);
        $template->set('tlp', $this->getEmailSubjectMarkForEvent($event));
        return $template;
    }

    /**
     * @param array $element
     * @param array $user
     * @param bool|false $server
     * @return array
     */
    public function captureSGForElement($element, $user, $server = false)
    {
        if (isset($element['SharingGroup'])) {
            $sg = $this->SharingGroup->captureSG($element['SharingGroup'], $user, $server);
            unset($element['SharingGroup']);
        } elseif (isset($element['sharing_group_id'])) {
            $sg = $this->SharingGroup->checkIfAuthorised($user, $element['sharing_group_id']) ? $element['sharing_group_id'] : false;
        } else {
            $sg = false;
        }
        if ($sg === false) {
            $sg = 0;
            $element['distribution'] = 0;
        }
        $element['sharing_group_id'] = $sg;
        return $element;
    }

    /**
     * When we receive an event via REST, we might end up with organisations, sharing groups, tags that we do not know
     * or which we need to update. All of that is controlled in this method.
     * @param array $event
     * @param array $user
     * @param array|false $server
     * @return array
     * @throws Exception
     */
    private function __captureObjects(array $event, array $user, $server = false)
    {
        // First we need to check whether the event or any attributes are tied to a sharing group and whether the user is even allowed to create the sharing group / is part of it
        if (isset($event['distribution']) && $event['distribution'] == 4) {
            $event = $this->captureSGForElement($event, $user, $server);
        }

        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $k => $a) {
                unset($event['Attribute'][$k]['id']);
                if (isset($a['distribution']) && $a['distribution'] == 4) {
                    $event['Attribute'][$k] = $this->captureSGForElement($a, $user, $server);
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $k => $o) {
                if (isset($o['distribution']) && $o['distribution'] == 4) {
                    $event['Object'][$k] = $this->captureSGForElement($o, $user, $server);
                }
                if (!empty($o['Attribute'])) {
                    foreach ($o['Attribute'] as $k2 => $a) {
                        if (isset($a['distribution']) && $a['distribution'] == 4) {
                            $event['Object'][$k]['Attribute'][$k2] = $this->captureSGForElement($a, $user, $server);
                        }
                    }
                }
            }
        }

        // first we want to see how the creator organisation is encoded
        // The options here are either by passing an organisation object along or simply passing a string along
        if (isset($event['Orgc'])) {
            $event['orgc_id'] = $this->Orgc->captureOrg($event['Orgc'], $user);
            unset($event['Orgc']);
        } elseif (isset($event['orgc'])) {
            $event['orgc_id'] = $this->Orgc->captureOrg($event['orgc'], $user);
            unset($event['orgc']);
        } else {
            $event['orgc_id'] = $user['org_id'];
        }

        $event_tag_ids = [];
        $capturedTags = []; // cache captured tag
        $eventTags = [];
        if (isset($event['EventTag'])) {
            if (isset($event['EventTag']['id'])) {
                $event['EventTag'] = [$event['EventTag']];
            }
            foreach ($event['EventTag'] as $tag) {
                $tagId = $this->captureTagWithCache($tag['Tag'], $user, $capturedTags);
                if ($tagId && !in_array($tagId, $event_tag_ids)) {
                    $eventTags[] = [
                        'tag_id' => $tagId,
                        'local' => isset($tag['local']) ? $tag['local'] : 0,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    ];
                    $event_tag_ids[] = $tagId;
                }
            }
        }
        if (isset($event['Tag'])) {
            if (isset($event['Tag']['name'])) {
                $event['Tag'] = [$event['Tag']];
            }
            foreach ($event['Tag'] as $tag) {
                $tag_id = $this->captureTagWithCache($tag, $user, $capturedTags);
                if ($tag_id && !in_array($tag_id, $event_tag_ids)) {
                    $eventTags[] = [
                        'tag_id' => $tag_id,
                        'local' => isset($tag['local']) ? $tag['local'] : 0,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    ];
                    $event_tag_ids[] = $tag_id;
                }
            }
            unset($event['Tag']);
        }
        $event['EventTag'] = $eventTags;

        if (!empty($event['Attribute'])) {
            $event['Attribute'] = $this->__captureAttributeTags($event['Attribute'], $user, $capturedTags);
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $k => $object) {
                if (!empty($object['Attribute'])) {
                    $event['Object'][$k]['Attribute'] = $this->__captureAttributeTags($object['Attribute'], $user, $capturedTags);
                }
            }
        }
        return $event;
    }

    /**
     * @param array $tag
     * @param array $user
     * @param array $capturedTags
     * @return false|int
     * @throws Exception
     */
    public function captureTagWithCache(array $tag, array $user, array &$capturedTags)
    {
        $tagName = $tag['name'];
        if (isset($capturedTags[$tagName])) {
            $tagId = $capturedTags[$tagName];
        } else {
            $tagId = $this->Attributes->AttributeTags->Tags->captureTag($tag, $user);
            if ($tagId) {
                $tagId = (int)$tagId;
                $capturedTags[$tagName] = $tagId;
            }
        }
        return $tagId;
    }

    /**
     * Capture tags for attributes and replace tags just by IDs
     * @param array $attributes
     * @param array $user
     * @param array $capturedTags
     * @return array
     * @throws Exception
     */
    private function __captureAttributeTags(array $attributes, array $user, array &$capturedTags)
    {
        foreach ($attributes as $k => $a) {
            $attributeTags = [];
            if (isset($a['AttributeTag'])) {
                if (isset($a['AttributeTag']['id'])) {
                    $a['AttributeTag'] = [$a['AttributeTag']];
                }
                foreach ($a['AttributeTag'] as $tag) {
                    $attributeTags[] = [
                        'tag_id' => $this->captureTagWithCache($tag['Tag'], $user, $capturedTags),
                        'local' => isset($tag['local']) ? $tag['local'] : 0,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    ];
                }
            }
            if (isset($a['Tag'])) {
                if (isset($a['Tag']['name'])) {
                    $a['Tag'] = [$a['Tag']];
                }
                foreach ($a['Tag'] as $tag) {
                    $tagId = $this->captureTagWithCache($tag, $user, $capturedTags);
                    if ($tagId) {
                        $attributeTags[] = [
                            'tag_id' => $tagId,
                            'local' => isset($tag['local']) ? $tag['local'] : 0,
                            'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                        ];
                    }
                }
                unset($attributes[$k]['Tag']);
            }
            $attributes[$k]['AttributeTag'] = $attributeTags;
        }
        return $attributes;
    }

    /**
     * @param array $event
     * @return bool
     */
    private function checkEventBlockRules(array $event)
    {
        if (!isset($this->eventBlockRule)) {
            $AdminSettingsTable = $this->fetchTable('AdminSettings');
            $setting = $AdminSettingsTable->getSetting('eventBlockRule');
            $this->eventBlockRule = $setting ? json_decode($setting, true) : false;
        }
        if (empty($this->eventBlockRule)) {
            return true;
        }
        if (!empty($this->eventBlockRule['tags'])) {
            if (!is_array($this->eventBlockRule['tags'])) {
                $this->eventBlockRule['tags'] = [$this->eventBlockRule['tags']];
            }
            $eventTags = Hash::extract($event, 'Events.Tag.{n}.name');
            if (empty($eventTags)) {
                $eventTags = Hash::extract($event, 'Events.EventTag.{n}.Tag.name');
            }
            if (!empty($eventTags)) {
                foreach ($this->eventBlockRule['tags'] as $blockTag) {
                    if (in_array($blockTag, $eventTags)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * @param array $user
     * @param string $data
     * @param bool $isXml
     * @param bool $takeOwnership
     * @param bool $publish
     * @return array[]
     * @throws Exception
     */
    public function addMISPExportFile(array $user, $data, $isXml = false, $takeOwnership = false, $publish = false)
    {
        if (empty($data)) {
            throw new Exception("File is empty");
        }

        if ($isXml) {
            $dataArray = Xml::toArray(Xml::build($data));
        } else {
            $dataArray = $this->jsonDecode($data);
            if (isset($dataArray['response'][0])) {
                foreach ($dataArray['response'] as $k => $temp) {
                    $dataArray['Event'][] = $temp['Event'];
                }
                unset($dataArray['response']);
            }
        }
        // In case we receive an event that is not encapsulated in a response. This should never happen (unless it's a copy+paste fail),
        // but just in case, let's clean it up anyway.
        if (isset($dataArray['Event'])) {
            $dataArray['response']['Event'] = $dataArray['Event'];
        } elseif (!isset($dataArray['response'])) {
            // Accept an event not containing the `Event` key
            $dataArray['response']['Event'] = $dataArray;
        }
        unset($dataArray['Event']);
        if (!isset($dataArray['response']) || !isset($dataArray['response']['Event'])) {
            $exception = $isXml ? __('This is not a valid MISP XML file.') : __('This is not a valid MISP JSON file.');
            throw new Exception($exception);
        }
        $dataArray = $this->updateXMLArray($dataArray);
        $eventsToAdd = isset($dataArray['response']['Event'][0]) ? $dataArray['response']['Event'] : [$dataArray['response']['Event']];
        $results = [];
        $validationIssues = [];
        foreach ($eventsToAdd as $event) {
            if ($takeOwnership) {
                $event['orgc_id'] = $user['org_id'];
                unset($event['Orgc']);
            }
            $event = ['Event' => $event];
            $created_id = 0;
            $event['locked'] = 1;
            $event['published'] = $publish;
            $result = $this->_add($event, true, $user, '', null, false, null, $created_id, $validationIssues);
            $results[] = [
                'info' => $event['info'],
                'result' => $result,
                'id' => $created_id,
                'validationIssues' => $validationIssues,
            ];
        }
        return $results;
    }

    /**
     * Low level function to add an Event based on an Event $data array.
     *
     * @param array $data
     * @param bool $fromXml
     * @param array $user
     * @param int $org_id
     * @param int|null $passAlong Server ID or null
     * @param bool $fromPull
     * @param int|null $jobId
     * @param int $created_id
     * @param array $validationErrors
     * @return bool|int|string True when new event was created, int when event with the same uuid already exists, string when validation errors
     * @throws Exception
     */
    public function _add(array &$data, $fromXml, array $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = [])
    {
        if (Configure::read('MISP.enableEventBlocklisting') !== false && isset($data['Event']['uuid'])) {
            $EventBlocklistsTable = $this->fetchTable('EventBlocklists');

            if ($EventBlocklistsTable->isBlocked($data['Event']['uuid'])) {
                return 'Blocked by blocklist';
            }
        }
        if (!$this->checkEventBlockRules($data)) {
            return 'Blocked by event block rules';
        }
        $breakOnDuplicate = !empty($data['Event']['breakOnDuplicate']);
        if (empty($data['Event']['Attribute']) && empty($data['Event']['Object']) && !empty($data['Event']['published']) && empty($data['Event']['EventReport'])) {
            $validationErrors['Event'] = 'Received a published event that was empty. Event add process blocked.';
            $this->loadLog()->createLogEntry($user, 'add', 'Event', 0, $validationErrors['Event']);
            return json_encode($validationErrors);
        }
        // force check userid and orgname to be from yourself
        $data['Event']['user_id'] = $user['id'];

        if ($fromPull) {
            $data['Event']['org_id'] = $org_id;
        } else {
            $data['Event']['org_id'] = $user['Organisation']['id'];
        }
        // set these fields if the event is freshly created and not pushed from another instance.
        // Moved out of if (!$fromXML), since we might get a restful event without the orgc/timestamp set
        if (!isset($data['Event']['orgc_id']) && !isset($data['Event']['orgc'])) {
            $data['Event']['orgc_id'] = $data['Event']['org_id'];
        } else {
            $orgc_id = $data['Event']['orgc_id'] ?? null;
            $orgc_uuid = $data['Event']['Orgc']['uuid'] ?? null;
            if (!$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                if ($orgc_uuid != $user['Organisation']['uuid'] && $orgc_id != $user['org_id']) {
                    throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
                }
            }
        }
        if (!Configure::check('MISP.enableOrgBlocklisting') || Configure::read('MISP.enableOrgBlocklisting') !== false) {
            if (!isset($data['Event']['Orgc']['uuid'])) {
                $orgc = $data['Event']['orgc_id'];
            } else {
                $orgc = $data['Event']['Orgc']['uuid'];
            }
            $OrgBlocklistsTable = $this->fetchTable('OrgBlocklists');
            if ($OrgBlocklistsTable->isBlocked($orgc)) {
                $OrgBlocklistsTable->saveEventBlocked($orgc);
                return 'blocked';
            }
        }
        if ($passAlong) {
            $ServersTable = $this->fetchTable('Servers');
            $server = $ServersTable->find(
                'all',
                [
                    'conditions' => [
                        'id' => $passAlong
                    ],
                    'recursive' => -1,
                    'fields' => [
                        'name',
                        'id',
                        'unpublish_event',
                        'publish_without_email',
                        'internal',
                        'url',
                        'remote_org_id',
                    ]
                ]
            )->first();
        } else {
            $server['Server']['internal'] = false;
        }
        if ($fromXml) {
            // Workaround for different structure in XML/array than what CakePHP expects
            $data = $this->cleanupEventArrayFromXML($data);
        }
        unset($data['Event']['id']);
        if (
            (Configure::read('MISP.block_publishing_for_same_creator', false) && !$user['Role']['perm_sync']) ||
            (isset($data['Event']['published']) && $data['Event']['published'] && $user['Role']['perm_publish'] == 0)
        ) {
            $data['Event']['published'] = 0;
        }
        if (isset($data['Event']['uuid'])) {
            // check if the uuid already exists
            $existingEvent = $this->find(
                'all',
                [
                    'conditions' => ['uuid' => $data['Event']['uuid']],
                    'fields' => ['id'],
                    'recursive' => -1,
                ]
            )->first();
            if ($existingEvent) {
                // RESTful, set response location header so client can find right URL to edit
                if ($fromPull) {
                    return false;
                }
                if ($fromXml) {
                    $created_id = $existingEvent['id'];
                }
                return $existingEvent['id'];
            }
        }
        if ($fromXml) {
            $data['Event'] = $this->__captureObjects($data['Event'], $user, $server);
        }
        $fieldList = [
            'org_id',
            'orgc_id',
            'date',
            'threat_level_id',
            'analysis',
            'info',
            'user_id',
            'published',
            'uuid',
            'timestamp',
            'distribution',
            'sharing_group_id',
            'locked',
            'disable_correlation',
            'extends_uuid',
            'protected'
        ];

        $eventEntity = $this->newEntity($data['Event'], ['fieldList' => $fieldList]);

        $saveResult = $this->saveOrFail($eventEntity, ['associated' => []]);
        if ($saveResult) {
            if ($jobId) {
                /** @var EventLocksTable $EventLocksTable */
                $EventLocksTable = $this->fetchTable('EventLocks');
                $EventLocksTable->insertLockBackgroundJob($eventEntity->id, $jobId);
            }

            if ($passAlong) {
                if ($server['publish_without_email'] == 0) {
                    $st = "enabled";
                } else {
                    $st = "disabled";
                }
                $logTitle = 'Event pulled from Server (' . $server['id'] . ') - "' . $server['name'] . '" - Notification by mail ' . $st;
                $this->loadLog()->createLogEntry($user, 'add', 'Event', $saveResult['id'], $logTitle);
            }
            if (!empty($data['Event']['EventTag'])) {
                $toSave = [];
                foreach ($data['Event']['EventTag'] as $et) {
                    $et['event_id'] = $eventEntity->id;
                    $toSave[] = $et;
                }
                $eventTagEntity = $this->EventTags->newEntities($toSave);
                if (!$this->EventTags->saveMany($eventTagEntity, ['validate' => true])) {
                    $this->log("Could not save tags when capturing event with ID {$eventEntity->id}.", LOG_WARNING);
                } else if (!empty($this->EventTag->validationErrors)) {
                    $this->log("Could not save some tags when capturing event with ID {$eventEntity->id}: " . json_encode($this->EventTag->validationErrors), LOG_WARNING);
                }
            }
            $parentEvent = $this->find(
                'all',
                [
                    'conditions' => ['id' => $eventEntity->id],
                    'recursive' => -1
                ]
            )->first();
            if (!empty($data['Event']['Attribute'])) {
                $attributeHashes = [];
                foreach ($data['Event']['Attribute'] as $attribute) {
                    if (!empty($attribute['deleted'])) {
                        $this->Attributes->captureAttribute($attribute, $eventEntity->id, $user, 0, null, $parentEvent);
                    } else {
                        $attributeHash = sha1($attribute['value'] . '|' . $attribute['type'] . '|' . $attribute['category'], true);
                        if (!isset($attributeHashes[$attributeHash])) { // do not save duplicate values
                            $attributeHashes[$attributeHash] = true;
                            $this->Attributes->captureAttribute($attribute, $eventEntity->id, $user, 0, null, $parentEvent);
                        }
                    }
                }
                unset($attributeHashes);
            }

            if (!empty($data['Event']['Object'])) {
                $referencesToCapture = [];
                foreach ($data['Event']['Object'] as $object) {
                    $result = $this->Objects->captureObject($object, $eventEntity->id, $user, false, $breakOnDuplicate, $parentEvent);
                    if (isset($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $objectRef) {
                            $objectRef['source_uuid'] = $object['uuid'];
                            $referencesToCapture[] = $objectRef;
                        }
                    }
                }
                foreach ($referencesToCapture as $referenceToCapture) {
                    $result = $this->Objects->ObjectReference->captureReference(
                        $referenceToCapture,
                        $eventEntity->id
                    );
                    if ($result !== true) {
                        $title = "Could not save object reference when capturing event with ID {$eventEntity->id}";
                        $this->loadLog()->validationError($user, 'add', 'ObjectReference', $title, $result, $referenceToCapture);
                    }
                }
            }
            if (!empty($data['Event']['EventReport'])) {
                foreach ($data['Event']['EventReport'] as $report) {
                    $result = $this->EventReport->captureReport($user, $report, $eventEntity->id);
                }
            }

            // capture new keys, update existing, remove those no longer in the pushed data
            if (!empty($data['Event']['CryptographicKey'])) {
                $this->CryptographicKey->captureCryptographicKeyUpdate(
                    $user,
                    $data['Event']['CryptographicKey'],
                    $eventEntity->id,
                    'Event'
                );
            }

            // zeroq: check if sightings are attached and add to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting->captureSightings($data['Sighting'], null, $eventEntity->id, $user);
            }
            if ($fromXml) {
                $created_id = $eventEntity->id;
            }
            $workflowResult = $this->afterAddWorkflow($eventEntity->id, $fromPull);
            if (is_array($workflowResult)) {
                return implode(', ', $workflowResult);
            }
            if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
                // do the necessary actions to publish the event (email, upload,...)
                if (('true' != Configure::read('MISP.disablerestalert')) && (empty($server) || empty($server['Server']['publish_without_email']))) {
                    $this->sendAlertEmailRouter($eventEntity->id, $user);
                }
                $this->publish($eventEntity->id, $passAlong);
            }
            if (empty($data['Event']['locked']) && !empty(Configure::read('MISP.default_event_tag_collection'))) {
                $TagCollectionsTable = $this->fetchTable('TagCollections');
                $tagCollection = $TagCollectionsTable->fetchTagCollection($user, ['conditions' => ['TagCollection.id' => Configure::read('MISP.default_event_tag_collection')]]);
                if (!empty($tagCollection)) {
                    $tag_id_list = [];
                    foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                        $tag_id_list[] = $tagCollectionTag['tag_id'];
                    }
                    foreach ($tag_id_list as $tag_id) {
                        $tag = $this->EventTag->Tag->find(
                            'all',
                            [
                                'conditions' => ['Tag.id' => $tag_id],
                                'recursive' => -1,
                                'fields' => ['Tag.name']
                            ]
                        )->first();
                        if (!empty($tag)) {
                            $found = $this->EventTag->find(
                                'all',
                                [
                                    'conditions' => [
                                        'event_id' => $eventEntity->id,
                                        'tag_id' => $tag_id
                                    ],
                                    'recursive' => -1,
                                ]
                            )->first();
                            if (empty($found)) {
                                $this->EventTag->create();
                                if ($this->EventTag->save(['event_id' => $eventEntity->id, 'tag_id' => $tag_id])) {
                                    $this->loadLog()->createLogEntry($user, 'tag', 'Event', $eventEntity->id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to event (' . $eventEntity->id . ')', 'Event (' . $eventEntity->id . ') tagged as Tag (' . $tag_id . ')');
                                }
                            }
                        }
                    }
                }
            }
            if ($jobId) {
                $this->EventLock->deleteBackgroundJobLock($eventEntity->id, $jobId);
            }

            return true;
        } else {
            $validationErrors['Event'] = $eventEntity->getErrors();
            return json_encode($validationErrors);
        }
    }

    /**
     * @param int $eventId
     * @param bool $fromPull
     * @return true|array
     */
    private function afterAddWorkflow($eventId, $fromPull)
    {
        $triggerId = $fromPull ? 'event-after-save-new-from-pull' : 'event-after-save-new';
        if (!$this->isTriggerCallable($triggerId)) {
            return true;
        }

        $userForWorkflow = $this->User->getAuthUser(Configure::read('CurrentUserId'), true);
        $userForWorkflow['Role']['perm_site_admin'] = 1;

        $fullSavedEvent = $this->fetchEvent(
            $userForWorkflow,
            [
                'eventid' => $eventId,
                'includeAttachments' => 1
            ]
        )[0];
        $workflowErrors = [];
        $logging = [
            'model' => 'Event',
            'action' => 'add',
            'id' => $eventId,
        ];
        $success = $this->executeTrigger($triggerId, $fullSavedEvent, $workflowErrors, $logging);
        if (!$success) {
            return $workflowErrors;
        }
        return true;
    }

    public function _edit(array &$data, array $user, $id = null, $jobId = null, $passAlong = null, $force = false, $fast_update = false)
    {
        $data = $this->cleanupEventArrayFromXML($data);
        // reposition to get the Events.id with given uuid
        if (isset($data['Event']['uuid'])) {
            $conditions = ['uuid' => $data['Event']['uuid']];
        } elseif ($id) {
            $conditions = ['id' => $id];
        } else {
            throw new InvalidArgumentException("No event UUID or ID provided.");
        }
        $existingEvent = $this->find('all', ['conditions' => $conditions, 'recursive' => -1])->first();
        if ($passAlong) {
            $ServersTable = $this->fetchTable('Servers');
            $server = $ServersTable->find(
                'all',
                [
                    'conditions' => [
                        'Server.id' => $passAlong
                    ],
                    'recursive' => -1,
                    'fields' => [
                        'Server.name',
                        'Server.id',
                        'Server.unpublish_event',
                        'Server.publish_without_email',
                        'Server.internal',
                        'Server.remove_missing_tags'
                    ]
                ]
            )->first();
        } else {
            $server['Server']['internal'] = false;
        }
        // If the event exists...
        if (!empty($existingEvent)) {
            $data['id'] = $existingEvent['id'];
            $id = $existingEvent['id'];
            // Conditions affecting all:
            // user.org == Events.org
            // edit timestamp newer than existing event timestamp
            if ($force || !isset($data['timestamp']) || $data['timestamp'] > $existingEvent['timestamp']) {
                if (!isset($data['timestamp'])) {
                    $data['timestamp'] = time();
                }
                if (isset($data['distribution']) && $data['distribution'] == 4) {
                    if (!isset($data['SharingGroup'])) {
                        if (!isset($data['sharing_group_id'])) {
                            return ['error' => 'Event could not be saved: Sharing group chosen as the distribution level, but no sharing group specified. Make sure that the event includes a valid sharing_group_id or change to a different distribution level.'];
                        }
                        if (!$this->SharingGroup->checkIfAuthorised($user, $data['sharing_group_id'])) {
                            return ['error' => 'Event could not be saved: Invalid sharing group or you don\'t have access to that sharing group.'];
                        }
                    } else {
                        $data['sharing_group_id'] = $this->SharingGroup->captureSG($data['SharingGroup'], $user, $server);
                        unset($data['SharingGroup']);
                        if ($data['sharing_group_id'] === false) {
                            return ['error' => 'Event could not be saved: User not authorised to create the associated sharing group.'];
                        }
                    }
                }
                // If the above is true, we have two more options:
                // For users that are of the creating org of the event, always allow the edit
                // For users that are sync users, only allow the edit if the event is locked
                if (
                    $existingEvent['orgc_id'] === $user['org_id']
                    || ($user['Role']['perm_sync'] && $existingEvent['locked']) || $user['Role']['perm_site_admin']
                ) {
                    if ($user['Role']['perm_sync']) {
                        if (isset($data['distribution']) && $data['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $data['sharing_group_id'])) {
                            return ['error' => 'Event could not be saved: The sync user has to have access to the sharing group in order to be able to edit it.'];
                        }
                    }
                } else {
                    return ['error' => 'Event could not be saved: The user used to edit the event is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the event whilst also not being a site administrator.'];
                }
            } else {
                return ['error' => 'Event could not be saved: Event in the request not newer than the local copy.'];
            }
            $changed = false;
            // If a field is not set in the request, just reuse the old value
            // Also, compare the event to the existing event and see whether this is a meaningful change
            $recoverFields = ['analysis', 'threat_level_id', 'info', 'distribution', 'date', 'org_id'];
            foreach ($recoverFields as $rF) {
                if (!isset($data[$rF])) {
                    $data[$rF] = $existingEvent[$rF];
                } else {
                    if ($data[$rF] != $existingEvent[$rF]) {
                        $changed = true;
                    }
                }
            }
        } else {
            return ['error' => 'Event could not be saved: Could not find the local Events.'];
        }
        if (
            (Configure::read('MISP.block_publishing_for_same_creator', false) && !$user['Role']['perm_sync'] && $user['id'] == $existingEvent['user_id']) ||
            (!empty($data['published']) && !$user['Role']['perm_publish'])
        ) {
            $data['published'] = 0;
        }
        if (!isset($data['published'])) {
            $data['published'] = 0;
        }
        $fieldList = [
            'date',
            'threat_level_id',
            'analysis',
            'info',
            'published',
            'uuid',
            'distribution',
            'timestamp',
            'sharing_group_id',
            'disable_correlation',
            'extends_uuid'
        ];

        $this->patchEntity($existingEvent, $data, ['fieldList' => $fieldList, 'validate' => 'update']);
        $saveResult = $this->save($existingEvent);
        if (empty($saveResult->getErrors())) {
            if ($jobId) {
                /** @var EventLock $eventLock */
                $EventLocksTable = $this->fetchTable('EventLocks');
                $EventLocksTable->insertLockBackgroundJob($data['id'], $jobId);
            }
            $validationErrors = [];

            // capture new keys, update existing, remove those no longer in the pushed data
            if (!empty($data['CryptographicKey'])) {
                $this->CryptographicKey->captureCryptographicKeyUpdate(
                    $user,
                    $data['CryptographicKey'],
                    $existingEvent['id'],
                    'Event'
                );
            }
            if (isset($data['Attribute'])) {
                $data['Attribute'] = array_values($data['Attribute']);
                $attributes = [];
                foreach ($data['Attribute'] as $k => $attribute) {
                    $nothingToChange = false;
                    $result = $this->Attributes->editAttribute($attribute, $saveResult, $user, 0, false, $force, $nothingToChange, $server);
                    if (is_array($result)) {
                        $attributes[] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
                $this->Attributes->editAttributeBulk($attributes, $saveResult, $user);
            }
            if (isset($data['Object'])) {
                $data['Object'] = array_values($data['Object']);
                foreach ($data['Object'] as $object) {
                    $nothingToChange = false;
                    $result = $this->Objects->editObject($object, $saveResult, $user, false, $force, $nothingToChange);
                    if ($result !== true) {
                        $validationErrors['Object'][] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
                foreach ($data['Object'] as $object) {
                    if (isset($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $objectRef) {
                            $nothingToChange = false;
                            $objectRef['source_uuid'] = $object['uuid'];
                            $result = $this->Objects->ObjectReference->captureReference($objectRef, $existingEvent->id);
                            if ($result !== true) {
                                $title = "Could not save object reference when capturing event with ID {$existingEvent->id}";
                                $this->loadLog()->validationError($user, 'edit', 'ObjectReference', $title, $result, $objectRef);
                            }
                            if ($result && !$nothingToChange) {
                                $changed = true;
                            }
                        }
                    }
                }
            }
            if (isset($data['EventReport'])) {
                foreach ($data['EventReport'] as $report) {
                    $nothingToChange = false;
                    $result = $this->EventReport->editReport($user, ['EventReport' => $report], $existingEvent->id, true, $nothingToChange);
                    if (!empty($result)) {
                        $validationErrors['EventReport'][] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
            }
            if (isset($data['Tag']) && $user['Role']['perm_tagger']) {
                foreach ($data['Tag'] as $tag) {
                    $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                    if ($tag_id) {
                        $nothingToChange = false;
                        $tag['id'] = $tag_id;
                        $result = $this->EventTag->handleEventTag($existingEvent->id, $tag, $nothingToChange);
                        if ($result && !$nothingToChange) {
                            $changed = true;
                        }
                    } else {
                        // If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
                        // However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
                        // In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
                        if ($user['Role']['perm_tag_editor']) {
                            $this->loadLog()->createLogEntry($user, 'edit', 'Event', $existingEvent->id, "Failed create or attach Tag {$tag['name']} to the Events.");
                        }
                    }
                }
            }
            // zeroq: if sightings then attach to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting->captureSightings($data['Sighting'], null, $existingEvent->id, $user);
            }
            // if published -> do the actual publishing
            if ($changed && (!empty($data['published']) && 1 == $data['published'])) {
                // The edited event is from a remote server ?
                if ($passAlong) {
                    $st = $server['Server']['publish_without_email'] == 0 ? 'enabled' : 'disabled';
                    $logTitle = 'Event edited from Server (' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '" - Notification by mail ' . $st;
                } else {
                    $logTitle = 'Event edited (locally)';
                }
                $this->loadLog()->createLogEntry($user, 'add', 'Event', $saveResult['id'], $logTitle);
                // do the necessary actions to publish the event (email, upload,...)
                if ((true != Configure::read('MISP.disablerestalert')) && (empty($server) || empty($server['Server']['publish_without_email']))) {
                    $this->sendAlertEmailRouter($id, $user, $existingEvent['publish_timestamp']);
                }
                $this->publish($existingEvent['id'], $passAlong);
            }
            if ($jobId) {
                $EventLocksTable->deleteBackgroundJobLock($data['id'], $jobId);
            }
            return true;
        }
        return $existingEvent->getErrors();
    }

    // format has to be:
    // array('Event' => array(), 'Attribute' => array('ShadowAttribute' => array()), 'EventTag' => array(), 'ShadowAttribute' => array());
    public function savePreparedEvent($event)
    {
        unset($event['id']);
        $eventEntity = $this->newEntity($event);
        $this->save($eventEntity);
        $event['id'] = $eventEntity->id;
        $objects = ['Attribute', 'ShadowAttribute', 'EventTag', 'Object'];
        foreach ($objects as $object_type) {
            if (!empty($event[$object_type])) {
                $saveMethod = '__savePrepared' . $object_type;
                foreach ($event[$object_type] as $object) {
                    $this->$saveMethod($object, $event);
                }
            }
        }
        if (!empty($event['Object'])) {
            $objectRefTypes = ['Attribute', 'Object'];
            foreach ($event['Object'] as $k => $object) {
                foreach ($object['ObjectReference'] as $k2 => $objectRef) {
                    $savedObjectRef = $this->Objects->ObjectReference->find(
                        'all',
                        [
                            'recursive' => -1,
                            'conditions' => ['ObjectReference.uuid' => $objectRef['uuid']]
                        ]
                    )->first();
                    $objectRefType = intval($savedObjectRef['ObjectReference']['referenced_type']);
                    $element = $this->{$objectRefTypes[$objectRefType]}->find(
                        'all',
                        [
                            'conditions' => [$objectRefTypes[$objectRefType] . '.uuid' => $objectRef['referenced_uuid']],
                            'recursive' => -1,
                            'fields' => [$objectRefTypes[$objectRefType] . '.id']
                        ]
                    )->first();
                    $savedObjectRef['ObjectReference']['referenced_id'] = $element[$objectRefTypes[$objectRefType]]['id'];
                    $result = $this->Objects->ObjectReference->save($savedObjectRef);
                }
            }
        }
        return $event['id'];
    }

    private function __savePreparedAttribute(&$attribute, $event, $object_id = 0)
    {
        unset($attribute['id']);
        $attribute['event_id'] = $event['id'];
        $attribute['object_id'] = $object_id;
        $this->Attributes->create();
        $this->Attributes->save($attribute);
        foreach ($attribute['ShadowAttribute'] as $k => $sa) {
            $this->__savePreparedShadowAttribute($sa, $event, $this->Attributes->id);
        }
        foreach ($attribute['AttributeTag'] as $k => $at) {
            $this->__savePreparedAttributeTag($at, $event, $this->Attributes->id);
        }
        return true;
    }

    private function __savePreparedObject(&$object, $event)
    {
        unset($object['id']);
        $object['event_id'] = $event['id'];
        $this->Objects->create();
        $this->Objects->save($object);
        foreach ($object['Attribute'] as $k => $a) {
            $this->__savePreparedAttribute($a, $event, $object->id);
        }
        foreach ($object['ObjectReference'] as $objectRef) {
            $this->__savePreparedObjectReference($objectRef, $event, $object->id, $object['uuid']);
        }
        return true;
    }

    #referenced IDs have to be updated after everything else is done!
    private function __savePreparedObjectReference($objectRef, $event, $object_id, $object_uuid)
    {
        unset($objectRef['id']);
        $objectRef['event_id'] = $event['id'];
        $objectRef['object_id'] = $object_id;
        $objectRef['object_uuid'] = $object_uuid;
        $this->Objects->ObjectReference->create();
        $this->Objects->ObjectReference->save($objectRef);
        return true;
    }

    private function __savePreparedShadowAttribute($shadow_attribute, $event, $old_id = 0)
    {
        unset($shadow_attribute['id']);
        $shadow_attribute['event_id'] = $event['id'];
        $shadow_attribute['old_id'] = $old_id;
        $this->ShadowAttribute->create();
        $this->ShadowAttribute->save($shadow_attribute);
        return true;
    }

    private function __savePreparedEventTag($event_tag, $event)
    {
        unset($event_tag['id']);
        $event_tag['event_id'] = $event['id'];
        $this->EventTag->create();
        $this->EventTag->save($event_tag);
        return true;
    }

    private function __savePreparedAttributeTag($attribute_tag, $event, $attribute_id)
    {
        unset($attribute_tag['id']);
        $attribute_tag['event_id'] = $event['id'];
        $attribute_tag['attribute_id'] = $attribute_id;
        $this->Attributes->AttributeTags->create();
        $this->Attributes->AttributeTags->save($attribute_tag);
        return true;
    }

    // pass an event or an attribute together with the server id.
    // If the distribution of the object outright allows for it to be shared, return true
    // If the distribution is org only / comm only, return false
    // If the distribution is sharing group only, check if the sync user is in the sharing group or not, return true if yes, false if no
    public function checkDistributionForPush($object, $server, $context = 'Event')
    {
        $model = $context;
        if ($context === 'Sighting') {
            $model = 'Event';
        }
        if (empty(Configure::read('MISP.host_org_id')) || !$server['internal'] || Configure::read('MISP.host_org_id') != $server['remote_org_id']) {
            if ($context != 'Sighting' && $object['distribution'] < 2) {
                return false;
            }
        }
        if ($object['distribution'] == 4) {
            if ($context === 'Event' || $context === 'Sighting') {
                return $this->SharingGroup->checkIfServerInSG($object['SharingGroup'], $server);
            } else {
                return $this->SharingGroup->checkIfServerInSG($object[$context]['SharingGroup'], $server);
            }
        }
        return true;
    }

    /**
     * New variant of uploadEventToServersRouter (since 2.4.137) for pushing sightings.
     * @param array $event with event tags and whole sharing group
     * @param null|int $passAlong Server ID that should be skipped from uploading.
     * @param array $sightingsUuidsToPush
     * @return array|bool
     * @throws Exception
     */
    private function uploadEventSightingsToServersRouter(array $event, $passAlong, array $sightingsUuidsToPush)
    {
        $ServersTable = $this->fetchTable('Servers');
        $conditions = ['Server.push_sightings' => 1];
        if ($passAlong) {
            $conditions[] = ['Server.id !=' => $passAlong];
        }
        $servers = $ServersTable->find(
            'all',
            [
                'conditions' => $conditions,
                'contain' => ['RemoteOrg'], // remote org required for checkDistributionForPush
                'recursive' => -1,
                'order' => ['Server.priority ASC', 'Server.id ASC'],
            ]
        );
        // TODO: This are new conditions, that was not used in old code
        // Filter out servers that do not match server conditions for event push
        $servers = $ServersTable->eventFilterPushableServers($event, $servers);
        // Filter out servers that do not match event sharing group distribution for event push
        $servers = array_filter(
            $servers,
            function (array $server) use ($event) {
                return $this->checkDistributionForPush($event, $server, 'Sighting');
            }
        );
        if (empty($servers)) {
            return true;
        }

        $failedServers = [];
        foreach ($servers as $server) {
            $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
            try {
                try {
                    if ($serverSync->eventExists($event) === false) {
                        continue; // skip if event not exists on remote server
                    }
                } catch (Exception $e) {
                }

                $this->pushSightingsToServer($serverSync, $event, $sightingsUuidsToPush);
            } catch (Exception $e) {
                $this->logException("Uploading sightings to server {$server['id']} failed.", $e);
                $failedServers[] = $server['url'];
            }
        }
        if (!empty($failedServers)) {
            return $failedServers;
        }
        return true;
    }

    /**
     * @param ServerSyncTool $serverSync
     * @param array $event
     * @param array $sightingsUuidsToPush
     * @throws HttpSocketJsonException
     * @throws Exception
     */
    private function pushSightingsToServer(ServerSyncTool $serverSync, array $event, array $sightingsUuidsToPush = [])
    {
        $fakeSyncUser = [
            'org_id' => $serverSync->server()['Server']['remote_org_id'],
            'Role' => [
                'perm_site_admin' => 0,
            ],
        ];

        // Process sightings in batch to keep memory requirements low
        foreach ($this->Sighting->fetchUuidsForEventToPush($event, $fakeSyncUser, $sightingsUuidsToPush) as $batch) {
            // Filter out sightings that already exists on remote server
            $existingSightings = $serverSync->filterSightingUuidsForPush($event, $batch);
            $newSightings = array_diff($batch, $existingSightings);
            if (empty($newSightings)) {
                continue;
            }

            $conditions = ['Sighting.uuid' => $newSightings];
            $sightings = $this->Sighting->attachToEvent($event, $fakeSyncUser, null, $conditions, true);
            $serverSync->uploadSightings($sightings, $event['uuid']);
        }
    }

    /**
     * @param int $id Event ID
     * @param int|null $passAlong ID of server that event will be not pushed
     * @return array|bool
     * @throws Exception
     */
    private function uploadEventToServersRouter($id, $passAlong = null)
    {
        $eventOrgcId = $this->find(
            'all',
            [
                'conditions' => ['id' => $id],
                'recursive' => -1,
                'fields' => ['Events.orgc_id']
            ]
        )->first();
        // we create a fake site admin user object to fetch the event with everything included
        // This replaces the old method of manually just fetching everything, staying consistent
        // with the fetchEvent() output
        $elevatedUser = [
            'Role' => [
                'perm_site_admin' => 1,
                'perm_sync' => 1,
                'perm_audit' => 0,
            ],
            'org_id' => $eventOrgcId['orgc_id']
        ];
        $event = $this->fetchEvent($elevatedUser, ['eventid' => $id, 'metadata' => 1]);
        if (empty($event)) {
            return true;
        }
        $event = $event[0];
        $event['locked'] = 1;
        // get a list of the servers
        $ServersTable = $this->fetchTable('Servers');
        $conditions = ['push' => 1];
        if ($passAlong) {
            $conditions[] = ['Servers.id !=' => $passAlong];
        }
        $servers = $ServersTable->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1,
                'contain' => ['RemoteOrg', 'Organisations'],
                'order' => ['Servers.priority ASC', 'Servers.id ASC'],
            ]
        );
        // iterate over the servers and upload the event
        if (empty($servers)) {
            return true;
        }
        $uploaded = true;
        $failedServers = [];

        foreach ($servers as $server) {
            if (
                (!isset($server['internal']) || !$server['internal']) && $event['distribution'] < 2
            ) {
                continue;
            }
            // Skip servers where the event has come from.
            if ($passAlong != $server['id']) {
                $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
                $params = [
                    'eventid' => $id,
                    'includeAttachments' => true,
                    'includeAllTags' => true,
                    'deleted' => [0, 1],
                    'excludeGalaxy' => 1,
                    'noSightings' => true, // sightings are pushed separately
                ];
                if (!empty($server['push_rules'])) {
                    $pushRules = json_decode($server['push_rules'], true);
                    if (!empty($pushRules['tags']['NOT'])) {
                        $params['blockedAttributeTags'] = $pushRules['tags']['NOT'];
                    }
                }
                if (!empty($server['internal'])) {
                    $params['excludeLocalTags'] = 0;
                }
                $event = $this->fetchEvent($elevatedUser, $params);
                $event = $event[0];
                $event['locked'] = 1;

                $fakeSyncUser = [
                    'org_id' => $server['remote_org_id'],
                    'Role' => [
                        'perm_site_admin' => 0
                    ]
                ];
                // TODO: We are pushing galaxy clusters to remove server even if event is not pushable to that server
                $ServersTable->syncGalaxyClusters($serverSync, $server, $fakeSyncUser, $technique = $event['id'], $event = $event);
                $thisUploaded = $this->uploadEventToServer($event, $server, $serverSync);
                if ($thisUploaded === 'Success') {
                    try {
                        $this->pushSightingsToServer($serverSync, $event); // push sighting by method that check for duplicates
                    } catch (Exception $e) {
                        $this->logException("Uploading sightings to server {$server['id']} failed.", $e);
                    }
                }
                if (isset($this->data['ShadowAttribute'])) {
                    $ServersTable->syncProposals(null, $server, null, $id, $this);
                }
                if (!$thisUploaded) {
                    $uploaded = !$uploaded ? $uploaded : $thisUploaded;
                    $failedServers[] = $server['url'];
                }
            }
        }
        if (!$uploaded) {
            if (empty($failedServers)) {
                return true;
            }
            return $failedServers;
        }
        return true;
    }

    /**
     * @param int $id Event ID
     * @param array $user
     * @param int|null $passAlong Server ID that should be skipped when pushing sightings.
     * @param array $sightingUuids Push just sightings with these UUIDs
     * @return array|bool
     * @throws Exception
     */
    public function publishSightingsRouter($id, array $user, $passAlong = null, array $sightingUuids = [])
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $message = empty($sightingUuids) ? __('Publishing sightings.') : __('Publishing %s sightings.', count($sightingUuids));
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'publish_event', "Event ID: $id", $message);

            $args = ['publish_sightings', $id, $passAlong, $jobId, $user['id']];
            if (!empty($sightingUuids)) {
                $args[] = $this->getBackgroundJobsTool()->enqueueDataFile($sightingUuids);
            }

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                $args,
                true,
                $jobId
            );
        }

        return $this->publishSightings($id, $passAlong, $sightingUuids);
    }

    public function publishRouter($id, $passAlong, $user)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob($user, Job::WORKER_PRIO, 'publish_event', "Event ID: $id", 'Publishing.');

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'publish',
                    $id,
                    $passAlong,
                    $jobId,
                    $user['id']
                ],
                true,
                $jobId
            );
        }
        return $this->publish($id, $passAlong);
    }

    /**
     * @param int|string $id Event ID or UUID
     * @param $passAlong
     * @param array $sightingsUuidsToPush
     * @return array|bool
     * @throws Exception
     */
    public function publishSightings($id, $passAlong = null, array $sightingsUuidsToPush = [])
    {
        if (is_numeric($id)) {
            $condition = ['id' => $id];
        } else {
            $condition = ['uuid' => $id];
        }
        $event = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => $condition,
                'contain' => ['EventTag', 'SharingGroup' => ['SharingGroupServer', 'SharingGroupOrg' => ['Organisation']]],
            ]
        )->first();
        if (empty($event)) {
            return false;
        }

        // update the DB to set the sightings timestamp
        // for background jobs, this should be done already
        $fieldList = ['sighting_timestamp'];
        $data = [
            'sighting_timestamp' => time(),
        ];
        $event['skip_zmq'] = 1;
        $event['skip_kafka'] = 1;

        $this->patchEntity($event, $data, ['fieldList' => $fieldList]);

        return $this->uploadEventSightingsToServersRouter($event, $passAlong, $sightingsUuidsToPush);
    }

    // Performs all the actions required to publish an event
    public function publish($id, $passAlong = null, $jobId = null)
    {
        $event = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['id' => $id]
            ]
        )->first();

        if (empty($event)) {
            return false;
        }
        $hostOrg = $this->Org->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => [
                    'id' => Configure::read('MISP.host_org_id')
                ],
            ]
        )->first();
        if (empty($hostOrg)) {
            $hostOrg = $this->Org->find(
                'all',
                [
                    'recursive' => -1,
                    'order' => ['id ASC']
                ]
            )->first();
        }
        $userForPubSub = [
            'id' => 0,
            'org_id' => $hostOrg['id'],
            'Role' => ['perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 1],
            'Organisation' => $hostOrg
        ];
        $allowZMQ = Configure::read('Plugin.ZeroMQ_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
        $allowKafka = Configure::read('Plugin.Kafka_enable') &&
            Configure::read('Plugin.Kafka_event_publish_notifications_enable') &&
            !empty($kafkaTopic);
        $triggerCallable = $this->isTriggerCallable('event-publish');

        if ($allowZMQ || $allowKafka || $triggerCallable) {
            $currentUserId = Configure::read('CurrentUserId');
            $userForWorkflow = $this->User->getAuthUser($currentUserId, true);
            $userForWorkflow['Role']['perm_site_admin'] = 1;
            $fullEvent = $this->fetchEvent(
                $userForWorkflow,
                [
                    'eventid' => $id,
                    'includeAttachments' => 1
                ]
            );
        }
        if ($triggerCallable) {
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => 'publish',
                'id' => $id,
                'message' => __('Publishing stopped by a blocking workflow.'),
            ];
            $success = $this->executeTrigger('event-publish', $fullEvent[0], $workflowErrors, $logging);
            if (empty($success)) {
                $errorMessage = implode(', ', $workflowErrors);

                return $errorMessage;
            }
        }
        if ($jobId) {
            $this->Behaviors->unload('SysLogLogable.SysLogLogable');
        } else {
            // update the DB to set the published flag
            // for background jobs, this should be done already
            $fieldList = ['published', 'publish_timestamp'];
            $data = [
                'published' => 1,
                'publish_timestamp' => time(),
            ];
            $event['skip_zmq'] = 1;
            $event['skip_kafka'] = 1;

            $this->patchEntity($event, $data, ['fieldList' => $fieldList, 'validate' => 'publish']);
            $this->save($event);
        }
        if ($allowZMQ) {
            $this->publishEventToZmq($id, $userForPubSub, $fullEvent);
        }
        if ($allowKafka) {
            $this->publishEventToKafka($id, $userForPubSub, $fullEvent, $kafkaTopic);
        }
        return $this->uploadEventToServersRouter($id, $passAlong);
    }

    // Sends out an email to all people within the same org with the request to be contacted about a specific Events.
    public function sendContactEmailRouter($id, $message, $creator_only, $user)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $user,
                Job::WORKER_EMAIL,
                'contact_alert',
                'Owner ' . ($creator_only ? 'user' : 'org') . ' of event #' . $id,
                'Contacting.'
            );

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::EMAIL_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'contactemail',
                    $id,
                    $message,
                    $creator_only,
                    $user['id'],
                    $jobId
                ],
                true,
                $jobId
            );

            return true;
        } else {
            return $this->sendContactEmail($id, $message, $creator_only, $user);
        }
    }

    public function reportValidationIssuesEvents()
    {
        $this->Behaviors->detach('Regexp');
        // get all events..
        $events = $this->find('all', ['recursive' => -1]);
        // for all events..
        $result = [];
        $k = 0;
        $i = 0;
        foreach ($events as $k => $event) {
            $this->set($event);
            if (!$this->validates()) {
                $errors = $this->validationErrors;
                $result[$i]['id'] = $event['id'];
                $result[$i]['error'] = $errors;
                $result[$i]['details'] = $event;
                $i++;
            }
        }
        return [$result, $k];
    }

    // check two version strings. If version 1 is older than 2, return -1, if they are the same return 0, if version 2 is older return 1
    public function compareVersions($version1, $version2)
    {
        $version1Array = explode('.', $version1);
        $version2Array = explode('.', $version2);

        if ($version1Array[0] != $version2Array[0]) {
            if ($version1Array[0] > $version2Array[0]) {
                return 1;
            } else {
                return -1;
            }
        }
        if ($version1Array[1] != $version2Array[1]) {
            if ($version1Array[1] > $version2Array[1]) {
                return 1;
            } else {
                return -1;
            }
        }
        if ($version1Array[2] != $version2Array[2]) {
            if ($version1Array[2] > $version2Array[2]) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    // main dispatch method for updating an incoming xmlArray - pass xmlArray to all of the appropriate transformation methods to make all the changes necessary to save the imported event
    public function updateXMLArray($xmlArray, $response = true)
    {
        if (isset($xmlArray['xml_version']) && $response) {
            $xmlArray['response']['xml_version'] = $xmlArray['xml_version'];
            unset($xmlArray['xml_version']);
        }

        if (!$response) {
            $xmlArray = ['response' => $xmlArray];
        }
        // if a version is set, it must be at least 2.2.0 - check the version and save the result of the comparison
        if (isset($xmlArray['response']['xml_version'])) {
            $version = $this->compareVersions($xmlArray['response']['xml_version'], $this->mispVersion);
        } else {
            // if no version is set, set the version to older (-1) manually
            $version = -1;
        }
        // same version, proceed normally
        if ($version != 0) {
            // The xml is from an instance that is newer than the local instance, let the user know that the admin needs to upgrade before it could be imported
            if ($version == 1) {
                throw new Exception('This XML file is from a MISP instance that is newer than the current instance. Please contact your administrator about upgrading this instance.');
            }

            // if the xml contains an event or events from an older MISP instance, let's try to upgrade it!
            // Let's manually set the version to something below 2.2.0 if there is no version set in the xml
            if (!isset($xmlArray['response']['xml_version'])) {
                $xmlArray['response']['xml_version'] = '2.1.0';
            }

            // Upgrade from versions below 2.2.0 will need to replace the risk field with threat level id
            if ($this->compareVersions($xmlArray['response']['xml_version'], '2.2.0') < 0) {
                if ($response) {
                    $xmlArray['response'] = $this->__updateXMLArray220($xmlArray['response']);
                } else {
                    $xmlArray = $this->__updateXMLArray220($xmlArray);
                }
            }
        }
        unset($xmlArray['response']['xml_version']);
        if ($response) {
            return $xmlArray;
        } else {
            return $xmlArray['response'];
        }
    }

    // replaces the old risk value with the new threat level id
    private function __updateXMLArray220($xmlArray)
    {
        $risk = ['Undefined' => 4, 'Low' => 3, 'Medium' => 2, 'High' => 1];
        if (isset($xmlArray['Event'][0])) {
            foreach ($xmlArray['Event'] as &$event) {
                if (!isset($event['threat_level_id'])) {
                    $event['threat_level_id'] = $risk[$event['risk']];
                }
            }
        } else {
            if (!isset($xmlArray['Event']['threat_level_id']) && isset($xmlArray['Event']['risk'])) {
                $xmlArray['Event']['threat_level_id'] = $risk[$xmlArray['Event']['risk']];
            }
        }
        return $xmlArray;
    }

    // expects a date string in the YYYY-MM-DD format
    // returns the passed string or false if the format is invalid
    // based on the fix provided by stevengoosensB
    public function dateFieldCheck($date)
    {
        // regex check for from / to field by stevengoossensB
        return (preg_match('/^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|1[0-9]|2[0-9]|3[01])$/', $date)) ? $date : false;
    }

    /**
     * @param array $attribute
     * @param array $correlatedAttributes
     * @param array $correlatedShadowAttributes
     * @param array $filterType
     * @param array $sightingsData
     * @return array|null
     */
    private function __prepareAttributeForView(
        $attribute,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType,
        $sightingsData
    ) {
        $attribute['objectType'] = 'attribute';

        if ($filterType) {
            $include = true;
            /* proposal */
            if ($filterType['proposal'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['ShadowAttribute'])) { // `include only`
                $include = $include && ($filterType['proposal'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['proposal'] == 2);
            }

            /* correlation */
            if ($filterType['correlation'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($correlatedAttributes[$attribute['id']])) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
            }

            if ($filterType['correlationId'] && $include) {
                $include = false;
                if (isset($correlatedAttributes[$attribute['id']])) {
                    foreach ($correlatedAttributes[$attribute['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            /* feed */
            if ($filterType['feed'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Feed'])) { // `include only`
                $include = $include && ($filterType['feed'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['feed'] == 2);
            }

            /* server */
            if ($filterType['server'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Server'])) { // `include only`
                $include = $include && ($filterType['server'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['server'] == 2);
            }

            /* sightings */
            if ($filterType['sighting'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($sightingsData['data'][$attribute['id']])) { // `include only`
                $include = $include && ($filterType['sighting'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['sighting'] == 2);
            }

            /* TypeGroupings */
            if (
                $filterType['attributeFilter'] !== 'all'
                && isset(Attribute::TYPE_GROUPINGS[$filterType['attributeFilter']])
                && !in_array($attribute['type'], Attribute::TYPE_GROUPINGS[$filterType['attributeFilter']], true)
            ) {
                return null;
            }

            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['warnings']) || !empty($attribute['validationIssue'])) { // `include only`
                $include = $include && ($filterType['warning'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['warning'] == 2);
            }

            if ($filterType['warninglistId'] && $include) {
                $include = false;
                if (isset($attribute['warnings'])) {
                    foreach ($attribute['warnings'] as $warning) {
                        if (in_array($warning['warninglist_id'], $filterType['warninglistId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            if (!$include) {
                return null;
            }
        }

        if (!empty($attribute['ShadowAttribute'])) {
            $temp = [];
            foreach ($attribute['ShadowAttribute'] as $proposal) {
                $result = $this->__prepareProposalForView($proposal, $correlatedShadowAttributes, $filterType);
                if ($result) {
                    $temp[] = $result;
                }
            }
            $attribute['ShadowAttribute'] = $temp;
        }
        return $this->__prepareGenericForView($attribute);
    }

    /**
     * @param array $proposal
     * @param array $correlatedShadowAttributes
     * @param array $filterType
     * @return array|null
     */
    private function __prepareProposalForView($proposal, $correlatedShadowAttributes, $filterType = false)
    {
        if ($proposal['proposal_to_delete']) {
            $proposal['objectType'] = 'proposal_delete';
        } else {
            $proposal['objectType'] = 'proposal';
        }

        $include = true;
        if ($filterType) {
            $include = $filterType['proposal'] != 2;

            /* correlation */
            if ($filterType['correlation'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($correlatedShadowAttributes[$proposal['id']])) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
            }

            if ($filterType['correlationId'] && $include) {
                $include = false;
                if (isset($correlatedShadowAttributes[$proposal['id']])) {
                    foreach ($correlatedShadowAttributes[$proposal['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            /* feed */
            if ($filterType['feed'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($proposal['Feed'])) { // `include only`
                $include = $include && ($filterType['feed'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['feed'] == 2);
            }

            /* server */
            if ($filterType['server'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Server'])) { // `include only`
                $include = $include && ($filterType['server'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['server'] == 2);
            }

            /* TypeGroupings */
            if (
                $filterType['attributeFilter'] !== 'all'
                && isset(Attribute::TYPE_GROUPINGS[$filterType['attributeFilter']])
                && !in_array($proposal['type'], Attribute::TYPE_GROUPINGS[$filterType['attributeFilter']], true)
            ) {
                return null;
            }

            /* warning */
            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($proposal['warnings']) || !empty($proposal['validationIssue'])) { // `include only`
                $include = $include && ($filterType['warning'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['warning'] == 2);
            }
        }

        if (!$include) {
            return null;
        }

        return $this->__prepareGenericForView($proposal);
    }

    private function __prepareObjectForView(
        $object,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType,
        $sightingsData
    ) {
        $object['category'] = $object['meta-category'];

        $include = empty($filterType['attributeFilter']) ||
            in_array($filterType['attributeFilter'], ['all', 'object', 'correlation', 'proposal', 'warning']) ||
            $object['meta-category'] === $filterType['attributeFilter'];

        if (!$include) {
            return null;
        }

        if (!empty($object['Attribute'])) {
            $temp = [];
            foreach ($object['Attribute'] as $attribute) {
                $result = $this->__prepareAttributeForView(
                    $attribute,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    false,
                    $sightingsData
                );
                if ($result) {
                    $temp[] = $result;
                }
            }
            $object['Attribute'] = $temp;
        }

        // filters depend on child objects
        if (
            in_array($filterType['attributeFilter'], ['correlation', 'proposal', 'warning'], true)
            || $filterType['correlation'] != 0
            || $filterType['proposal'] != 0
            || $filterType['warning'] != 0
            || $filterType['sighting'] != 0
            || $filterType['feed'] != 0
            || $filterType['server'] != 0
            || $filterType['warninglistId'] !== null
            || $filterType['correlationId'] !== null
        ) {
            $include = $this->__checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData);
            if (!$include) {
                return null;
            }
        }

        return $object;
    }

    /**
     * @param array $object
     * @param array $filterType
     * @param array $correlatedAttributes
     * @param array $correlatedShadowAttributes
     * @param array $sightingsData
     * @return bool
     */
    private function __checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData)
    {
        if (empty($object['Attribute'])) { // reject empty object
            return false;
        }

        /* proposal */
        if ($filterType['proposal'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['proposal'] == 1 || $filterType['proposal'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 proposal
                if (!empty($attribute['ShadowAttribute'])) {
                    $flagKeep = ($filterType['proposal'] == 1); // keep if proposal are included
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* warning */
        if ($filterType['warning'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['warning'] == 1 || $filterType['warning'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['warnings'])) {
                    $flagKeep = ($filterType['warning'] == 1); // keep if warnings are included
                } else {
                    $flagKeep = ($filterType['warning'] == 2); // keep if warnings are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['warnings'])) {
                            $flagKeep = ($filterType['warning'] == 1); // do not keep if warning are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        if ($filterType['warninglistId']) {
            // check if object contains at least one attribute that is part of given warninglist
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) {
                if (isset($attribute['warnings'])) {
                    foreach ($attribute['warnings'] as $warning) {
                        if (in_array($warning['warninglist_id'], $filterType['warninglistId'])) {
                            $flagKeep = true;
                            break 2;
                        }
                    }
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        if ($filterType['correlationId']) {
            $flagKeep = false;
            // check if object contains at least one attribute that is correlating with given event ID
            foreach ($object['Attribute'] as $attribute) {
                if (isset($correlatedAttributes[$attribute['id']])) {
                    foreach ($correlatedAttributes[$attribute['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $flagKeep = true;
                            break 2;
                        }
                    }
                }
                if (!empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($correlatedShadowAttributes[$shadowAttribute['id']])) {
                            foreach ($correlatedShadowAttributes[$shadowAttribute['id']] as $correlation) {
                                if (in_array($correlation['id'], $filterType['correlationId'])) {
                                    $flagKeep = true;
                                    break 2;
                                }
                            }
                        }
                    }
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* correlation */
        if ($filterType['correlation'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['correlation'] == 1 || $filterType['correlation'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (isset($correlatedAttributes[$attribute['id']])) {
                    $flagKeep = ($filterType['correlation'] == 1); // keep if correlations are included
                } else {
                    $flagKeep = ($filterType['correlation'] == 2); // keep if correlations are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($correlatedShadowAttributes[$shadowAttribute['id']])) {
                            $flagKeep = ($filterType['correlation'] == 1); // keep if correlations are included
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* sighting */
        if ($filterType['sighting'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['sighting'] == 1 || $filterType['sighting'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (isset($sightingsData['data'][$attribute['id']])) {
                    $flagKeep = ($filterType['sighting'] == 1); // keep if server are included
                } else {
                    $flagKeep = ($filterType['sighting'] == 2); // keep if server are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($sightingsData['data'][$attribute['id']])) {
                            $flagKeep = ($filterType['sighting'] == 1); // do not keep if server are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* feed */
        if ($filterType['feed'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['feed'] == 1 || $filterType['feed'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['Feed'])) {
                    $flagKeep = ($filterType['feed'] == 1); // keep if feed are included
                } else {
                    $flagKeep = ($filterType['feed'] == 2); // keep if feed are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['Feed'])) {
                            $flagKeep = ($filterType['feed'] == 1); // do not keep if feed are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* server */
        if ($filterType['server'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['server'] == 1 || $filterType['server'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['Server'])) {
                    $flagKeep = ($filterType['server'] == 1); // keep if server are included
                } else {
                    $flagKeep = ($filterType['server'] == 2); // keep if server are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['Server'])) {
                            $flagKeep = ($filterType['server'] == 1); // do not keep if server are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array $object
     * @return array
     */
    private function __prepareGenericForView($object)
    {
        if ($this->Attributes->isImage($object)) {
            if (!empty($object['data'])) {
                $object['image'] = $object['data'];
            } else {
                if (extension_loaded('gd')) {
                    // if extension is loaded, the data is not passed to the view because it is asynchronously fetched
                    $object['image'] = true; // tell the view that it is an image despite not having the actual data
                } else {
                    if ($object['objectType'] === 'proposal') {
                        $object['image'] = $this->ShadowAttribute->base64EncodeAttachment($object);
                    } else {
                        $object['image'] = $this->Attributes->base64EncodeAttachment($object);
                    }
                }
            }
        }
        if ($object['type'] === 'attachment' && $this->loadAttachmentScan()->isEnabled()) {
            $type = $object['objectType'] === 'attribute' ? AttachmentScan::TYPE_ATTRIBUTE : AttachmentScan::TYPE_SHADOW_ATTRIBUTE;
            $object['infected'] = $this->loadAttachmentScan()->isInfected($type, $object['id']);
            ;
        }
        return $object;
    }

    /**
     * @param array $event
     * @param array $passedArgs
     * @param false $all
     * @param array $sightingsData
     * @return array
     */
    public function rearrangeEventForView(&$event, $passedArgs = [], $all = false, $sightingsData = [])
    {
        foreach ($event as $k => $v) {
            if (is_array($v)) {
                $event[$k] = $v;
                unset($event[$k]);
            }
        }
        $filterType = [
            'attributeFilter' => isset($passedArgs['attributeFilter']) ? $passedArgs['attributeFilter'] : 'all',
            'proposal' => isset($passedArgs['proposal']) ? $passedArgs['proposal'] : 0,
            'correlation' => isset($passedArgs['correlation']) ? $passedArgs['correlation'] : 0,
            'warning' => isset($passedArgs['warning']) ? $passedArgs['warning'] : 0,
            'deleted' => isset($passedArgs['deleted']) ? $passedArgs['deleted'] : 0,
            'toIDS' => isset($passedArgs['toIDS']) ? $passedArgs['toIDS'] : 0,
            'sighting' => isset($passedArgs['sighting']) ? $passedArgs['sighting'] : 0,
            'feed' => isset($passedArgs['feed']) ? $passedArgs['feed'] : 0,
            'server' => isset($passedArgs['server']) ? $passedArgs['server'] : 0,
            'warninglistId' => isset($passedArgs['warninglistId']) ? (is_array($passedArgs['warninglistId']) ? $passedArgs['warninglistId'] : [$passedArgs['warninglistId']]) : null,
            'correlationId' => isset($passedArgs['correlationId']) ? (is_array($passedArgs['correlationId']) ? $passedArgs['correlationId'] : [$passedArgs['correlationId']]) : null,
        ];
        // update proposal, correlation and warning accordingly
        if (in_array($filterType['attributeFilter'], ['proposal', 'correlation', 'warning'], true)) {
            $filterType[$filterType['attributeFilter']] = 1;
        }

        $correlatedAttributes = isset($event['RelatedAttribute']) ? $event['RelatedAttribute'] : [];
        $correlatedShadowAttributes = isset($event['RelatedShadowAttribute']) ? $event['RelatedShadowAttribute'] : [];
        $objects = [];

        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                $result = $this->__prepareAttributeForView(
                    $attribute,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    $filterType,
                    $sightingsData
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['Attribute']);
        }

        if (isset($event['ShadowAttribute'])) {
            foreach ($event['ShadowAttribute'] as $proposal) {
                $result = $this->__prepareProposalForView(
                    $proposal,
                    $correlatedShadowAttributes,
                    $filterType
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['ShadowAttribute']);
        }
        if (isset($event['Object'])) {
            foreach ($event['Object'] as $object) {
                $object['objectType'] = 'object';
                $result = $this->__prepareObjectForView(
                    $object,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    $filterType,
                    $sightingsData
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['Object']);
        }

        $referencedByArray = [];
        foreach ($objects as $object) {
            $objectType = $object['objectType'];
            if (($objectType === 'attribute' || $objectType === 'object') && !empty($object['ObjectReference'])) {
                foreach ($object['ObjectReference'] as $reference) {
                    if (isset($reference['referenced_uuid'])) {
                        $referencedByArray[$reference['referenced_uuid']][$objectType][] = [
                            'meta-category' => $object['meta-category'],
                            'name' => $object['name'],
                            'uuid' => $object['uuid'],
                            'id' => isset($object['id']) ? $object['id'] : 0,
                            'object_type' => $objectType,
                            'relationship_type' => $reference['relationship_type']
                        ];
                    }
                }
            }
        }
        $customPagination = new CustomPaginationTool();
        if ($all) {
            $passedArgs['page'] = 0;
        }
        $params = $customPagination->applyRulesOnArray($objects, $passedArgs, 'events', 'category');
        foreach ($objects as $k => $object) {
            if (isset($referencedByArray[$object['uuid']])) {
                foreach ($referencedByArray[$object['uuid']] as $objectType => $references) {
                    $objects[$k]['referenced_by'][$objectType] = $references;
                }
            }
        }
        $event['objects'] = $objects;
        $params['total_elements'] = count($objects);
        return $params;
    }

    // pass along a json from the server filter rules
    // returns a conditions set to be merged into pagination / event fetch / etc
    public function filterRulesToConditions($rules)
    {
        $rules = json_decode($rules, true);
        $operators = ['OR', 'NOT'];
        foreach ($operators as $op) {
            if (!empty($rules['tags'][$op])) {
                $event_ids = $this->EventTag->find(
                    'list',
                    [
                        'recursive' => -1,
                        'conditions' => ['EventTag.tag_id' => $rules['tags'][$op]],
                        'fields' => ['EventTag.event_id']
                    ]
                );
                $rules['events'][$op] = $event_ids;
            }
        }
        $conditions = [];
        $fields = ['events' => 'id', 'orgs' => 'Events.orgc_id'];
        foreach ($fields as $k => $field) {
            $temp = [];
            if (!empty($rules[$k]['OR'])) {
                $temp['OR'][$field] = $rules[$k]['OR'];
            }
            if (!empty($rules[$k]['NOT'])) {
                $temp['AND'][$field . ' !='] = $rules[$k]['NOT'];
            }
            $conditions['AND'][] = $temp;
        }
        return $conditions;
    }

    public function fetchInitialObject($event_id, $object_id)
    {
        $initial_object = $this->Objects->find(
            'all',
            [
                'conditions' => [
                    'Object.id' => $object_id,
                    'Object.event_id' => $event_id,
                    'Object.deleted' => 0
                ],
                'recursive' => -1,
                'fields' => ['Object.id', 'Object.uuid', 'Object.name', 'Object.distribution', 'Object.sharing_group_id']
            ]
        )->first();
        if (!empty($initial_object)) {
            $initial_attributes = $this->Attributes->find(
                'all',
                [
                    'conditions' => [
                        'Attributes.object_id' => $object_id,
                        'Attributes.deleted' => 0
                    ],
                    'recursive' => -1,
                    'fields' => [
                        'Attributes.id', 'Attributes.uuid', 'Attributes.type',
                        'Attributes.object_relation', 'Attributes.value'
                    ]
                ]
            );
            if (!empty($initial_attributes)) {
                $initial_object['Attribute'] = [];
                foreach ($initial_attributes as $initial_attribute) {
                    array_push($initial_object['Attribute'], $initial_attribute['Attribute']);
                }
            }
            $initial_references = $this->Objects->ObjectReference->find(
                'all',
                [
                    'conditions' => [
                        'ObjectReference.object_id' => $object_id,
                        'ObjectReference.event_id' => $event_id,
                        'ObjectReference.deleted' => 0
                    ],
                    'recursive' => -1,
                    'fields' => ['ObjectReference.referenced_uuid', 'ObjectReference.relationship_type']
                ]
            );
            if (!empty($initial_references)) {
                $initial_object['ObjectReference'] = [];
                foreach ($initial_references as $initial_reference) {
                    array_push($initial_object['ObjectReference'], $initial_reference['ObjectReference']);
                }
            }
        }
        return $initial_object;
    }

    public function handleModuleResult($result, $event_id)
    {
        $resultArray = [];
        $freetextResults = [];
        $complexTypeTool = new ComplexTypeTool();
        if (isset($result['results']) && !empty($result['results'])) {
            foreach ($result['results'] as $k => &$r) {
                if (!is_array($r['values'])) {
                    $r['values'] = [$r['values']];
                }
                if (!isset($r['types']) && isset($r['type'])) {
                    $r['types'] = [$r['type']];
                }
                if (!is_array($r['types'])) {
                    $r['types'] = [$r['types']];
                }
                if (isset($r['categories']) && !is_array($r['categories'])) {
                    $r['categories'] = [$r['categories']];
                }
                if (isset($r['tags']) && !is_array($r['tags'])) {
                    $r['tags'] = [$r['tags']];
                }
                foreach ($r['values'] as &$value) {
                    if (!is_array($r['values']) || !isset($r['values'][0])) {
                        $r['values'] = [$r['values']];
                    }
                }
                foreach ($r['values'] as $valueKey => &$value) {
                    if (empty($value)) {
                        unset($r['values'][$valueKey]);
                        continue;
                    }
                    if (in_array('freetext', $r['types'])) {
                        if (is_array($value)) {
                            $value = json_encode($value);
                        }
                        $WarninglistsTable = $this->fetchTable('Warninglists');
                        $complexTypeTool->setTLDs($WarninglistsTable->fetchTLDLists());
                        $complexTypeTool->setSecurityVendorDomains($WarninglistsTable->fetchSecurityVendorDomains());
                        $freetextResults = array_merge($freetextResults, $complexTypeTool->checkFreeText($value));
                        if (!empty($freetextResults)) {
                            foreach ($freetextResults as &$ft) {
                                $temp = [];
                                foreach ($ft['types'] as $type) {
                                    $temp[$type] = $type;
                                }
                                $ft['event_id'] = $event_id;
                                $ft['types'] = $temp;
                                $ft['comment'] = isset($r['comment']) ? $r['comment'] : false;
                            }
                        }
                        $r['types'] = array_diff($r['types'], ['freetext']);
                        // if we just removed the only type in the result then more on to the next result
                        if (empty($r['types'])) {
                            continue 2;
                        }
                        $r['types'] = array_values($r['types']);
                    }
                }
                foreach ($r['values'] as &$value) {
                    $temp = [
                        'event_id' => $event_id,
                        'types' => $r['types'],
                        'default_type' => $r['types'][0],
                        'comment' => isset($r['comment']) ? $r['comment'] : false,
                        'to_ids' => isset($r['to_ids']) ? $r['to_ids'] : false,
                        'value' => $value,
                        'tags' => isset($r['tags']) ? $r['tags'] : false
                    ];
                    if (isset($r['categories'])) {
                        $temp['categories'] = $r['categories'];
                        $temp['default_category'] = $r['categories'][0];
                    }
                    if (isset($r['data'])) {
                        $temp['data'] = $r['data'];
                    }
                    if (isset($r['distribution'])) {
                        $temp['distribution'] = $r['distribution'];
                    }
                    // if data_is_handled is set then MISP assumes that the sample is already zipped and encrypted
                    // in this case it will not try to do this by itself - however it also won't create additional hashes
                    if (isset($r['data_is_handled'])) {
                        $temp['data_is_handled'] = $r['data_is_handled'];
                    }
                    $resultArray[] = $temp;
                }
            }
            $resultArray = array_merge($resultArray, $freetextResults);
        }
        return $resultArray;
    }

    /**
     * @param array $result
     * @return array
     */
    public function handleMispFormatFromModuleResult(&$result)
    {
        $defaultDistribution = $this->Attributes->defaultDistribution();
        $event = [];
        if (!empty($result['results']['Attribute'])) {
            $attributes = [];
            foreach ($result['results']['Attribute'] as &$tmp_attribute) {
                $tmp_attribute = $this->__fillAttribute($tmp_attribute, $defaultDistribution);
                $attributes[] = $tmp_attribute;
            }
            $event['Attribute'] = $attributes;
        }
        if (!empty($result['results']['Object'])) {
            $objects = [];
            foreach ($result['results']['Object'] as $tmp_object) {
                $tmp_object['distribution'] = (isset($tmp_object['distribution']) ? (int)$tmp_object['distribution'] : $defaultDistribution);
                $tmp_object['sharing_group_id'] = (isset($tmp_object['sharing_group_id']) ? (int)$tmp_object['sharing_group_id'] : 0);
                if (!empty($tmp_object['Attribute'])) {
                    foreach ($tmp_object['Attribute'] as &$tmp_attribute) {
                        $tmp_attribute = $this->__fillAttribute($tmp_attribute, $defaultDistribution);
                    }
                }
                $objects[] = $tmp_object;
            }
            $event['Object'] = $objects;
        }
        if (!empty($result['results']['EventReport'])) {
            $event['EventReport'] = $result['results']['EventReport'];
        }
        foreach (['Tag', 'Galaxy'] as $field) {
            if (!empty($result['results'][$field])) {
                $event[$field] = $result['results'][$field];
            }
        }
        return $event;
    }

    /**
     * @param array $attribute
     * @param int $defaultDistribution
     * @return array
     */
    private function __fillAttribute($attribute, $defaultDistribution)
    {
        if (is_array($attribute['type'])) {
            $attribute_type = $attribute['type'][0];
            if (empty($attribute['category'])) {
                $categories = [];
                foreach ($attribute['type'] as $type) {
                    $category = $this->Attributes->typeDefinitions[$type]['default_category'];
                    if (!in_array($category, $categories)) {
                        $categories[] = $category;
                    }
                }
                $attribute['category'] = count($categories) === 1 ? $categories[0] : $categories;
            }
        } else {
            $attribute_type = $attribute['type'];
            if (empty($attribute['category'])) {
                $attribute['category'] = $this->Attributes->typeDefinitions[$attribute_type]['default_category'];
            }
        }
        if (!isset($attribute['to_ids'])) {
            $attribute['to_ids'] = $this->Attributes->typeDefinitions[$attribute_type]['to_ids'];
        }
        $attribute['value'] = $this->Attributes->runRegexp($attribute['type'], $attribute['value']);
        $attribute['distribution'] = (isset($attribute['distribution']) ? (int)$attribute['distribution'] : $defaultDistribution);
        $attribute['sharing_group_id'] = (isset($attribute['sharing_group_id']) ? (int)$attribute['sharing_group_id'] : 0);
        return $attribute;
    }

    /**
     * @param array $user
     * @param string $module
     * @param array $options
     * @return array
     * @throws Exception
     */
    public function export(array $user, $module, array $options = [])
    {
        if (empty($module)) {
            throw new InvalidArgumentException('Invalid module.');
        }
        $ModulesTable = $this->fetchTable('Modules');
        $module = $ModulesTable->getEnabledModule($module, 'Export');
        if (!is_array($module)) {
            throw new NotFoundException('Invalid module.');
        }
        // Export module can specify additional options for event fetch
        if (isset($module['meta']['fetch_options'])) {
            $options = array_merge($options, $module['meta']['fetch_options']);
        }
        $events = $this->fetchEvent($user, $options);
        if (empty($events)) {
            throw new NotFoundException('Invalid Events.');
        }
        $modulePayload = ['module' => $module['name']];
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $modulePayload['config'][$conf] = Configure::read('Plugin.Export_' . $module['name'] . '_' . $conf);
            }
        }
        $standard_format = !empty($module['meta']['require_standard_format']);
        if ($standard_format) {
            foreach ($events as $k => $event) {
                $events[$k] = JSONConverterTool::convert($event, false, true);
            }
        }
        $modulePayload['data'] = $events;
        $result = $ModulesTable->queryModuleServer($modulePayload, false, 'Export');
        return [
            'data' => $result['data'],
            'extension' => $module['mispattributes']['outputFileExtension'],
            'response' => $module['mispattributes']['responseType']
        ];
    }

    public function __cacheSharingGroupData($user, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['sharingGroupData'])) {
            return $this->assetCache['sharingGroupData'];
        } else {
            $sharingGroupDataTemp = $this->SharingGroup->fetchAllAuthorised($user, 'simplified');
            $sharingGroupData = [];
            foreach ($sharingGroupDataTemp as $v) {
                if (isset($v['Organisation'])) {
                    $v['SharingGroup']['Organisation'] = $v['Organisation'];
                }
                if (isset($v['SharingGroupOrg'])) {
                    $v['SharingGroup']['SharingGroupOrg'] = $v['SharingGroupOrg'];
                }
                if (isset($v['SharingGroupServer'])) {
                    $v['SharingGroup']['SharingGroupServer'] = $v['SharingGroupServer'];
                    foreach ($v['SharingGroup']['SharingGroupServer'] as &$sgs) {
                        if ($sgs['server_id'] == 0) {
                            $sgs['Server'] = [
                                'id' => '0',
                                'url' => $this->__getAnnounceBaseurl(),
                                'name' => $this->__getAnnounceBaseurl()
                            ];
                        }
                    }
                }
                $sharingGroupData[$v['SharingGroup']['id']] = $v['SharingGroup'];
            }
            if ($useCache) {
                $this->assetCache['sharingGroupData'] = $sharingGroupData;
            }
            return $sharingGroupData;
        }
    }

    private function __cachedelegatedEventIDs($user, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['delegatedEventIDs'])) {
            return $this->assetCache['delegatedEventIDs'];
        } else {
            $EventDelegationsTable = $this->fetchTable('EventDelegations');
            $delegatedEventIDs = $EventDelegationsTable->find(
                'list',
                [
                    'conditions' => ['EventDelegation.org_id' => $user['org_id']],
                    'fields' => ['event_id']
                ]
            );
            if ($useCache) {
                $this->assetCache['delegationEventIDs'] = $delegatedEventIDs;
            }
            return $delegatedEventIDs;
        }
    }

    private function __generateCachedTagFilters($tagRules, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['tagFilters'])) {
            return $this->assetCache['tagFilters'];
        } else {
            $filters = [];
            $args = $this->Attributes->dissectArgs($tagRules);
            $tagArray = $this->EventTag->fetchEventTagIds($args[0], $args[1]);
            if (!empty($tagArray[0])) {
                $filters[] = ['OR' => ['id' => $tagArray[0]]];
            } else {
                $filters[] = ['AND' => ['id NOT IN' => $tagArray[1]]];
            }
            if ($useCache) {
                $this->assetCache['tagFilters'] = $filters;
            }
            return $filters;
        }
    }

    /**
     * @param int|array $eventOrEventId Event ID or event array
     * @param bool $proposalLock
     * @param int|null $timestamp If not provided, current time will be used
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function unpublishEvent($eventOrEventId, $proposalLock = false, $timestamp = null)
    {
        if (is_array($eventOrEventId)) {
            $event = $eventOrEventId;
            if (!isset($event['id'])) {
                throw new InvalidArgumentException('Invalid event array provided.');
            }
        } else {
            $event = $this->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['id' => $eventOrEventId],
                    'fields' => ['id', 'info'], // info is required because of SysLogLogableBehavior
                ]
            )->first();
            if (empty($event)) {
                return false;
            }
        }

        $fields = ['published', 'timestamp'];
        $data = [
            'published' => 0,
            'timestamp' => $timestamp ?: time(),
        ];
        if ($proposalLock) {
            $data['proposal_email_lock'] = 0;
            $fields[] = 'proposal_email_lock';
        }
        $event['unpublishAction'] = true;

        $this->patchEntity($event, $data, $fields);
        return $this->save($event);
    }

    /**
     * @param array $user
     * @param string $file Path
     * @param string $stixVersion
     * @param string $originalFile
     * @param bool $publish
     * @param int $distribution
     * @param int|null $sharingGroupId
     * @param bool $galaxiesAsTags
     * @param bool $debug
     * @return int|string|array
     * @throws JsonException
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function upload_stix(array $user, $file, $stixVersion, $originalFile, $publish, $distribution, $sharingGroupId, $galaxiesAsTags, $debug = false)
    {
        $decoded = $this->convertStixToMisp($stixVersion, $file, $distribution, $sharingGroupId, $galaxiesAsTags, $debug);

        if (!empty($decoded['success'])) {
            $data = JsonTool::decodeArray($decoded['converted']);
            if (empty($data['Event'])) {
                $data = ['Event' => $data];
            }
            if (!$galaxiesAsTags) {
                if (!isset($GalaxyClustersTable)) {
                    $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
                }
                $this->__handleGalaxiesAndClusters($user, $data['Event']);
                if (!empty($data['Event']['Attribute'])) {
                    foreach ($data['Event']['Attribute'] as &$attribute) {
                        $this->__handleGalaxiesAndClusters($user, $attribute);
                    }
                }
                if (!empty($data['Event']['Object'])) {
                    foreach ($data['Event']['Object'] as &$misp_object) {
                        if (!empty($misp_object['Attribute'])) {
                            foreach ($misp_object['Attribute'] as &$attribute) {
                                $this->__handleGalaxiesAndClusters($user, $attribute);
                            }
                        }
                    }
                }
            }
            $stixVersion = $decoded['stix_version'];
            $created_id = false;
            $validationIssues = false;
            $result = $this->_add($data, true, $user, '', null, false, null, $created_id, $validationIssues);
            if ($result === true) {
                if ($originalFile) {
                    $this->add_original_file($decoded['original'], $originalFile, $created_id, $stixVersion);
                }
                if ($publish && $user['Role']['perm_publish']) {
                    if (!Configure::read('MISP.block_publishing_for_same_creator', false) || $user['Role']['perm_sync']) {
                        $this->publish($created_id);
                    }
                }
                return $created_id;
            } else if (is_numeric($result)) {
                return __('Event with the same UUID already exists.');
            } else if (is_string($result)) {
                return $result;
            }
            return $validationIssues;
        }
        $response = __($decoded['error']);
        if (!$user['Role']['perm_site_admin']) {
            $response .= ' ' . __('Please ask your administrator to');
        } else {
            $response .= ' '  . __('Please');
        }
        $response .= ' ' . __('check whether the dependencies for STIX are met via the diagnostic tool.');
        return $response;
    }

    /**
     * @param string $stixVersion
     * @param string $file
     * @param int $distribution
     * @param int|null $sharingGroupId
     * @param bool $galaxiesAsTags
     * @param bool $debug
     * @return array
     * @throws Exception
     */
    private function convertStixToMisp($stixVersion, $file, $distribution, $sharingGroupId, $galaxiesAsTags, $debug)
    {
        $scriptDir = APP . 'files' . DS . 'scripts';
        if ($stixVersion === '2' || $stixVersion === '2.0' || $stixVersion === '2.1') {
            $scriptFile = $scriptDir . DS . 'stix2' . DS . 'stix2misp.py';
            $outputPath = $file . '.out';
            $shellCommand = [
                ProcessTool::pythonBin(),
                $scriptFile,
                '-i', $file,
                '--distribution', $distribution,
            ];
            if ($distribution == 4) {
                array_push($shellCommand, '--sharing_group_id', $sharingGroupId);
            }
            if ($galaxiesAsTags) {
                $shellCommand[] = '--galaxies_as_tags';
            }
            if ($debug) {
                $shellCommand[] = '--debug';
            }
            $stixVersion = "STIX 2.1";
        } else if ($stixVersion === '1' || $stixVersion === '1.1' || $stixVersion === '1.2') {
            $scriptFile = $scriptDir . DS . 'stix2misp.py';
            $outputPath = $file . '.json';
            $shellCommand = [
                ProcessTool::pythonBin(),
                $scriptFile,
                $file,
                Configure::read('MISP.default_event_distribution'),
                Configure::read('MISP.default_attribute_distribution'),
                $this->__getTagNamesFromSynonyms($scriptDir)
            ];
            $stixVersion = "STIX 1.1";
        } else {
            throw new InvalidArgumentException('Invalid STIX version');
        }

        try {
            $stdout = ProcessTool::execute($shellCommand, null, true);
        } catch (ProcessException $e) {
            $stdout = $e->stdout();
        }

        $stdout = preg_split("/\r\n|\n|\r/", trim($stdout));
        $stdout = trim(end($stdout));
        $decoded = JsonTool::decode($stdout);

        if (empty($decoded['stix_version'])) {
            $decoded['stix_version'] = $stixVersion;
        }

        $decoded['original'] = FileAccessTool::readAndDelete($file);
        if (!empty($decoded['success'])) {
            $decoded['converted'] = FileAccessTool::readAndDelete($outputPath);
        }

        return $decoded;
    }

    private function __handleGalaxiesAndClusters($user, &$data)
    {
        if (!empty($data['Galaxy'])) {
            $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            $tag_names = $GalaxyClustersTable->convertGalaxyClustersToTags($user, $data['Galaxy']);
            if (empty($data['Tag'])) {
                $data['Tag'] = [];
            }
            foreach ($tag_names as $tag_name) {
                $data['Tag'][] = ['name' => $tag_name];
            }
        }
    }

    /**
     * @param string $scriptDir
     * @return string
     * @throws Exception
     */
    private function __getTagNamesFromSynonyms($scriptDir)
    {
        $synonymsToTagNames = $scriptDir . DS . 'tmp' . DS . 'synonymsToTagNames.json';
        if (!file_exists($synonymsToTagNames) || (time() - filemtime($synonymsToTagNames)) > 600) {
            if (!isset($GalaxyClustersTable)) {
                $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            }
            $clusters = $GalaxyClustersTable->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => [
                        'GalaxyCluster.value',
                        'MAX(GalaxyCluster.version)',
                        'GalaxyCluster.tag_name',
                        'GalaxyCluster.id'
                    ],
                    'group' => ['GalaxyCluster.tag_name']
                ]
            );
            $synonyms = $GalaxyClustersTable->GalaxyElement->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => ['galaxy_cluster_id', 'value'],
                    'conditions' => ['key' => 'synonyms']
                ]
            );
            $idToSynonyms = [];
            foreach ($synonyms as $synonym) {
                $idToSynonyms[$synonym['GalaxyElement']['galaxy_cluster_id']][] = $synonym['GalaxyElement']['value'];
            }
            $mapping = [];
            foreach ($clusters as $cluster) {
                $mapping[$cluster['GalaxyCluster']['value']][] = $cluster['GalaxyCluster']['tag_name'];
                if (!empty($idToSynonyms[$cluster['GalaxyCluster']['id']])) {
                    foreach ($idToSynonyms[$cluster['GalaxyCluster']['id']] as $synonym) {
                        $mapping[$synonym][] = $cluster['GalaxyCluster']['tag_name'];
                    }
                }
            }
            FileAccessTool::writeToFile($synonymsToTagNames, JsonTool::encode($mapping));
        }
        return $synonymsToTagNames;
    }

    public function enrichmentRouter($options)
    {
        $result = $this->enrichment($options);
        return __('#' . $result . ' attributes have been created during the enrichment process.');
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $options['user'],
                Job::WORKER_PRIO,
                'enrichment',
                'Event ID: ' . $options['event_id'] . ' modules: ' . json_encode($options['modules']),
                'Enriching Events.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'enrichment',
                    $options['user']['id'],
                    $options['event_id'],
                    json_encode($options['modules']),
                    $jobId
                ],
                true,
                $jobId
            );

            return true;
        } else {
            $result = $this->enrichment($options);
            return __('#' . $result . ' attributes have been created during the enrichment process.');
        }
    }

    public function enrichment($params)
    {
        $option_fields = ['user', 'event_id', 'modules'];
        foreach ($option_fields as $option_field) {
            if (empty($params[$option_field])) {
                throw new MethodNotAllowedException(__('%s not set', $option_field));
            }
        }
        $event = [];
        if (!empty($params['attribute_uuids'])) {
            $attributes = $this->Attributes->fetchAttributes(
                $params['user'],
                [
                    'conditions' => [
                        'Attributes.uuid' => $params['attribute_uuids'],
                    ],
                    'withAttachments' => 1,
                ]
            );
            $event = [
                [
                    'Event' => ['id' => $params['event_id']],
                    'Attribute' => Hash::extract($attributes, '{n}.Attribute')
                ]
            ];
        } else {
            $event = $this->fetchEvent(
                $params['user'],
                [
                    'eventid' => $params['event_id'],
                    'includeAttachments' => 1,
                    'flatten' => 1,
                ]
            );
        }
        $ModulesTable = $this->fetchTable('Modules');
        $enabledModules = $ModulesTable->getEnabledModules($params['user']);
        if (empty($enabledModules) || is_string($enabledModules)) {
            return true;
        }
        $options = [];
        foreach ($enabledModules['modules'] as $k => $temp) {
            if (isset($temp['meta']['config'])) {
                $settings = [];
                foreach ($temp['meta']['config'] as $conf) {
                    $settings[$conf] = Configure::read('Plugin.Enrichment_' . $temp['name'] . '_' . $conf);
                }
                $enabledModules['modules'][$k]['config'] = $settings;
            }
        }
        if (empty($event)) {
            throw new MethodNotAllowedException('Invalid Events.');
        }
        $attributes_added = 0;
        $initial_objects = [];
        $event_id = $event[0]['Event']['id'];
        foreach ($event[0]['Attribute'] as $attribute) {
            $object_id = $attribute['object_id'];
            if ($object_id != '0' && empty($initial_objects[$object_id])) {
                $initial_objects[$object_id] = $this->fetchInitialObject($event_id, $object_id);
            }
            foreach ($enabledModules['modules'] as $module) {
                if (in_array($module['name'], $params['modules'])) {
                    if (in_array($attribute['type'], $module['mispattributes']['input'])) {
                        $data = ['module' => $module['name'], 'event_id' => $event_id, 'attribute_uuid' => $attribute['uuid']];
                        if (!empty($module['config'])) {
                            $data['config'] = $module['config'];
                        }
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
                            $data['attribute'] = $attribute;
                        } else {
                            $data[$attribute['type']] = $attribute['value'];
                        }
                        if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                            $attribute['Object'] = $initial_objects[$object_id]['Object'];
                        }
                        $triggerData = $event[0];
                        $triggerData['Attribute'] = [$attribute];
                        $result = $ModulesTable->queryModuleServer($data, false, 'Enrichment', false, $triggerData);
                        if ($result === false) {
                            throw new MethodNotAllowedException(h($module['name']) . ' service not reachable.');
                        } else if (!is_array($result)) {
                            continue 2;
                        }
                        //if (isset($result['error'])) $this->Session->setFlash($result['error']);
                        if (!is_array($result)) {
                            throw new Exception($result);
                        }
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
                            if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                                $result['initialObject'] = $initial_objects[$object_id];
                            }
                            $default_comment = $attribute['value'] . ': enriched via the ' . $module['name'] . ' module.';
                            $attributes_added += $this->processModuleResultsData($params['user'], $result['results'], $event_id, $default_comment, false, false, true);
                        } else {
                            $attributes = $this->handleModuleResult($result, $event_id);
                            foreach ($attributes as $a) {
                                $this->Attributes->create();
                                $a['distribution'] = $attribute['distribution'];
                                $a['sharing_group_id'] = $attribute['sharing_group_id'];
                                $comment = 'Attribute #' . $attribute['id'] . ' enriched by ' . $module['name'] . '.';
                                if (!empty($a['comment'])) {
                                    $a['comment'] .= PHP_EOL . $comment;
                                } else {
                                    $a['comment'] = $comment;
                                }
                                $a['type'] = empty($a['default_type']) ? $a['types'][0] : $a['default_type'];
                                $result = $this->Attributes->save($a);
                                if ($result) {
                                    $attributes_added++;
                                }
                            }
                        }
                    }
                }
            }
        }
        return $attributes_added;
    }

    /**
     * @param array $user
     * @param array $data
     * @param string $dataType
     * @param bool $excludeGalaxy
     * @param bool $cullGalaxyTags
     * @return array
     */
    public function massageTags(array $user, array $data, $dataType = 'Event', $excludeGalaxy = false, $cullGalaxyTags = false)
    {
        $data['Galaxy'] = [];

        // unset empty event tags that got added because the tag wasn't exportable
        if (!empty($data[$dataType . 'Tag'])) {
            if (!isset($GalaxyClustersTable)) {
                $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            }
            foreach ($data[$dataType . 'Tag'] as $k => &$dataTag) {
                if (empty($dataTag['Tag'])) {
                    unset($data[$dataType . 'Tag'][$k]);
                    continue;
                }
                $dataTag['Tag']['local'] = empty($dataTag['local']) ? 0 : 1;
                if (!isset($excludeGalaxy) || !$excludeGalaxy) {
                    if (substr($dataTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
                        $cluster = $GalaxyClustersTable->getCluster($dataTag['Tag']['name'], $user);
                        if ($cluster) {
                            $found = false;
                            $cluster['GalaxyCluster']['local'] = $dataTag['local'] ?? false;
                            $cluster['GalaxyCluster'][strtolower($dataType) . '_tag_id'] = $dataTag['id'];
                            foreach ($data['Galaxy'] as $j => $galaxy) {
                                if ($galaxy['id'] == $cluster['GalaxyCluster']['Galaxy']['id']) {
                                    $found = true;
                                    $temp = $cluster;
                                    unset($temp['GalaxyCluster']['Galaxy']);
                                    $data['Galaxy'][$j]['GalaxyCluster'][] = $temp['GalaxyCluster'];
                                    break;
                                }
                            }
                            if (!$found) {
                                $data['Galaxy'][] = $cluster['GalaxyCluster']['Galaxy'];
                                $temp = $cluster;
                                unset($temp['GalaxyCluster']['Galaxy']);
                                $data['Galaxy'][count($data['Galaxy']) - 1]['GalaxyCluster'][] = $temp['GalaxyCluster'];
                            }
                            if ($cullGalaxyTags) {
                                unset($data[$dataType . 'Tag'][$k]);
                            }
                        }
                    }
                }
            }
            $data[$dataType . 'Tag'] = array_values($data[$dataType . 'Tag']);
        }
        return $data;
    }

    public function insertLock($user, $id)
    {
        $EventLocksTable = $this->fetchTable('EventLocks');
        $EventLocksTable->insertLock($user, $id);
    }

    /**
     * @param array $server
     * @param array $event
     * @param mixed $newTextBody
     * @throws Exception
     */
    private function __logUploadResult(array $server, array $event, $newTextBody)
    {
        if (!is_string($newTextBody)) {
            $newTextBody = JsonTool::encode($newTextBody);
        }

        $title = 'Uploading Event (' . $event['id'] . ') to Server (' . $server['id'] . ')';
        $change = 'Returned message: ' . $newTextBody;

        $this->loadLog()->createLogEntry('SYSTEM', 'warning', 'Server', $server['id'], $title, $change);
    }

    /**
     * @param array $user
     * @param array $attributes
     * @param int $id Event ID
     * @param string $default_comment
     * @param bool $proposals
     * @param bool $adhereToWarninglists
     * @param int|false $jobId
     * @param bool $returnRawResults
     * @return array|false|string
     * @throws Exception
     */
    public function processFreeTextData(array $user, $attributes, $id, $default_comment = '', $proposals = false, $adhereToWarninglists = false, $jobId = false, $returnRawResults = false)
    {
        $event = $this->find(
            'all',
            [
                'conditions' => ['id' => $id],
                'recursive' => -1,
                'fields' => ['id', 'uuid', 'Events.distribution', 'Events.org_id', 'Events.orgc_id', 'Events.sharing_group_id', 'Events.disable_correlation'],
            ]
        )->first();
        if (empty($event)) {
            return false;
        }
        $results = [];
        $objectType = $proposals ? 'ShadowAttribute' : 'Attribute';
        /** @var Model $model */
        $model = $this->$objectType;

        if ($adhereToWarninglists) {
            $WarninglistsTable = $this->fetchTable('Warninglists');
        }
        $saved = 0;
        $failed = 0;
        $attributeSources = ['attributes', 'ontheflyattributes'];
        $ontheflyattributes = [];
        $i = 0;
        if ($jobId) {
            /** @var EventLock $eventLock */
            $EventLocksTable = $this->fetchTable('EventLocks');
            $EventLocksTable->insertLockBackgroundJob($event['id'], $jobId);

            $JobsTable = $this->fetchTable('Jobs');
            $total = count($attributeSources);
        }
        foreach ($attributeSources as $source) {
            foreach (${$source} as $attribute) {
                if ($attribute['type'] === 'ip-src/ip-dst') {
                    $types = ['ip-src', 'ip-dst'];
                } elseif ($attribute['type'] === 'ip-src|port/ip-dst|port') {
                    $types = ['ip-src|port', 'ip-dst|port'];
                } elseif ($attribute['type'] === 'malware-sample') {
                    if (!isset($attribute['data_is_handled']) || !$attribute['data_is_handled']) {
                        $result = $this->Attributes->handleMaliciousBase64($id, $attribute['value'], $attribute['data'], ['md5', 'sha1', 'sha256'], $objectType === 'ShadowAttribute' ? true : false);
                        if (!$result['success']) {
                            $failed++;
                            continue;
                        }
                        $attribute['data'] = $result['data'];
                        $shortValue = $attribute['value'];
                        $attribute['value'] = $shortValue . '|' . $result['md5'];
                        $additionalHashes = ['sha1', 'sha256'];
                        foreach ($additionalHashes as $hash) {
                            $temp = $attribute;
                            $temp['type'] = 'filename|' . $hash;
                            $temp['value'] = $shortValue . '|' . $result[$hash];
                            unset($temp['data']);
                            $ontheflyattributes[] = $temp;
                        }
                    }
                    $types = [$attribute['type']];
                } else {
                    $types = [$attribute['type']];
                }
                foreach ($types as $type) {
                    $model->create();
                    $attribute['type'] = $type;
                    if (empty($attribute['comment'])) {
                        $attribute['comment'] = $default_comment;
                    }
                    $attribute['event_id'] = $id;
                    if ($objectType === 'ShadowAttribute') {
                        $attribute['org_id'] = $user['org_id'];
                        $attribute['event_org_id'] = $event['orgc_id'];
                        $attribute['email'] = $user['email'];
                        $attribute['event_uuid'] = $event['uuid'];
                    }
                    // adhere to the warninglist
                    if ($adhereToWarninglists) {
                        if (!$WarninglistsTable->filterWarninglistAttribute($attribute)) {
                            if ($adhereToWarninglists === 'soft') {
                                $attribute['to_ids'] = 0;
                            } else {
                                // just ignore the attribute
                                continue;
                            }
                        }
                    }
                    $saved_attribute = $model->save($attribute, ['parentEvent' => $event]);
                    if ($saved_attribute) {
                        $results[] = $saved_attribute;
                        // If Tags, attach each tags to attribute
                        if (!empty($attribute['tags'])) {
                            foreach (explode(",", $attribute['tags']) as $tagName) {
                                $tagId = $this->Attributes->AttributeTags->Tags->captureTag(['name' => trim($tagName)], $user);
                                if ($tagId === false) {
                                    continue;  // user don't have permission to use that tag
                                }
                                if (!$this->Attributes->AttributeTags->attachTagToAttribute($saved_attribute['Attribute']['id'], $id, $tagId)) {
                                    throw new MethodNotAllowedException(__('Could not add tags.'));
                                }
                            }
                        }
                        $saved++;
                    } else {
                        $lastError = $model->validationErrors;
                        $failed++;
                    }
                }
                if ($jobId) {
                    if ($i % 20 === 0) {
                        $JobsTable->saveProgress($jobId, 'Attribute ' . $i . '/' . $total, $i * 80 / $total);
                    }
                }
            }
        }
        $emailResult = '';
        $messageScope = $objectType === 'ShadowAttribute' ? 'proposals' : 'attributes';
        if ($saved > 0) {
            if ($objectType !== 'ShadowAttribute') {
                $this->unpublishEvent($id);
            } else {
                if (!$this->ShadowAttribute->sendProposalAlertEmail($id)) {
                    $emailResult = " but sending out the alert e-mails has failed for at least one recipient";
                }
            }
        }
        $messageScopeSaved = $this->__apply_inflector($saved, $messageScope);
        if ($failed > 0) {
            if ($failed == 1) {
                $messageScopeFailed = Inflector::singularize($messageScope);
                $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '. ' . $failed . ' ' . $messageScopeFailed . ' could not be saved. Reason for the failure: ' . json_encode($lastError);
            } else {
                $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '. ' . $failed . ' ' . $messageScope . ' could not be saved. This may be due to attributes with similar values already existing.';
            }
        } else {
            $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '.';
        }
        if ($jobId) {
            $EventLocksTable->deleteBackgroundJobLock($event['id'], $jobId);
            $JobsTable->saveStatus($jobId, true, __('Processing complete. %s', $message));
        }
        if (!empty($returnRawResults)) {
            return $results;
        }
        return $message;
    }

    /**
     * @param array $user
     * @param array $resolved_data
     * @param int $id
     * @param string $default_comment
     * @param int|false $jobId
     * @param bool $adhereToWarninglists
     * @param bool $event_level
     * @return int|string
     * @throws JsonException
     */
    public function processModuleResultsData(array $user, $resolved_data, $id, $default_comment = '', $jobId = false, $adhereToWarninglists = false, $event_level = false)
    {
        $lastObjectError = [];

        $event = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['id' => $id],
            ]
        )->first();
        if (empty($event)) {
            throw new Exception("Event with ID `$id` not found.");
        }
        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');

            /** @var EventLock $eventLock */
            $EventLocksTable = $this->fetchTable('EventLocks');
            $EventLocksTable->insertLockBackgroundJob($event['id'], $jobId);
        }
        $failed_attributes = $failed_objects = $failed_object_attributes = $failed_reports = 0;
        $saved_attributes = $saved_objects = $saved_object_attributes = $saved_reports = 0;
        $items_count = 0;
        $failed = [];
        $recovered_uuids = [];
        foreach (['Attribute', 'Object', 'EventReport'] as $feature) {
            if (isset($resolved_data[$feature])) {
                $items_count += count($resolved_data[$feature]);
            }
        }
        if (!empty($resolved_data['Tag'])) {
            foreach ($resolved_data['Tag'] as $tag) {
                $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                if ($tag_id) {
                    $tag['id'] = $tag_id;
                    $this->EventTag->attachTagToEvent($id, $tag);
                }
            }
        }

        if (!empty($resolved_data['Attribute'])) {
            $total_attributes = count($resolved_data['Attribute']);
            $processedAttributes = 0;
            foreach ($resolved_data['Attribute'] as $attribute) {
                $this->Attributes->create();
                if (empty($attribute['comment'])) {
                    $attribute['comment'] = $default_comment;
                }
                if (!empty($attribute['data']) && !empty($attribute['encrypt'])) {
                    $attribute = $this->Attributes->onDemandEncrypt($attribute);
                }
                $attribute['event_id'] = $id;
                if ($this->Attributes->save($attribute)) {
                    $saved_attributes++;
                    if (!empty($attribute['Tag'])) {
                        foreach ($attribute['Tag'] as $tag) {
                            $tag_id = $this->Attributes->AttributeTags->Tags->captureTag($tag, $user);
                            if ($tag_id) {
                                $relationship_type = empty($tag['relationship_type']) ? false : $tag['relationship_type'];
                                $this->Attributes->AttributeTags->attachTagToAttribute($this->Attributes->id, $id, $tag_id, !empty($tag['local']), $relationship_type);
                            }
                        }
                    }
                } else {
                    $this->Attributes->logDropped($user, $attribute);
                    $failed_attributes++;
                    $lastAttributeError = $this->Attributes->validationErrors;
                    $original_uuid = $this->__findOriginalUUID(
                        $attribute['type'],
                        $attribute['value'],
                        $id
                    );
                    if (!empty($original_uuid)) {
                        $recovered_uuids[$attribute['uuid']] = $original_uuid;
                    } else {
                        $failed[] = $attribute['uuid'];
                    }
                }
                if ($jobId) {
                    $processedAttributes++;
                    $JobsTable->saveProgress($jobId, "Attribute $processedAttributes/$total_attributes", $processedAttributes * 100 / $items_count);
                }
            }
        } else {
            $total_attributes = 0;
        }

        if (!empty($resolved_data['Object'])) {
            $initial_object_id = isset($resolved_data['initialObject']) ? $resolved_data['initialObject']['Object']['id'] : "0";
            $total_objects = count($resolved_data['Object']);
            $processedObjects = 0;
            $references = [];
            foreach ($resolved_data['Object'] as $object) {
                if (isset($object['meta_category']) && !isset($object['meta-category'])) {
                    $object['meta-category'] = $object['meta_category'];
                    unset($object['meta_category']);
                }
                if (empty($object['comment'])) {
                    $object['comment'] = $default_comment;
                }
                $object['event_id'] = $id;
                if (isset($object['id']) && $object['id'] == $initial_object_id) {
                    $initial_object = $resolved_data['initialObject'];
                    $recovered_uuids[$object['uuid']] = $initial_object['Object']['uuid'];
                    if ($object['name'] != $initial_object['Object']['name']) {
                        throw new NotFoundException(__('Invalid object.'));
                    }
                    $initial_attributes = [];
                    if (!empty($initial_object['Attribute'])) {
                        foreach ($initial_object['Attribute'] as $initial_attribute) {
                            $initial_attributes[$initial_attribute['object_relation']][] = $initial_attribute['value'];
                        }
                    }
                    $initial_references = [];
                    if (!empty($initial_object['ObjectReference'])) {
                        foreach ($initial_object['ObjectReference'] as $initial_reference) {
                            $initial_references[$initial_reference['relationship_type']][] = $initial_reference['referenced_uuid'];
                        }
                    }
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $object_attribute) {
                            $object_relation = $object_attribute['object_relation'];
                            if (isset($initial_attributes[$object_relation]) && in_array($object_attribute['value'], $initial_attributes[$object_relation])) {
                                continue;
                            }
                            if ($this->__saveObjectAttribute($object_attribute, null, $event, $initial_object_id, $user)) {
                                $saved_object_attributes++;
                            } else {
                                $failed_object_attributes++;
                                $lastObjectAttributeError = $this->Attributes->validationErrors;
                            }
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $object_reference) {
                            $references[] = ['objectId' => $initial_object_id, 'reference' => $object_reference];
                        }
                    }
                    $saved_objects++;
                } else {
                    if (!empty($object['Attribute'])) {
                        $current_object_id = $this->__findCurrentObjectId($id, $object['Attribute']);
                        if ($current_object_id) {
                            $original_uuid = $this->Objects->find(
                                'all',
                                [
                                    'conditions' => [
                                        'Object.id' => $current_object_id, 'Object.event_id' => $id,
                                        'Object.name' => $object['name'], 'Object.deleted' => 0
                                    ],
                                    'recursive' => -1,
                                    'fields' => ['Object.uuid']
                                ]
                            )->first();
                            if (!empty($original_uuid)) {
                                $recovered_uuids[$object['uuid']] = $original_uuid['Object']['uuid'];
                            }
                            $object_id = $current_object_id;
                        } else {
                            $object = $this->Objects->newEntity($object);
                            if ($this->Objects->save($object)) {
                                $object_id = $object->id;
                                foreach ($object['Attribute'] as $object_attribute) {
                                    if ($this->__saveObjectAttribute($object_attribute, null, $event, $object_id, $user)) {
                                        $saved_object_attributes++;
                                    } else {
                                        $failed_object_attributes++;
                                        $lastObjectAttributeError = $this->Attributes->validationErrors;
                                    }
                                }
                                $saved_objects++;
                            } else {
                                $failed_objects++;
                                $lastObjectError = $object->getErrors();
                                $failed[] = $object['uuid'];
                                continue;
                            }
                        }
                    } else {
                        $object = $this->Objects->newEntity($object);
                        if ($this->Objects->save($object)) {
                            $object_id = $object->id;
                            $saved_objects++;
                        } else {
                            $failed_objects++;
                            $lastObjectError = $object->getErrors();
                            $failed[] = $object['uuid'];
                            continue;
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $object_reference) {
                            $references[] = ['objectId' => $object_id, 'reference' => $object_reference];
                        }
                    }
                }
                if ($jobId) {
                    $processedObjects++;
                    $JobsTable->saveProgress($jobId, "Object $processedObjects/$total_objects", ($processedObjects + $total_attributes) * 100 / $items_count);
                }
            }

            if (!empty($references)) {
                $reference_errors = [];
                foreach ($references as $reference) {
                    $object_id = $reference['objectId'];
                    $reference = $reference['reference'];
                    if (in_array($reference['object_uuid'], $failed)) {
                        continue; // if object that contains reference couldn't be added, skip
                    }
                    if (isset($recovered_uuids[$reference['object_uuid']])) {
                        $reference['object_uuid'] = $recovered_uuids[$reference['object_uuid']];
                    }
                    if (isset($recovered_uuids[$reference['referenced_uuid']])) {
                        $reference['referenced_uuid'] = $recovered_uuids[$reference['referenced_uuid']];
                    }
                    $current_reference = $this->Objects->ObjectReference->hasAny(
                        [
                            'ObjectReference.object_id' => $object_id,
                            'ObjectReference.referenced_uuid' => $reference['referenced_uuid'],
                            'ObjectReference.relationship_type' => $reference['relationship_type'],
                            'ObjectReference.event_id' => $id,
                            'ObjectReference.deleted' => 0,
                        ]
                    );
                    if ($current_reference) {
                        continue; // Reference already exists, skip.
                    }
                    list($referenced_id, $referenced_uuid, $referenced_type) = $this->Objects->ObjectReference->getReferencedInfo(
                        $reference['referenced_uuid'],
                        ['Event' => ['id' => $id]],
                        false,
                        $user
                    );
                    if (!$referenced_id && !$referenced_uuid && !$referenced_type) {
                        continue;
                    }
                    $reference = [
                        'event_id' => $id,
                        'referenced_id' => $referenced_id,
                        'referenced_uuid' => $referenced_uuid,
                        'referenced_type' => $referenced_type,
                        'object_id' => $object_id,
                        'object_uuid' => $reference['object_uuid'],
                        'relationship_type' => $reference['relationship_type']
                    ];
                    $this->Objects->ObjectReference->create();
                    if (!$this->Objects->ObjectReference->save($reference)) {
                        $reference_errors[] = $this->Objects->ObjectReference->validationErrors;
                    }
                }
            }
        }

        if (!empty($resolved_data['EventReport'])) {
            $total_reports = count($resolved_data['EventReport']);
            foreach ($resolved_data['EventReport'] as $i => $report) {
                $this->EventReport->create();
                $report['event_id'] = $id;
                if ($this->EventReport->save($report)) {
                    $saved_reports++;
                } else {
                    $failed_reports++;
                    $lastReportError = $this->EventReport->validationErrors;
                }
                if ($jobId) {
                    $current = ($i + 1);
                    $JobsTable->saveProgress($jobId, "EventReport $current/$total_reports", $current * 100 / $items_count);
                }
            }
        }

        if ($saved_attributes > 0 || $saved_objects > 0 || $saved_reports > 0) {
            $this->unpublishEvent($event);
        }
        if ($event_level) {
            return $saved_attributes + $saved_object_attributes + $saved_reports;
        }
        $message = '';
        if ($saved_attributes > 0) {
            $message .= $saved_attributes . ' ' . $this->__apply_inflector($saved_attributes, 'attribute') . ' created. ';
        }
        if ($failed_attributes > 0) {
            if ($failed_attributes == 1) {
                $reason = ' attribute could not be saved. Reason for the failure: ' . json_encode($lastAttributeError) . ' ';
            } else {
                $reason = ' attributes could not be saved. This may be due to attributes with similar values already existing. ';
            }
            $message .= $failed_attributes . $reason;
        }
        if ($saved_objects > 0) {
            $message .= $saved_objects . ' ' . $this->__apply_inflector($saved_objects, 'object') . ' created';
            if ($saved_object_attributes > 0) {
                $message .= ' (including a total of ' . $saved_object_attributes . ' object ' . $this->__apply_inflector($saved_object_attributes, 'attribute') . '). ';
            } else {
                $message .= '. ';
            }
        }
        if ($failed_objects > 0) {
            if ($failed_objects == 1) {
                $reason = ' object could not be saved. Reason for the failure: ';
            } else {
                $reason = ' objects could not be saved. An example of reason for the failure: ';
            }
            $message .= $failed_objects . $reason . json_encode($lastObjectError) . ' ';
        }
        if ($failed_object_attributes > 0) {
            if ($failed_object_attributes == 1) {
                $reason = 'object attribute could not be saved. Reason for the failure: ';
            } else {
                $reason = 'object attributes could not be saved. An example of reason for the failure: ';
            }
            $message .= 'By the way, ' . $failed_object_attributes . $reason . json_encode($lastObjectAttributeError) . '.';
        }
        if (!empty($reference_errors)) {
            $reference_error = count($reference_errors) == 1 ? 'a reference is' : 'some references are';
            $message .= ' Also, be aware that ' . $reference_error . ' missing: ';
            foreach ($reference_errors as $error) {
                $message .= $error;
            }
            $message .= 'you can have a look at the module results view you just left, to compare.';
        }
        if ($saved_reports > 0) {
            $message .= $saved_reports . ' ' . $this->__apply_inflector($saved_reports, 'eventReport') . ' created. ';
        }
        if ($failed_reports > 0) {
            if ($failed_reports == 1) {
                $reason = ' eventReport could not be saved. Reason for the failure: ' . json_encode($lastReportError) . ' ';
            } else {
                $reason = ' eventReport could not be saved. ';
            }
            $message .= $failed_reports . $reason;
        }
        if ($jobId) {
            $JobsTable->saveStatus($jobId, true, 'Processing complete. ' . $message);
            $EventLocksTable->deleteBackgroundJobLock($event['id'], $jobId);
        }
        return $message;
    }

    private function __apply_inflector($count, $scope)
    {
        return ($count == 1 ? Inflector::singularize($scope) : Inflector::pluralize($scope));
    }

    private function __findCurrentObjectId($event_id, $attributes)
    {
        $conditions = [];
        foreach ($attributes as $attribute) {
            $conditions[] = [
                'AND' => [
                    'Attributes.object_relation' => $attribute['object_relation'],
                    'Attributes.value' => $attribute['value'],
                    'Attributes.type' => $attribute['type']
                ]

            ];
        }
        $ids = [];
        foreach (
            $this->Objects->Attribute->find(
                'all',
                [
                    'conditions' => [
                        'Attributes.event_id' => $event_id,
                        'Attributes.object_id !=' => 0,
                        'Attributes.deleted' => 0,
                        'OR' => $conditions
                    ],
                    'recursive' => -1,
                    'fields' => ['Attributes.object_id']
                ]
            ) as $found_id
        ) {
            $ids[] = $found_id['Attribute']['object_id'];
        }
        $attributes_count = count($attributes);
        foreach (array_count_values($ids) as $id => $count) {
            if ($count >= $attributes_count) {
                return $id;
            }
        }
        return 0;
    }

    private function __findOriginalUUID($attribute_type, $attribute_value, $event_id)
    {
        $original_uuid = $this->Objects->Attribute->find(
            'all',
            [
                'conditions' => [
                    'Attributes.event_id' => $event_id,
                    'Attributes.deleted' => 0,
                    'Attributes.object_id' => 0,
                    'Attributes.type' => $attribute_type,
                    'Attributes.value' => $attribute_value
                ],
                'recursive' => -1,
                'fields' => ['Attributes.uuid']
            ]
        )->first();
        if (!empty($original_uuid)) {
            return $original_uuid['Attribute']['uuid'];
        }
        $original_uuid = $this->Objects->find(
            'all',
            [
                'conditions' => [
                    'Attributes.event_id' => $event_id,
                    'Attributes.deleted' => 0,
                    'Attributes.type' => $attribute_type,
                    'Attributes.value1' => $attribute_value,
                    'Object.event_id' => $event_id
                ],
                'recursive' => -1,
                'fields' => ['Object.uuid'],
                'joins' => [
                    [
                        'table' => 'attributes',
                        'alias' => 'Attribute',
                        'type' => 'inner',
                        'conditions' => [
                            'Attributes.object_id = Object.id'
                        ]
                    ]
                ]
            ]
        )->first();
        return (!empty($original_uuid)) ? $original_uuid['Object']['uuid'] : $original_uuid;
    }

    /**
     * @param array $attribute
     * @param string|null $default_comment
     * @param array $event
     * @param int $object_id
     * @param array $user
     * @return array|bool|mixed
     * @throws Exception
     */
    private function __saveObjectAttribute(array $attribute, $default_comment, array $event, $object_id, array $user)
    {
        $attribute['object_id'] = $object_id;
        $attribute['event_id'] = $event['id'];
        if (empty($attribute['comment']) && $default_comment) {
            $attribute['comment'] = $default_comment;
        }
        if (!empty($attribute['data']) && !empty($attribute['encrypt'])) {
            $attribute = $this->Attributes->onDemandEncrypt($attribute);
        }
        $this->Attributes->create();
        $attribute_save = $this->Attributes->save($attribute, ['parentEvent' => $event]);
        if ($attribute_save) {
            if (!empty($attribute['Tag'])) {
                foreach ($attribute['Tag'] as $tag) {
                    $tag_id = $this->Attributes->AttributeTags->Tags->captureTag($tag, $user);
                    $relationship_type = empty($tag['relationship_type']) ? false : $tag['relationship_type'];
                    if ($tag_id) {
                        $this->Attributes->AttributeTags->attachTagToAttribute($this->Attributes->id, $event['id'], $tag_id, !empty($tag['local']), $relationship_type);
                    }
                }
            }
        } else {
            $this->Attributes->logDropped($user, $attribute);
        }
        return $attribute_save;
    }

    public function processFreeTextDataRouter(array $user, array $attributes, $id, $default_comment = '', $proposals = false, $adhereToWarninglists = false, $returnRawResults = false)
    {
        if (Configure::read('MISP.background_jobs') && count($attributes) > 5) { // on background process just big attributes batch
            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $user,
                Job::WORKER_PRIO,
                "process_freetext_data",
                'Event: ' . $id,
                'Processing...'
            );

            $tempData = [
                'user' => $user,
                'attributes' => $attributes,
                'id' => $id,
                'default_comment' => $default_comment,
                'proposals' => $proposals,
                'adhereToWarninglists' => $adhereToWarninglists,
                'jobId' => $jobId,
            ];

            try {
                $filePath = $this->getBackgroundJobsTool()->enqueueDataFile($tempData);
                $this->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        'processfreetext',
                        $filePath
                    ],
                    true,
                    $jobId
                );

                return 'Freetext ingestion queued for background processing. Attributes will be added to the event as they are being processed.';
            } catch (Exception $e) {
                $this->logException("Could not process freetext in background.", $e, LOG_NOTICE);
            }
        }
        return $this->processFreeTextData($user, $attributes, $id, $default_comment, $proposals, $adhereToWarninglists, false, $returnRawResults);
    }

    public function processModuleResultsDataRouter($user, $resolved_data, $id, $default_comment = '')
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob($user, Job::WORKER_PRIO, "process_module_results_data", 'Event: ' . $id, 'Processing...');

            $tempData = [
                'user' => $user,
                'misp_format' => $resolved_data,
                'id' => $id,
                'default_comment' => $default_comment,
                'jobId' => $jobId
            ];

            try {
                $filePath = $this->getBackgroundJobsTool()->enqueueDataFile($tempData);

                $this->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        'processmoduleresult',
                        $filePath
                    ],
                    true,
                    $jobId
                );

                return 'Module results ingestion queued for background processing. Related data will be added to the event as it is being processed.';
            } catch (Exception $e) {
                $this->logException("Could not process module results in background.", $e, LOG_NOTICE);
            }
        }
        return $this->processModuleResultsData($user, $resolved_data, $id, $default_comment);
    }

    /**
     * Attach references to objects faster than CakePHP.
     * @param array $events
     */
    private function __attachReferences(array &$events)
    {
        $eventIds = [];
        foreach ($events as $event) {
            if (!empty($event['Object'])) {
                $eventIds[] = $event['id']; // event contains objects
            }
        }
        if (!empty($eventIds)) {
            // Do not fetch fields that we already know to reduce memory usage
            $schema = $this->Objects->ObjectReference->schema();
            unset($schema['event_id']);
            unset($schema['source_uuid']);

            $references = $this->Objects->ObjectReference->find(
                'all',
                [
                    'conditions' => ['ObjectReference.event_id' => $eventIds],
                    'fields' => array_keys($schema),
                    'recursive' => -1,
                ]
            );
        }
        if (empty($references)) {
            // Assign empty object reference object
            foreach ($events as &$event) {
                foreach ($event['Object'] as &$object) {
                    $object['ObjectReference'] = [];
                }
            }
            return;
        }
        $referencesForObject = [];
        foreach ($references as $reference) {
            $referencesForObject[$reference['ObjectReference']['object_id']][] = $reference['ObjectReference'];
        }
        $fieldsToCopy = [
            'common' => ['distribution', 'sharing_group_id', 'uuid'],
            'Attribute' => ['value', 'type', 'category', 'to_ids'],
            'Object' => ['name', 'meta-category']
        ];
        foreach ($events as &$event) {
            $eventIdCache = [];
            foreach ($event['Object'] as &$object) {
                $objectReferences = $referencesForObject[$object['id']] ?? [];
                foreach ($objectReferences as &$reference) {
                    $reference['event_id'] = $event['id'];
                    $reference['source_uuid'] = $object['uuid'];
                    // find referenced object in current event
                    $type = $reference['referenced_type'] == 0 ? 'Attribute' : 'Object';
                    // construct array with ID in key, so we can search attributes and objects by ID faster
                    if (!isset($eventIdCache[$type])) {
                        $eventIdCache[$type] = array_column($event[$type], null, 'id');
                    }
                    $found = $eventIdCache[$type][$reference['referenced_id']] ?? null;

                    if ($found) {
                        // copy requested fields
                        $copied = [];
                        foreach (array_merge($fieldsToCopy['common'], $fieldsToCopy[$type]) as $field) {
                            $copied[$field] = $found[$field];
                        }
                        $reference[$type] = $copied;
                    } else { // object / attribute might be from an extended event
                        $otherEventText = __('%s from another event', $type);
                        $reference[$type] = [
                            'name' => '',
                            'meta-category' => $otherEventText,
                            'category' => $otherEventText,
                            'type' => '',
                            'value' => '',
                            'uuid' => $reference['referenced_uuid']
                        ];
                    }
                }
                $object['ObjectReference'] = $objectReferences;
            }
        }
    }

    /**
     * Faster way how to attach tags to events that integrated in CakePHP.
     * @param array $events
     * @param bool $excludeLocalTags
     */
    private function __attachAttributeTags(array &$events, $excludeLocalTags = false)
    {
        $eventIds = array_column($events, 'id');
        $conditions = ['AttributeTags.event_id IN' => $eventIds];
        if ($excludeLocalTags) {
            $conditions['AttributeTags.local'] = false;
        }
        $ats = $this->Attributes->AttributeTags->find(
            'all',
            [
                'conditions' => $conditions,
                'fields' => ['AttributeTags.id', 'AttributeTags.attribute_id', 'AttributeTags.tag_id', 'AttributeTags.local', 'AttributeTags.relationship_type'], // we don't need id or event_id
                'recursive' => -1,
            ]
        );
        if (empty($ats)) {
            foreach ($events as &$event) {
                foreach ($event['Attribute'] as &$attribute) {
                    $attribute['AttributeTag'] = [];
                }
            }
            return;
        }
        $atForAttributes = [];
        foreach ($ats as $at) {
            $atForAttributes[$at['AttributeTag']['attribute_id']][] = $at['AttributeTag'];
        }
        foreach ($events as &$event) {
            foreach ($event['Attribute'] as &$attribute) {
                $attribute['AttributeTag'] = $atForAttributes[$attribute['id']] ?? [];
            }
        }
    }

    /**
     * Get tag from cache by given ID.
     *
     * @param int $tagId
     * @param bool $justExportable If true, return just exportable tags.
     * @return array|null
     */
    private function __getCachedTag($tagId, $justExportable)
    {
        if (!isset($this->assetCache['tags'][$tagId])) {
            return null;
        }
        $tag = $this->assetCache['tags'][$tagId];
        if ($justExportable && !$tag['exportable']) {
            return null;
        }
        return $tag;
    }

    /**
     * Fetches all tags for event and event attributes in one query and save to cache.
     *
     * @param array $event
     * @param bool $justExportable If true, cache just exportable tags.
     */
    private function __precacheTagsForEvent(array $event, $justExportable)
    {
        $tagIds = [];
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                $tagIds[$eventTag['tag_id']] = true;
            }
        }

        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                foreach ($attribute['AttributeTag'] as $attributeTag) {
                    $tagIds[$attributeTag['tag_id']] = true;
                }
            }
        }

        $notCachedTags = array_diff_key($tagIds, $this->assetCache['tags'] ?? []);
        if (empty($notCachedTags)) {
            return;
        }
        $conditions = ['Tags.id IN' => array_keys($notCachedTags)];
        if ($justExportable) {
            $conditions['Tags.exportable'] = 1;
        }
        $tags = $this->EventTags->Tags->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => $conditions,
            ]
        );
        foreach ($tags as $tag) {
            $this->assetCache['tags'][$tag['id']] = $tag;
        }
    }

    /**
     * Attach tags to attributes and Events.
     *
     * @param array $event
     * @param bool $justExportable If true, attach just exportable tags.
     */
    private function __attachTags(array &$event, $justExportable)
    {
        $this->__precacheTagsForEvent($event, $justExportable);

        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $etk => $eventTag) {
                $tag = $this->__getCachedTag($eventTag['tag_id'], $justExportable);
                if ($tag !== null) {
                    $tag['local'] = empty($eventTag['local']) ? 0 : 1;
                    $tag['relationship_type'] = empty($eventTag['relationship_type']) ? null : $eventTag['relationship_type'];
                    $event['EventTag'][$etk]['Tag'] = $tag;
                } else {
                    unset($event['EventTag'][$etk]);
                }
            }
            $event['EventTag'] = array_values($event['EventTag']);
        }
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $ak => $attribute) {
                if (!empty($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $atk => $attributeTag) {
                        $tag = $this->__getCachedTag($attributeTag['tag_id'], $justExportable);
                        if ($tag !== null) {
                            $tag['local'] = empty($attributeTag['local']) ? 0 : 1;
                            $tag['relationship_type'] = empty($attributeTag['relationship_type']) ? null : $attributeTag['relationship_type'];
                            $event['Attribute'][$ak]['AttributeTag'][$atk]['Tag'] = $tag;
                        } else {
                            unset($event['Attribute'][$ak]['AttributeTag'][$atk]);
                        }
                    }
                    $event['Attribute'][$ak]['AttributeTag'] = array_values($event['Attribute'][$ak]['AttributeTag']);
                }
            }
        }
    }


    public function restSearchFilterMassage($filters, $non_restrictive_export, $user)
    {
        if (!empty($filters['ignore'])) {
            $filters['to_ids'] = [0, 1];
            $filters['published'] = [0, 1];
        }
        if (!empty($filters['quickFilter'])) {
            $filters['searchall'] = $filters['quickFilter'];
            if (!empty($filters['value'])) {
                unset($filters['value']);
            }
        }
        if (isset($filters['searchall'])) {
            if (!empty($filters['value'])) {
                $filters['wildcard'] = $filters['value'];
            } else {
                $filters['wildcard'] = $filters['searchall'];
            }
        }

        if (isset($filters['tag']) and !isset($filters['tags'])) {
            $filters['tags'] = $filters['tag'];
        }
        if (!empty($filters['withAttachments'])) {
            $filters['includeAttachments'] = 1;
        }
        if (empty($non_restrictive_export)) {
            if (!isset($filters['to_ids'])) {
                $filters['to_ids'] = 1;
            }
            if (!isset($filters['published'])) {
                $filters['published'] = 1;
            }
            $filters['allow_proposal_blocking'] = 1;
        }
        $subqueryElements = $this->harvestSubqueryElements($filters);
        $filters = $this->addFiltersFromSubqueryElements($filters, $subqueryElements, $user);
        return $filters;
    }

    /**
     * @param array $user
     * @param string $returnFormat
     * @param array $filters
     * @param bool $paramsOnly
     * @param int|false $jobId
     * @param int $elementCounter
     * @param bool $renderView
     * @return TmpFileTool
     * @throws Exception
     */
    public function restSearch(array $user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        $exportTool = new $this->validFormats[$returnFormat][1]();

        if ($jobId) {
            $JobsTable = $this->fetchTable('Jobs');
        }

        if (method_exists($exportTool, 'setDefaultFilters')) {
            $exportTool->setDefaultFilters($filters);
        }

        if (!empty($exportTool->renderView)) {
            $renderView = $exportTool->renderView;
        }
        $non_restrictive_export = !empty($exportTool->non_restrictive_export);
        $filters = $this->restSearchFilterMassage($filters, $non_restrictive_export, $user);

        $filters = $this->addFiltersFromUserSettings($user, $filters);
        if (empty($exportTool->mock_query_only)) {
            $filters['include_attribute_count'] = 1;
            $eventid = $this->filterEventIds($user, $filters, $elementCounter);
            $eventCount = count($eventid);
            $eventids_chunked = $this->clusterEventIds($exportTool, $eventid);
            unset($eventid);
        } else {
            $eventids_chunked = [];
        }
        if (!empty($exportTool->additional_params)) {
            $filters = array_merge($filters, $exportTool->additional_params);
        }
        $exportToolParams = [
            'user' => $user,
            'params' => [],
            'returnFormat' => $returnFormat,
            'scope' => 'Event',
            'filters' => $filters
        ];
        if (empty($exportTool->non_restrictive_export)) {
            if (!isset($filters['to_ids'])) {
                $filters['to_ids'] = 1;
            }
            if (!isset($filters['published'])) {
                $filters['published'] = 1;
            }
        }
        $tmpfile = new TmpFileTool();
        $tmpfile->write($exportTool->header($exportToolParams));
        $i = 0;
        $AllowedlistsTable = $this->fetchTable('Allowedlists');
        $separator = $exportTool->separator($exportToolParams);
        unset($filters['page']);
        unset($filters['limit']);
        foreach ($eventids_chunked as $chunk) {
            $filters['eventid'] = $chunk;
            if (!empty($filters['tags']['NOT'])) {
                $filters['blockedAttributeTags'] = $filters['tags']['NOT'];
                unset($filters['tags']['NOT']);
            }
            $result = $this->fetchEvent($user, $filters, true);
            $result = $AllowedlistsTable->removeAllowedlistedFromArray($result, false);
            foreach ($result as $event) {
                if ($jobId && $i % 10 == 0) {
                    $JobsTable->saveField('progress', intval((100 * $i) / $eventCount));
                    $JobsTable->saveField('message', 'Converting Event ' . $i . '/' . $eventCount . '.');
                }
                $temp = $exportTool->handler($event, $exportToolParams);
                if ($temp !== '') {
                    $tmpfile->writeWithSeparator($temp, $separator);
                    $i++;
                }
            }
        }
        $footer = $exportTool->footer($exportToolParams);
        if ($footer instanceof TmpFileTool) {
            return $footer; // Some exports returns TmpFileTool with all data when ends, so we can just pass the file as output
        }

        $tmpfile->write($footer);
        return $tmpfile;
    }

    /*
     *  Receive a list of eventids in the id=>count format
     *  Chunk them by the attribute count to fit the memory limits
     *
     */
    public function clusterEventIds($exportTool, $eventIds)
    {
        $memory_in_mb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
        $default_attribute_memory_coefficient = Configure::check('MISP.default_attribute_memory_coefficient') ? Configure::read('MISP.default_attribute_memory_coefficient') : 80;
        $default_event_memory_divisor = Configure::check('MISP.default_event_memory_multiplier') ? Configure::read('MISP.default_event_memory_divisor') : 3;
        $memory_scaling_factor = isset($exportTool->memory_scaling_factor) ? $exportTool->memory_scaling_factor : $default_attribute_memory_coefficient;
        // increase the cost per attribute to account for the overhead of object metadata
        $memory_scaling_factor = $memory_scaling_factor / $default_event_memory_divisor;
        $limit = $memory_in_mb * $memory_scaling_factor;
        $eventIdList = [];
        $continue = true;
        $i = 0;
        $current_chunk_size = 0;
        $largest_event = 0;
        $largest_event_id = 0;
        foreach ($eventIds as $id => $count) {
            if ($count > $largest_event) {
                $largest_event = $count;
                $largest_event_id = $id;
            }
            if ($current_chunk_size == 0 && $count > $limit) {
                $eventIdList[$i][] = $id;
                $current_chunk_size = $count;
                $i++;
            } else {
                if (($current_chunk_size + $count) > $limit) {
                    $i++;
                    $eventIdList[$i][] = $id;
                    $current_chunk_size = $count;
                } else {
                    $current_chunk_size += $count;
                    $eventIdList[$i][] = $id;
                }
            }
        }
        if ($largest_event / $memory_scaling_factor > $memory_in_mb) {
            $LogsTable = $this->fetchTable('Logs');
            $LogsTable->saveOrFailSilently(
                [
                    'org' => 'SYSTEM',
                    'model' => 'Event',
                    'model_id' => 0,
                    'email' => 'SYSTEM',
                    'action' => 'error',
                    'title' => sprintf('Event fetch potential memory exhaustion.' . PHP_EOL . 'During the fetching of events, a large event (#%s) was detected that exceeds the available PHP memory.' . PHP_EOL . 'Consider raising the PHP max_memory setting to at least %sM', $largest_event_id, ceil($largest_event / $memory_scaling_factor)),
                    'change' => null,
                ]
            );
        }
        return $eventIdList;
    }

    /**
     * @param string $file File content
     * @param string $original_filename
     * @param int $event_id
     * @param string $format
     * @return bool
     * @throws Exception
     */
    public function add_original_file($file, $original_filename, $event_id, $format)
    {
        $distribution = $this->Attributes->defaultDistribution();
        $object = $this->Objects->newEntity(
            [
                'name' => 'original-imported-file',
                'meta-category' => 'file',
                'description' => 'Object describing the original file used to import data in MISP.',
                'template_uuid' => '4cd560e9-2cfe-40a1-9964-7b2e797ecac5',
                'template_version' => '2',
                'event_id' => $event_id,
                'distribution' => $distribution
            ]
        );
        if (!$this->Objects->save($object)) {
            throw new Exception("Could not save object for original file because of validation errors:" . json_encode($object->getErrors()));
        }
        $object_id = $object->id;
        $attributes = [
            [
                'type' => 'attachment',
                'category' => 'External analysis',
                'to_ids' => false,
                'event_id' => $event_id,
                'distribution' => $distribution,
                'object_relation' => 'imported-sample',
                'value' => $original_filename,
                'data_raw' => $file,
                'object_id' => $object_id,
                'disable_correlation' => true
            ],
            [
                'type' => 'text',
                'category' => 'Other',
                'to_ids' => false,
                'event_id' => $event_id,
                'distribution' => $distribution,
                'object_id' => $object_id,
                'object_relation' => 'format',
                'value' => $format,
                'disable_correlation' => true
            ]
        ];
        if (!$this->Attributes->saveMany($attributes)) {
            throw new Exception("Could not save attributes for original file because of validation errors:" . json_encode($this->Attributes->validationErrors));
        }
        return true;
    }

    private function getRequiredTaxonomies()
    {
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        return $TaxonomiesTable->find(
            'column',
            [
                'conditions' => ['required' => 1, 'enabled' => 1],
                'fields' => ['namespace']
            ]
        )->toArray();
    }

    public function missingTaxonomies(array $event)
    {
        $requiredTaxonomies = $this->getRequiredTaxonomies();
        return $this->checkMissingTaxonomies($requiredTaxonomies, $event['EventTag']);
    }

    public function checkIfPublishable($id)
    {
        $requiredTaxonomies = $this->getRequiredTaxonomies();
        if (!empty($requiredTaxonomies)) {
            $eventTags = $this->EventTag->find(
                'all',
                [
                    'conditions' => ['EventTag.event_id' => $id],
                    'recursive' => -1,
                    'contain' => ['Tag' => ['fields' => ['name']]]
                ]
            );
            $missing = $this->checkMissingTaxonomies($requiredTaxonomies, $eventTags);
            if (!empty($missing)) {
                return $missing;
            }
        }
        return true;
    }

    /**
     * @param array $requiredTaxonomies
     * @param array $eventTags
     * @return array
     */
    private function checkMissingTaxonomies(array $requiredTaxonomies, array $eventTags)
    {
        $missing = [];
        foreach ($requiredTaxonomies as $requiredTaxonomy) {
            $found = false;
            foreach ($eventTags as $tag) {
                $splits = $this->Taxonomy->splitTagToComponents($tag['Tag']['name']);
                if ($splits !== null && $splits['namespace'] === $requiredTaxonomy) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $missing[] = $requiredTaxonomy;
            }
        }
        return $missing;
    }

    public function harvestSubqueryElements($options)
    {
        $acceptedRules = [
            'galaxy' => 1,
            'org' => ['sector', 'local', 'nationality']
        ];
        $subqueryElement = [
            'galaxy' => [],
            'org' => [],
        ];
        foreach ($options as $rule => $value) {
            $split = explode(".", $rule, 2);
            if (count($split) > 1) {
                $scope = $split[0];
                $element = $split[1];
                if (isset($acceptedRules[$scope])) {
                    if (is_array($acceptedRules[$scope]) && !in_array($element, $acceptedRules[$scope])) {
                        continue;
                    } else {
                        $subqueryElement[$scope][$element] = $value;
                    }
                }
            }
        }
        return $subqueryElement;
    }

    public function addFiltersFromSubqueryElements($filters, $subqueryElements, $user)
    {
        if (!empty($subqueryElements['galaxy'])) {
            $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
            $tagsFromGalaxyMeta = $GalaxyClustersTable->getClusterTagsFromMeta($subqueryElements['galaxy'], $user);
            if (empty($tagsFromGalaxyMeta)) {
                $filters['eventid'] = -1;
            }
            if (!empty($filters['tags'])) {
                $filters['tags'][] = $tagsFromGalaxyMeta;
            } else {
                $filters['tags'] = $tagsFromGalaxyMeta;
            }
        }
        if (!empty($subqueryElements['org'])) {
            $OrganisationsTable = $this->fetchTable('Organisations');
            $orgcIdsFromMeta = $OrganisationsTable->getOrgIdsFromMeta($subqueryElements['org']);
            if (!empty($filters['org'])) {
                $filters['org'][] = $orgcIdsFromMeta;
            } else {
                $filters['org'] = $orgcIdsFromMeta;
            }
        }
        return $filters;
    }

    public function addFiltersFromUserSettings($user, $filters)
    {
        $UserSettingsTable = $this->fetchTable('UserSettings');
        $defaultParameters = $UserSettingsTable->getDefaultRestSearchParameters($user);
        $filters = array_replace_recursive($defaultParameters, $filters);
        return $filters;
    }

    /**
     * @param array $event
     */
    public function removeGalaxyClusterTags(array &$event)
    {
        $galaxyTagIds = [];
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                $galaxyTagIds[$galaxyCluster['tag_id']] = true;
            }
        }

        if (empty($galaxyTagIds)) {
            return;
        }

        foreach ($event['EventTag'] as $k => $eventTag) {
            if (isset($galaxyTagIds[$eventTag['tag_id']])) {
                unset($event['EventTag'][$k]);
            }
        }
    }

    /**
     * Returns all tag names attached to any elements in an event
     *
     * @param  array $event
     * @return array All tag names in the event with tag name in key and also in value
     */
    public function extractAllTagNames(array $event)
    {
        $tags = [];
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                $tagName = $eventTag['Tag']['name'];
                $tags[$tagName] = $tagName;
            }
        }
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                foreach ($attribute['AttributeTag'] as $attributeTag) {
                    $tagName = $attributeTag['Tag']['name'];
                    $tags[$tagName] = $tagName;
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $object) {
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        foreach ($attribute['AttributeTag'] as $attributeTag) {
                            $tagName = $attributeTag['Tag']['name'];
                            $tags[$tagName] = $tagName;
                        }
                    }
                }
            }
        }
        return $tags;
    }

    public function recoverEvent($id)
    {
        $LogsTable = $this->fetchTable('Logs');
        $result = $LogsTable->recoverDeletedEvent($id);
        return $result;
    }

    /**
     * @param array $event Event with assigned `EventTag`
     * @return string
     */
    private function getEmailSubjectMarkForEvent(array $event)
    {
        $subjTag = Configure::read('MISP.email_subject_tag') ?: "tlp";
        $tagLen = strlen($subjTag);
        foreach ($event['EventTag'] as $tag) {
            $tagName = $tag['Tag']['name'];
            if (strncasecmp($subjTag, $tagName, $tagLen) === 0 && strlen($tagName) > $tagLen && ($tagName[$tagLen] === ':' || $tagName[$tagLen] === '=')) {
                if (Configure::read('MISP.email_subject_include_tag_name') === false) {
                    return trim(substr($tagName, $tagLen + 1), '"');
                } else {
                    return $tagName;
                }
            }
        }

        // default value if no match found
        return Configure::read('MISP.email_subject_TLP_string') ?: "tlp:amber";
    }

    public function getExtendingEventIdsFromEvent($user, $eventID)
    {
        $event = $this->fetchSimpleEvent($user, $eventID);
        if (!empty($event)) {
            $extendingEventIds = $this->fetchSimpleEventIds(
                $user,
                [
                    'conditions' => [
                        'extends_uuid' => $event['uuid']
                    ]

                ]
            );
            return $extendingEventIds;
        }
        return [];
    }

    public function getEventRepublishBanStatus($eventID)
    {
        $banStatus = [
            'error' => false,
            'active' => false,
            'message' => __('Event publish is not banned')
        ];
        if (Configure::read('MISP.event_alert_republish_ban')) {
            $event = $this->find(
                'all',
                [
                    'conditions' => ['id' => $eventID],
                    'recursive' => -1,
                    'fields' => ['uuid']
                ]
            )->first();
            if (empty($event)) {
                $banStatus['error'] = true;
                $banStatus['active'] = true;
                $banStatus['message'] = __('Event not found');
                return $banStatus;
            }
            $banThresholdMinutes = intval(Configure::read('MISP.event_alert_republish_ban_threshold'));
            $banThresholdSeconds = 60 * $banThresholdMinutes;
            $redis = $this->setupRedis();
            if ($redis === false) {
                $banStatus['error'] = true;
                $banStatus['active'] = true;
                $banStatus['message'] =  __('Reason: Could not reach redis to check republish emailing ban status.');
                return $banStatus;
            }
            $redisKey = "misp:event_alert_republish_ban:{$event['uuid']}";
            $banLiftTimestamp = $redis->get($redisKey);
            if (!empty($banLiftTimestamp)) {
                $remainingMinutes = (intval($banLiftTimestamp) - time()) / 60;
                $banStatus['active'] = true;
                if (Configure::read('MISP.event_alert_republish_ban_refresh_on_retry')) {
                    $redis->multi(\Redis::PIPELINE)
                        ->set($redisKey, time() + $banThresholdSeconds)
                        ->expire($redisKey, $banThresholdSeconds)
                        ->exec();
                    $banStatus['message'] = __('Reason: Event is banned from sending out emails. Ban has been refreshed and will be lifted in %smin', $banThresholdMinutes);
                } else {
                    $banStatus['message'] = __('Reason: Event is banned from sending out emails. Ban will be lifted in %smin %ssec.', floor($remainingMinutes), $remainingMinutes % 60);
                }
                return $banStatus;
            } else {
                $redis->multi(\Redis::PIPELINE)
                    ->set($redisKey, time() + $banThresholdSeconds)
                    ->expire($redisKey, $banThresholdSeconds)
                    ->exec();
                return $banStatus;
            }
        }
        $banStatus['message'] = __('Emailing republishing ban setting is not enabled');
        return $banStatus;
    }

    /**
     * @return array[]
     * @deprecated
     */
    public function exportTypes()
    {
        return [
            'json' => [
                'extension' => '.json',
                'type' => 'JSON',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => ['includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'json'],
                'description' => __('Click this to download all events and attributes that you have access to in MISP JSON format.'),
            ],
            'xml' => [
                'extension' => '.xml',
                'type' => 'XML',
                'scope' => 'Event',
                'params' => ['includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'xml'],
                'requiresPublished' => 0,
                'description' => __('Click this to download all events and attributes that you have access to in MISP XML format.'),
            ],
            'csv_sig' => [
                'extension' => '.csv',
                'type' => 'CSV_Sig',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['published' => 1, 'to_ids' => 1, 'returnFormat' => 'csv'],
                'description' => __('Click this to download all attributes that are indicators and that you have access to (except file attachments) in CSV format.'),
            ],
            'csv_all' => [
                'extension' => '.csv',
                'type' => 'CSV_All',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => ['ignore' => 1, 'returnFormat' => 'csv'],
                'description' => __('Click this to download all attributes that you have access to (except file attachments) in CSV format.'),
            ],
            'suricata' => [
                'extension' => '.rules',
                'type' => 'Suricata',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'suricata'],
                'description' => __('Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'snort' => [
                'extension' => '.rules',
                'type' => 'Snort',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'snort'],
                'description' => __('Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'bro' => [
                'extension' => '.intel',
                'type' => 'Bro',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'bro'],
                'description' => __('Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'stix' => [
                'extension' => '.xml',
                'type' => 'STIX',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'stix', 'includeAttachments' => 1],
                'description' => __('Click this to download a STIX document containing the STIX version of all events and attributes that you have access to.')
            ],
            'stix2' => [
                'extension' => '.json',
                'type' => 'STIX2',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'stix2', 'includeAttachments' => 1],
                'description' => __('Click this to download a STIX2 document containing the STIX2 version of all events and attributes that you have access to.')
            ],
            'rpz' => [
                'extension' => '.txt',
                'type' => 'RPZ',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'rpz'],
                'description' => __('Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.')
            ],
            'text' => [
                'extension' => '.txt',
                'type' => 'TEXT',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'text', 'includeAttachments' => 1],
                'description' => __('Click on one of the buttons below to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.')
            ],
            'yara' => [
                'extension' => '.yara',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'yara'],
                'description' => __('Click this to download Yara rules generated from all relevant attributes.')
            ],
            'yara-json' => [
                'extension' => '.json',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'yara-json'],
                'description' => __('Click this to download Yara rules generated from all relevant attributes. Rules are returned in a JSON format with information about origin (generated or parsed) and validity.')
            ],
        ];
    }

    private function __prepareEventForPubSub($id, $user, &$fullEvent)
    {
        if ($fullEvent) {
            if (empty(Configure::read('Plugin.ZeroMQ_include_attachments'))) {
                if (!empty($fullEvent[0]['Attribute'])) {
                    foreach ($fullEvent[0]['Attribute'] as $k => $attribute) {
                        if (isset($attribute['data'])) {
                            unset($fullEvent[0]['Attribute'][$k]['data']);
                        }
                    }
                }
                if (!empty($fullEvent[0]['Object'])) {
                    foreach ($fullEvent[0]['Object'] as $k => $object) {
                        if (!empty($object['Attribute'])) {
                            foreach ($object['Attribute'] as $k2 => $attribute) {
                                if (isset($attribute['data'])) {
                                    unset($fullEvent[0]['Object'][$k]['Attribute'][$k2]['data']);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            $params = [
                'eventid' => $id
            ];
            if (Configure::read('Plugin.ZeroMQ_include_attachments')) {
                $params['includeAttachments'] = 1;
            }
            $fullEvent = $this->fetchEvent($user, $params);
        }
        return $fullEvent;
    }

    public function publishEventToZmq($id, $user, &$fullEvent)
    {
        $fullEvent = $this->__prepareEventForPubSub($id, $user, $fullEvent);
        if (!empty($fullEvent)) {
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->publishEvent($fullEvent[0], 'publish');
        }
    }

    public function publishEventToKafka($id, $user, &$fullEvent, $kafkaTopic)
    {
        $fullEvent = $this->__prepareEventForPubSub($id, $user, $fullEvent);
        if (!empty($fullEvent)) {
            $kafkaPubTool = $this->getKafkaPubTool();
            $kafkaPubTool->publishJson($kafkaTopic, $fullEvent[0], 'publish');
        }
    }

    public function getTrendsForTags(array $user, array $eventFilters, int $baseDayRange, int $rollingWindows = 3, $tagFilterPrefixes = null): array
    {
        $fullDayNumber = $baseDayRange + $baseDayRange * $rollingWindows;
        $fullRange = $this->resolveTimeDelta($fullDayNumber . 'd');
        $eventFilters['last'] = $fullRange . 'd';
        $eventFilters['order'] = 'timestamp DESC';
        $events = $this->fetchEvent($user, $eventFilters);
        $trendingTool = new TrendingTool($this);
        $trendAnalysis = $trendingTool->getTrendsForTags($events, $baseDayRange, $rollingWindows, $tagFilterPrefixes);
        $clusteredTags = $trendAnalysis['clustered_tags'];
        $trendAnalysis = $trendAnalysis['trend_analysis'];
        return [
            'clustered_tags' => $trendAnalysis,
            'clustered_events' => $clusteredTags['eventNumberPerRollingWindow'],
            'all_tags' => $clusteredTags['allTagsPerPrefix'],
            'all_timestamps' => array_keys($clusteredTags['eventNumberPerRollingWindow']),
        ];
    }

    public function getTrendsForTagsFromEvents(array $events, int $baseDayRange, int $rollingWindows = 3, $tagFilterPrefixes = null): array
    {
        $oldestTimestamp = $this->resolveTimeDelta($baseDayRange + $baseDayRange * $rollingWindows . 'd');
        $events = array_filter(
            $events,
            function ($event) use ($oldestTimestamp) {
                // Filter out events having old modification compared to their publish_timestamp
                return $event['timestamp'] >= $oldestTimestamp;
            }
        );
        $trendingTool = new TrendingTool($this);
        $trendAnalysis = $trendingTool->getTrendsForTags($events, $baseDayRange, $rollingWindows, $tagFilterPrefixes);
        $clusteredTags = $trendAnalysis['clustered_tags'];
        $trendAnalysis = $trendAnalysis['trend_analysis'];
        return [
            'clustered_tags' => $trendAnalysis,
            'clustered_events' => $clusteredTags['eventNumberPerRollingWindow'],
            'all_tags' => $clusteredTags['allTagsPerPrefix'],
            'all_timestamps' => array_keys($clusteredTags['eventNumberPerRollingWindow']),
        ];
    }

    public function extractRelatedCourseOfActions(array $events): array
    {
        $mitre_attack_galaxy_type = 'mitre-attack-pattern';
        $mitre_coa_galaxy_type = 'mitre-course-of-action';
        $allowedRelationTypes = ['mitigates'];
        $coa = [];
        foreach ($events as $event) {
            foreach ($event['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    foreach ($cluster['GalaxyClusterRelation'] as $relation) {
                        if (in_array($relation['referenced_galaxy_cluster_type'], $allowedRelationTypes) && $relation['TargetCluster']['type'] == $mitre_coa_galaxy_type) {
                            if (!isset($coa[$relation['TargetCluster']['tag_name']])) {
                                $coa[$relation['TargetCluster']['tag_name']] = $relation['TargetCluster'];
                                $coa[$relation['TargetCluster']['tag_name']]['occurrence'] = 0;
                                $coa[$relation['TargetCluster']['tag_name']]['techniques'] = [];
                            }
                            $coa[$relation['TargetCluster']['tag_name']]['occurrence'] += 1;
                            if ($cluster['type'] == $mitre_attack_galaxy_type) {
                                $coa[$relation['TargetCluster']['tag_name']]['techniques'][$cluster['tag_name']] = $cluster;
                            }
                        }
                    }
                    if (!empty($cluster['TargetingClusterRelation'])) {
                        foreach ($cluster['TargetingClusterRelation'] as $relation) {
                            if (in_array($relation['referenced_galaxy_cluster_type'], $allowedRelationTypes) && $relation['GalaxyCluster']['type'] == $mitre_coa_galaxy_type) {
                                if (!isset($coa[$relation['GalaxyCluster']['tag_name']])) {
                                    $coa[$relation['GalaxyCluster']['tag_name']] = $relation['GalaxyCluster'];
                                    $coa[$relation['GalaxyCluster']['tag_name']]['techniques'] = [];
                                    $coa[$relation['GalaxyCluster']['tag_name']]['occurrence'] = 0;
                                }
                                $coa[$relation['GalaxyCluster']['tag_name']]['occurrence'] += 1;
                                if (
                                    $cluster['type'] == $mitre_attack_galaxy_type
                                ) {
                                    $coa[$relation['GalaxyCluster']['tag_name']]['techniques'][$cluster['tag_name']] = $cluster;
                                }
                            }
                        }
                    }
                }
            }
        }
        uasort(
            $coa,
            function ($a, $b) {
                return $a['occurrence'] > $b['occurrence'] ? -1 : 1;
            }
        );

        return $coa;
    }

    // /**
    //  * Low level function to add an Event based on an Event $data array.
    //  *
    //  * @param array $data
    //  * @param bool $fromXml
    //  * @param array $user
    //  * @param int $org_id
    //  * @param int|null $passAlong Server ID or null
    //  * @param bool $fromPull
    //  * @param int|null $jobId
    //  * @param int $created_id
    //  * @param array $validationErrors
    //  * @return bool|int|string True when new event was created, int when event with the same uuid already exists, string when validation errors
    //  * @throws Exception
    //  */
    // public function _add(array &$data, $fromXml, array $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = [])
    // {
    //     // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391

    //     // THIS IS A PLACEHOLDER !
    //     $data['Event']['user_id'] = $user['id'];
    //     if ($fromPull) {
    //         $data['Event']['org_id'] = $org_id;
    //     } else {
    //         $data['Event']['org_id'] = $user['Organisation']['id'];
    //     }
    //     if (!isset($data['Event']['orgc_id']) && !isset($data['Event']['orgc'])) {
    //         $data['Event']['orgc_id'] = $data['Event']['org_id'];
    //     }

    //     $event = $this->newEntity($data['Event']);
    //     $this->saveOrFail($event);

    //     return true;
    // }

    // public function _edit(array &$data, array $user, $id = null, $jobId = null, $passAlong = null, $force = false, $fast_update = false)
    // {
    //     // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391

    //     // THIS IS A PLACEHOLDER !
    //     return true;
    // }

    // public function fetchEvent($user, $options = [], $useCache = false)
    // {
    //     // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391

    //     // THIS IS A PLACEHOLDER !
    //     if (isset($options['event_uuid'])) {
    //         return $this->find(
    //             'all',
    //             [
    //                 'conditions' => [
    //                     'uuid' => $options['event_uuid']
    //                 ]
    //             ]
    //         )->disableHydration()->toArray();
    //     }

    //     return [];
    // }

    // /**
    //  * @param array $event
    //  * @param array $server
    //  * @param ServerSyncTool $serverSync
    //  * @return false|string
    //  * @throws HttpSocketJsonException
    //  * @throws JsonException
    //  * @throws Exception
    //  */
    // public function uploadEventToServer(array $event, array $server, ServerSyncTool $serverSync)
    // {
    //     // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391
    //     // THIS IS A PLACEHOLDER !

    //     $serverSync->pushEvent($event)->getJson();

    //     return 'Success';
    // }
}
