<?php
App::uses('AppModel', 'Model');
App::uses('TmpFileTool', 'Tools');
App::uses('ServerSyncTool', 'Tools');
App::uses('ProcessTool', 'Tools');
App::uses('JsonTool', 'Tools');

/**
 * @property MispAttribute $Attribute
 * @property Event $Event
 * @property Organisation $Organisation
 */
class Sighting extends AppModel
{
    const ONE_DAY = 86400; // in seconds

    // Possible values of `Plugin.Sightings_policy` setting
    const SIGHTING_POLICY_EVENT_OWNER = 0,
        SIGHTING_POLICY_SIGHTING_REPORTER = 1,
        SIGHTING_POLICY_EVERYONE = 2,
        SIGHTING_POLICY_HOST_ORG = 3; // the same as SIGHTING_POLICY_EVENT_OWNER, but also sightings from host org are visible

    private $orgCache = [];

    public $useTable = 'sightings';

    public $recursive = -1;

    private $__blockedOrgs = null;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'event_id' => 'numeric',
        'attribute_id' => 'numeric',
        'org_id' => 'numeric',
        'date_sighting' => 'numeric',
        'uuid' => 'uuid',
        'type' => array(
            'rule' => array('inList', array(0, 1, 2)),
            'message' => 'Invalid type. Valid options are: 0 (Sighting), 1 (False-positive), 2 (Expiration).'
        )
    );

    public $belongsTo = array(
            'Attribute' => [
                'className' => 'MispAttribute',
                'foreignKey' => 'attribute_id',
                'dependent' => false,
            ],
            'Event',
            'Organisation' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id'
            ),
    );

    const TYPE = array(
        0 => 'sighting',
        1 => 'false-positive',
        2 => 'expiration'
    );

    public $validFormats = array(
        'json' => array('json', 'JsonExport', 'json'),
        'xml' => array('xml', 'XmlExport', 'xml'),
        'csv' => array('csv', 'CsvExport', 'csv')
    );

    public function beforeValidate($options = array())
    {
        if (empty($this->data['Sighting']['id']) && empty($this->data['Sighting']['date_sighting'])) {
            $this->data['Sighting']['date_sighting'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['Sighting']['uuid'])) {
            $this->data['Sighting']['uuid'] = CakeText::uuid();
        } else {
            $this->data['Sighting']['uuid'] = strtolower($this->data['Sighting']['uuid']);
        }
        if ($this->__blockedOrgs === null) {
            $SightingBlocklist = ClassRegistry::init('SightingBlocklist');
            $this->__blockedOrgs = $SightingBlocklist->find('column', [
                'recursive' => -1,
                'fields' => ['org_uuid']
            ]);
        }
        if (!empty($this->data['Sighting']['org_uuid']) && in_array($this->data['Sighting']['org_uuid'], $this->__blockedOrgs)) {
            return false;
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $pubToZmq = $this->pubToZmq('sighting');
        $kafkaTopic = $this->kafkaTopic('sighting');
        $isTriggerCallable = $this->isTriggerCallable('sighting-after-save');
        if ($pubToZmq || $kafkaTopic || $isTriggerCallable) {
            $sighting = $this->getSighting($this->id);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->sighting_save($sighting, 'add');
            }
            if ($kafkaTopic) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $sighting, 'add');
            }

            if($isTriggerCallable) {
                $workflowErrors = [];
                $logging = [
                    'model' => 'Sighting',
                    'action' => $created ? 'add' : 'edit',
                    'id' => $sighting['Sighting']['id'],
                ];
                $triggerData = $sighting;
                $this->executeTrigger('sighting-after-save', $triggerData, $workflowErrors, $logging);
            }
        }
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        $pubToZmq = $this->pubToZmq('sighting');
        $kafkaTopic = $this->kafkaTopic('sighting');
        if ($pubToZmq || $kafkaTopic) {
            $sighting = $this->getSighting($this->id);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->sighting_save($sighting, 'delete');
            }
            if ($kafkaTopic) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $sighting, 'delete');
            }
        }
    }

    /**
     * @param array $sightings
     * @param int|null $attributeId
     * @param int $eventId
     * @param array $user
     * @return bool
     */
    public function captureSightings(array $sightings, $attributeId, $eventId, array $user)
    {
        // Since sightings are immutable (it is not possible to change it from web interface), we can check
        // if sighting with given uuid already exists and skip them
        $existingSighting = $this->existing($sightings);

        // Fetch existing organisations in bulk
        $existingOrganisations = $this->existingOrganisations($sightings);

        if ($attributeId === null) {
            // If attribute ID is not set, check real ID and also check if user can access that attribute
            $attributes = $this->Attribute->fetchAttributesSimple($user, [
                'conditions' => [
                    'Attribute.uuid' => array_column($sightings, 'attribute_uuid'),
                    'Attribute.event_id' => $eventId,
                ],
                'fields' => ['Attribute.id', 'Attribute.uuid'],
            ]);
            $attributes = array_column(array_column($attributes, 'Attribute'), 'id', 'uuid');
        }

        $toSave = [];
        foreach ($sightings as $sighting) {
            if (!empty($sighting['uuid']) && isset($existingSighting[$sighting['uuid']])) {
                continue; // already exists, skip
            }

            if ($attributeId === null) {
                if (isset($attributes[$sighting['attribute_uuid']])) {
                    $sighting['attribute_id'] = $attributes[$sighting['attribute_uuid']];
                } else {
                    continue; // attribute not exists ar user don't have permission to access it
                }
            } else {
                $sighting['attribute_id'] = $attributeId;
            }

            $orgId = 0;
            if (isset($sighting['Organisation'])) {
                if (isset($existingOrganisations[$sighting['Organisation']['uuid']])) {
                    $orgId = $existingOrganisations[$sighting['Organisation']['uuid']];
                } else {
                    $orgId = $this->Organisation->captureOrg($sighting['Organisation'], $user);
                }
            } else if (isset($user['org_id'])) {
                $orgId = $user['org_id'];
            }
            unset($sighting['id']);

            $sighting['org_id'] = $orgId;
            $sighting['event_id'] = $eventId;
            $toSave[] = $sighting;
        }

        return $this->saveMany($toSave);
    }

    /**
     * Fetch sightings with proper ACL checks
     *
     * @param array $user
     * @param array $ids Sightings IDs
     * @param bool $includeEvent
     * @param bool $includeAttribute
     * @param bool $includeUuid Add attribute and event UUID to sighting
     * @return array
     */
    private function getSightings(array $user, array $ids, $includeEvent = true, $includeAttribute = false, $includeUuid = false)
    {
        $eventFields = $includeEvent ? ['Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.org_id', 'Event.info'] : ['Event.org_id'];
        if ($includeUuid && !$includeEvent) {
            $eventFields[] = 'Event.uuid';
        }

        $attributeFields = $includeAttribute ? ['Attribute.id', 'Attribute.value','Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.to_ids'] : ['Attribute.id', 'Attribute.value'];
        if ($includeUuid && !$includeAttribute) {
            $attributeFields[] = 'Attribute.uuid';
        }

        // Fetch all attributes that are connected to sightings and user can see them
        $attributeConditions = $this->Attribute->buildConditions($user);
        $subQueryOptions = [
            'fields' => ['DISTINCT Sighting.attribute_id'],
            'conditions' => ['Sighting.id' => $ids],
        ];
        $attributeConditions[] = $this->subQueryGenerator($this, $subQueryOptions, 'Attribute.id');
        $attributes = $this->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => $attributeConditions,
            'contain' => [
                'Event' => [
                    'fields' => $eventFields,
                ],
                'Object',
            ],
            'fields' => $attributeFields,
            'order' => [],
        ]);

        if (empty($attributes)) {
            return [];
        }

        $sightings = $this->filterSightingsByAttributeACL($user, $attributes, $ids);

        if (empty($sightings)) {
            return [];
        }

        $attributesById = [];
        foreach ($attributes as $attribute) {
            $attributesById[$attribute['Attribute']['id']] = $attribute;
        }

        $anonymise = Configure::read('Plugin.Sightings_anonymise');
        $results = [];
        foreach ($sightings as $sighting) {
            $sightingAttribute = $attributesById[$sighting['Sighting']['attribute_id']];

            if ($anonymise && $sighting['Sighting']['org_id'] != $user['org_id']) {
                unset($sighting['Sighting']['org_id']);
            }

            // rearrange it to match the event format of fetchevent
            $result = $sighting['Sighting'];
            $result['value'] = $sightingAttribute['Attribute']['value'];
            if ($includeUuid) {
                $result['attribute_uuid'] = $sightingAttribute['Attribute']['uuid'];
                $result['event_uuid'] = $sightingAttribute['Event']['uuid'];
            }
            if ($includeAttribute) {
                $result['Attribute'] = $sightingAttribute['Attribute'];
            }
            if ($includeEvent) {
                $sightingAttribute['Event']['Orgc']['name'] = $this->getOrganisationById($sightingAttribute['Event']['orgc_id'])['name'];
                $result['Event'] = $sightingAttribute['Event'];
            }
            if (isset($result['org_id']) && $result['org_id'] != 0) {
                $result['Organisation'] = $this->getOrganisationById($result['org_id']);
            }
            $results[] = ['Sighting' => $result];
        }

        return $results;
    }

    /**
     * Return sighting without ACL checks
     *
     * @param int $id
     * @return array
     */
    public function getSighting($id)
    {
        $sighting = $this->find('first', array(
            'recursive' => -1,
            'contain' => array(
                'Attribute' => array(
                    'fields' => array('Attribute.value', 'Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.to_ids')
                ),
                'Event' => array(
                    'fields' => ['Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.org_id', 'Event.info'],
                )
            ),
            'conditions' => array('Sighting.id' => $id)
        ));
        if (empty($sighting)) {
            return array();
        }

        // Put event organisation name from cache
        $sighting['Event']['Orgc']['name'] = $this->getOrganisationById($sighting['Event']['orgc_id'])['name'];

        // rearrange it to match the event format of fetchevent
        $result = array(
            'Sighting' => $sighting['Sighting']
        );
        $result['Sighting']['Event'] = $sighting['Event'];
        $result['Sighting']['Attribute'] = $sighting['Attribute'];
        return $result;
    }

    /**
     * @param array $tagIds
     * @param array $user
     * @param null|string $type
     * @return array
     */
    public function tagsSparkline(array $tagIds, array $user, $type = null)
    {
        if (empty($tagIds)) {
            return [];
        }

        $conditions = ['Sighting.date_sighting >' => $this->getMaximumRange()];
        if ($type !== null) {
            $conditions['Sighting.type'] = $type;
        }
        $sightingsPolicy = $this->sightingsPolicy();
        if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
            $conditions['Sighting.org_id'] = $user['org_id'];
        } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
            $conditions['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
        }
        // TODO: Currently, we dont support `SIGHTING_POLICY_SIGHTING_REPORTER` for tags
        $sparklineData = [];
        foreach (['event', 'attribute'] as $context) {
            $sightings = $this->fetchGroupedSightingsForTags($tagIds, $conditions, $context);
            $objectElement = ucfirst($context) . 'Tag';
            foreach ($sightings as $sighting) {
                $tagId = $sighting[$objectElement]['tag_id'];
                $date = $sighting['Sighting']['date'];
                $count = (int)$sighting['Sighting']['sighting_count'];

                if (isset($sparklineData[$tagId][$date]['sighting'])) {
                    $sparklineData[$tagId][$date]['sighting'] += $count;
                } else {
                    $sparklineData[$tagId][$date]['sighting'] = $count;
                }
            }
        }
        return $this->generateSparkline($sparklineData, false);
    }

    /**
     * @param array $attributes Attribute must contain Event
     * @param array $user
     * @param bool $csvWithFalsePositive
     * @return array[]
     */
    public function attributesStatistics(array $attributes, array $user, $csvWithFalsePositive = false)
    {
        if (empty($attributes)) {
            return ['data' => [], 'csv' => []];
        }

        $conditions = $this->createConditionsByAttributes($user, $attributes);
        $groupedSightings = $this->fetchGroupedSightings($conditions, $user);
        return $this->generateStatistics($groupedSightings, $csvWithFalsePositive);
    }

    /**
     * @param array $user
     * @param array $attributes Attributes with `Attribute.id`, `Event.id` and `Event.org_id` fields
     * @param array $ids
     * @return array
     */
    private function filterSightingsByAttributeACL(array $user, array $attributes, array $ids)
    {
        $sightingsPolicy = $this->sightingsPolicy();
        $attributesKeyed = [];
        $hostOrgId = Configure::read('MISP.host_org_id');
        $userOrgId = $user['org_id'];
        foreach ($attributes as $attribute) {
            $attributesKeyed[$attribute['Attribute']['id']] = $attribute;
        }
        unset($attributes);
        $sightings = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'Sighting.id' => $ids
            ],
            'order' => 'Sighting.id'
        ]);
        foreach ($sightings as $k => $sighting) {
            $attribute = $attributesKeyed[$sighting['Sighting']['attribute_id']];
            $ownEvent = $attribute['Event']['org_id'] == $userOrgId;
            if (!$ownEvent) {
                if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                    if ($sighting['Sighting']['org_id'] != $userOrgId) {
                        unset($sightings[$k]);
                    }
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                    if (!$this->isreporter($attribute['Event']['id'], $userOrgId)) {
                        unset($sightings[$k]);
                    }
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                    if (!in_array($sighting['Sighting']['org_id'], [$userOrgId, $hostOrgId])) {
                        unset($sightings[$k]);
                    }
                }
            }
        }
        return array_values($sightings);
    }

    /**
     * @param array $user
     * @param array $attributes Attributes with `Attribute.id`, `Event.id` and `Event.org_id` fields
     * @return array
     */
    private function createConditionsByAttributes(array $user, array $attributes)
    {
        $sightingsPolicy = $this->sightingsPolicy();

        if ($sightingsPolicy === self::SIGHTING_POLICY_EVERYONE || $user['Role']['perm_site_admin']) {
            return ['Sighting.attribute_id' => array_column(array_column($attributes, 'Attribute'), 'id')];
        }

        // Merge attributes by Event ID
        $userOrgId = $user['org_id'];
        $attributesByEventId = [];
        foreach ($attributes as $attribute) {
            $eventId = $attribute['Event']['id'];
            if (isset($attributesByEventId[$eventId])) {
                $attributesByEventId[$eventId]['ids'][] = $attribute['Attribute']['id'];
            } else {
                $ownEvent = $attribute['Event']['org_id'] == $userOrgId;
                $attributesByEventId[$eventId] = [
                    'ids' => [$attribute['Attribute']['id']],
                    'ownEvent' => $ownEvent,
                ];
            }
        }

        // Create conditions for merged attributes
        $hostOrgId = Configure::read('MISP.host_org_id');
        $conditions = [];
        foreach ($attributesByEventId as $eventId => $eventAttributes) {
            $attributeConditions = ['Sighting.attribute_id' => $eventAttributes['ids']];
            if (!$eventAttributes['ownEvent']) {
                if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                    $attributeConditions['Sighting.org_id'] = $userOrgId;
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                    if (!$this->isReporter($eventId, $userOrgId)) {
                        continue; // skip event
                    }
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                    $attributeConditions['Sighting.org_id'] = [$userOrgId, $hostOrgId];
                }
            }
            $conditions['OR'][] = $attributeConditions;
        }
        return $conditions;
    }

    /**
     * @param array $events
     * @param array $user
     * @param bool $csvWithFalsePositive
     * @return array
     */
    public function eventsStatistic(array $events, array $user, $csvWithFalsePositive = false)
    {
        if (empty($events)) {
            return ['data' => [], 'csv' => []];
        }

        $sightingsPolicy = $this->sightingsPolicy();

        $conditions = [];
        foreach ($events as $event) {
            $eventCondition = ['Sighting.event_id' => $event['Event']['id']];
            $ownEvent = $user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id'];
            if (!$ownEvent) {
                if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                    $eventCondition['Sighting.org_id'] = $user['org_id'];
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                    if (!$this->isReporter($event['Event']['id'], $user['org_id'])) {
                        continue;
                    }
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                    $eventCondition['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
                }
            }
            $conditions['OR'][] = $eventCondition;
        }

        $groupedSightings = $this->fetchGroupedSightings($conditions, $user);
        return $this->generateStatistics($groupedSightings, $csvWithFalsePositive);
    }

    /**
     * @param array $conditions
     * @param array $user
     * @return array
     */
    private function fetchGroupedSightings(array $conditions, array $user)
    {
        if (empty($conditions)) {
            return [];
        }

        // Returns date in `Y-m-d` format
        $this->virtualFields['date'] = $this->dateVirtualColumn();
        $this->virtualFields['sighting_count'] = 'COUNT(id)';
        $this->virtualFields['last_timestamp'] = 'MAX(date_sighting)';
        $groupedSightings = $this->find('all', array(
            'conditions' => $conditions,
            'fields' => ['org_id', 'attribute_id', 'type', 'date', 'last_timestamp', 'sighting_count'],
            'recursive' => -1,
            'group' => ['org_id', 'attribute_id', 'type', 'date'],
            'order' => ['date'], // from oldest
        ));
        unset(
            $this->virtualFields['date'],
            $this->virtualFields['sighting_count'],
            $this->virtualFields['last_timestamp']
        );
        return $this->attachOrgToSightings($groupedSightings, $user, false);
    }

    /**
     * @param array $tagIds
     * @param array $conditions
     * @param string $context
     * @return array
     */
    private function fetchGroupedSightingsForTags(array $tagIds, array $conditions, $context)
    {
        $conditions[ucfirst($context) . 'Tag.tag_id'] = $tagIds;
        // Temporary bind EventTag or AttributeTag model
        $this->bindModel([
            'hasOne' => [
                ucfirst($context) . 'Tag' => [
                    'foreignKey' => false,
                    'conditions' => ucfirst($context) . 'Tag.' . $context . '_id = Sighting.' . $context . '_id',
                ]
            ]
        ]);
        // Returns date in `Y-m-d` format
        $this->virtualFields['date'] = $this->dateVirtualColumn();
        $this->virtualFields['sighting_count'] = 'COUNT(Sighting.id)';
        $sightings = $this->find('all', [
            'recursive' => -1,
            'contain' => [ucfirst($context) . 'Tag'],
            'conditions' => $conditions,
            'fields' => [ucfirst($context) . 'Tag.tag_id', 'date', 'sighting_count'],
            'group' => [ucfirst($context) . 'Tag.tag_id', 'date'],
            'order' => ['date'], // from oldest
        ]);
        unset($this->virtualFields['date'], $this->virtualFields['sighting_count']);
        return $sightings;
    }

    /**
     * @param array $groupedSightings
     * @param bool $csvWithFalsePositive
     * @return array[]
     */
    private function generateStatistics(array $groupedSightings, $csvWithFalsePositive = false)
    {
        $sightingsData = [];
        $sparklineData = [];
        $range = $this->getMaximumRange();
        foreach ($groupedSightings as $sighting) {
            $type = self::TYPE[$sighting['type']];
            $orgName = isset($sighting['Organisation']['name']) ? $sighting['Organisation']['name'] : __('Others');
            $count = (int)$sighting['sighting_count'];
            $inRange = strtotime($sighting['date']) >= $range;

            foreach ([$sighting['attribute_id'], 'all'] as $needle) {
                if (!isset($sightingsData[$needle][$type])) {
                    $sightingsData[$needle][$type] = ['count' => 0, 'orgs' => []];
                }

                $ref = &$sightingsData[$needle][$type];
                $ref['count'] += $count;

                if (!isset($ref['orgs'][$orgName])) {
                    $ref['orgs'][$orgName] = ['count' => $count, 'date' => $sighting['last_timestamp']];
                } else {
                    $ref['orgs'][$orgName]['count'] += $count;
                    $ref['orgs'][$orgName]['date'] = $sighting['last_timestamp'];
                }

                if ($inRange) {
                    if (isset($sparklineData[$needle][$sighting['date']][$type])) {
                        $sparklineData[$needle][$sighting['date']][$type] += $count;
                    } else {
                        $sparklineData[$needle][$sighting['date']][$type] = $count;
                    }
                }
            }
        }
        return ['data' => $sightingsData, 'csv' => $this->generateSparkline($sparklineData, $csvWithFalsePositive)];
    }

    /**
     * @param array $sparklineData
     * @param bool $csvWithFalsePositive
     * @return array
     */
    private function generateSparkline(array $sparklineData, $csvWithFalsePositive)
    {
        $todayString = date('Y-m-d');
        $today = strtotime($todayString);

        // If nothing found, generate default "empty" CSV for 'all'
        if (!isset($sparklineData['all'])) {
            $sparklineData['all'][$todayString] = null;
        }

        $csv = [];
        foreach ($sparklineData as $object => $data) {
            $startDate = key($data); // oldest date for sparkline
            $startDate = strtotime($startDate) - (self::ONE_DAY * 3);
            $csvForObject = $csvWithFalsePositive ? 'Date,Sighting,False-positive\n' : 'Date,Close\n';
            for ($date = $startDate; $date <= $today; $date += self::ONE_DAY) {
                $dateAsString = date('Y-m-d', $date);
                $csvForObject .= $dateAsString . ',' . (isset($data[$dateAsString]['sighting']) ? $data[$dateAsString]['sighting'] : '0');

                if ($csvWithFalsePositive) {
                    $csvForObject .= ',' . (isset($data[$dateAsString]['false-positive']) ? $data[$dateAsString]['false-positive'] : '0');
                }

                $csvForObject .= '\n';
            }
            $csv[$object] = $csvForObject;
        }
        return $csv;
    }

    /**
     * @param array $sightings
     * @param array $user
     * @param false $forSync
     * @return array
     */
    private function attachOrgToSightings(array $sightings, array $user, $forSync = false)
    {
        $showOrg = Configure::read('MISP.showorg');
        $anonymise = Configure::read('Plugin.Sightings_anonymise');
        $anonymiseAs = Configure::read('Plugin.Sightings_anonymise_as');

        $anonOrg = null;
        if ($forSync && !empty($anonymiseAs)) {
            $anonOrg = $this->getOrganisationById($anonymiseAs);
        }

        foreach ($sightings as $k => $sighting) {
            $sighting = $sighting['Sighting'];
            if ($showOrg && $sighting['org_id']) {
                $sighting['Organisation'] = $this->getOrganisationById($sighting['org_id']);
            }
            if ($sighting['org_id'] != $user['org_id'] && $anonymise) {
                if (empty($anonOrg)) {
                    unset($sighting['org_id']);
                    unset($sighting['Organisation']);
                } else {
                    $sighting['org_id'] = $anonOrg['id'];
                    $sighting['Organisation'] = $anonOrg;
                }
            }
            $sightings[$k] = $sighting;
        }
        $this->orgCache = []; // clear org cache
        return $sightings;
    }

    /**
     * @param array $event
     * @param array $user
     * @param array $sightingsUuidsToPush
     * @return Generator<array>
     */
    public function fetchUuidsForEventToPush(array $event, array $user, array $sightingsUuidsToPush = [])
    {
        $conditions = $this->createConditions($user, $event);
        if ($conditions === false) {
            return null;
        }
        $conditions['Sighting.event_id'] = $event['Event']['id'];
        if (!empty($sightingsUuidsToPush)) {
            $conditions['Sighting.uuid'] = $sightingsUuidsToPush;
        }

        while (true) {
            $uuids = $this->find('column', [
                'conditions' => $conditions,
                'fields' => ['Sighting.uuid'],
                'limit' => 250000,
                'order' => ['Sighting.uuid'],
            ]);
            $count = count($uuids);
            if ($count === 0) {
                return null;
            }
            yield $uuids;
            if ($count !== 250000) {
                return;
            }
            $conditions['Sighting.uuid >'] = $uuids[$count - 1];
        }
    }

    /**
     * @param array $event Just 'Event' object is enough
     * @param array $user
     * @param array|int|null $attribute Attribute model or attribute ID
     * @param array|bool $extraConditions
     * @param bool $forSync
     * @return array|int
     */
    public function attachToEvent(array $event, array $user, $attribute = null, $extraConditions = false, $forSync = false)
    {
        $conditions = $this->createConditions($user, $event);
        if ($conditions === false) {
            return [];
        }

        $conditions['Sighting.event_id'] = $event['Event']['id'];
        if (isset($attribute['Attribute']['id'])) {
            $conditions['Sighting.attribute_id'] = $attribute['Attribute']['id'];
        } elseif (is_numeric($attribute)) {
            $conditions['Sighting.attribute_id'] = $attribute;
            $attribute = $this->Attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $attribute],
                'fields' => ['Attribute.uuid']
            ]);
        }

        if ($extraConditions !== false) {
            $conditions['AND'] = $extraConditions;
        }
        $sightings = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        if (empty($sightings)) {
            return [];
        }
        if ($attribute === null) {
            // Do not add attribute uuid in contain query, joining is slow and takes more memory
            $attributeUuids = $this->Attribute->find('all', [
                'conditions' => ['Attribute.event_id' => $event['Event']['id']],
                'fields' => ['Attribute.id', 'Attribute.uuid'],
                'recursive' => -1,
            ]);
            // `array_column` is much faster than find('list')
            $attributeUuids = array_column(array_column($attributeUuids, 'Attribute'), 'uuid', 'id');
            foreach ($sightings as $k => $sighting) {
                $sighting['Sighting']['attribute_uuid'] = $attributeUuids[$sighting['Sighting']['attribute_id']];
                $sightings[$k] = $sighting;
            }
            unset($attributeUuids);
        } else {
            foreach ($sightings as $k => $sighting) {
                $sighting['Sighting']['attribute_uuid'] = $attribute['Attribute']['uuid'];
                $sightings[$k] = $sighting;
            }
        }
        return $this->attachOrgToSightings($sightings, $user, $forSync);
    }

    public function saveSightings($id, $values, $timestamp, $user, $type = false, $source = false, $sighting_uuid = false, $publish = false, $saveOnBehalfOf = false, $filters=[])
    {
        if (!in_array($type, array(0, 1, 2))) {
            return 'Invalid type, please change it before you POST 1000000 sightings.';
        }

        if ($sighting_uuid) {
            // Since sightings are immutable (it is not possible to change it from web interface), we can check
            // if sighting with given uuid already exists and quit early
            $existing_sighting = $this->find('count', array(
                'recursive' => -1,
                'conditions' => array('uuid' => $sighting_uuid),
                'callbacks' => false,
            ));
            if ($existing_sighting) {
                return 0;
            }
        }

        $conditions = array();
        if ($id && $id !== 'stix') {
            $id = $this->explodeIdList($id);
            if (!is_array($id) && strlen($id) == 36) {
                $conditions = array('Attribute.uuid' => $id);
            } else {
                $conditions = array('Attribute.id' => $id);
            }
        } else {
            if (!$values) {
                return 'No valid attributes found.';
            }
            if (!is_array($values)) {
                $values = array($values);
            }
            if (empty($filters)) {
                foreach ($values as $value) {
                    foreach (array('value1', 'value2') as $field) {
                        $conditions['OR'][] = array(
                            'Attribute.' . $field => $value
                        );
                    }
                }
            }
        }
        $attributes = [];
        if (empty($filters)) {
            $attributes = $this->Attribute->fetchAttributesSimple($user, [
                'conditions' => $conditions,
                'fields' => ['Attribute.id', 'Attribute.event_id'],
            ]);
        } else {
            $filters['value'] = $values;
            $params = $this->Attribute->restSearch($user, 'json', $filters, true);
            $attributes = $this->Attribute->fetchAttributes($user, $params);
        }
        if (empty($attributes)) {
            return 'No valid attributes found that match the criteria.';
        }
        $sightingsAdded = 0;
        foreach ($attributes as $attribute) {
            if ($type === '2') {
                // remove existing expiration by the same org if it exists
                $this->deleteAll(array(
                    'Sighting.org_id' => $user['org_id'],
                    'Sighting.type' => $type,
                    'Sighting.attribute_id' => $attribute['Attribute']['id'],
                ));
            }
            $this->create();
            $sighting = array(
                'attribute_id' => $attribute['Attribute']['id'],
                'event_id' => $attribute['Attribute']['event_id'],
                'org_id' => ($saveOnBehalfOf === false) ? $user['org_id'] : $saveOnBehalfOf,
                'date_sighting' => $timestamp,
                'type' => $type,
                'source' => $source,
            );
            // zeroq: allow setting a specific uuid
            if ($sighting_uuid) {
                $sighting['uuid'] = $sighting_uuid;
            }
            $result = $this->save($sighting);
            if ($result === false) {
                return json_encode($this->validationErrors);
            }
            ++$sightingsAdded;
            if ($publish) {
                $this->Event->publishSightingsRouter($sighting['event_id'],  $user);
            }
        }
        return $sightingsAdded;
    }

    public function handleStixSighting($data)
    {
        $randomFileName = $this->generateRandomFileName();
        $tempFile = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName, true, 0644);

        // save the json_encoded event(s) to the temporary file
        if (!$tempFile->write($data)) {
            return array('success' => 0, 'message' => 'Could not write the Sightings file to disk.');
        }
        $tempFile->close();
        $scriptFile = APP . "files" . DS . "scripts" . DS . "stixsighting2misp.py";
        // Execute the python script and point it to the temporary filename
        $result = ProcessTool::execute([ProcessTool::pythonBin(), $scriptFile, $randomFileName]);
        // The result of the script will be a returned JSON object with 2 variables: success (boolean) and message
        // If success = 1 then the temporary output file was successfully written, otherwise an error message is passed along
        $result = json_decode($result, true);

        if ($result['success'] == 1) {
            $file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
            $result['data'] = $file->read();
            $file->close();
            $file->delete();
        }
        $tempFile->delete();
        return $result;
    }

    /**
     * @return bool
     * @deprecated
     */
    public function addUuids()
    {
        $sightings = $this->find('all', array(
            'recursive' => -1,
            'conditions' => array('uuid' => '')
        ));
        $this->saveMany($sightings);
        return true;
    }

    public function explodeIdList($id)
    {
        if (strpos($id, '|')) {
            $id = explode('|', $id);
            foreach ($id as $k => $v) {
                if (!is_numeric($v)) {
                    unset($id[$k]);
                }
            }
            $id = array_values($id);
        }
        return $id;
    }

    /**
     * @param array $user
     * @param $ids
     * @param string $context
     * @param int|false $orgId
     * @param int|false $sightingsType
     * @param bool $orderDesc
     * @return array|int|null
     * @throws Exception
     */
    public function listSightings(array $user, $ids, $context, $orgId = false, $sightingsType = false, $orderDesc = true)
    {
        $ids = is_array($ids) ? $ids : $this->explodeIdList($ids);

        $objectIds = [];
        $eventOwnerOrgIdList = [];
        if ($context === 'attribute') {
            $objects = $this->Event->Attribute->fetchAttributes($user, ['conditions' => ['Attribute.id' => $ids, 'Attribute.deleted' => 0], 'flatten' => 1]);
            foreach ($objects as $object) {
                $objectIds[] = $object['Attribute']['id'];
                $eventOwnerOrgIdList[$object['Event']['id']] = $object['Event']['orgc_id'];
            }
        } elseif ($context === 'event') {
            // let's set the context to event here, since we reuse the variable later on for some additional lookups.
            // Passing $context = 'org' could have interesting results otherwise...
            $objects = $this->Event->fetchSimpleEvents($user, ['conditions' => ['Event.id' => $ids]]);
            foreach ($objects as $object) {
                $objectIds[] = $object['Event']['id'];
                $eventOwnerOrgIdList[$object['Event']['id']] = $object['Event']['orgc_id'];
            }
        } else {
            throw new InvalidArgumentException("Invalid context '$context'.");
        }
        unset($objects);
        if (empty($objectIds)) {
            throw new MethodNotAllowedException('Invalid object.');
        }
        $conditions = array(
            'Sighting.' . $context . '_id' => $objectIds
        );
        if ($orgId) {
            $conditions[] = array('Sighting.org_id' => $orgId);
        }
        if ($sightingsType !== false) {
            $conditions[] = array('Sighting.type' => $sightingsType);
        }
        $sightings = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array('Organisation.name'),
            'order' => array(sprintf('Sighting.date_sighting %s', $orderDesc ? 'DESC' : ''))
        ));
        if (empty($sightings)) {
            return [];
        }
        if ($user['Role']['perm_site_admin']) {
            return $sightings; // site admin can see all sightings, do not limit him
        }
        $sightingsPolicy = $this->sightingsPolicy();
        if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER || $sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
            $userOrgId = $user['org_id'];
            $allowedOrgs = [$userOrgId];
            if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                $allowedOrgs[] = Configure::read('MISP.host_org_id');
            }
            foreach ($sightings as $k => $sighting) {
                if ($eventOwnerOrgIdList[$sighting['Sighting']['event_id']] !== $userOrgId && !in_array($sighting['Sighting']['org_id'], $allowedOrgs)) {
                    unset($sightings[$k]);
                }
            }
            $sightings = array_values($sightings);

        } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
            $eventsWithOwnSightings = array();
            foreach ($sightings as $k => $sighting) {
                $eventId = $sighting['Sighting']['event_id'];
                if (!isset($eventsWithOwnSightings[$eventId])) {
                    $isReporter = $this->isReporter($eventId, $user['org_id']);
                    if ($isReporter) {
                        $eventsWithOwnSightings[$eventId] = true;
                    } else {
                        $ownEvent = $eventOwnerOrgIdList[$eventId] == $user['org_id'];
                        $eventsWithOwnSightings[$eventId] = $ownEvent;
                    }
                }
                if (!$eventsWithOwnSightings[$eventId]) {
                    unset($sightings[$k]);
                }
            }
            $sightings = array_values($sightings);
        }
        if (Configure::read('Plugin.Sightings_anonymise')) {
            foreach ($sightings as $k => $v) {
                if ($v['Sighting']['org_id'] != $user['org_id']) {
                    $sightings[$k]['Organisation']['name'] = '';
                    $sightings[$k]['Sighting']['org_id'] = 0;
                }
            }
        }
        return $sightings;
    }

     /**
     * @param int $id
     * @return array
     */
    public function getLastSightingForAttribute(array $user, $id): array
    {
        $conditions = [
            'Sighting.attribute_id' => $id,
            'Sighting.type' => 0,
        ];

        $sightingsPolicy = $this->sightingsPolicy();
        if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER || $sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
            $conditions['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
        } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
            $all_sightings = $this->listSightings($user, [$id], 'attribute', false, 0, true);
            $sighting = $all_sightings[0]['Sighting']['date_sighting'];
            return $sighting;
        }
        $sighting = $this->find('first', [
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => ['Sighting.date_sighting DESC']
        ]);
        return empty($sighting) ? [] : $sighting;
    }

    /**
     * @param array $user
     * @param string $returnFormat
     * @param array $filters
     * @return TmpFileTool
     * @throws Exception
     */
    public function restSearch(array $user, $returnFormat, array $filters)
    {
        $allowedContext = array('event', 'attribute');
        // validate context
        if (isset($filters['context']) && !in_array($filters['context'], $allowedContext, true)) {
            throw new BadRequestException(__('Invalid context %s.', $filters['context']));
        }
        // ensure that an id or uuid is provided if context is set
        if (!empty($filters['context']) && !(isset($filters['id']) || isset($filters['uuid'])) ) {
            throw new BadRequestException(__('An ID or UUID must be provided if the context is set.'));
        }

        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();

        // construct filtering conditions
        if (isset($filters['from']) && isset($filters['to'])) {
            $timeCondition = array($filters['from'], $filters['to']);
            unset($filters['from']);
            unset($filters['to']);
        } elseif (isset($filters['last'])) {
            $timeCondition = $filters['last'];
            unset($filters['last']);
        } else {
            $timeCondition = '30d';
        }

        $contain = [];
        $conditions = $this->Attribute->setTimestampConditions($timeCondition, [], $scope = 'Sighting.date_sighting');

        if (isset($filters['type'])) {
            $conditions['Sighting.type'] = $filters['type'];
        }

        if (isset($filters['org_id'])) {
            if (!is_array($filters['org_id'])) {
                $filters['org_id'] = array($filters['org_id']);
            }
            foreach ($filters['org_id'] as $k => $org_id) {
                $negation = false;
                if (is_string($org_id) && $org_id[0] === '!') {
                    $negation = true;
                    $org_id = substr($org_id, 1);
                }
                if (Validation::uuid($org_id)) {
                    $org = $this->Organisation->find('first', array(
                        'conditions' => array('Organisation.uuid' => $org_id),
                        'recursive' => -1,
                        'fields' => array('Organisation.id'),
                    ));
                    if (!empty($org)) {
                        $temp = $org['Organisation']['id'];
                    }
                }
                if ($negation) {
                    $conditions['Sighting.org_id NOT IN'][] = $temp;
                } else {
                    $conditions['Sighting.org_id'][] = $temp;
                }
                if (empty($conditions['Sighting.org_id']) && empty($conditions['Sighting.org_id NOT IN'])) {
                    $conditions['Sighting.org_id'] = -1;
                }
            }
        }

        if (isset($filters['source'])) {
            $conditions['Sighting.source'] = $filters['source'];
        }

        if (!empty($filters['id'])) {
            if (is_array($filters['id'])) {
                foreach ($filters['id'] as $id) {
                    if (!is_int($id) || !is_numeric($id)) {
                        throw new BadRequestException("Invalid ID `$id` provided.");
                    }
                }
            } else if (!is_int($filters['id']) || !is_numeric($filters['id'])) {
                throw new BadRequestException("Invalid ID `{$filters['id']}` provided.");
            }

            if ($filters['context'] === 'attribute') {
                $conditions['Sighting.attribute_id'] = $filters['id'];
            } elseif ($filters['context'] === 'event') {
                $conditions['Sighting.event_id'] = $filters['id'];
            }
        }

        if (!empty($filters['uuid'])) {
            if ($filters['context'] === 'attribute') {
                $conditions['Attribute.uuid'] = $filters['uuid'];
                $contain[] = 'Attribute';
            } elseif ($filters['context'] === 'event') {
                $temp = $this->Event->find('column', [
                    'recursive' => -1,
                    'fields' => ['Event.id'],
                    'conditions' => ['Event.uuid IN' => $filters['uuid']]
                ]);
                $conditions['Sighting.event_id'] = empty($temp) ? -1 : $temp;
            }
        }

        $includeAttribute = isset($filters['includeAttribute']) && $filters['includeAttribute'];
        $includeEvent = isset($filters['includeEvent']) && $filters['includeEvent'];
        $includeUuid = isset($filters['includeUuid']) && $filters['includeUuid'];

        $requestedAttributes = ['id', 'attribute_id', 'event_id', 'org_id', 'date_sighting', 'uuid', 'source', 'type'];
        if ($includeAttribute) {
            $requestedAttributes = array_merge($requestedAttributes, ['attribute_uuid', 'attribute_type', 'attribute_category', 'attribute_to_ids', 'attribute_value']);
        }
        if ($includeEvent) {
            $requestedAttributes = array_merge($requestedAttributes, ['event_uuid', 'event_orgc_id', 'event_org_id', 'event_info', 'event_Orgc_name']);
        }
        $filters['requested_attributes'] = $requestedAttributes;

        $exportToolParams = array(
            'user' => $user,
            'params' => ['conditions' => []],  //result already filtered
            'returnFormat' => $returnFormat,
            'scope' => 'Sighting',
            'filters' => $filters
        );

        $tmpfile = new TmpFileTool();
        $tmpfile->write($exportTool->header($exportToolParams));
        $separator = $exportTool->separator($exportToolParams);


        if (empty(Configure::read('MISP.disable_sighting_loading'))) {
            // fetch sightings matching the query without ACL checks
            if (!empty($conditions['Sighting.event_id']) && is_array($conditions['Sighting.event_id'])) {
                $conditions_copy = $conditions;
                $sightingIds = [];
                foreach ($conditions['Sighting.event_id'] as $e_id) {
                    $conditions_copy['Sighting.event_id'] = $e_id;
                    $tempIds = $this->find('column', [
                        'conditions' => $conditions_copy,
                        'fields' => ['Sighting.id'],
                        'contain' => $contain
                    ]);
                    if (!empty($tempIds)) {
                        $sightingIds = array_merge($sightingIds, $tempIds);
                    }
                }
            } else {
                $sightingIds = $this->find('column', [
                    'conditions' => $conditions,
                    'fields' => ['Sighting.id'],
                    'contain' => $contain
                ]);
            }

            foreach (array_chunk($sightingIds, 10000) as $chunk) {
                // fetch sightings with ACL checks and sighting policies
                $sightings = $this->getSightings($user, $chunk, $includeEvent, $includeAttribute, $includeUuid);
                JsonTool::convertIntegersToStrings($sightings);
                foreach ($sightings as $sighting) {
                    $tmpfile->writeWithSeparator($exportTool->handler($sighting, $exportToolParams), $separator);
                }
            }
        }

        $tmpfile->write($exportTool->footer($exportToolParams));
        return $tmpfile;
    }

    /**
     * @param int|string $eventId Event ID or UUID
     * @param array $sightings
     * @param array $user
     * @param int|null $passAlong Server ID
     * @return int Number of saved sightings
     * @throws Exception
     */
    public function bulkSaveSightings($eventId, array $sightings, array $user, $passAlong = null)
    {
        $event = $this->Event->fetchSimpleEvent($user, $eventId);
        if (empty($event)) {
            throw new NotFoundException('Event not found or not accessible by this user.');
        }

        // Since sightings are immutable (it is not possible to change it from web interface), we can check
        // if sighting with given uuid already exists and skip them
        $existingSighting = $this->existing($sightings);

        // Fetch existing organisations in bulk
        $existingOrganisations = $this->existingOrganisations($sightings);

        // Fetch attributes IDs and event IDs
        $attributesToTransform = $this->Attribute->fetchAttributesSimple($user, [
            'conditions' => ['Attribute.uuid' => array_unique(array_column($sightings, 'attribute_uuid'))],
            'fields' => ['Attribute.id', 'Attribute.uuid', 'Attribute.event_id'],
        ]);
        $attributes = [];
        foreach ($attributesToTransform as $attribute) {
            $attributes[$attribute['Attribute']['uuid']] = [$attribute['Attribute']['id'], $attribute['Attribute']['event_id']];
        }

        $toSave = [];
        foreach ($sightings as $s) {
            if (isset($existingSighting[$s['uuid']])) {
                continue; // sighting already exists
            }
            if (!isset($attributes[$s['attribute_uuid']])) {
                continue; // attribute doesn't exists or user don't have permission to access it
            }
            $existingSighting[$s['uuid']] = true; // just to be sure that there are no sigthings with duplicated UUID

            list($attributeId, $eventId) = $attributes[$s['attribute_uuid']];

            if ($s['type'] === '2') {
                // remove existing expiration by the same org if it exists
                $this->deleteAll(array(
                    'Sighting.org_id' => $user['org_id'],
                    'Sighting.type' => 2,
                    'Sighting.attribute_id' => $attributeId,
                ));
            }

            $saveOnBehalfOf = false;
            if ($user['Role']['perm_sync']) {
                if (isset($s['org_id'])) {
                    if ($s['org_id'] != 0 && !empty($s['Organisation'])) {
                        $saveOnBehalfOf = $existingOrganisations[$s['Organisation']['uuid']] ??
                            $this->Organisation->captureOrg($s['Organisation'], $user);
                    } else {
                        $saveOnBehalfOf = 0;
                    }
                }
            }

            $toSave[] = [
                'attribute_id' => $attributeId,
                'event_id' => $eventId,
                'org_id' => $saveOnBehalfOf === false ? $user['org_id'] : $saveOnBehalfOf,
                'date_sighting' => $s['date_sighting'],
                'type' => $s['type'],
                'source' => $s['source'],
                'uuid' => $s['uuid'],
            ];
        }
        if (empty($toSave)) {
            return 0;
        }

        if ($this->saveMany($toSave)) {
            $sightingsUuidsToPush = array_column($toSave, 'uuid');
            $this->Event->publishSightingsRouter($event['Event']['id'], $user, $passAlong, $sightingsUuidsToPush);
            return count($toSave);
        }

        return 0;
    }

    /**
     * Push sightings to remote server.
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    public function pushSightings(array $user, ServerSyncTool $serverSync)
    {
        $server = $serverSync->server();

        if (!$serverSync->server()['Server']['push_sightings']) {
            return [];
        }
        $this->Server = ClassRegistry::init('Server');

        try {
            $eventArray = $this->Server->getEventIndexFromServer($serverSync);
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
            return [];
        }

        // Fetch local events that has sightings
        $localEvents = $this->Event->find('list', [
            'fields' => ['Event.uuid', 'Event.sighting_timestamp'],
            'conditions' => [
                'Event.uuid' => array_column($eventArray, 'uuid'),
                'Event.sighting_timestamp >' => 0,
            ],
        ]);

        // Filter just local events that has sighting_timestamp newer than remote event
        $eventUuids = [];
        foreach ($eventArray as $event) {
            if (isset($localEvents[$event['uuid']]) && $localEvents[$event['uuid']] > $event['sighting_timestamp']) {
                $eventUuids[] = $event['uuid'];
            }
        }
        unset($localEvents, $eventArray);

        $fakeSyncUser = [
            'org_id' => $server['Server']['remote_org_id'],
            'Role' => [
                'perm_site_admin' => 0,
            ],
        ];

        $successes = [];
        // now process the $eventUuids to push each of the events sequentially
        // check each event and push sightings when needed
        foreach ($eventUuids as $eventUuid) {
            $event = $this->Event->fetchEvent($user, ['event_uuid' => $eventUuid, 'metadata' => true]);
            if (empty($event)) {
                continue;
            }
            $event = $event[0];

            if (empty($this->Server->eventFilterPushableServers($event, [$server]))) {
                continue;
            }
            if (!$this->Event->checkDistributionForPush($event, $server)) {
                continue;
            }

            // Process sightings in batch to keep memory requirements low
            foreach ($this->fetchUuidsForEventToPush($event, $fakeSyncUser) as $batch) {
                // Filter out sightings that already exists on remote server
                $existingSightings = $serverSync->filterSightingUuidsForPush($event, $batch);
                $newSightings = array_diff($batch, $existingSightings);
                if (empty($newSightings)) {
                    continue;
                }

                $conditions = ['Sighting.uuid' => $newSightings];
                $sightings = $this->attachToEvent($event, $fakeSyncUser, null, $conditions, true);
                $serverSync->uploadSightings($sightings, $event['Event']['uuid']);
            }

            $successes[] = 'Sightings for event ' .  $event['Event']['id'];
        }
        return $successes;
    }

    /**
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int Number of saved sighting.
     * @throws Exception
     */
    public function pullSightings(array $user, ServerSyncTool $serverSync)
    {
        $serverSync->debug("Fetching event index for pulling sightings");

        $this->Server = ClassRegistry::init('Server');
        try {
            $remoteEvents = $this->Server->getEventIndexFromServer($serverSync);
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server {$serverSync->serverName()}", $e);
            return 0;
        }
        // Remove events from list that do not have published sightings.
        foreach ($remoteEvents as $k => $remoteEvent) {
            if ($remoteEvent['sighting_timestamp'] == 0) {
                unset($remoteEvents[$k]);
            }
        }
        // Downloads sightings just from events that exists locally and remote sighting_timestamp is newer than local.
        $localEvents = $this->Event->find('list', [
            'fields' => ['Event.uuid', 'Event.sighting_timestamp'],
            'conditions' => (count($remoteEvents) > 10000) ? [] : ['Event.uuid' => array_column($remoteEvents, 'uuid')],
        ]);
        $eventUuids = [];
        foreach ($remoteEvents as $remoteEvent) {
            if (isset($localEvents[$remoteEvent['uuid']]) && $localEvents[$remoteEvent['uuid']] < $remoteEvent['sighting_timestamp']) {
                $eventUuids[$remoteEvent['uuid']] = $remoteEvent['sighting_timestamp'];
            }
        }
        unset($remoteEvents, $localEvents);
        if (empty($eventUuids)) {
            return 0;
        }

        $this->removeFetched($serverSync->serverId(), $eventUuids);
        if (empty($eventUuids)) {
            return 0;
        }

        $serverSync->debug("Pulling sightings for " . count($eventUuids) . " events");

        if ($serverSync->isSupported(ServerSyncTool::FEATURE_SIGHTING_REST_SEARCH)) {
            return $this->pullSightingNewWay($user, $eventUuids, $serverSync);
        } else {
            return $this->pullSightingOldWay($user, $eventUuids, $serverSync);
        }
    }

    /**
     * New way how to fetch sighting for events without fetching the whole event.
     *
     * @param array $user
     * @param array $eventUuids With UUID in key and remote sighting_timestamp as value
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws Exception
     */
    private function pullSightingNewWay(array $user, array $eventUuids, ServerSyncTool $serverSync)
    {
        $SightingBlocklist = ClassRegistry::init('SightingBlocklist');
        $blockedSightingsOrgs = $SightingBlocklist->find('column', [
            'recursive' => -1,
            'fields' => ['org_uuid']
        ]);

        $uuids = array_keys($eventUuids);
        shuffle($uuids); // shuffle array to avoid keeping events with a lof ot sightings in same batch all the time
        $saved = 0;
        $savedEventUuids = [];
        foreach (array_chunk($uuids, 20) as $chunk) {
            try {
                $sightings = $serverSync->fetchSightingsForEvents($chunk, $blockedSightingsOrgs);
            } catch (Exception $e) {
                $this->logException("Failed to download sightings from remote server {$serverSync->server()['Server']['name']}.", $e);
                continue;
            }
            $sightingsToSave = [];
            foreach ($sightings as $sighting) {
                $sighting = $sighting['Sighting'];
                $eventUuid = $sighting['event_uuid'];
                $sightingsToSave[$eventUuid][] = $sighting;
            }

            foreach ($sightingsToSave as $eventUuid => $sightings) {
                $savedForEvent = $this->bulkSaveSightings($eventUuid, $sightings, $user, $serverSync->serverId());
                if ($savedForEvent) {
                    $saved += $savedForEvent;
                    $savedEventUuids[] = $eventUuid;
                }
            }
        }

        // Save to Redis that we fetched event sightings, that was not saved. This avoid fetching sightings for
        // same event that has sightings not visible to user again and again.
        foreach (array_diff($uuids, $savedEventUuids) as $notSavedUuid) {
            $this->saveEmptyFetchedEvent($serverSync->serverId(), $notSavedUuid, $eventUuids[$notSavedUuid]);
        }

        return $saved;
    }

    /**
     * @param array $user
     * @param array $eventUuids With UUID in key and remote sighting_timestamp as value
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws Exception
     */
    private function pullSightingOldWay(array $user, array $eventUuids, ServerSyncTool $serverSync)
    {
        $saved = 0;
        $savedEventUuids = [];
        // We don't need some of the event data, like correlations and event reports
        $params = [
            'deleted' => [0, 1],
            'excludeGalaxy' => 1,
            'excludeLocalTags' => 1,
            'includeAttachments' => 0,
            'includeEventCorrelations' => 0,
            'includeFeedCorrelations' => 0,
            'includeWarninglistHits' => 0,
            'noEventReports' => 1,
            'noShadowAttributes' => 1,
        ];
        // now process the $eventUuids to pull each of the events sequentially
        // download each event and save sightings
        foreach ($eventUuids as $eventUuid => $sightingTimestamp) {
            try {
                $event = $serverSync->fetchEvent($eventUuid, $params)->json();
            } catch (Exception $e) {
                $this->logException("Failed downloading the event $eventUuid from {$serverSync->server()['Server']['name']}.", $e);
                continue;
            }
            $sightings = [];
            if (!empty($event['Event']['Attribute'])) {
                foreach ($event['Event']['Attribute'] as $attribute) {
                    if (!empty($attribute['Sighting'])) {
                        $sightings = array_merge($sightings, $attribute['Sighting']);
                    }
                }
            }
            if (!empty($event['Event']['Object'])) {
                foreach ($event['Event']['Object'] as $object) {
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $attribute) {
                            if (!empty($attribute['Sighting'])) {
                                $sightings = array_merge($sightings, $attribute['Sighting']);
                            }
                        }
                    }
                }
            }
            if (!empty($sightings)) {
                $result = $this->bulkSaveSightings($eventUuid, $sightings, $user, $serverSync->serverId());
                if ($result) {
                    $saved += $result;
                    $savedEventUuids[] = $eventUuid;
                }
            }
        }

        // Save to Redis that we fetched event sightings, that was not saved. This avoid fetching sightings for
        // same event that has sightings not visible to user again and again.
        foreach (array_diff(array_keys($eventUuids), $savedEventUuids) as $notSavedEventUuid) {
            $this->saveEmptyFetchedEvent($serverSync->serverId(), $notSavedEventUuid, $eventUuids[$notSavedEventUuid]);
        }

        return $saved;
    }

    /**
     * Remove from fetching events that was already fetched with the same sighting_timestamp
     * @param int $serverId
     * @param array $eventUuids
     * @return void
     * @throws RedisException
     */
    private function removeFetched($serverId, array &$eventUuids)
    {
        $lastFetched = RedisTool::init()->hMGet("misp:fetched_sightings:$serverId", array_keys($eventUuids));
        foreach ($lastFetched as $uuid => $savedTimestamp) {
            if ($savedTimestamp == $eventUuids[$uuid]) {
                unset($eventUuids[$uuid]); // event with the same sighting_timestamp was already fetched
            }
        }
    }

    /**
     * Save to Redis event uuid with sighting timestamp that was fetched from remote server, but no sightings was
     * saved to database.
     *
     * @param int $serverId
     * @param string $eventUuid
     * @param int $sightingTimestamp
     * @return void
     * @throws RedisException
     */
    private function saveEmptyFetchedEvent($serverId, $eventUuid, $sightingTimestamp)
    {
        $redis = RedisTool::init();
        $redis->hSet("misp:fetched_sightings:$serverId", $eventUuid, $sightingTimestamp);
        $redis->expire("misp:fetched_sightings:$serverId", 24 * 3600); // keep for one day
    }

    /**
     * @return int Timestamp
     */
    public function getMaximumRange()
    {
        $rangeInDays = Configure::read('MISP.Sightings_range');
        $rangeInDays = (!empty($rangeInDays) && is_numeric($rangeInDays)) ? $rangeInDays : 365;
        return strtotime("-$rangeInDays days");
    }

    /**
     * @param array $sightings
     * @return array Existing sightings UUID in key
     */
    private function existing(array $sightings)
    {
        $existingSighting = $this->find('column', [
            'fields' => ['Sighting.uuid'],
            'conditions' => ['uuid' => array_column($sightings, 'uuid')],
        ]);
        // Move UUID to array key
        return array_flip($existingSighting);
    }

    /**
     * @param array $sightings
     * @return array Organisation UUID => Organisation ID
     */
    private function existingOrganisations(array $sightings)
    {
        $organisations = array_column($sightings, 'Organisation');
        if (empty($organisations)) {
            return [];
        }
        return $this->Organisation->find('list', [
            'fields' => ['Organisation.uuid', 'Organisation.id'],
            'conditions' => ['Organisation.uuid' => array_unique(array_column($organisations, 'uuid'), SORT_REGULAR)],
        ]);
    }

    /**
     * Sighting reporters setting
     * If the event has any sightings for the user's org, then the user is a sighting reporter for the event too.
     * This means that he /she has access to the sightings data contained within.
     *
     * @param int $eventId
     * @param int $orgId
     * @return bool
     */
    private function isReporter($eventId, $orgId)
    {
        return $this->hasAny([
            'Sighting.event_id' => $eventId,
            'Sighting.org_id' => $orgId,
        ]);
    }

    /**
     * Reduce memory usage by not fetching organisation object for every sighting but just once. Then organisation
     * object will be deduplicated in memory.
     *
     * @param int $orgId
     * @return array
     */
    private function getOrganisationById($orgId)
    {
        if (isset($this->orgCache[$orgId])) {
            return $this->orgCache[$orgId];
        }
        $org = $this->Organisation->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => $orgId],
            'fields' => ['Organisation.id', 'Organisation.uuid', 'Organisation.name']
        ]);
        if (!empty($org)) {
            $org = $org['Organisation'];
        }
        $this->orgCache[$orgId] = $org;
        return $org;
    }

    /**
     * @return int
     */
    private function sightingsPolicy()
    {
        $policy = Configure::read('Plugin.Sightings_policy');
        if ($policy === null) { // default policy
            return self::SIGHTING_POLICY_EVENT_OWNER;
        }
        return (int)$policy;
    }

    private function dateVirtualColumn()
    {
        if ($this->isMysql()) {
            return 'DATE(FROM_UNIXTIME(Sighting.date_sighting))';
        } else {
            return "to_char(date(to_timestamp(Sighting.date_sighting)), 'YYYY-MM-DD')"; // PostgreSQL
        }
    }

    /**
     * @param array $user
     * @param array $event
     * @return array|false
     */
    private function createConditions(array $user, array $event)
    {
        $sightingsPolicy = $this->sightingsPolicy();
        $ownEvent = $user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id'];
        if (!$ownEvent) {
            if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                return ['Sighting.org_id' => $user['org_id']];
            } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                if (!$this->isReporter($event['Event']['id'], $user['org_id'])) {
                    return false;
                }
            } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                return ['Sighting.org_id' => [$user['org_id'], Configure::read('MISP.host_org_id')]];
            }
        }
        return [];
    }
}
