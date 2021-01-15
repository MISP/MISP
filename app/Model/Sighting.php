<?php
App::uses('AppModel', 'Model');
App::uses('TmpFileTool', 'Tools');

/**
 * @property Attribute $Attribute
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
            'Attribute',
            'Event',
            'Organisation' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id'
            ),
    );

    public $type = array(
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
        parent::beforeValidate();
        if (empty($this->data['Sighting']['id']) && empty($this->data['Sighting']['date_sighting'])) {
            $this->data['Sighting']['date_sighting'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['Sighting']['uuid'])) {
            $this->data['Sighting']['uuid'] = CakeText::uuid();
        } else {
            $this->data['Sighting']['uuid'] = strtolower($this->data['Sighting']['uuid']);
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options = array());
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_sighting_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_sighting_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_sighting_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            $user = array(
                'org_id' => -1,
                'Role' => array(
                    'perm_site_admin' => 1
                )
            );
            $sighting = $this->getSighting($this->id, $user);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->sighting_save($sighting, 'add');
            }
            if ($pubToKafka) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $sighting, 'add');
            }
        }
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        parent::beforeDelete();
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_sighting_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_sighting_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_sighting_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            $user = array(
                'org_id' => -1,
                'Role' => array(
                    'perm_site_admin' => 1
                )
            );
            $sighting = $this->getSighting($this->id, $user);
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->sighting_save($sighting, 'delete');
            }
            if ($pubToKafka) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $sighting, 'delete');
            }
        }
    }

    /**
     * @param array $sightings
     * @param int $attributeId
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

        $toSave = [];
        foreach ($sightings as $sighting) {
            if (isset($existingSighting[$sighting['uuid']])) {
                continue; // already exists, skip
            }

            $orgId = 0;
            if (isset($sighting['Organisation'])) {
                if (isset($existingOrganisations[$sighting['Organisation']['uuid']])) {
                    $orgId = $existingOrganisations[$sighting['Organisation']['uuid']];
                } else {
                    $orgId = $this->Organisation->captureOrg($sighting['Organisation'], $user);
                }
            }
            unset($sighting['id']);

            $sighting['org_id'] = $orgId;
            $sighting['event_id'] = $eventId;
            $sighting['attribute_id'] = $attributeId;
            $toSave[] = $sighting;
        }

        return $this->saveMany($toSave);
    }

    /**
     * @param int $id
     * @param array $user
     * @param bool $withEvent
     * @return array
     */
    public function getSighting($id, array $user, $withEvent = true)
    {
        $sighting = $this->find('first', array(
            'recursive' => -1,
            'contain' => array(
                'Attribute' => array(
                    'fields' => array('Attribute.value', 'Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.to_ids')
                ),
                'Event' => array(
                    'fields' => $withEvent ? ['Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.org_id', 'Event.info'] : ['Event.org_id'],
                )
            ),
            'conditions' => array('Sighting.id' => $id)
        ));
        if (empty($sighting)) {
            return array();
        }

        $ownEvent = $user['Role']['perm_site_admin'] || $sighting['Event']['org_id'] == $user['org_id'];
        if (!$ownEvent) {
            $sightingPolicy = $this->sightingsPolicy();
            // if sighting policy == 0 then return false if the sighting doesn't belong to the user
            if ($sightingPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                if ($sighting['Sighting']['org_id'] != $user['org_id']) {
                    return array();
                }
            }
            // if sighting policy == 1, the user can only see the sighting if they've sighted something in the event once
            else if ($sightingPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                if (!$this->isReporter($sighting['Sighting']['event_id'], $user['org_id'])) {
                    return array();
                }
            }
            else if ($sightingPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                if ($sighting['Sighting']['org_id'] != $user['org_id'] || $sighting['Sighting']['org_id'] != Configure::read('MISP.host_org_id')) {
                    return array();
                }
            }
        }

        // Put event organisation name from cache
        if ($withEvent) {
            $sighting['Event']['Orgc']['name'] = $this->getOrganisationById($sighting['Event']['orgc_id'])['name'];
        }

        $anonymise = Configure::read('Plugin.Sightings_anonymise');
        if ($anonymise && $sighting['Sighting']['org_id'] != $user['org_id']) {
            unset($sighting['Sighting']['org_id']);
        }
        // rearrange it to match the event format of fetchevent
        $result = array(
            'Sighting' => $sighting['Sighting']
        );
        if ($withEvent) {
            $result['Sighting']['Event'] = $sighting['Event'];
        }
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

        $sightingsPolicy = $this->sightingsPolicy();

        $conditions = [];
        foreach ($attributes as $attribute) {
            $attributeConditions = ['Sighting.attribute_id' => $attribute['Attribute']['id']];
            $ownEvent = $user['Role']['perm_site_admin'] || $attribute['Event']['org_id'] == $user['org_id'];
            if (!$ownEvent) {
                if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                    $attributeConditions['Sighting.org_id'] = $user['org_id'];
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                    if (!$this->isReporter($attribute['Event']['id'], $user['org_id'])) {
                        continue; // skip attribute
                    }
                } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                    $attributeConditions['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
                }
            }
            $conditions['OR'][] = $attributeConditions;
        }

        $groupedSightings = $this->fetchGroupedSightings($conditions, $user);
        return $this->generateStatistics($groupedSightings, $csvWithFalsePositive);
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
            $type = $this->type[$sighting['type']];
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
            if ($sighting['org_id'] != $user['org_id'] && ($anonymise || !empty($anonOrg))) {
                if (empty($anonOrg)) {
                    unset($sighting['org_id']);
                    unset($sighting['Organisation']);
                } else {
                    $sighting['org_id'] = $anonOrg['Organisation']['id'];
                    $sighting['Organisation'] = $anonOrg['Organisation'];
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
     * @param array|int|null $attribute Attribute model or attribute ID
     * @param array|bool $extraConditions
     * @param bool $forSync
     * @return array|int
     */
    public function attachToEvent(array $event, array $user, $attribute = null, $extraConditions = false, $forSync = false)
    {
        $contain = [];
        $conditions = array('Sighting.event_id' => $event['Event']['id']);
        if (isset($attribute['Attribute']['id'])) {
            $conditions['Sighting.attribute_id'] = $attribute['Attribute']['id'];
        } elseif (is_numeric($attribute)) {
            $conditions['Sighting.attribute_id'] = $attribute;
            $attribute = $this->Attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $attribute],
                'fields' => ['Attribute.uuid']
            ]);
        } else {
            $contain['Attribute'] = ['fields' => 'Attribute.uuid'];
        }

        $ownEvent = $user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id'];
        if (!$ownEvent) {
            $sightingsPolicy = $this->sightingsPolicy();
            if ($sightingsPolicy === self::SIGHTING_POLICY_EVENT_OWNER) {
                $conditions['Sighting.org_id'] = $user['org_id'];
            } elseif ($sightingsPolicy === self::SIGHTING_POLICY_SIGHTING_REPORTER) {
                if (!$this->isReporter($event['Event']['id'], $user['org_id'])) {
                    return array();
                }
            } else if ($sightingsPolicy === self::SIGHTING_POLICY_HOST_ORG) {
                $conditions['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
            }
        }
        if ($extraConditions !== false) {
            $conditions['AND'] = $extraConditions;
        }
        $sightings = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => $contain,
        ));
        if (empty($sightings)) {
            return array();
        }
        foreach ($sightings as $k => $sighting) {
            if (isset($sighting['Attribute']['uuid'])) {
                $sighting['Sighting']['attribute_uuid'] = $sighting['Attribute']['uuid'];
            } else {
                $sighting['Sighting']['attribute_uuid'] = $attribute['Attribute']['uuid'];
            }
            $sightings[$k] = $sighting;
        }
        return $this->attachOrgToSightings($sightings, $user, $forSync);
    }

    public function saveSightings($id, $values, $timestamp, $user, $type = false, $source = false, $sighting_uuid = false, $publish = false, $saveOnBehalfOf = false)
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
            foreach ($values as $value) {
                foreach (array('value1', 'value2') as $field) {
                    $conditions['OR'][] = array(
                        'LOWER(Attribute.' . $field . ') LIKE' => strtolower($value)
                    );
                }
            }
        }
        $attributes = $this->Attribute->fetchAttributesSimple($user, [
            'conditions' => $conditions,
            'fields' => ['Attribute.id', 'Attribute.event_id'],
        ]);
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
                $this->Event->publishRouter($sighting['event_id'], null, $user, 'sightings');
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
        $result = shell_exec($this->getPythonVersion() . ' ' . $scriptFile . ' ' . $randomFileName);
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
        $this->Event = ClassRegistry::init('Event');
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

    public function restSearch($user, $returnFormat, $filters)
    {
        $allowedContext = array('event', 'attribute');
        // validate context
        if (isset($filters['context']) && !in_array($filters['context'], $allowedContext, true)) {
            throw new MethodNotAllowedException(__('Invalid context.'));
        }
        // ensure that an id or uuid is provided if context is set
        if (!empty($filters['context']) && !(isset($filters['id']) || isset($filters['uuid'])) ) {
            throw new MethodNotAllowedException(__('An ID or UUID must be provided if the context is set.'));
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
            $this->Organisation = ClassRegistry::init('Organisation');
            if (!is_array($filters['org_id'])) {
                $filters['org_id'] = array($filters['org_id']);
            }
            foreach ($filters['org_id'] as $k => $org_id) {
                if (Validation::uuid($org_id)) {
                    $org = $this->Organisation->find('first', array(
                        'conditions' => array('Organisation.uuid' => $org_id),
                        'recursive' => -1,
                        'fields' => array('Organisation.id'),
                    ));
                    if (empty($org)) {
                        $filters['org_id'][$k] = -1;
                    } else {
                        $filters['org_id'][$k] = $org['Organisation']['id'];
                    }
                }
            }
            $conditions['Sighting.org_id'] = $filters['org_id'];
        }

        if (isset($filters['source'])) {
            $conditions['Sighting.source'] = $filters['source'];
        }

        if (!empty($filters['id'])) {
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
                $conditions['Event.uuid'] = $filters['uuid'];
                $contain[] = 'Event';
            }
        }

        // fetch sightings matching the query
        $sightingIds = $this->find('column', [
            'conditions' => $conditions,
            'fields' => ['Sighting.id'],
            'contain' => $contain,
        ]);

        $includeAttribute = isset($filters['includeAttribute']) && $filters['includeAttribute'];
        $includeEvent = isset($filters['includeEvent']) && $filters['includeEvent'];
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

        foreach ($sightingIds as $sightingId) {
            // apply ACL and sighting policies
            $sighting = $this->getSighting($sightingId, $user, $includeEvent);
            if (!empty($sighting)) {
                $sighting['Sighting']['value'] = $sighting['Sighting']['Attribute']['value'];
                if (!$includeAttribute) {
                    unset($sighting['Sighting']['Attribute']);
                }
                $tmpfile->writeWithSeparator($exportTool->handler($sighting, $exportToolParams), $separator);
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
                        if (isset($existingOrganisations[$s['Organisation']['uuid']])) {
                            $saveOnBehalfOf = $existingOrganisations[$s['Organisation']['uuid']];
                        } else {
                            $saveOnBehalfOf = $this->Organisation->captureOrg($s['Organisation'], $user);
                        }
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
            $this->Event->publishRouter($event['Event']['id'], $passAlong, $user, 'sightings');
            return count($toSave);
        } else {
            return 0;
        }
    }

    public function pullSightings($user, $server)
    {
        $HttpSocket = $this->setupHttpSocket($server);
        $this->Server = ClassRegistry::init('Server');
        try {
            $eventIds = $this->Server->getEventIdsFromServer($server, false, $HttpSocket, false, 'sightings');
        } catch (Exception $e) {
            $this->logException("Could not fetch event IDs from server {$server['Server']['name']}", $e);
            return 0;
        }
        $saved = 0;
        // now process the $eventIds to pull each of the events sequentially
        // download each event and save sightings
        foreach ($eventIds as $k => $eventId) {
            try {
                $event = $this->Event->downloadEventFromServer($eventId, $server);
            } catch (Exception $e) {
                $this->logException("Failed downloading the event $eventId from {$server['Server']['name']}.", $e);
                continue;
            }
            $sightings = array();
            if (!empty($event) && !empty($event['Event']['Attribute'])) {
                foreach ($event['Event']['Attribute'] as $attribute) {
                    if (!empty($attribute['Sighting'])) {
                        $sightings = array_merge($sightings, $attribute['Sighting']);
                    }
                }
            }
            if (!empty($event) && !empty($sightings)) {
                $result = $this->bulkSaveSightings($event['Event']['uuid'], $sightings, $user, $server['Server']['id']);
                if (is_numeric($result)) {
                    $saved += $result;
                }
            }
        }
        return $saved;
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
            'conditions' => ['Organisation.uuid' => array_unique(array_column($organisations, 'uuid'))],
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
        return (bool)$this->find('first', array(
            'recursive' => -1,
            'callbacks' => false,
            'fields' => ['Sighting.id'],
            'conditions' => array(
                'Sighting.event_id' => $eventId,
                'Sighting.org_id' => $orgId,
            )
        ));
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
        return $this->orgCache[$orgId];
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
        if (in_array($this->getDataSource()->config['datasource'], ['Database/Mysql', 'Database/MysqlObserver'], true)) {
            return 'DATE(FROM_UNIXTIME(Sighting.date_sighting))';
        } else {
            return "to_char(date(to_timestamp(Sighting.date_sighting)), 'YYYY-MM-DD')"; // PostgreSQL
        }
    }
}
