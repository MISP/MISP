<?php

App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

/**
 * Default correlation behaviour
 */
class DefaultCorrelationBehavior extends ModelBehavior
{

    private $__tableName = 'default_correlations';

    private $__config = [
        'AttributeFetcher' => [
            'fields' =>  [
                'Attribute.event_id',
                'Attribute.object_id',
                'Attribute.id',
                'Attribute.type',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => [
                        'Event.id',
                        'Event.org_id',
                        'Event.distribution',
                        'Event.sharing_group_id',
                        'Event.disable_correlation',
                    ]
                ],
                'Object' => [
                    'fields' => [
                        'Object.id',
                        'Object.distribution',
                        'Object.sharing_group_id',
                    ]
                ]
            ],
        ]
    ];

    public $Correlation = null;

    private $deadlockAvoidance = false;

    public function setup(Model $Model, $settings = []) {
        $Model->useTable = $this->__tableName;
        $this->Correlation = $Model;
        $this->deadlockAvoidance = $settings['deadlockAvoidance'];
    }

    public function getTableName(Model $Model)
    {
        return $this->__tableName;
    }

    public function createCorrelationEntry(Model $Model, $value, $a, $b) {
        $value_id = $this->Correlation->CorrelationValue->getValueId($value);
        if ($this->deadlockAvoidance) {
            return [
                'value_id' => $value_id,
                '1_event_id' => $a['Event']['id'],
                '1_object_id' => $a['Attribute']['object_id'],
                '1_attribute_id' => $a['Attribute']['id'],
                '1_org_id' => $a['Event']['org_id'],
                '1_distribution' => $a['Attribute']['distribution'],
                '1_event_distribution' => $a['Event']['distribution'],
                '1_object_distribution' => empty($a['Attribute']['object_id']) ? 0 : $a['Object']['distribution'],
                '1_sharing_group_id' => $a['Attribute']['sharing_group_id'],
                '1_event_sharing_group_id' => $a['Event']['sharing_group_id'],
                '1_object_sharing_group_id' => empty($a['Attribute']['object_id']) ? 0 : $a['Object']['sharing_group_id'],
                'event_id' => $b['Event']['id'],
                'object_id' => $b['Attribute']['object_id'],
                'attribute_id' => $b['Attribute']['id'],
                'org_id' => $b['Event']['org_id'],
                'distribution' => $b['Attribute']['distribution'],
                'event_distribution' => $b['Event']['distribution'],
                'object_distribution' => empty($b['Attribute']['object_id']) ? 0 : $b['Object']['distribution'],
                'sharing_group_id' => $b['Attribute']['sharing_group_id'],
                'event_sharing_group_id' => $b['Event']['sharing_group_id'],
                'object_sharing_group_id' => empty($b['Attribute']['object_id']) ? 0 : $b['Object']['sharing_group_id'],
            ];
        } else {
            return [
                (int) $value_id,
                (int) $a['Event']['id'],
                (int) $a['Attribute']['object_id'],
                (int) $a['Attribute']['id'],
                (int) $a['Event']['org_id'],
                (int) $a['Attribute']['distribution'],
                (int) $a['Event']['distribution'],
                (int) empty($a['Attribute']['object_id']) ? 0 : $a['Object']['distribution'],
                (int) $a['Attribute']['sharing_group_id'],
                (int) $a['Event']['sharing_group_id'],
                (int) empty($a['Attribute']['object_id']) ? 0 : $a['Object']['sharing_group_id'],
                (int) $b['Event']['id'],
                (int) $b['Attribute']['object_id'],
                (int) $b['Attribute']['id'],
                (int) $b['Event']['org_id'],
                (int) $b['Attribute']['distribution'],
                (int) $b['Event']['distribution'],
                (int) empty($b['Attribute']['object_id']) ? 0 : $b['Object']['distribution'],
                (int) $b['Attribute']['sharing_group_id'],
                (int) $b['Event']['sharing_group_id'],
                (int) empty($b['Attribute']['object_id']) ? 0 : $b['Object']['sharing_group_id']
            ];
        }
    }

    public function saveCorrelations(Model $Model, $correlations)
    {
        $fields = [
            'value_id',
            '1_event_id',
            '1_object_id',
            '1_attribute_id',
            '1_org_id',
            '1_distribution',
            '1_event_distribution',
            '1_object_distribution',
            '1_sharing_group_id',
            '1_event_sharing_group_id',
            '1_object_sharing_group_id',
            'event_id',
            'object_id',
            'attribute_id',
            'org_id',
            'distribution',
            'event_distribution',
            'object_distribution',
            'sharing_group_id',
            'event_sharing_group_id',
            'object_sharing_group_id'
        ];

        if ($this->deadlockAvoidance) {
          return $this->Correlation->saveMany($correlations, array(
                'atomic' => false,
                'callbacks' => false,
                'deep' => false,
                'validate' => false,
                'fieldList' => $fields
            ));
        } else {
            $db = $this->Correlation->getDataSource();
            // Split to chunks datasource is is enabled
            if (count($correlations) > 100) {
                foreach (array_chunk($correlations, 100) as $chunk) {
                    $db->insertMulti('default_correlations', $fields, $chunk);
                }
                return true;
            } else {
                return $db->insertMulti('default_correlations', $fields, $correlations);
            }
        }
    }

    public function runBeforeSaveCorrelation(Model $Model, $attribute)
    {
        // (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
        // ==> DELETE FROM default_correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
        // first check if it's an update
        if (isset($attribute['id'])) {
            $Model->deleteAll([
                'OR' => [
                    '1_attribute_id' => $attribute['id'],
                    'attribute_id' => $attribute['id']
                ],
            ], false);
        }
        if ($attribute['type'] === 'ssdeep') {
            $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
            $this->FuzzyCorrelateSsdeep->purge(null, $attribute['id']);
        }
    }

    public function getContainRules(Model $Model, $filter = null)
    {
        if (empty($filter)) {
            return $this->__config['AttributeFetcher']['contain'];
        } else {
            return empty($this->__config['AttributeFetcher']['contain'][$filter]) ? false : $this->__config['AttributeFetcher']['contain'][$filter];
        }
    }

    public function getFieldRules(Model $Model)
    {
        return $this->__config['AttributeFetcher']['fields'];
    }

    private function __collectCorrelations($user, $id, $sgids, $primary)
    {
        $max_correlations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $source = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $correlations = $this->Correlation->find('all', array(
            'fields' => [
                $source . 'attribute_id',
                $prefix . 'attribute_id',
                $prefix . 'org_id',
                $prefix . 'event_id',
                $prefix . 'event_distribution',
                $prefix . 'event_sharing_group_id',
                $prefix . 'object_id',
                $prefix . 'object_distribution',
                $prefix . 'object_sharing_group_id',
                $prefix . 'distribution',
                $prefix . 'sharing_group_id'
            ],
            'conditions' => [
                'OR' => [
                    $source . 'event_id' => $id
                ],
                'AND' => [
                    [
                        'CorrelationValue.value NOT IN (select value from correlation_exclusions)'
                    ],
                    [
                        'CorrelationValue.value NOT IN (select value from over_correlating_values)'
                    ]
                ]
            ],
            'recursive' => -1,
            'contain' => [
                'CorrelationValue' => [
                    'fields' => [
                        'CorrelationValue.id',
                        'CorrelationValue.value'
                    ]
                ]
            ],
            'order' => false,
            'limit' => $max_correlations
        ));
        foreach ($correlations as $k => &$correlation) {
            if (!$this->checkCorrelationACL($user, $correlation['Correlation'], $sgids, $prefix)) {
                unset($correlations[$k]);
            }
        }
        $correlations = array_values($correlations);
        return $correlations;
    }

    public function runGetAttributesRelatedToEvent(Model $Model, $user, $id, $sgids)
    {
        $temp_correlations = $this->__collectCorrelations($user, $id, $sgids, false);
        $temp_correlations_1 = $this->__collectCorrelations($user, $id, $sgids, true);
        $correlations = [];
        $event_ids = [];
        foreach ($temp_correlations as $temp_correlation) {
            $correlations[] = [
                'id' => $temp_correlation['Correlation']['event_id'],
                'attribute_id' => $temp_correlation['Correlation']['attribute_id'],
                'parent_id' => $temp_correlation['Correlation']['1_attribute_id'],
                'value' => $temp_correlation['CorrelationValue']['value']
            ];
            $event_ids[$temp_correlation['Correlation']['event_id']] = true;
        }
        foreach ($temp_correlations_1 as $temp_correlation) {
            $correlations[] = [
                'id' => $temp_correlation['Correlation']['1_event_id'],
                'attribute_id' => $temp_correlation['Correlation']['1_attribute_id'],
                'parent_id' => $temp_correlation['Correlation']['attribute_id'],
                'value' => $temp_correlation['CorrelationValue']['value']
            ];
            $event_ids[$temp_correlation['Correlation']['1_event_id']] = true;
        }
        if (empty($correlations)) {
            return [];
        }
        $conditions = $Model->Event->createEventConditions($user);
        $conditions['Event.id'] = array_keys($event_ids);
        $events = $Model->Event->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.info', 'Event.date'],
        ]);

        $events = array_column(array_column($events, 'Event'), null, 'id');
        $relatedAttributes = [];
        foreach ($correlations as $correlation) {
            $eventId = $correlation['id'];
            if (!isset($events[$eventId])) {
                continue;
            }
            $event = $events[$eventId];
            $correlation['org_id'] = $events[$eventId]['orgc_id'];
            $correlation['info'] = $events[$eventId]['info'];
            $correlation['date'] = $events[$eventId]['date'];
            $parentId = $correlation['parent_id'];
            unset($correlation['parent_id']);
            $relatedAttributes[$parentId][] = $correlation;
        }
        return $relatedAttributes;
    }

    public function runGetRelatedAttributes(Model $Model, $user, $sgids, $attribute, $fields = [], $includeEventData = false)
    {
        // LATER getRelatedAttributes($attribute) this might become a performance bottleneck
        // prepare the conditions
        $conditions = [
            [
                'Correlation.1_event_id !=' => $attribute['event_id'],
                'Correlation.attribute_id' => $attribute['id']
            ],
            [
                'Correlation.event_id !=' => $attribute['event_id'],
                'Correlation.1_attribute_id' => $attribute['id']
            ]
        ];
        $corr_fields = [
            [
                '1_attribute_id',
                '1_object_id',
                '1_event_id',
                '1_distribution',
                '1_object_distribution',
                '1_event_distribution',
                '1_sharing_group_id',
                '1_object_sharing_group_id',
                '1_event_sharing_group_id',
                '1_org_id',
                'value_id'
            ],
            [
                'attribute_id',
                'object_id',
                'event_id',
                'distribution',
                'object_distribution',
                'event_distribution',
                'sharing_group_id',
                'object_sharing_group_id',
                'event_sharing_group_id',
                'org_id',
                'value_id'
            ]
        ];
        $prefixes = ['1_', ''];
        $correlated_attribute_ids = [];
        foreach ($conditions as $k => $condition) {
            $temp_correlations = $Model->find('all', [
                'recursive' => -1,
                'conditions' => $condition,
                'fields' => $corr_fields[$k]
            ]);
            if (!empty($temp_correlations)) {
                foreach ($temp_correlations as $temp_correlation) {
                    if (empty($user['Role']['perm_site_admin'])) {
                        if (!$this->checkCorrelationACL($user, $temp_correlation, $sgids, $prefixes[$k])) {
                            continue;
                        }
                    }
                    $correlated_attribute_ids[] = $temp_correlation['Correlation'][$prefixes[$k] . 'attribute_id'];
                }
            }
        }
        $contain = [];
        if (!empty($includeEventData)) {
            $contain['Event'] = [
                'fields' => [
                    'Event.id',
                    'Event.uuid',
                    'Event.threat_level_id',
                    'Event.analysis',
                    'Event.info',
                    'Event.extends_uuid',
                    'Event.distribution',
                    'Event.sharing_group_id',
                    'Event.published',
                    'Event.date',
                    'Event.orgc_id',
                    'Event.org_id'
                ]
            ];
        }
        $relatedAttributes = $Model->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => [
                'Attribute.id' => $correlated_attribute_ids
            ],
            'fields' => $fields,
            'contain' => $contain
        ]);
        if (!empty($includeEventData)) {
            $results = [];
            foreach ($relatedAttributes as $k => $attribute) {
                $temp = $attribute['Attribute'];
                $temp['Event'] = $attribute['Event'];
                $results[] = $temp;
            }
            return $results;
        } else {
            return $relatedAttributes;
        }
    }

    public function fetchRelatedEventIds(Model $Model, array $user, int $eventId, array $sgids)
    {
        // search the correlation table for the event ids of the related events
        // Rules:
        // 1. Event is owned by the user (org_id matches)
        // 2. User is allowed to see both the event and the org:
        //    a.  Event:
        //        i. Event has a distribution between 1-3 (community only, connected communities, all orgs)
        //        ii. Event has a sharing group that the user is accessible to view
        //    b.  Attribute:
        //        i. Attribute has a distribution of 5 (inheritance of the event, for this the event check has to pass anyway)
        //        ii. Atttibute has a distribution between 1-3 (community only, connected communities, all orgs)
        //        iii. Attribute has a sharing group that the user is accessible to view
        $primaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, true);
        $secondaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, $sgids, false);
        return array_unique(array_merge($primaryEventIds,$secondaryEventIds));

    }

    private function __filterRelatedEvents(Model $Model, array $user, int $eventId, array $sgids, bool $primary)
    {
        $current = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $correlations = $Model->find('all', [
            'recursive' => -1,
            'fields' => [
                $prefix . 'org_id',
                $prefix . 'event_id',
                $prefix . 'event_distribution',
                $prefix . 'event_sharing_group_id',
                $prefix . 'object_id',
                $prefix . 'object_distribution',
                $prefix . 'object_sharing_group_id',
                $prefix . 'distribution',
                $prefix . 'sharing_group_id'
            ],
            'conditions' => [
                $current . 'event_id' => $eventId
            ],
            'unique' => true,
        ]);
        $eventIds = [];
        if (empty($user['Role']['perm_site_admin'])) {
            foreach ($correlations as $k => $correlation) {
                // if we have already added this event as a valid target, no need to check again.
                if (isset($eventIds[$correlation['Correlation'][$prefix . 'event_id']])) {
                    continue;
                }
                $correlation = $correlation['Correlation'];
                if (!$this->checkCorrelationACL($user, $correlation, $sgids, $prefix)) {
                    unset($correlations[$k]);
                    continue;
                }
                $eventIds[$correlation[$prefix . 'event_id']] = true;
            }
            return array_keys($eventIds);
        } else {
            $eventIds = Hash::extract($correlations, '{n}.Correlation.' . $prefix . 'event_id');
            return $eventIds;
        }
    }

    private function checkCorrelationACL($user, $correlation, $sgids, $prefix)
    {
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        // check if user can see the event
        if (isset($correlation['Correlation'])) {
            $correlation = $correlation['Correlation'];
        }
        if (
            $correlation[$prefix . 'org_id'] != $user['org_id'] &&
            (
                $correlation[$prefix . 'event_distribution'] == 0 ||
                (
                    $correlation[$prefix . 'event_distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'event_sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }

        //check if the user can see the object, if we're looking at an object attribute
        if (
            $correlation[$prefix . 'object_id'] &&
            (
                $correlation[$prefix . 'object_distribution'] == 0 ||
                $correlation[$prefix . 'object_distribution'] == 5 ||
                (
                    $correlation[$prefix . 'object_distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'object_sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }

        //check if the user can see the attribute
        if (
            (
                $correlation[$prefix . 'distribution'] == 0 ||
                (
                    $correlation[$prefix . 'distribution'] == 4 &&
                    !in_array($correlation[$prefix . 'sharing_group_id'], $sgids)
                )
            )
        ) {
            return false;
        }
        return true;
    }

    public function updateContainedCorrelations(
        Model $Model,
        array $data,
        string $type = 'event',
        array $options = []
    )
    {
        $updateCorrelation = [];
        $updateFields = [
            'Correlation.' . $type . '_id',
            'Correlation.1_' . $type . '_id'
        ];
        if (
            isset($data['distribution']) &&
            (
                empty($options['fieldList']) ||
                in_array('distribution', $options['fieldList'])
            )
        ) {
            $updateCorrelation[0]['Correlation.' . $type . '_distribution'] = (int)$data['distribution'];
            $updateCorrelation[1]['Correlation.1_' . $type . '_distribution'] = (int)$data['distribution'];
        }
        if (
            isset($data['sharing_group_id']) &&
            (
                empty($options['fieldList']) ||
                in_array('sharing_group_id', $options['fieldList'])
            )
        ) {
            $updateCorrelation[0]['Correlation.' . $type . '_sharing_group_id'] = (int)$data['sharing_group_id'];
            $updateCorrelation[1]['Correlation.1_' . $type . '_sharing_group_id'] = (int)$data['sharing_group_id'];
        }
        if (!empty($updateCorrelation)) {
            foreach ($updateCorrelation as $k => $side) {
                $Model->updateAll(
                    $side,
                    [
                        $updateFields[$k] => (int)$data['id']]
                );
            }
        }
        return true;
    }

    public function purgeCorrelations(Model $Model, $eventId = null)
    {
        if (!$eventId) {
            $Model->query('TRUNCATE TABLE default_correlations;');
            //$Model->query('TRUNCATE TABLE correlation_values;');
            //$Model->query('TRUNCATE TABLE over_correlating_values;');
        } else {
            $Model->deleteAll([
                'OR' => array(
                    'Correlation.1_event_id' => $eventId,
                    'Correlation.event_id' => $eventId,
                )
            ], false);
        }
    }

    public function purgeByValue(Model $Model, string $value)
    {
        $valueIds = $Model->CorrelationValue->find('column', [
            'recursive' => -1,
            'conditions' => [
                'OR' => [
                    'CorrelationValue.value LIKE' => '%' . $value,
                    'CorrelationValue.value LIKE' => $value . '%'
                ]
            ],
            'fields' => [
                'CorrelationValue.id'
            ]
        ]);
        $Model->deleteAll([
            'Correlation.value_id' => $valueIds
        ]);
    }
}
