<?php

App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

/**
 * ACL-less correlation behaviour for end-point instances
 */
class NoAclCorrelationBehavior extends ModelBehavior
{

    private $__tableName = 'no_acl_correlations';

    private $__config = [
        'AttributeFetcher' => [
            'fields' =>  [
                'Attribute.event_id',
                'Attribute.id',
                'Attribute.type',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => [
                        'Event.id',
                        'Event.disable_correlation',
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
                '1_attribute_id' => $a['Attribute']['id'],
                'event_id' => $b['Event']['id'],
                'attribute_id' => $b['Attribute']['id']
            ];
        } else {
            return [
                (int) $value_id,
                (int) $a['Event']['id'],
                (int) $a['Attribute']['id'],
                (int) $b['Event']['id'],
                (int) $b['Attribute']['id']
            ];
        }
    }

    public function saveCorrelations(Model $Model, $correlations)
    {
        $fields = [
            'value_id',
            '1_event_id',
            '1_attribute_id',
            'event_id',
            'attribute_id'
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
                    $db->insertMulti('no_acl_correlations', $fields, $chunk);
                }
                return true;
            } else {
                return $db->insertMulti('no_acl_correlations', $fields, $correlations);
            }
        }
    }

    public function runBeforeSaveCorrelation(Model $Model, $attribute) {
        // (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
        // ==> DELETE FROM no_acl_correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
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

    private function __collectCorrelations($user, $id, $primary)
    {
        $max_correlations = Configure::read('MISP.max_correlations_per_event') ?: 5000;
        $source = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $correlations = $this->Correlation->find('all', [
            'fields' => [
                $source . 'attribute_id',
                $prefix . 'attribute_id',
                $prefix . 'event_id'
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
        ]);
        return $correlations;
    }

    public function runGetAttributesRelatedToEvent(Model $Model, $user, $id)
    {
        $temp_correlations = $this->__collectCorrelations($user, $id, false);
        $temp_correlations_1 = $this->__collectCorrelations($user, $id, true);
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
        $conditions = [
            'Event.id' => array_keys($event_ids)
        ];
        $events = $Model->Event->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.info', 'Event.date'],
        ));

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
                '1_event_id',
                'value_id'
            ],
            [
                'attribute_id',
                'event_id',
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
        $primaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, true);
        $secondaryEventIds = $this->__filterRelatedEvents($Model, $user, $eventId, false);
        return array_unique(array_merge($primaryEventIds,$secondaryEventIds));

    }

    private function __filterRelatedEvents(Model $Model, array $user, int $eventId, bool $primary)
    {
        $current = $primary ? '' : '1_';
        $prefix = $primary ? '1_' : '';
        $correlations = $Model->find('all', [
            'recursive' => -1,
            'fields' => [
                $prefix . 'event_id'
            ],
            'conditions' => [
                $current . 'event_id' => $eventId
            ],
            'unique' => true,
        ]);
        $eventIds = Hash::extract($correlations, '{n}.Correlation.' . $prefix . 'event_id');
        return $eventIds;
    }

    public function updateContainedCorrelations(
        Model $Model,
        array $data,
        string $type = 'event',
        array $options = []
    ): bool
    {
        // We don't care. No ACL means nothing to change.
        return true;
    }

    public function purgeCorrelations(Model $Model, $eventId = null)
    {
        if (!$eventId) {
            $Model->query('TRUNCATE TABLE no_acl_correlations;');
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
