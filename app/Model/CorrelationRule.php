<?php
App::uses('AppModel', 'Model');

class CorrelationRule extends AppModel
{
    public $recursive = -1;

    public $virtualTable = false;

    private $__conditionCache = [
        'orgc_id' => [],
        'org_id' => [],
        'event_id' => [],
        'event_info' => []
    ];

    private $__eventCache = null;

    private $__ruleCache = null;

    public $valid_types = [
        'orgc_id' => 'Creator org ID',
        'org_id' => 'Local owner org ID',
        'event_id' => 'Event ID',
        'event_info' => 'Event info (sub-)string'
    ];

    const TYPE_FUNCTION_MAPPING = [
        'orgc_id' => '__generateOrgcIdRule',
        'org_id' => '__generateOrgIdRule',
        'event_id' => '__generateEventIdRule',
        'event_info' => '__generateEventInfoRule',
    ];

    private $Event = null;

    public function beforeValidate($options = array())
    {
        if (empty($this->data['CorrelationRule'])) {
            $this->data = ['CorrelationRule' => $this->data];
        }
        if (empty($this->id) && empty($this->data['CorrelationRule']['uuid'])) {
            $this->data['CorrelationRule']['uuid'] = CakeText::uuid();
        }
        if (empty($this->id)) {
            $this->data['CorrelationRule']['created'] = time();    
        }
        $this->data['CorrelationRule']['timestamp'] = time();
        if (!is_array($this->data['CorrelationRule']['selector_list'])) {
            $this->data['CorrelationRule']['selector_list'] = json_decode($this->data['CorrelationRule']['selector_list'], true);
        }
        if (empty($this->data['CorrelationRule']['selector_list'])) {
            return false;
        }
        $this->data['CorrelationRule']['selector_list'] = json_encode($this->data['CorrelationRule']['selector_list'], JSON_PRETTY_PRINT);
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$result) {
            $result['CorrelationRule']['selector_list'] = json_decode($result['CorrelationRule']['selector_list'], true);
        }
        return $results;
    }

    public function generateVirtualTable()
    {
        $this->__loadRuleCache();
        if (!$this->virtualTable) {
            $query = '
            CREATE TEMPORARY TABLE tmp_excludes (
                event_id BIGINT NOT NULL,
                rule_id  INT    NOT NULL,
                PRIMARY KEY(event_id,rule_id)
            ) ENGINE=MEMORY
            ';
            if ($this->query($query)) {
                $this->Event = ClassRegistry::init('Event');
                foreach ($this->__ruleCache as $rule) {
                    $values = [];
                    $ruleId = intval($rule['CorrelationRule']['id']);
                    if (empty($rule['CorrelationRule']['selector_list'])) {
                        continue;
                    }
                    if ($rule['CorrelationRule']['selector_type'] === 'event_id') {
                        foreach ($rule['CorrelationRule']['selector_list'] as $eventId) {
                            $values[] = '(' . intval($eventId) . ',' . $ruleId . ')';
                        }
                    } elseif ($rule['CorrelationRule']['selector_type'] === 'orgc_id') {
                        $eventIds = $this->Event->find('column', [
                            'recursive' => -1,
                            'conditions' => [
                                'Event.orgc_id' => $rule['CorrelationRule']['selector_list']
                            ],
                            'fields' => ['Event.id']
                        ]);
                        foreach ($eventIds as $eventId) {
                            $values[] = '(' . intval($eventId) . ',' . $ruleId . ')';
                        }
                    } elseif ($rule['CorrelationRule']['selector_type'] === 'org_id') {
                        $eventIds = $this->Event->find('column', [
                            'recursive' => -1,
                            'conditions' => [
                                'Event.org_id' => $rule['CorrelationRule']['selector_list']
                            ],
                            'fields' => ['Event.id']
                        ]);
                        foreach ($eventIds as $eventId) {
                            $values[] = '(' . intval($eventId) . ',' . $ruleId . ')';
                        }
                    } elseif ($rule['CorrelationRule']['selector_type'] === 'event_info') {
                        $subConditions = [];
                        foreach ($rule['CorrelationRule']['selector_list'] as $selector) {
                            $subConditions[] = ['LOWER(Event.info) LIKE' => mb_strtolower($selector)];
                        }
                        $eventIds = $this->Event->find('column', [
                            'recursive' => -1,
                            'conditions' => [
                                'OR' => $subConditions
                            ],
                            'fields' => ['Event.id']
                        ]);
                        foreach ($eventIds as $eventId) {
                            $values[] = '(' . intval($eventId) . ',' . $ruleId . ')';
                        }
                    }
                    $this->query('INSERT INTO tmp_excludes (event_id, rule_id) VALUES ' . implode(", ", $values) . ';');
                }
                $this->virtualTable = true;
            } else {
                return false;
            }
        }
        return true;
    }

    public function generateConditionsForEvent($event)
    {
        $conditions = [];
        if (!isset($this->__conditionCache[$event['id']])) {
            foreach ($this->__ruleCache as $rule) {
                $this->__generateEventRule($event, $rule);
            }
        }
        if (!empty($this->__conditionCache[$event['id']]['event_id'])) {
            $conditions['Attribute.event_id NOT IN'] = $this->__conditionCache[$event['id']]['event_id'];
        }
        if (!empty($this->__conditionCache[$event['id']]['orgc_id'])) {
            $conditions['Event.orgc_id NOT IN'] = $this->__conditionCache[$event['id']]['orgc_id'];
        }
        if (!empty($this->__conditionCache[$event['id']]['org_id'])) {
            $conditions['Event.org_id NOT IN'] = $this->__conditionCache[$event['id']]['org_id'];
        }
        if (!empty($this->__conditionCache[$event['id']]['event_info'])) {
            $conditions['AND'][] = ['Event.id NOT IN' => $this->__conditionCache[$event['id']]['event_info']];
        }
        return $conditions;
    }

    public function attachCustomCorrelationRules($attribute, $conditions)
    {
        $this->__loadRuleCache();
        if (empty($attribute['Event']['id'])) {
            // If no event ID is set, we cannot filter by correlation rules
            return $conditions;
        } else if ($this->virtualTable) {
            $rules = $this->query('SELECT DISTINCT(rule_id) as rule FROM tmp_excludes WHERE event_id = ' . intval($attribute['Attribute']['event_id']));
            if (!empty($rules)) {
                $ruleIds = [];
                foreach ($rules as $rule) {
                    $ruleIds[] = intval($rule['tmp_excludes']['rule']);
                }
                $conditions['AND'][] = sprintf(
                    'NOT EXISTS (SELECT 1 FROM tmp_excludes WHERE tmp_excludes.event_id = Event.id AND tmp_excludes.rule_id IN (%s))',
                    implode(', ', $ruleIds)
                );
            }
        } else {
            $filterConditions = $this->generateConditionsForEvent($attribute['Event']);
            $conditions['AND'][] = $filterConditions;
        }
        return $conditions;
    }

    public function canCorrelate($data)
    {
        if (!isset($data['Event'])) {
            return true;
        }
        if (!isset($this->__eventCache[$data['Event']['id']])) {
            $this->__loadRuleCache();
            foreach ($this->__ruleCache as $rule) {
                if ($this->__checkEventAgainstRule($data, $rule)) {
                    return false;
                }
            }
        }
        return true;
    }

    private function __checkEventAgainstRule($data, $rule)
    {
        if ($rule['CorrelationRule']['selector_type'] === 'event_id') {
            return in_array($data['Event']['id'], $rule['CorrelationRule']['selector_list']);
        } elseif ($rule['CorrelationRule']['selector_type'] === 'orgc_id') {
            return in_array($data['Event']['orgc_id'], $rule['CorrelationRule']['selector_list']);
        } elseif ($rule['CorrelationRule']['selector_type'] === 'org_id') {
            return in_array($data['Event']['org_id'], $rule['CorrelationRule']['selector_list']);
        } elseif ($rule['CorrelationRule']['selector_type'] === 'event_info') {
            $info = strtolower($data['Event']['info']);
            foreach ($rule['CorrelationRule']['selector_list'] as $selector) {
                if ($selector[0] === '%' && $selector[-1] === '%') {
                    if (str_contains($info, substr($selector, 1, -1))) {
                        return true;
                    }
                } elseif ($selector[0] === '%') {
                    if (str_ends_with($info, substr($selector, 1))) {
                        return true;
                    }
                } elseif ($selector[-1] === '%') {
                    if (str_starts_with($info, substr($selector, 0, -1))) {
                        return true;
                    }
                } elseif ($info === $selector) {
                    return true;
                }
            }
        }
        return false;
    }

    private function __loadRuleCache()
    {
        if ($this->__ruleCache !== null) {
            return true;
        }
        $this->__ruleCache = $this->find('all', ['recursive' => -1]);
        return true;
    }

    private function __generateEventRule($event, $rule)
    {
        return $this->{self::TYPE_FUNCTION_MAPPING[$rule['CorrelationRule']['selector_type']]}($event, $rule['CorrelationRule']);
    }

    private function __createEmptyArrayIfNotSet($id, $field)
    {
        if (!isset($this->__conditionCache[$id][$field])) {
            $this->__conditionCache[$id][$field] = [];
        }
        return true;
    }

    private function __generateEventIdRule($event, $rule)
    {
        if (in_array($event['id'], $rule['selector_list'])) {
            $this->__createEmptyArrayIfNotSet($event['id'], 'event_id');
            $this->__conditionCache[$event['id']]['event_id'] = array_merge($this->__conditionCache[$event['id']]['event_id'], $rule['selector_list']);
        }
        return true;
    }

    private function __generateOrgcIdRule($event, $rule)
    {
        if (in_array($event['orgc_id'], $rule['selector_list'])) {
            $this->__createEmptyArrayIfNotSet($event['id'], 'orgc_id');
            $this->__conditionCache[$event['id']]['orgc_id'] = array_merge($this->__conditionCache[$event['id']]['orgc_id'], $rule['selector_list']);
        }
        return true;
    }

    private function __generateOrgIdRule($event, $rule)
    {
        if (in_array($event['org_id'], $rule['selector_list'])) {
            $this->__createEmptyArrayIfNotSet($event['id'], 'org_id');
            $this->__conditionCache[$event['id']]['org_id'] = array_merge($this->__conditionCache[$event['id']]['org_id'], $rule['selector_list']);
        }
        return true;
    }

    private function __generateEventInfoRule($event, $rule)
    {
        $this->Event = ClassRegistry::init('Event');
        $conditions = [];
        foreach ($rule['selector_list'] as $selector) {
            $conditions[] = ['LOWER(Event.info) LIKE' => mb_strtolower($selector)];
        }
        $ids = $this->Event->find('column', [
            'recursive' => -1,
            'conditions' => [
                'OR' => $conditions
            ],
            'fields' => ['Event.id']
        ]);
        if (!empty($ids)) {
            $this->__createEmptyArrayIfNotSet($event['id'], 'event_info');
            $this->__conditionCache[$event['id']]['event_info'] = array_merge($this->__conditionCache[$event['id']]['event_info'], $ids);
        }
        return true;
    }

    public function getEventIdsForRule($rule)
    {
        if (is_numeric($rule)) {
            $rule = $this->find('first', [
                'conditions' => ['CorrelationRule.id' => $rule],
                'recursive' => -1
            ]);
            if (empty($rule)) {
                throw new NotFoundException(__('Invalid Correlation Rule'));
            }
        }
        if ($rule['CorrelationRule']['selector_type'] === 'event_id') {
            $eventIds = $rule['CorrelationRule']['selector_list'];
        } elseif ($rule['CorrelationRule']['selector_type'] === 'orgc_id') {
            $this->Event = ClassRegistry::init('Event');
            $eventIds = $this->Event->find('column', [
                'recursive' => -1,
                'conditions' => ['Event.orgc_id' => $rule['CorrelationRule']['selector_list']],
                'fields' => ['Event.id']
            ]);
        } elseif ($rule['CorrelationRule']['selector_type'] === 'org_id') {
            $this->Event = ClassRegistry::init('Event');
            $eventIds = $this->Event->find('column', [
                'recursive' => -1,
                'conditions' => ['Event.org_id' => $rule['CorrelationRule']['selector_list']],
                'fields' => ['Event.id']
            ]);
        } elseif ($rule['CorrelationRule']['selector_type'] === 'event_info') {
            $this->Event = ClassRegistry::init('Event');
            $conditions = [];
            foreach ($rule['CorrelationRule']['selector_list'] as $selector) {
                $conditions[] = ['LOWER(Event.info) LIKE' => mb_strtolower($selector)];
            }
            $eventIds = $this->Event->find('column', [
                'recursive' => -1,
                'conditions' => ['OR' => $conditions],
                'fields' => ['Event.id']
            ]);
        } else {
            throw new InvalidArgumentException(__('Invalid selector type'));
        }
        $eventIds = array_map(function($id) {
            return intval($id);
        }, $eventIds);
        return $eventIds;
    }

    public function checkEventIds($id1, $id2)
    {
        if ($this->__eventCache === null) {
            $this->__loadEventCache();
        }
        foreach ($this->__eventCache as $eventGroup) {
            if (isset($eventGroup[$id1]) && (isset($eventGroup[$id2]))) {
                return false;
            }
        }
        return true;
    }

    private function __loadEventCache()
    {
        if ($this->__ruleCache === null) {
            $this->__loadRuleCache();
        }
        $this->__eventCache = [];
        foreach ($this->__ruleCache as $rule) {
            $temp = $this->getEventIdsForRule($rule);
            $ids = [];
            foreach ($temp as $id) {
                $ids[$id] = true;
            }
            $this->__eventCache[] = $ids;
        }
        return true;
    }
}
