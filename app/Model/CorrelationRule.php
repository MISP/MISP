<?php
App::uses('AppModel', 'Model');

class CorrelationRule extends AppModel
{
    public $recursive = -1;

    private $__conditionCache = [
        'orgc_id' => [],
        'org_id' => [],
        'event_id' => []
    ];

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
        return $conditions;
    }

    public function attachCustomCorrelationRules($attribute, $conditions)
    {
        $this->__loadRuleCache();
        $filterConditions = $this->generateConditionsForEvent($attribute['Event']);
        $conditions['AND'][] = $filterConditions;
        return $conditions;
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
        $execute = false;
        $info = strtolower($event['info']);
        foreach ($rule['selector_list'] as $selector) {
            $selector = strtolower($selector);
            if ($selector[0] === '%' && $selector[-1] === '%') {
                if (str_contains($info, substr($selector, 1, (strlen($selector) - 2)))) {
                    $execute = true;
                    break;
                }
            } else if ($selector[0] === '%') {
                $needle = substr($selector, 1);
                if (substr_compare($info, $needle, -strlen($needle)) === 0) {
                    $execute = true;
                    break;
                }
            } else if ($selector[-1] === '%') {
                $needle = substr($selector, 1);
                if (substr_compare($info, $needle, -strlen($needle)) === 0) {
                    $execute = true;
                    break;
                }
            } else {
                if ($info === $selector) {
                    $execute = true;
                    break;
                }
            }
        }
        if ($execute) {
            $this->Event = ClassRegistry::init('Event');
            $conditions = [];
            foreach ($rule['selector_list'] as $selector) {
                $conditions[] = ['Event.info LIKE' => $selector];
            }
            $ids = $this->Event->find('column', [
                'recursive' => -1,
                'conditions' => [
                    'OR' => $conditions
                ],
                'fields' => ['Event.id']
            ]);
            if (!empty($ids)) {
                $this->__createEmptyArrayIfNotSet($event['id'], 'event_id');
                $this->__conditionCache[$event['id']]['event_id'] = array_merge($this->__conditionCache[$event['id']]['event_id'], $ids);
            }   
        }
        return true;
    }
}
