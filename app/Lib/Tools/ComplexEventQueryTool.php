<?php
App::uses('ComplexQueryTool', 'Tools');

/**
 * The `query` tree of /events/restSearch. It only selects events: event
 * fields are native conditions, while attribute, object and attribute tag
 * leaves select an event when it holds at least one matching element that
 * the user can see. Negated tags also strip the tagged attributes and event
 * reports from the output (blockedTagIds()).
 */
class ComplexEventQueryTool extends ComplexQueryTool
{
    const POSITIVE_STRING_OPS = ['=', 'IN', 'LIKE'];
    const NEGATIONS = ['!=', 'NOT IN'];

    /**
     * A field whose level names attributes or objects is matched against the
     * event's elements (see isElementField()).
     */
    const FIELDS = [
        'id' => ['kind' => 'int', 'column' => 'Event.id', 'level' => ['event']],
        'event_id' => ['kind' => 'int', 'column' => 'Event.id', 'level' => ['event']],
        'uuid' => ['kind' => 'string', 'column' => 'Event.uuid', 'ops' => self::EXACT_STRING_OPS, 'level' => ['event']],
        'distribution' => ['kind' => 'int', 'column' => 'Event.distribution', 'level' => ['event']],
        'analysis' => ['kind' => 'int', 'column' => 'Event.analysis', 'level' => ['event']],
        'threat_level_id' => ['kind' => 'int', 'column' => 'Event.threat_level_id', 'level' => ['event']],
        'org_id' => ['kind' => 'int', 'column' => 'Event.org_id', 'level' => ['event']],
        'orgc_id' => ['kind' => 'int', 'column' => 'Event.orgc_id', 'level' => ['event']],
        'org' => ['kind' => 'string', 'handler' => 'set_filter_org', 'ops' => self::EXACT_STRING_OPS, 'level' => ['event']],
        'eventinfo' => ['kind' => 'string', 'handler' => 'set_filter_eventinfo', 'level' => ['event']],
        'date' => ['kind' => 'date', 'column' => 'Event.date', 'level' => ['event']],
        'timestamp' => ['kind' => 'time', 'column' => 'Event.timestamp', 'level' => ['event']],
        'event_timestamp' => ['kind' => 'time', 'column' => 'Event.timestamp', 'level' => ['event']],
        'publish_timestamp' => ['kind' => 'time', 'column' => 'Event.publish_timestamp', 'level' => ['event']],
        'published' => ['kind' => 'bool', 'column' => 'Event.published', 'level' => ['event']],
        'tags' => ['kind' => 'string', 'level' => ['event', 'attribute']],
        'type' => ['kind' => 'string', 'handler' => 'set_filter_type', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'category' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'object_relation' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'comment' => ['kind' => 'string', 'handler' => 'set_filter_comment', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'value' => ['kind' => 'string', 'handler' => 'set_filter_value', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'to_ids' => ['kind' => 'bool', 'column' => 'Attribute.to_ids', 'ops' => ['='], 'level' => ['attribute']],
        'object_name' => ['kind' => 'string', 'column' => 'Object.name', 'ops' => ['=', 'IN'], 'level' => ['object']],
        'object_template_uuid' => ['kind' => 'string', 'column' => 'Object.template_uuid', 'ops' => ['=', 'IN'], 'level' => ['object']],
    ];

    private $user;
    private $sharingGroupIds;
    private $blockedTagIds = [];

    /**
     * @param object $model the Attribute model: set_filter_* handlers, subqueries and associations
     * @param array $user
     * @param array $limits
     */
    public function __construct($model, array $user, array $limits = [])
    {
        parent::__construct($model, $limits, self::FIELDS);
        $this->user = $user;
    }

    public function validate($query)
    {
        $tree = parent::validate($query);
        $this->errors = [];
        $this->checkNegations($tree, 'query', true, false);
        if (!empty($this->errors)) {
            throw new ComplexQueryException($this->errors);
        }
        return $tree;
    }

    public function compile(array $tree)
    {
        $this->blockedTagIds = [];
        return parent::compile($tree);
    }

    /**
     * @return array ids of the tags a negated tags leaf excludes, set by compile()
     */
    public function blockedTagIds()
    {
        return $this->blockedTagIds;
    }

    /**
     * Element leaves cannot be negated: whether a negated one should exclude
     * the event or strip the elements is ambiguous. Negated tags do both, so
     * they are only allowed where the whole tree around them must hold.
     */
    private function checkNegations(array $node, $path, $andOnly, $negated)
    {
        if ($node[0] === 'AND' || $node[0] === 'OR') {
            foreach ($node[1] as $i => $child) {
                $this->checkNegations($child, "{$path}.{$node[0]}[{$i}]", $andOnly && $node[0] === 'AND', $negated);
            }
            return;
        }
        if ($node[0] === 'NOT') {
            $this->checkNegations($node[1], "$path.NOT", false, true);
            return;
        }
        if (!self::isElementField($this->fields[$node[1]])) {
            return;
        }
        if ($negated) {
            $this->fail("$path.{$node[1]}", 'bad_shape', 'NOT cannot hold attribute, object or tag fields when searching events; use != on tags');
        } elseif (!$andOnly && in_array($node[2], self::NEGATIONS, true)) {
            $this->fail("$path.{$node[1]}", 'bad_shape', 'negated tags are only allowed under AND when searching events');
        }
    }

    protected function operatorMessage(array $def, $op)
    {
        if (self::isElementField($def) && in_array($op, self::NEGATIONS, true)) {
            return 'attribute and object fields cannot be negated when searching events';
        }
        return parent::operatorMessage($def, $op);
    }

    protected function typed($kind, $value, $op, $field, $path)
    {
        if ($kind !== 'date') {
            return parent::typed($kind, $value, $op, $field, $path);
        }
        if (is_string($value) && (preg_match('/^[0-9]{1,9}d$/', $value) || self::isDate($value))) {
            return $value;
        }
        return $this->fail($path, 'bad_type', 'this field expects a YYYY-MM-DD date or a number of days such as 7d');
    }

    private static function isDate($value)
    {
        return preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/', $value, $m) && checkdate((int)$m[2], (int)$m[3], (int)$m[1]);
    }

    protected function buildLeaf($field, $op, array $values, $path, $selectiveSiblings)
    {
        $def = $this->fields[$field];
        if ($field === 'tags') {
            return $this->tags($op, $values);
        }
        if ($def['kind'] === 'date') {
            $values = array_map(function ($value) {
                return self::isDate($value) ? $value : date('Y-m-d', $this->model->resolveTimeDelta($value));
            }, $values);
        }
        $fragment = parent::buildLeaf($field, $op, $values, $path, false);
        if ($fragment === null || !self::isElementField($def)) {
            return $fragment;
        }
        return $this->visibleElements($def['level'] === ['object'] ? $this->model->Object : $this->model, $fragment);
    }

    private static function isElementField(array $def)
    {
        return $def['level'] !== ['event'];
    }

    /**
     * Positive: the event or a visible attribute of it carries the tag.
     * Negated: the event does not carry it; the attributes and event reports
     * carrying it are stripped from the output instead.
     */
    private function tags($op, array $values)
    {
        $tagIds = $this->model->AttributeTag->Tag->fetchTagIdsSimple($values);
        $EventTag = $this->model->Event->EventTag;
        $eventTagged = $this->subquery($EventTag, 'event_id', [$EventTag->alias . '.tag_id' => $tagIds], 'Event.id');
        if (in_array($op, self::NEGATIONS, true)) {
            foreach ($tagIds as $tagId) {
                if ((int)$tagId !== -1 && !in_array($tagId, $this->blockedTagIds)) {
                    $this->blockedTagIds[] = $tagId;
                }
            }
            return ['NOT' => $eventTagged];
        }
        $AttributeTag = $this->model->AttributeTag;
        $attributeTagged = $this->subquery($AttributeTag, 'attribute_id', [$AttributeTag->alias . '.tag_id' => $tagIds], $this->model->alias . '.id');
        return ['OR' => [$eventTagged, $this->visibleElements($this->model, $attributeTagged)]];
    }

    /**
     * Events holding a non-deleted element that matches and that the user
     * can see, by the rules of MispAttribute::buildConditions(). The outer
     * query has already checked that the event itself is visible.
     *
     * @param object $model the Attribute or the Object model
     * @param array $conditions on the element
     * @return array
     */
    private function visibleElements($model, array $conditions)
    {
        $alias = $model->alias;
        $conditions = [$alias . '.deleted' => 0, $conditions];
        if (empty($this->user['Role']['perm_site_admin'])) {
            $rules = [$this->distributionRules($alias)];
            if ($alias === $this->model->alias) {
                $Object = $this->model->Object;
                $rules[] = ['OR' => [
                    $alias . '.object_id' => 0,
                    $this->subquery($Object, 'id', $this->distributionRules($Object->alias), $alias . '.object_id'),
                ]];
            }
            $conditions[] = ['OR' => [
                $this->subquery($this->model->Event, 'id', ['OwnEvent.org_id' => $this->user['org_id']], $alias . '.event_id', 'OwnEvent'),
                ['AND' => $rules],
            ]];
        }
        return $this->subquery($model, 'event_id', $conditions, 'Event.id');
    }

    private function distributionRules($alias)
    {
        if ($this->sharingGroupIds === null) {
            $this->sharingGroupIds = $this->model->SharingGroup->authorizedIds($this->user);
        }
        return ['OR' => [
            $alias . '.distribution' => [1, 2, 3, 5],
            'AND' => [
                $alias . '.distribution' => 4,
                $alias . '.sharing_group_id' => $this->sharingGroupIds,
            ],
        ]];
    }

    private function subquery($model, $field, array $conditions, $lookupKey, $alias = null)
    {
        $alias = $alias ?? $model->alias;
        return $this->model->subQueryGenerator($model, [
            'alias' => $alias,
            'fields' => ["$alias.$field"],
            'conditions' => $conditions,
        ], $lookupKey);
    }
}
