<?php
App::uses('ComplexEventQueryTool', 'Tools');

/**
 * The `query` tree of /objects/restSearch. It only selects objects: object
 * and event fields are native conditions, while attribute and attribute tag
 * leaves select an object when it holds a matching attribute that the user
 * can see. Negated tags exclude the objects of events carrying them and strip
 * the tagged attributes from the output (blockedTagIds()).
 */
class ComplexObjectQueryTool extends ComplexEventQueryTool
{
    const NATIVE_LEVELS = ['object', 'event'];
    const EVENT_KEY = 'Object.event_id';
    const NEGATED_ELEMENT_MESSAGE = 'attribute fields cannot be negated when searching objects';
    const NOT_ELEMENT_MESSAGE = 'NOT cannot hold attribute or tag fields when searching objects; use != on tags';
    const NEGATED_TAGS_MESSAGE = 'negated tags are only allowed under AND when searching objects';

    const FIELDS = [
        'id' => ['kind' => 'int', 'column' => 'Object.id', 'level' => ['object']],
        'object_id' => ['kind' => 'int', 'column' => 'Object.id', 'level' => ['object']],
        'uuid' => ['kind' => 'string', 'column' => 'Object.uuid', 'ops' => self::EXACT_STRING_OPS, 'level' => ['object']],
        'distribution' => ['kind' => 'int', 'column' => 'Object.distribution', 'level' => ['object']],
        'timestamp' => ['kind' => 'time', 'column' => 'Object.timestamp', 'level' => ['object']],
        'object_name' => ['kind' => 'string', 'column' => 'Object.name', 'nullable' => 'Object.name', 'level' => ['object']],
        'object_template_uuid' => ['kind' => 'string', 'column' => 'Object.template_uuid', 'nullable' => 'Object.template_uuid', 'ops' => self::EXACT_STRING_OPS, 'level' => ['object']],
        'event_id' => ['kind' => 'int', 'column' => 'Object.event_id', 'level' => ['event']],
        'orgc_id' => ['kind' => 'int', 'column' => 'Event.orgc_id', 'level' => ['event']],
        'org' => ['kind' => 'string', 'handler' => 'set_filter_org', 'ops' => self::EXACT_STRING_OPS, 'level' => ['event']],
        'eventinfo' => ['kind' => 'string', 'handler' => 'set_filter_eventinfo', 'level' => ['event']],
        'date' => ['kind' => 'date', 'column' => 'Event.date', 'level' => ['event']],
        'event_timestamp' => ['kind' => 'time', 'column' => 'Event.timestamp', 'level' => ['event']],
        'publish_timestamp' => ['kind' => 'time', 'column' => 'Event.publish_timestamp', 'level' => ['event']],
        'threat_level_id' => ['kind' => 'int', 'column' => 'Event.threat_level_id', 'level' => ['event']],
        'published' => ['kind' => 'bool', 'column' => 'Event.published', 'level' => ['event']],
        'tags' => ['kind' => 'string', 'level' => ['event', 'attribute']],
        'type' => ['kind' => 'string', 'handler' => 'set_filter_type', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'category' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'object_relation' => ['kind' => 'string', 'handler' => 'set_filter_simple_attribute', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'comment' => ['kind' => 'string', 'handler' => 'set_filter_comment', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'value' => ['kind' => 'string', 'handler' => 'set_filter_value', 'ops' => self::POSITIVE_STRING_OPS, 'level' => ['attribute']],
        'to_ids' => ['kind' => 'bool', 'column' => 'Attribute.to_ids', 'ops' => ['='], 'level' => ['attribute']],
    ];

    /**
     * Objects holding a matching attribute the user can see. The outer query
     * has already checked that the object itself is visible.
     */
    protected function elementLeaf(array $def, array $fragment)
    {
        $attribute = $this->model->alias;
        // object_id != 0 is redundant, but keeps MariaDB on the attributes' object_id index
        return $this->subquery($this->model, 'object_id', $this->visibleElementConditions(
            $this->model, [$attribute . '.object_id !=' => 0, $fragment], false
        ), 'Object.id');
    }

    protected function attributeTagged(array $tagIds)
    {
        $AttributeTag = $this->model->AttributeTag;
        $attribute = $this->model->alias;
        $tagged = $this->subquery($AttributeTag, 'attribute_id', [
            $AttributeTag->alias . '.tag_id' => $tagIds,
            "{$AttributeTag->alias}.attribute_id = $attribute.id",
        ], "$attribute.id");
        // The event prefilter and both correlations are redundant: they probe per event, then
        // per object (driven by the tag rows, MariaDB scanned every attribute)
        return ['AND' => [
            $this->subquery($AttributeTag, 'event_id', [$AttributeTag->alias . '.tag_id' => $tagIds], 'Object.event_id'),
            $this->subquery($this->model, 'object_id', $this->visibleElementConditions(
                $this->model, ["$attribute.object_id = Object.id", $tagged], false
            ), 'Object.id'),
        ]];
    }
}
