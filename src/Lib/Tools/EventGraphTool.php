<?php

namespace App\Lib\Tools;

use App\Model\Entity\Distribution;
use Cake\Http\Exception\NotFoundException;

class EventGraphTool
{
    private $__lookupTables = [];
    private $__user = false;
    private $__json = [];
    private $__eventModel;
    private $__refModel;
    # Will be use latter on
    private $__related_events = [];
    private $__related_attributes = [];
    private $__Tag;
    private $__filterRules;
    private $__extended_view = 0;
    private $__extendedEventUUIDMapping = [];
    private $__paletteTool;
    private $__authorized_JSON_key;

    public function construct($eventModel, $tagModel, $user, $filterRules, $extended_view = 0)
    {
        $this->__eventModel = $eventModel;
        $this->__Tag = $tagModel;
        $this->__user = $user;
        $this->__filterRules = $filterRules;
        $this->__json = [];
        $this->__json['existing_tags'] = $this->__Tag->find(
            'list',
            [
                'fields' => ['Tag.id', 'Tag.name'],
                'sort' => ['lower(Tag.name) asc'],
            ]
        );
        $this->__extendedEventUUIDMapping = [];
        $this->__extended_view = $extended_view;
        $this->__lookupTables = [
            'analysisLevels' => $this->__eventModel->analysisLevels,
            'distributionLevels' => Distribution::DESCRIPTIONS
        ];
        $this->__authorized_JSON_key = ['event_id', 'distribution', 'category', 'type', 'value', 'comment', 'uuid', 'to_ids', 'timestamp', 'id'];

        $this->__paletteTool = new ColourPaletteTool();
        return true;
    }

    public function construct_for_ref($refModel, $user)
    {
        $this->__refModel = $refModel;
        $this->__user = $user;
        $this->__json = [];
        return true;
    }

    private function __get_event($id)
    {
        $this->__json['available_pivot_key'] = $this->__authorized_JSON_key;

        $fullevent = $this->__eventModel->fetchEvent($this->__user, ['eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'extended' => $this->__extended_view]);
        $event = [];
        if (empty($fullevent)) {
            return $event;
        }

        if (!empty($fullevent[0]['Object'])) {
            $event['Object'] = $fullevent[0]['Object'];
        } else {
            $event['Object'] = [];
        }

        if (!empty($fullevent[0]['Attribute'])) {
            $event['Attribute'] = $fullevent[0]['Attribute'];
        } else {
            $event['Attribute'] = [];
        }

        return $event;
    }

    private function __get_filtered_event($id)
    {
        $event = $this->__get_event($id);
        if (empty($this->__filterRules)) {
            return $event;
        }

        // perform filtering
        foreach ($event['Object'] as $i => $obj) {
            $check1 = $this->__satisfy_obj_filtering($obj);
            $check2 = $this->__satisfy_obj_tag($obj);
            if (!($check1 && $check2)) {
                unset($event['Object'][$i]);
            }
            foreach ($obj['ObjectReference'] as $j => $rel) {
                if ($rel['deleted']) {
                    unset($event['Object'][$i]['ObjectReference'][$j]);
                }
            }
        }
        foreach ($event['Attribute'] as $i => $attr) {
            $check1 = $this->__satisfy_val_filtering($attr, false);
            $check2 = $this->__satisfy_attr_tag($attr);
            if (!($check1 && $check2)) {
                unset($event['Attribute'][$i]);
            }
        }

        return $event;
    }

    // NOT OPTIMIZED: But allow clearer code
    // perform filtering on obj_rel presence and then perform filtering on obj_rel value
    private function __satisfy_obj_filtering($obj)
    {
        // presence rule - search in the object's attribute
        $presenceMatch = true;
        foreach ($this->__filterRules['presence'] as $rule) {
            $relation = $rule[0];
            $obj_rel = $rule[1];
            if ($relation === "Contains") {
                $presenceMatch = $this->__contain_object_relation($obj['Attribute'], $obj_rel);
            } elseif ($relation == "Do not contain") {
                $presenceMatch = !$this->__contain_object_relation($obj['Attribute'], $obj_rel);
            }
            if (!$presenceMatch) { // Does not match, can stop filtering
                return false;
            }
        }

        // value rule - search in the object's attribute value
        $valueMatch = true;
        if (isset($obj['Attribute'])) {
            foreach ($obj['Attribute'] as $attr) {
                $valueMatch = $this->__satisfy_val_filtering($attr);
                if (!$valueMatch) {
                    return false;
                }
            }
        }
        return true;
    }

    private function __satisfy_val_filtering($attr, $different_type_return = true)
    {
        if (count($this->__filterRules['value']) == 0) {
            return true;
        }

        foreach ($this->__filterRules['value'] as $rule) {
            $attr_type = $rule[0];
            $comparison = $rule[1];
            $attr_value = $rule[2];

            if ($attr['object_relation'] != $attr_type) {
                return $different_type_return; // cannot compare different type
            }

            $value = $attr['value'];
            switch ($comparison) {
                case "<":
                    return $value < $attr_value;
                case "<=":
                    return $value <= $attr_value;
                case "==":
                    return $value == $attr_value;
                case ">":
                    return $value > $attr_value;
                case ">=":
                    return $value >= $attr_value;

                default:
                    return false;
            }
        }
    }

    // iterate over all filter rules for obj
    private function __satisfy_obj_tag($obj)
    {
        foreach ($this->__filterRules['tag_presence'] as $rule) {
            $relation = $rule[0];
            $tagName = $rule[1];
            if ($relation === "Contains") {
                $presenceMatch = $this->__contain_tag($obj['Attribute'], $tagName);
            } elseif ($relation === "Do not contain") {
                $presenceMatch = !$this->__contain_tag($obj['Attribute'], $tagName);
            }
            if (!$presenceMatch) { // Does not match, can stop filtering
                return false;
            }
        }
        return true;
    }

    // iterate over all filter rules for attr
    private function __satisfy_attr_tag($attr)
    {
        foreach ($this->__filterRules['tag_presence'] as $rule) {
            $relation = $rule[0];
            $tagName = $rule[1];
            if ($relation === "Contains") {
                $presenceMatch = $this->__contain_tag([$attr], $tagName);
            } elseif ($relation === "Do not contain") {
                $presenceMatch = !$this->__contain_tag([$attr], $tagName);
            }
            if (!$presenceMatch) { // Does not match, can stop filtering
                return false;
            }
        }
        return true;
    }

    // iterate over all attributes
    private function __contain_tag($attrList, $tagName)
    {
        foreach ($attrList as $attr) {
            if (empty($attr['AttributeTag'])) {
                continue;
            }
            $presenceMatch = $this->__tag_in_AttributeTag($attr['AttributeTag'], $tagName);
            if ($presenceMatch) {
                return true;
            }
        }
        return false;
    }

    // iterate over all tags
    private function __tag_in_AttributeTag($attrTag, $tagName)
    {
        foreach ($attrTag as $tag) {
            if ($tag['Tag']['name'] === $tagName) {
                return true;
            }
        }
        return false;
    }

    private function __contain_object_relation($attrList, $obj_rel)
    {
        foreach ($attrList as $attr) {
            if ($attr['object_relation'] === $obj_rel) {
                return true;
            }
        }
        return false;
    }

    public function get_references($id)
    {
        $event = $this->__get_filtered_event($id);
        $this->__json['items'] = [];
        $this->__json['relations'] = [];

        $this->__json['existing_object_relation'] = [];
        if (empty($event)) {
            return $this->__json;
        }

        if (!empty($event['Object'])) {
            $object = $event['Object'];
        } else {
            $object = [];
        }

        if (!empty($event['Attribute'])) {
            $attribute = $event['Attribute'];
        } else {
            $attribute = [];
        }

        // extract links and node type
        foreach ($attribute as $attr) {
            $toPush = [
                'id' => $attr['id'],
                'uuid' => $attr['uuid'],
                'type' => $attr['type'],
                'label' => $attr['value'],
                'event_id' => $attr['event_id'],
                'node_type' => 'attribute',
                'comment' => $attr['comment'],
            ];
            array_push($this->__json['items'], $toPush);
            $this->__extendedEventUUIDMapping[$toPush['event_id']] = '';
        }

        $templatesCount = [];
        foreach ($object as $obj) {
            $toPush = [
                'id' => sprintf('o-%s', $obj['id']),
                'uuid' => $obj['uuid'],
                'type' => $obj['name'],
                'label' => '',
                'Attribute' => [],
                'node_type' => 'object',
                'meta-category' => $obj['meta-category'],
                'template_uuid' => $obj['template_uuid'],
                'event_id' => $obj['event_id'],
                'comment' => $obj['comment'],
            ];
            if (isset($obj['Attribute'])) {
                $toPush['Attribute'] = $obj['Attribute'];

                // Record existing object_relation
                foreach ($obj['Attribute'] as $attr) {
                    $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
                }
            }
            if (empty($templatesCount[$obj['template_uuid']])) {
                $templatesCount[$obj['template_uuid']] = 0;
            }
            $templatesCount[$obj['template_uuid']]++;

            array_push($this->__json['items'], $toPush);
            $this->__extendedEventUUIDMapping[$toPush['event_id']] = '';

            foreach ($obj['ObjectReference'] as $rel) {
                $toPush = [
                    'id' => $rel['id'],
                    'uuid' => $rel['uuid'],
                    'from' => sprintf('o-%s', $obj['id']),
                    'to' => $rel['referenced_type'] == 1 ? sprintf('o-%s', $rel['referenced_id']) : $rel['referenced_id'],
                    'type' => $rel['relationship_type'],
                    'comment' => $rel['comment'],
                    'event_id' => $rel['event_id'],
                ];
                array_push($this->__json['relations'], $toPush);
            }
        }
        $this->__json['items'] = $this->addObjectColors($this->__json['items'], $templatesCount);

        if ($this->__extended_view) {
            $this->fetchEventUUIDFromId();
            $this->__json['extended_event_uuid_mapping'] = $this->__extendedEventUUIDMapping;
        }

        return $this->__json;
    }

    public function get_tags($id)
    {
        $event = $this->__get_filtered_event($id);
        $this->__json['items'] = [];
        $this->__json['relations'] = [];
        $this->__json['existing_object_relation'] = [];
        if (empty($event)) {
            return $this->__json;
        }

        if (!empty($event['Object'])) {
            $object = $event['Object'];
        } else {
            $object = [];
        }

        if (!empty($event['Attribute'])) {
            $attribute = $event['Attribute'];
        } else {
            $attribute = [];
        }

        $tagSet = [];
        $i = 0;

        // extract links and node type
        foreach ($attribute as $attr) {
            $Tags = $attr['AttributeTag'];
            $toPush = [
                'id' => $attr['id'],
                'uuid' => $attr['uuid'],
                'type' => $attr['type'],
                'label' => $attr['value'],
                'event_id' => $attr['event_id'],
                'node_type' => 'attribute',
                'comment' => $attr['comment'],
            ];
            array_push($this->__json['items'], $toPush);

            foreach ($Tags as $tag) {
                $tag = $tag['Tag'];
                $toPush = [
                    'id' => 'tag_edge_id_' . $i,
                    'from' => $attr['id'],
                    'to' => $tag['name'],
                    'type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    'comment' => '',
                ];
                $tagSet[$tag['name']] = $tag;
                array_push($this->__json['relations'], $toPush);
                $i = $i + 1;
            }
        }

        $j = 0;
        foreach ($object as $obj) {
            $toPush = [
                'id' => sprintf('o-%s', $obj['id']),
                'uuid' => $obj['uuid'],
                'type' => $obj['name'],
                'Attribute' => $obj['Attribute'],
                'label' => '',
                'node_type' => 'object',
                'meta-category' => $obj['meta-category'],
                'template_uuid' => $obj['template_uuid'],
                'event_id' => $obj['event_id'],
                'comment' => $obj['comment'],
            ];
            array_push($this->__json['items'], $toPush);


            // get all  attributes and tags in the Object's Attributes
            $added_value = [];
            foreach ($obj['Attribute'] as $ObjAttr) {
                // Record existing object_relation
                $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
                $Tags = $ObjAttr['AttributeTag'];
                foreach ($Tags as $tag) {
                    $tag = $tag['Tag'];
                    if (!in_array($tag['name'], $added_value)) {
                        $toPush = [
                            'id' => $ObjAttr['id'],
                            'uuid' => $ObjAttr['uuid'],
                            'type' => $ObjAttr['type'],
                            'label' => $ObjAttr['value'],
                            'event_id' => $ObjAttr['event_id'],
                            'node_type' => 'attribute',
                            'comment' => $ObjAttr['comment'],
                        ];
                        array_push($this->__json['items'], $toPush);

                        $toPush = [
                            'id' => 'obj_edge_id_' . $j,
                            'from' => sprintf('o-%s', $obj['id']),
                            'to' => $ObjAttr['id'],
                            'type' => '',
                            'comment' => '',
                        ];
                        $j = $j + 1;
                        array_push($this->__json['relations'], $toPush);

                        $toPush = [
                            'id' => "tag_edge_id_" . $i,
                            'from' => $ObjAttr['id'],
                            'to' => $tag['name'],
                            'type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                            'comment' => '',
                        ];
                        $tagSet[$tag['name']] = $tag;
                        array_push($added_value, $tag['name']);
                        array_push($this->__json['relations'], $toPush);
                        $i = $i + 1;
                    }
                }
            }
        }

        // Add tags as nodes
        foreach ($tagSet as $tag) {
            $toPush = [
                'id' => $tag['name'],
                'uuid' => $tag['id'], // id is used for linking edges in vis.js, this uuid (which is not the tag uuid) is used to store the real tag id
                'type' => 'tag',
                'label' => $tag['name'],
                'node_type' => 'tag',
                'tagContent' => $tag,
            ];
            array_push($this->__json['items'], $toPush);
        }

        return $this->__json;
    }

    public function get_generic_from_key($id, $keyType)
    {
        $event = $this->__get_filtered_event($id);
        $this->__json['items'] = [];
        $this->__json['relations'] = [];
        $this->__json['existing_object_relation'] = [];
        if (empty($event)) {
            return $this->__json;
        }

        if (!empty($event['Object'])) {
            $object = $event['Object'];
        } else {
            $object = [];
        }

        if (!empty($event['Attribute'])) {
            $attribute = $event['Attribute'];
        } else {
            $attribute = [];
        }

        if (!in_array($keyType, $this->__authorized_JSON_key)) { // not valid key
            return $this->__json;
        }

        $keySet = [];
        $i = 0;

        // extract links and node type
        foreach ($attribute as $attr) {
            $toPush = [
                'id' => $attr['id'],
                'uuid' => $attr['uuid'],
                'type' => $attr['type'],
                'label' => $attr['value'],
                'event_id' => $attr['event_id'],
                'node_type' => 'attribute',
                'comment' => $attr['comment'],
            ];
            array_push($this->__json['items'], $toPush);

            // Add edge
            $keyVal = $attr[$keyType];
            $keyVal = json_encode($keyVal); // in case the value is false...
            $toPush = [
                'id' => "keyval_edge_id_" . $i,
                'from' => $attr['id'],
                'to' => "keyType_" . $keyVal,
            ];
            $keySet[$keyVal] = 0; // set-alike
            array_push($this->__json['relations'], $toPush);
            $i = $i + 1;
        }

        foreach ($object as $obj) {
            $toPush = [
                'id' => sprintf('o-%s', $obj['id']),
                'uuid' => $obj['uuid'],
                'type' => $obj['name'],
                'Attribute' => $obj['Attribute'],
                'label' => '',
                'node_type' => 'object',
                'meta-category' => $obj['meta-category'],
                'template_uuid' => $obj['template_uuid'],
                'event_id' => $obj['event_id'],
                'comment' => $obj['comment'],
            ];
            array_push($this->__json['items'], $toPush);

            // Record existing object_relation
            foreach ($obj['Attribute'] as $attr) {
                $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
            }

            // get all values in the Object's Attributes
            $added_value = [];
            foreach ($obj['Attribute'] as $ObjAttr) {
                $keyVal = $ObjAttr[$keyType];
                $keyVal = json_encode($keyVal); // in case the value is false...
                if (!in_array($keyVal, $added_value)) {
                    $toPush = [
                        'id' => "keyType_edge_id_" . $i,
                        'from' => sprintf('o-%s', $obj['id']),
                        'to' => "keyType_" . $keyVal,
                    ];
                    array_push($added_value, $keyVal);
                    $keySet[$keyVal] = 42; // set-alike
                    array_push($this->__json['relations'], $toPush);
                    $i = $i + 1;
                }
            }

            foreach ($obj['ObjectReference'] as $rel) {
                $toPush = [
                    'id' => $rel['id'],
                    'uuid' => $rel['uuid'],
                    'from' => sprintf('o-%s', $obj['id']),
                    'to' => $rel['referenced_type'] == 1 ? sprintf('o-%s', $rel['referenced_id']) : $rel['referenced_id'],
                    'type' => $rel['relationship_type'],
                    'comment' => $rel['comment'],
                    'event_id' => $rel['event_id'],
                ];
                array_push($this->__json['relations'], $toPush);
            }
        }

        // Add KeyType as nodes
        foreach ($keySet as $keyVal => $useless) {
            $toPush = [
                'id' => "keyType_" . $keyVal,
                'type' => 'keyType',
                'label' => $keyVal,
                'node_type' => 'keyType',
            ];
            array_push($this->__json['items'], $toPush);
        }

        return $this->__json;
    }

    public function get_reference_data($uuid)
    {
        $objectReference = $this->__refModel->ObjectReference->find(
            'all',
            [
                'conditions' => ['ObjectReference.uuid' => $uuid, 'ObjectReference.deleted' => false],
                'recursive' => -1,
            //'fields' => array('ObjectReference.id', 'relationship_type', 'comment', 'referenced_uuid')
            ]
        );
        if (empty($objectReference)) {
            throw new NotFoundException('Invalid object reference');
        }
        return $objectReference;
    }

    public function get_object_templates()
    {
        $templates = $this->__refModel->ObjectTemplate->find(
            'all',
            [
                'recursive' => -1,
                'contain' => [
                    'ObjectTemplateElement'
                ]
            ]
        );
        if (empty($templates)) {
            throw new NotFoundException('No templates');
        }
        return $templates;
    }

    public function fetchEventUUIDFromId()
    {
        $eventUUIDs = $this->__eventModel->find(
            'list',
            [
                'conditions' => ['id' => array_keys($this->__extendedEventUUIDMapping)],
                'fields' => ['uuid']
            ]
        );
        $this->__extendedEventUUIDMapping = $eventUUIDs;
    }

    private function addObjectColors($items, $templatesCount)
    {
        $colours = [];
        foreach ($templatesCount as $templateUUID => $count) {
            $colours[$templateUUID] = $this->__paletteTool->generatePaletteFromString($templateUUID, $count);
        }
        foreach ($items as $i => $item) {
            if ($item['node_type'] == 'object') {
                $items[$i]['color'] = array_shift($colours[$item['template_uuid']]);
            }
        }
        return $items;
    }
}