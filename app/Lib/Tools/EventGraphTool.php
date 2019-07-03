<?php
    class EventGraphTool
    {
        private $__lookupTables = array();
        private $__user = false;
        private $__json = array();
        private $__eventModel = false;
        private $__refModel = false;
        # Will be use latter on
        private $__related_events = array();
        private $__related_attributes = array();

        public function construct($eventModel, $tagModel, $user, $filterRules, $extended_view=0)
        {
            $this->__eventModel = $eventModel;
            $this->__Tag = $tagModel;
            $this->__user = $user;
            $this->__filterRules = $filterRules;
            $this->__json = array();
            $this->__json['existing_tags'] = $this->__Tag->find('list', array(
                'fields' => array('Tag.id', 'Tag.name'),
                'sort' => array('lower(Tag.name) asc'),
            ));
            $this->__extended_view = $extended_view;
            $this->__lookupTables = array(
                'analysisLevels' => $this->__eventModel->analysisLevels,
                'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
            );
            $this->__authorized_JSON_key = array('event_id', 'distribution', 'category', 'type', 'value', 'comment', 'uuid', 'to_ids', 'timestamp', 'id');
            return true;
        }

        public function construct_for_ref($refModel, $user)
        {
            $this->__refModel = $refModel;
            $this->__user = $user;
            $this->__json = array();
            return true;
        }

        private function __get_event($id)
        {
            $this->__json['available_rotation_key'] = $this->__authorized_JSON_key;

            $fullevent = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'extended' => $this->__extended_view));
            $event = array();
            if (empty($fullevent)) {
                return $event;
            }

            if (!empty($fullevent[0]['Object'])) {
                $event['Object'] = $fullevent[0]['Object'];
            } else {
                $event['Object'] = array();
            }

            if (!empty($fullevent[0]['Attribute'])) {
                $event['Attribute'] = $fullevent[0]['Attribute'];
            } else {
                $event['Attribute'] = array();
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

            // value rule - search in the object's atribute value
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

        private function __satisfy_val_filtering($attr, $different_type_return=true)
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
                    $presenceMatch = $this->__contain_tag(array($attr), $tagName);
                } elseif ($relation === "Do not contain") {
                    $presenceMatch = !$this->__contain_tag(array($attr), $tagName);
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
            $this->__json['items'] = array();
            $this->__json['relations'] = array();
            
            $this->__json['existing_object_relation'] = array();
            if (empty($event)) {
                return $this->__json;
            }
            
            if (!empty($event['Object'])) {
                $object = $event['Object'];
            } else {
                $object = array();
            }

            if (!empty($event['Attribute'])) {
                $attribute = $event['Attribute'];
            } else {
                $attribute = array();
            }

            // extract links and node type
            foreach ($attribute as $attr) {
                $toPush = array(
                    'id' => $attr['id'],
                    'uuid' => $attr['uuid'],
                    'type' => $attr['type'],
                    'label' => $attr['value'],
                    'event_id' => $attr['event_id'],
                    'node_type' => 'attribute',
                );
                array_push($this->__json['items'], $toPush);
            }

            foreach ($object as $obj) {
                $toPush = array(
                    'id' => $obj['id'],
                    'uuid' => $obj['uuid'],
                    'type' => $obj['name'],
                    'label' => '',
                    'Attribute' => [],
                    'node_type' => 'object',
                    'meta-category' => $obj['meta-category'],
                    'template_uuid' => $obj['template_uuid'],
                    'event_id' => $obj['event_id'],
                );
                if (isset($obj['Attribute'])) {
                    $toPush['Attribute'] = $obj['Attribute'];

                    // Record existing object_relation
                    foreach ($obj['Attribute'] as $attr) {
                        $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
                    }
                }

                array_push($this->__json['items'], $toPush);

                foreach ($obj['ObjectReference'] as $rel) {
                    $toPush = array(
                        'id' => $rel['id'],
                        'uuid' => $rel['uuid'],
                        'from' => $obj['id'],
                        'to' => $rel['referenced_id'],
                        'type' => $rel['relationship_type'],
                        'comment' => $rel['comment'],
                        'event_id' => $rel['event_id'],
                    );
                    array_push($this->__json['relations'], $toPush);
                }
            }

            return $this->__json;
        }

        public function get_tags($id)
        {
            $event = $this->__get_filtered_event($id);
            $this->__json['items'] = array();
            $this->__json['relations'] = array();
            $this->__json['existing_object_relation'] = array();
            if (empty($event)) {
                return $this->__json;
            }
            
            if (!empty($event['Object'])) {
                $object = $event['Object'];
            } else {
                $object = array();
            }

            if (!empty($event['Attribute'])) {
                $attribute = $event['Attribute'];
            } else {
                $attribute = array();
            }

            $tagSet = array();
            $i = 0;

            // extract links and node type
            foreach ($attribute as $attr) {
                $Tags = $attr['AttributeTag'];
                $toPush = array(
                    'id' => $attr['id'],
                    'uuid' => $attr['uuid'],
                    'type' => $attr['type'],
                    'label' => $attr['value'],
                    'event_id' => $attr['event_id'],
                    'node_type' => 'attribute',
                );
                array_push($this->__json['items'], $toPush);

                foreach ($Tags as $tag) {
                    $tag = $tag['Tag'];
                    $toPush = array(
                        'id' => 'tag_edge_id_' . $i,
                        'from' => $attr['id'],
                        'to' => $tag['name'],
                    );
                    $tagSet[$tag['name']] = $tag;
                    array_push($this->__json['relations'], $toPush);
                    $i = $i+1;
                }
            }

            foreach ($object as $obj) {
                $toPush = array(
                    'id' => $obj['id'],
                    'uuid' => $obj['uuid'],
                    'type' => $obj['name'],
                    'Attribute' => $obj['Attribute'],
                    'label' => '',
                    'node_type' => 'object',
                    'meta-category' => $obj['meta-category'],
                    'template_uuid' => $obj['template_uuid'],
                    'event_id' => $obj['event_id'],
                );
                array_push($this->__json['items'], $toPush);

                // Record existing object_relation
                foreach ($obj['Attribute'] as $attr) {
                    $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
                }

                // get all tags in the Object's Attributes
                $added_value = array();
                foreach ($obj['Attribute'] as $ObjAttr) {
                    $Tags = $ObjAttr['AttributeTag'];
                    foreach ($Tags as $tag) {
                        $tag = $tag['Tag'];
                        if (!in_array($tag['name'], $added_value)) {
                            $toPush = array(
                                'id' => "tag_edge_id_" . $i,
                                'from' => $obj['id'],
                                'to' => $tag['name'],
                            );
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
                $toPush = array(
                    'id' => $tag['name'],
                    'uuid' => $tag['id'], // id is used for linking edges in vis.js, this uuid (which is not the tag uuid) is used to store the real tag id
                    'type' => 'tag',
                    'label' => $tag['name'],
                    'node_type' => 'tag',
                    'tagContent' => $tag,
                );
                array_push($this->__json['items'], $toPush);
            }

            return $this->__json;
        }

        public function get_generic_from_key($id, $keyType)
        {
            $event = $this->__get_filtered_event($id);
            $this->__json['items'] = array();
            $this->__json['relations'] = array();
            $this->__json['existing_object_relation'] = array();
            if (empty($event)) {
                return $this->__json;
            }
            
            if (!empty($event['Object'])) {
                $object = $event['Object'];
            } else {
                $object = array();
            }

            if (!empty($event['Attribute'])) {
                $attribute = $event['Attribute'];
            } else {
                $attribute = array();
            }

            if (!in_array($keyType, $this->__authorized_JSON_key)) { // not valid key
                return $this->__json;
            }

            $keySet = array();
            $i = 0;

            // extract links and node type
            foreach ($attribute as $attr) {
                $toPush = array(
                    'id' => $attr['id'],
                    'uuid' => $attr['uuid'],
                    'type' => $attr['type'],
                    'label' => $attr['value'],
                    'event_id' => $attr['event_id'],
                    'node_type' => 'attribute',
                );
                array_push($this->__json['items'], $toPush);

                // Add edge
                $keyVal = $attr[$keyType];
                $keyVal = json_encode($keyVal); // in case the value is false...
                $toPush = array(
                    'id' => "keyval_edge_id_" . $i,
                    'from' => $attr['id'],
                    'to' => "keyType_" . $keyVal,
                );
                $keySet[$keyVal] = 0; // set-alike
                array_push($this->__json['relations'], $toPush);
                $i = $i + 1;
            }

            foreach ($object as $obj) {
                $toPush = array(
                    'id' => $obj['id'],
                    'uuid' => $obj['uuid'],
                    'type' => $obj['name'],
                    'Attribute' => $obj['Attribute'],
                    'label' => '',
                    'node_type' => 'object',
                    'meta-category' => $obj['meta-category'],
                    'template_uuid' => $obj['template_uuid'],
                    'event_id' => $obj['event_id'],
                );
                array_push($this->__json['items'], $toPush);

                // Record existing object_relation
                foreach ($obj['Attribute'] as $attr) {
                    $this->__json['existing_object_relation'][$attr['object_relation']] = 0; // set-alike
                }

                // get all values in the Object's Attributes
                $added_value = array();
                foreach ($obj['Attribute'] as $ObjAttr) {
                    $keyVal = $ObjAttr[$keyType];
                    $keyVal = json_encode($keyVal); // in case the value is false...
                    if (!in_array($keyVal, $added_value)) {
                        $toPush = array(
                            'id' => "keyType_edge_id_" . $i,
                            'from' => $obj['id'],
                            'to' => "keyType_" . $keyVal,
                        );
                        array_push($added_value, $keyVal);
                        $keySet[$keyVal] = 42; // set-alike
                        array_push($this->__json['relations'], $toPush);
                        $i = $i + 1;
                    }
                }
            }

            // Add KeyType as nodes
            foreach ($keySet as $keyVal => $useless) {
                $toPush = array(
                    'id' => "keyType_" . $keyVal,
                    'type' => 'keyType',
                    'label' => $keyVal,
                    'node_type' => 'keyType',
                );
                array_push($this->__json['items'], $toPush);
            }

            return $this->__json;
        }

        public function get_reference_data($uuid)
        {
            $objectReference = $this->__refModel->ObjectReference->find('all', array(
                'conditions' => array('ObjectReference.uuid' => $uuid),
                'recursive' => -1,
                //'fields' => array('ObjectReference.id', 'relationship_type', 'comment', 'referenced_uuid')
                ));
            if (empty($objectReference)) {
                throw new NotFoundException('Invalid object reference');
            }
            return $objectReference;
        }

        public function get_object_templates()
        {
            $templates = $this->__refModel->ObjectTemplate->find('all', array(
                'recursive' => -1,
                'contain' => array(
                    'ObjectTemplateElement'
                )
            ));
            if (empty($templates)) {
                throw new NotFoundException('No templates');
            }
            return $templates;
        }
    }
