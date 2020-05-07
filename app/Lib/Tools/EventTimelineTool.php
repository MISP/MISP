<?php
    class EventTimelineTool
    {
        private $__lookupTables = array();
        private $__user = false;
        private $__json = array();
        private $__eventModel = false;
        private $__refModel = false;
        # Will be use latter on
        private $__related_events = array();
        private $__related_attributes = array();

        public function construct($eventModel, $user, $filterRules, $extended_view=0)
        {
            $this->__eventModel = $eventModel;
            $this->__objectTemplateModel = $eventModel->Object->ObjectTemplate;
            $this->__user = $user;
            $this->__filterRules = $filterRules;
            $this->__json = array();
            $this->__extended_view = $extended_view;
            $this->__lookupTables = array(
                'analysisLevels' => $this->__eventModel->analysisLevels,
                'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
            );
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

        public function get_timeline($id)
        {
            $event = $this->__get_event($id);
            $this->__json['items'] = array();

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
                    'content' => $attr['value'],
                    'event_id' => $attr['event_id'],
                    'group' => 'attribute',
                    'timestamp' => $attr['timestamp'],
                    'first_seen' => $attr['first_seen'],
                    'last_seen' => $attr['last_seen'],
                );
                $this->__json['items'][] = $toPush;
            }

            foreach ($object as $obj) {
                $toPush_obj = array(
                    'id' => $obj['id'],
                    'uuid' => $obj['uuid'],
                    'content' => $obj['name'],
                    'group' => 'object',
                    'meta-category' => $obj['meta-category'],
                    'template_uuid' => $obj['template_uuid'],
                    'event_id' => $obj['event_id'],
                    'timestamp' => $obj['timestamp'],
                    'Attribute' => array(),
                );

                $toPush_obj['first_seen'] = $obj['first_seen'];
                $toPush_obj['last_seen'] = $obj['last_seen'];
                $toPush_obj['first_seen_overwrite'] = false;
                $toPush_obj['last_seen_overwrite'] = false;

                foreach ($obj['Attribute'] as $obj_attr) {
                    // replaced *_seen based on object attribute
                    if ($obj_attr['object_relation'] == 'first-seen' && is_null($toPush_obj['first_seen'])) {
                        $toPush_obj['first_seen'] = $obj_attr['value']; // replace first_seen of the object to seen of the element
                        $toPush_obj['first_seen_overwrite'] = true;
                    } elseif ($obj_attr['object_relation'] == 'last-seen' && is_null($toPush_obj['last_seen'])) {
                        $toPush_obj['last_seen'] = $obj_attr['value']; // replace last_seen of the object to seen of the element
                        $toPush_obj['last_seen_overwrite'] = true;
                    }
                    $toPush_attr = array(
                        'id' => $obj_attr['id'],
                        'uuid' => $obj_attr['uuid'],
                        'content' => $obj_attr['value'],
                        'contentType' => $obj_attr['object_relation'],
                        'event_id' => $obj_attr['event_id'],
                        'group' => 'object_attribute',
                        'timestamp' => $obj_attr['timestamp'],
                    );
                    $toPush_obj['Attribute'][] = $toPush_attr;
                }
                $this->__json['items'][] = $toPush_obj;
            }

            return $this->__json;
        }

        /*
         * Extrapolation strategy:
         *  - If only positive sightings: Will be from first to last sighting
         *  - If both positive and false positive: False positive get priority. It will be marked as false positive until next positive sighting
        */
        public function get_sighting_timeline($id)
        {
            $event = $this->__eventModel->fetchEvent($this->__user, array(
                'eventid' => $id,
                'flatten' => 1,
                'includeTagRelations' => 1,
                'extended' => $this->__extended_view
            ));
            $this->__json['items'] = array();

            if (empty($event)) {
                return $this->__json;
            } else {
                $event = $event[0];
            }

            $lookupAttribute = array();
            foreach ($event['Attribute'] as $k => $attribute) {
                $lookupAttribute[$attribute['id']] = &$event['Attribute'][$k];
            }

            // regroup sightings per attribute
            $regroupedSightings = array();
            foreach ($event['Sighting'] as $k => $sighting) {
                $event['Sighting'][$k]['date_sighting'] *= 1000; // adapt to use micro
                $regroupedSightings[$sighting['attribute_id']][] = &$event['Sighting'][$k];
            }
            // make sure sightings are ordered
            uksort($regroupedSightings, function ($a, $b) {
                return $a['date_sighting'] > $b['date_sighting'];
            });
            // generate extrapolation
            $now = time()*1000;
            foreach ($regroupedSightings as $attributeId => $sightings) {
                $i = 0;
                while ($i < count($sightings)) {
                    $sighting = $sightings[$i];
                    $attribute = $lookupAttribute[$attributeId];
                    $fpSightingIndex = $this->getNextFalsePositiveSightingIndex($sightings, $i+1);
                    if ($fpSightingIndex === false) { // No next FP, extrapolate to now
                        $this->__json['items'][] = array(
                            'attribute_id' => $attributeId,
                            'id' => sprintf('%s-%s', $attributeId, $sighting['id']),
                            'uuid' => $sighting['uuid'],
                            'content' => $attribute['value'],
                            'event_id' => $attribute['event_id'],
                            'group' => 'sighting_positive',
                            'timestamp' => $attribute['timestamp'],
                            'first_seen' => $sighting['date_sighting'],
                            'last_seen' => $now,
                        );
                        break;
                    } else {
                        // set up until last positive
                        $pSightingIndex = $fpSightingIndex - 1;
                        $halfTime = 0;
                        if ($pSightingIndex == $i) {
                            // we have only one positive sighting, thus the UP time should be take from a pooling frequence
                            // for now, consider it UP only for half the time until the next FP
                            $halfTime = ($sightings[$i+1]['date_sighting'] - $sighting['date_sighting'])/2;
                        }
                        $pSighting = $sightings[$pSightingIndex];
                        $this->__json['items'][] = array(
                            'attribute_id' => $attributeId,
                            'id' => sprintf('%s-%s', $attributeId, $sighting['id']),
                            'uuid' => $sighting['uuid'],
                            'content' => $attribute['value'],
                            'event_id' => $attribute['event_id'],
                            'group' => 'sighting_positive',
                            'timestamp' => $attribute['timestamp'],
                            'first_seen' => $sighting['date_sighting'],
                            'last_seen' => $pSighting['date_sighting'] + $halfTime,
                        );
                        // No next FP, extrapolate to now
                        $fpSighting = $sightings[$fpSightingIndex];
                        $secondNextPSightingIndex = $this->getNextPositiveSightingIndex($sightings, $fpSightingIndex+1);
                        if ($secondNextPSightingIndex === false) { // No next P, extrapolate to now
                            $this->__json['items'][] = array(
                                'attribute_id' => $attributeId,
                                'id' => sprintf('%s-%s', $attributeId, $sighting['id']),
                                'uuid' => $sighting['uuid'],
                                'content' => $attribute['value'],
                                'event_id' => $attribute['event_id'],
                                'group' => 'sighting_negative',
                                'timestamp' => $attribute['timestamp'],
                                'first_seen' => $pSighting['date_sighting'] - $halfTime,
                                'last_seen' => $now,
                            );
                            break;
                        } else {
                            if ($halfTime > 0) { // We need to fake a previous P
                                $pSightingIndex = $pSightingIndex+1;
                                $pSighting = $sightings[$pSightingIndex];
                            }
                            // set down until next postive
                            $secondNextPSighting = $sightings[$secondNextPSightingIndex];
                            $this->__json['items'][] = array(
                                'attribute_id' => $attributeId,
                                'id' => sprintf('%s-%s', $attributeId, $sighting['id']),
                                'uuid' => $pSighting['uuid'],
                                'content' => $attribute['value'],
                                'event_id' => $attribute['event_id'],
                                'group' => 'sighting_negative',
                                'timestamp' => $attribute['timestamp'],
                                'first_seen' => $pSighting['date_sighting'] - $halfTime,
                                'last_seen' => $secondNextPSighting['date_sighting'],
                            );
                            $i = $secondNextPSightingIndex;
                        }
                    }
                }
            }
            return $this->__json;
        }

        private function getNextFalsePositiveSightingIndex($sightings, $startIndex)
        {
            for ($i=$startIndex; $i < count($sightings) ; $i++) {
                $sighting = $sightings[$i];
                if ($sighting['type'] == 1) { // is false positive
                    return $i;
                }
            }
            return false;
        }
        private function getNextPositiveSightingIndex($sightings, $startIndex)
        {
            for ($i=$startIndex; $i < count($sightings) ; $i++) {
                $sighting = $sightings[$i];
                if ($sighting['type'] == 0) { // is false positive
                    return $i;
                }
            }
            return false;
        }
    }
