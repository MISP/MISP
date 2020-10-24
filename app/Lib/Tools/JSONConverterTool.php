<?php
class JSONConverterTool
{
    public function convertAttribute($attribute, $raw = false)
    {
        $toRearrange = array('AttributeTag');
        foreach ($toRearrange as $object) {
          if (isset($attribute[$object])) {
            $attribute['Attribute'][$object] = $attribute[$object];
            unset($attribute[$object]);
          }
        }

        // Submit as list to the attribute cleaner but obtain the only attribute
        $attribute['Attribute'] = $this->__cleanAttributes(array($attribute['Attribute']))[0];
        if ($raw) {
            return $attribute;
        }
        return json_encode($attribute, JSON_PRETTY_PRINT);
    }

    public function convertObject($object, $isSiteAdmin = false, $raw = false)
    {
        $toRearrange = array('SharingGroup', 'Attribute', 'ShadowAttribute', 'Event');
        foreach ($toRearrange as $element) {
            if (isset($object[$element])) {
                $object['Object'][$element] = $object[$element];
                unset($object[$element]);
            }
            if ($element == 'SharingGroup' && isset($object['Object']['SharingGroup']) && empty($object['Object']['SharingGroup'])) {
                unset($object['Object']['SharingGroup']);
            }
        }
        $result = array('Object' => $object['Object']);
        if (isset($event['errors'])) {
            $result = array_merge($result, array('errors' => $event['errors']));
        }
        if ($raw) {
            return $result;
        }
        return json_encode($result, JSON_PRETTY_PRINT);
    }

    public function convert($event, $isSiteAdmin=false, $raw = false)
    {
        $toRearrange = array('Org', 'Orgc', 'SharingGroup', 'Attribute', 'ShadowAttribute', 'RelatedAttribute', 'RelatedEvent', 'Galaxy', 'Object', 'EventReport');
        foreach ($toRearrange as $object) {
            if (isset($event[$object])) {
                $event['Event'][$object] = $event[$object];
                unset($event[$object]);
            }
        }

        if (isset($event['Event']['SharingGroup']) && empty($event['Event']['SharingGroup'])) {
            unset($event['Event']['SharingGroup']);
        }

        if (!empty($event['Event']['Galaxy'])) {
            foreach ($event['Event']['Galaxy'] as $k => $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $k2 => $cluster) {
                    if (empty($cluster['meta'])) {
                        $event['Event']['Galaxy'][$k]['GalaxyCluster'][$k2]['meta'] = new stdclass();
                    }
                }
            }
        }

        if (isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $k => $tag) {
                unset($tag['Tag']['org_id']);
                $event['Event']['Tag'][$k] = $tag['Tag'];
            }
        }

        // cleanup the array from things we do not want to expose
        $tempSightings = array();
        if (!empty($event['Sighting'])) {
            foreach ($event['Sighting'] as $sighting) {
                $tempSightings[$sighting['attribute_id']][] = $sighting;
            }
            unset($event['Sighting']);
        }
        unset($event['Event']['user_id']);
        if (isset($event['Event']['Attribute'])) {
            $event['Event']['Attribute'] = $this->__cleanAttributes($event['Event']['Attribute'], $tempSightings);
        }
        if (isset($event['Event']['Object'])) {
            $event['Event']['Object'] = $this->__cleanObjects($event['Event']['Object'], $tempSightings);
        }
        unset($tempSightings);
        unset($event['Event']['RelatedAttribute']);
        if (isset($event['Event']['RelatedEvent'])) {
            foreach ($event['Event']['RelatedEvent'] as $key => $value) {
                unset($event['Event']['RelatedEvent'][$key]['Event']['user_id']);
            }
        }
        $result = array('Event' => $event['Event']);
        if (isset($event['errors'])) {
            $result = array_merge($result, array('errors' => $event['errors']));
        }
        if ($raw) {
            return $result;
        }
        return json_encode($result, JSON_PRETTY_PRINT);
    }

    /**
     * Event to JSON stream convertor.
     * @param array $event
     * @return Generator<string>
     */
    public function streamConvert(array $event)
    {
        $event = $this->convert($event, false, true);
        // Fast and inaccurate way how to check if event is too big for to convert in one call. This can be changed in future.
        $isBigEvent = (isset($event['Event']['Attribute']) ? count($event['Event']['Attribute']) : 0) +
            (isset($event['Event']['Object']) ? count($event['Event']['Object']) : 0) > 100;
        if (!$isBigEvent) {
            yield json_encode($event, JSON_PRETTY_PRINT);
            return;
        }

        yield '{"Event":{';
        $firstKey = key($event['Event']);
        foreach ($event['Event'] as $key => $value) {
            if ($key === 'Attribute' || $key === 'Object') { // Encode every object or attribute separately
                yield ($firstKey === $key ? '' : ',') . json_encode($key) . ":[";
                $firstInnerKey = key($value);
                foreach ($value as $i => $attribute) {
                    yield ($firstInnerKey === $i ? '' : ',')  . json_encode($attribute);
                }
                yield "]";
            } else {
                yield ($firstKey === $key ? '' : ',') . json_encode($key) . ":" . json_encode($value);
            }
        }
        if (isset($event['errors'])) {
            yield '},"errors":' . json_encode($event['errors']) . '}';
        } else {
            yield "}}";
        }
    }

    private function __cleanAttributes($attributes, $tempSightings = array())
    {
        // remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
        foreach ($attributes as $key => $attribute) {
            if (isset($attribute['SharingGroup']) && empty($attribute['SharingGroup'])) {
                unset($attributes[$key]['SharingGroup']);
            }
            unset($attributes[$key]['value1']);
            unset($attributes[$key]['value2']);
            if (isset($attributes[$key]['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $atk => $tag) {
                    unset($tag['Tag']['org_id']);
                    $attributes[$key]['Tag'][$atk] = $tag['Tag'];
                }
                unset($attributes[$key]['AttributeTag']);
            }
            if (isset($tempSightings[$attribute['id']])) {
                $attributes[$key]['Sighting'] = $tempSightings[$attribute['id']];
            }
        }
        return $attributes;
    }

    private function __cleanObjects($objects, $tempSightings = array())
    {
        foreach ($objects as $k => $object) {
            if (!empty($object['Attribute'])) {
                $objects[$k]['Attribute'] = $this->__cleanAttributes($object['Attribute'], $tempSightings);
            } else {
                unset($objects[$k]);
            }
        }
        $objects = array_values($objects);
        return $objects;
    }

    public function arrayPrinter($array, $root = true)
    {
        if (is_array($array)) {
            $resultArray = array();
            foreach ($array as $k => $element) {
                $temp = $this->arrayPrinter($element, false);
                if (!is_array($temp)) {
                    $resultArray[] = '[' . $k .']' . $temp;
                } else {
                    foreach ($temp as $t) {
                        $resultArray[] = '[' . $k . ']' . $t;
                    }
                }
            }
        } else {
            $resultArray = ': ' . $array . PHP_EOL;
        }
        if ($root) {
            $text = '';
            foreach ($resultArray as $r) {
                $text .= $r;
            }
            return $text;
        } else {
            return $resultArray;
        }
    }
}
