<?php
class JSONConverterTool
{
    public function generateTop()
    {
        return '{"response":[';
    }

    public function generateBottom()
    {
        return ']}' . PHP_EOL;
    }

    public function convert($event, $isSiteAdmin=false, $raw = false)
    {
        $toRearrange = array('Org', 'Orgc', 'SharingGroup', 'Attribute', 'ShadowAttribute', 'RelatedAttribute', 'RelatedEvent', 'Galaxy', 'Object');
        foreach ($toRearrange as $object) {
            if (isset($event[$object])) {
                $event['Event'][$object] = $event[$object];
                unset($event[$object]);
            }
            if ($object == 'SharingGroup' && isset($event['Event']['SharingGroup']) && empty($event['Event']['SharingGroup'])) {
                unset($event['Event']['SharingGroup']);
            }
            if ($object == 'Galaxy') {
                foreach ($event['Event']['Galaxy'] as $k => $galaxy) {
                    foreach ($galaxy['GalaxyCluster'] as $k2 => $cluster) {
                        if (empty($cluster['meta'])) {
                            $event['Event']['Galaxy'][$k]['GalaxyCluster'][$k2]['meta'] = new stdclass();
                        }
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

        //
        // cleanup the array from things we do not want to expose
        //
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
        if (!empty($event['Sighting'])) {
            unset($event['Sighting']);
        }

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

    private function __cleanAttributes($attributes, $tempSightings = array())
    {
        // remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
        foreach ($attributes as $key => $attribute) {
            if (isset($attribute['SharingGroup']) && empty($attribute['SharingGroup'])) {
                unset($attributes[$key]['SharingGroup']);
            }
            unset($attributes[$key]['value1']);
            unset($attributes[$key]['value2']);
            unset($attributes[$key]['category_order']);
            if (isset($event['RelatedAttribute'][$attribute['id']])) {
                $attributes[$key]['RelatedAttribute'] = $event['Event']['RelatedAttribute'][$attribute['id']];
                foreach ($attributes[$key]['RelatedAttribute'] as &$ra) {
                    $ra = array('Attribute' => $ra);
                }
            }
            if (isset($attributes[$key]['AttributeTag'])) {
                foreach ($attributes[$key]['AttributeTag'] as $atk => $tag) {
                    unset($tag['Tag']['org_id']);
                    $attributes[$key]['Tag'][$atk] = $tag['Tag'];
                }
                unset($attributes[$key]['AttributeTag']);
            }
            if (!empty($tempSightings[$attribute['id']])) {
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

    public function eventCollection2Format($events, $isSiteAdmin=false)
    {
        $results = array();
        foreach ($events as $event) {
            $results[] = $this->convert($event, $isSiteAdmin);
        }
        return implode(',' . PHP_EOL, $results);
    }

    public function frameCollection($input, $mispVersion = false)
    {
        $result = '{"response":[';
        $result .= $input;
        if ($mispVersion) {
            $result .= ',' . PHP_EOL . '{"xml_version":"' . $mispVersion . '"}' . PHP_EOL;
        }
        return $result . ']}';
    }
}
