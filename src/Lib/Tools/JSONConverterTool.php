<?php

namespace App\Lib\Tools;

class JSONConverterTool
{
    public static function convertAttribute($attribute, $raw = false)
    {
        $toRearrange = ['AttributeTag'];
        foreach ($toRearrange as $object) {
            if (isset($attribute[$object])) {
                $attribute['Attribute'][$object] = $attribute[$object];
                unset($attribute[$object]);
            }
        }

        // Submit as list to the attribute cleaner but obtain the only attribute
        $attribute['Attribute'] = self::__cleanAttributes([$attribute['Attribute']])[0];
        if ($raw) {
            return $attribute;
        }
        return json_encode($attribute, JSON_PRETTY_PRINT);
    }

    public static function convertObject($object, $isSiteAdmin = false, $raw = false)
    {
        $toRearrange = ['SharingGroup', 'Attribute', 'ShadowAttribute', 'Event', 'CryptographicKey'];
        foreach ($toRearrange as $element) {
            if (isset($object[$element])) {
                $object['Object'][$element] = $object[$element];
                unset($object[$element]);
            }
            if ($element == 'SharingGroup' && isset($object['Object']['SharingGroup']) && empty($object['Object']['SharingGroup'])) {
                unset($object['Object']['SharingGroup']);
            }
        }
        $result = ['Object' => $object['Object']];
        if ($raw) {
            return $result;
        }
        return json_encode($result, JSON_PRETTY_PRINT);
    }

    public static function convert($event, $isSiteAdmin = false, $raw = false)
    {
        $toRearrange = ['Org', 'Orgc', 'SharingGroup', 'Attribute', 'ShadowAttribute', 'RelatedAttribute', 'RelatedEvent', 'Galaxy', 'Object', 'EventReport', 'CryptographicKey'];
        foreach ($toRearrange as $object) {
            if (isset($event[$object])) {
                $event[$object] = $event[$object];
                unset($event[$object]);
            }
        }

        if (empty($event['SharingGroup'])) {
            unset($event['SharingGroup']);
        }

        if (!empty($event['Galaxy'])) {
            foreach ($event['Galaxy'] as $k => $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $k2 => $cluster) {
                    if (empty($cluster['meta'])) {
                        $event['Galaxy'][$k]['GalaxyCluster'][$k2]['meta'] = new \stdclass();
                    }
                }
            }
        }

        if (isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $k => $tag) {
                unset($tag['Tag']['org_id']);
                $event['Tag'][$k] = $tag['Tag'];
            }
        }

        // cleanup the array from things we do not want to expose
        $tempSightings = [];
        if (!empty($event['Sighting'])) {
            foreach ($event['Sighting'] as $sighting) {
                $tempSightings[$sighting['attribute_id']][] = $sighting;
            }
            unset($event['Sighting']);
        }
        if (isset($event['Attribute'])) {
            $event['Attribute'] = self::__cleanAttributes($event['Attribute'], $tempSightings);
            if (!empty($event['RelatedAttribute'])) {
                foreach ($event['Attribute'] as $k => $attribute) {
                    if (isset($event['RelatedAttribute'][$attribute['id']])) {
                        foreach ($event['RelatedAttribute'][$attribute['id']] as $correlation) {
                            $event['Attribute'][$k]['RelatedAttribute'][] = [
                                'id' => $correlation['attribute_id'],
                                'value' => $correlation['value'],
                                'org_id' => $correlation['org_id'],
                                'info' => $correlation['info'],
                                'event_id' => $correlation['id']
                            ];
                        }
                    }
                }
            }
        }
        if (isset($event['Object'])) {
            $event['Object'] = self::__cleanObjects($event['Object'], $tempSightings);
            if (!empty($event['RelatedAttribute'])) {
                foreach ($event['Object'] as $k => $object) {
                    foreach ($event['Attribute'] as $k2 => $attribute) {
                        if (isset($event['RelatedAttribute'][$attribute['id']])) {
                            foreach ($event['RelatedAttribute'][$attribute['id']] as $correlation) {
                                $event['Object'][$k]['Attribute'][$k2]['RelatedAttribute'][] = [
                                    'id' => $correlation['attribute_id'],
                                    'value' => $correlation['value'],
                                    'org_id' => $correlation['org_id'],
                                    'info' => $correlation['info'],
                                    'event_id' => $correlation['id']
                                ];
                            }
                        }
                    }
                }
            }
        }
        unset($tempSightings);
        unset($event['RelatedAttribute']);

        // Remove information about user_id from JSON export
        unset($event['user_id']);
        if (isset($event['extensionEvents'])) {
            foreach ($event['extensionEvents'] as $k => $extensionEvent) {
                unset($event['extensionEvents'][$k]['user_id']);
            }
        }

        $result = ['Event' => $event];
        if (isset($event['errors'])) {
            $result = array_merge($result, ['errors' => $event['errors']]);
        }
        if ($raw) {
            return $result;
        }
        return json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Event to JSON convertor, but that is intended for machine to machine communication
     * @param array $event
     * @return Generator<string>
     */
    public static function streamConvert(array $event)
    {
        $event = self::convert($event, false, true);

        // Fast and inaccurate way how to check if event is too big for to convert in one call. This can be changed in future.
        $isBigEvent = (isset($event['Attribute']) ? count($event['Attribute']) : 0) +
            (isset($event['Object']) ? count($event['Object']) : 0) > 100;
        if (!$isBigEvent) {
            yield json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            return;
        }
        yield '{"Event":{';
        $firstKey = array_key_first($event);
        foreach ($event as $key => $value) {
            if ($key === 'Attribute' || $key === 'Object') { // Encode every object or attribute separately
                yield ($firstKey === $key ? '' : ',') . json_encode($key) . ":[";
                $firstInnerKey = key($value);
                foreach ($value as $i => $attribute) {
                    yield ($firstInnerKey === $i ? '' : ',')  . json_encode($attribute, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                }
                yield "]";
            } else {
                yield ($firstKey === $key ? '' : ',') . json_encode($key) . ":" . json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }
        }
        if (isset($event['errors'])) {
            yield '},"errors":' . json_encode($event['errors'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . '}';
        } else {
            yield "}}";
        }
    }

    private static function __cleanAttributes($attributes, $tempSightings = [])
    {
        // remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
        foreach ($attributes as $key => $attribute) {
            if (empty($attribute['SharingGroup'])) {
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

    private static function __cleanObjects($objects, $tempSightings = [])
    {
        foreach ($objects as $k => $object) {
            if (!empty($object['Attribute'])) {
                $objects[$k]['Attribute'] = self::__cleanAttributes($object['Attribute'], $tempSightings);
            } else {
                unset($objects[$k]);
            }
        }
        $objects = array_values($objects);
        return $objects;
    }

    public static function arrayPrinter($array, $root = true)
    {
        if (is_array($array)) {
            $resultArray = [];
            foreach ($array as $k => $element) {
                $temp = self::arrayPrinter($element, false);
                if (!is_array($temp)) {
                    $resultArray[] = '[' . $k . ']' . $temp;
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
            return implode('', $resultArray);
        } else {
            return $resultArray;
        }
    }
}