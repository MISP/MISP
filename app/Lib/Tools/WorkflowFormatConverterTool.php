<?php
App::uses('JSONConverterTool', 'Tools');

/**
 * WorkflowFormatConverterTool convert passed data into the MISP core format with these additional properties:
 * - Attributes are encapsulated in the Event they belong to as well as their object (if applicable)
 * - Events have an additional key `_AttributeFlattened` which combines both Attribute and ObjectAttribute in the same array
 * - Attributes have an additional key `_allTags` which group both AttributeTag and EventTag.
 *      - Tags in this `_allTags` key have an additional flag `inherited` indicating if the tag has been propagated from the Event to the Attribute
 */
class WorkflowFormatConverterTool
{
    private static $fakeSiteAdminUser = ['Role' => ['perm_site_admin' => true]];

    public static function convert(array $data, $scope=''): array
    {
        if (empty($scope)) {
            $scope = self::__guessScopeFromData($data);
        }
        $converted = [];
        switch ($scope) {
            case 'event':
                $converted = self::__convertEvent($data);
                break;
            case 'attribute':
                $converted = self::__convertAttribute($data);
                break;
            case 'object':
                $converted = self::__convertObject($data);
                break;
            default:
                break;
        }
        foreach (array_keys($data) as $key) {
            if (substr($key, 0, 1) == '_') { // include additional data
                $converted[$key] = $data[$key];
            }
        }
        $converted = self::__includeFlattenedAttributes($converted);
        return $converted;
    }

    private static function __convertEvent(array $event): array
    {
        $converted = [];
        $converted = JSONConverterTool::convert($event, false, true);
        $eventTags = !empty($converted['Event']['Tag']) ? $converted['Event']['Tag'] : [];
        if (!empty($converted['Event']['Attribute'])) {
            foreach ($converted['Event']['Attribute'] as $i => $attribute) {
                $converted['Event']['Attribute'][$i] = self::__propagateTagToAttributes($attribute, $eventTags);
            }
        }
        if (!empty($converted['Event']['Object'])) {
            foreach ($converted['Event']['Object'] as $i => $object) {
                $converted['Event']['Object'][$i] = self::__propagateTagToObjectAttributes($object, $eventTags);
            }
        }
        return $converted;
    }

    private static function __convertObject(array $object): array
    {
        $converted = [];
        $convertedObject = JSONConverterTool::convertObject($object, false, true);
        $convertedObject = ['Object' => $convertedObject['Object']];
        $converted = self::__encapsulateEntityWithEvent($convertedObject);
        return $converted;
    }

    /**
     * __convertAttribute Convert and clean an attribute. May also transform the attribute into an Object if applicable.
     * However, the object will not be full and will only contain the attribute
     *
     * @param array $attribute
     * @return array
     */
    private static function __convertAttribute(array $attribute): array
    {
        $allTags = [];
        if (!empty($attribute['AttributeTag'])) {
            foreach ($attribute['AttributeTag'] as $attributeTag) {
                $attributeTag['Tag']['inherited'] = false;
                $allTags[] = $attributeTag['Tag'];
            }
        }
        if (!empty($attribute['EventTag'])) {
            foreach ($attribute['EventTag'] as $eventTag) {
                $eventTag['Tag']['inherited'] = true;
                $allTags[] = $eventTag['Tag'];
            }
        }
        $convertedAttribute = JSONConverterTool::convertAttribute($attribute, true);
        $convertedAttribute['Attribute']['_allTags'] = $allTags;
        if ($convertedAttribute['Attribute']['object_id'] != 0) {
            $objectModel = ClassRegistry::init('MispObject');
            $object = $objectModel->fetchObjectSimple(self::$fakeSiteAdminUser, [
                'conditions' => [
                    'Object.id' => $convertedAttribute['Attribute']['object_id'],
                ],
            ]);
            if (!empty($object)) {
                $object = $object[0]['Object'];
                $object['Attribute'][] = $convertedAttribute['Attribute'];
                $convertedAttribute = ['Object' => $object];
            } else {
                $convertedAttribute = ['Attribute' => $convertedAttribute['Attribute']];
            }
        } else {
            $convertedAttribute = ['Attribute' => $convertedAttribute['Attribute']];
        }
        $converted = self::__encapsulateEntityWithEvent($convertedAttribute);
        return $converted;
    }

    private static function __propagateTagToAttributes(array $attribute, array $eventTags): array
    {
        $allTags = [];
        if (!empty($eventTags)) {
            foreach ($eventTags as $eventTag) {
                $eventTag['inherited'] = true;
                $allTags[] = $eventTag;
            }
        }
        if (!empty($attribute['Tag'])) {
            foreach ($attribute['Tag'] as $tag) {
                $tag['inherited'] = false;
                $allTags[] = $tag;
            }
        }
        $attribute['_allTags'] = $allTags;
        return $attribute;
    }

    private static function __propagateTagToObjectAttributes(array $object, array $eventTags): array
    {
        foreach ($object['Attribute'] as $i => $attribute) {
            $object['Attribute'][$i] = self::__propagateTagToAttributes($attribute, $eventTags);
        }
        return $object;
    }

    private static function __encapsulateEntityWithEvent(array $data): array
    {
        $eventModel = ClassRegistry::init('Event');
        $event = $eventModel->fetchSimpleEvent(self::$fakeSiteAdminUser, $data['Attribute']['event_id'] ?? $data['Object']['event_id'], [
            'contain' => [
                'EventTag' => ['Tag']
            ]
        ]);
        if (empty($event)) {
            return [];
        }
        reset($data);
        $entityType = key($data);
        $event['Event'][$entityType][] = $data[$entityType];
        $event = self::__convertEvent($event);
        return $event;
    }

    private static function __includeFlattenedAttributes(array $event): array
    {
        $attributes = $event['Event']['Attribute'] ?? [];
        $objectAttributes = Hash::extract($event['Event']['Object'] ?? [], '{n}.Attribute.{n}');
        $event['Event']['_AttributeFlattened'] = array_merge($attributes, $objectAttributes);
        return $event;
    }

    private static function __guessScopeFromData(array $data)
    {
        if (isset($data['Object']) && !isset($data['Attribute'])) {
            return 'object';
        }
        if (!isset($data['Attribute'])) {
            return 'event';
        }
        if (!isset($data['Event'])) {
            return 'attribute';
        }
        if (isset($data['RelatedEvent']) || isset($data['Orgc']) || isset($data['Org'])) {
            return 'event';
        }
        if (!empty($data['Attribute'])) {
            return 'attribute';
        }
    }
}
