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
        $converted = self::__includeFlattenedAttributes($converted);
        return $converted;
    }

    private static function __convertEvent(array $event): array
    {
        $converted = [];
        $converted = JSONConverterTool::convert($event, false, true);
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
        if (!empty($attribute['EventTag'])) {
            foreach ($attribute['AttributeTag'] as $attributeTag) {
                $attributeTag['Tag']['inherited'] = false;
                $allTags[] = $attributeTag['Tag'];
            }
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
        $event = self::__convertEvent($event);
        $event = $event['Event'];
        reset($data);
        $entityType = key($data);
        $event[$entityType][] = $data[$entityType];
        return ['Event' => $event];
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
