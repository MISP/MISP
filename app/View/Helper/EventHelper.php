<?php
App::uses('AppHelper', 'View/Helper');

class EventHelper extends AppHelper
{
    public function attachRelatedAttributesToItems(array $items, array $relatedAttributes)
    {
        if (empty($items) || empty($relatedAttributes)) {
            return $items;
        }

        $relatedMap = [];
        foreach ($relatedAttributes as $attributeId => $relations) {
            $relatedMap[(int)$attributeId] = $relations;
        }

        foreach ($items as &$item) {
            if (($item['objectType'] ?? null) === 'attribute') {
                $attributeId = isset($item['id']) ? (int)$item['id'] : 0;
                if ($attributeId && isset($relatedMap[$attributeId])) {
                    $item['RelatedAttribute'] = $relatedMap[$attributeId];
                }
            } elseif (($item['objectType'] ?? null) === 'object' && !empty($item['Attribute']) && is_array($item['Attribute'])) {
                foreach ($item['Attribute'] as &$subAttr) {
                    $attributeId = isset($subAttr['id']) ? (int)$subAttr['id'] : 0;
                    if ($attributeId && isset($relatedMap[$attributeId])) {
                        $subAttr['RelatedAttribute'] = $relatedMap[$attributeId];
                    }
                }
                unset($subAttr);
            }
        }
        unset($item);

        return $items;
    }
}
