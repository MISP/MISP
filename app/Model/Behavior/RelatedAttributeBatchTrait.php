<?php

/** Shared stored-correlation lookup for Default and NoAcl engines. */
trait RelatedAttributeBatchTrait
{
    /**
     * Resolve one bounded source batch without changing the single-attribute
     * API's ACLs or hydration order. Neither stored engine limits this lookup.
     */
    private function fetchRelatedAttributesBatch(
        Model $Model,
        array $user,
        array $sgids,
        array $attributes,
        array $fields,
        $includeEventData,
        $checkAcl
    ) {
        $sources = [];
        $results = [];
        foreach ($attributes as $attribute) {
            $sources[$attribute['id']] = $attribute['event_id'];
            $results[$attribute['id']] = [];
        }
        if (empty($sources)) {
            return $results;
        }

        $sourcesByTarget = [];
        foreach (['1_', ''] as $targetPrefix) {
            $sourcePrefix = $targetPrefix === '1_' ? '' : '1_';
            $sourceField = $sourcePrefix . 'attribute_id';
            $corrFields = [
                $sourceField,
                $targetPrefix . 'attribute_id',
                $targetPrefix . 'event_id',
            ];
            if ($checkAcl) {
                foreach ([
                    'object_id', 'distribution', 'object_distribution',
                    'event_distribution', 'sharing_group_id',
                    'object_sharing_group_id', 'event_sharing_group_id',
                    'org_id',
                ] as $field) {
                    $corrFields[] = $targetPrefix . $field;
                }
            }
            $rows = $Model->find('all', [
                'recursive' => -1,
                'conditions' => [
                    'Correlation.' . $sourceField => array_keys($sources),
                ],
                'fields' => $corrFields,
            ]);
            foreach ($rows as $row) {
                $correlation = $row['Correlation'];
                $sourceId = $correlation[$sourceField];
                if ($correlation[$targetPrefix . 'event_id'] == $sources[$sourceId]) {
                    continue;
                }
                if ($checkAcl && !$this->checkCorrelationACL(
                    $user, $correlation, $sgids, $targetPrefix
                )) {
                    continue;
                }
                $targetId = $correlation[$targetPrefix . 'attribute_id'];
                $sourcesByTarget[$targetId][$sourceId] = true;
            }
        }
        if (empty($sourcesByTarget)) {
            return $results;
        }

        $contain = [];
        if ($includeEventData) {
            $contain['Event'] = ['fields' => [
                'Event.id', 'Event.uuid', 'Event.threat_level_id',
                'Event.analysis', 'Event.info', 'Event.extends_uuid',
                'Event.distribution', 'Event.sharing_group_id',
                'Event.published', 'Event.date', 'Event.orgc_id', 'Event.org_id',
            ]];
        }
        // ID is required for regrouping, even when callers omit it. Strip only
        // the field we added so the existing projection contract is retained.
        $stripId = !empty($fields)
            && !in_array('id', $fields, true)
            && !in_array('Attribute.id', $fields, true)
            && !in_array('Attribute.*', $fields, true)
            && !in_array('*', $fields, true);
        if ($stripId) {
            $fields[] = 'Attribute.id';
        }
        $related = $Model->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => ['Attribute.id' => array_keys($sourcesByTarget)],
            'fields' => $fields,
            'contain' => $contain,
        ]);
        // Keep the Attribute model's normal ordering, just as the individual
        // lookup does. Iterate hydration rows rather than correlation edges.
        foreach ($related as $row) {
            $targetId = $row['Attribute']['id'];
            if ($stripId) {
                unset($row['Attribute']['id']);
            }
            if ($includeEventData) {
                $result = $row['Attribute'];
                $result['Event'] = $row['Event'];
            } else {
                $result = $row;
            }
            foreach ($sourcesByTarget[$targetId] as $sourceId => $unused) {
                $results[$sourceId][] = $result;
            }
        }
        return $results;
    }
}
