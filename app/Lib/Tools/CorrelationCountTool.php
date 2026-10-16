<?php

class CorrelationCountTool
{
    /**
     * Fold an event's correlations into per-element and per-event counts.
     *
     * @param array $related Event::getRelatedAttributes() output: correlated
     *   rows keyed by the event's own attribute id, each row's `id` being the
     *   correlated event's id
     * @param array $attributes the event's attributes the user may see, as
     *   ['id', 'uuid', 'object_uuid' (null outside an object)]; a key of
     *   $related with no entry here is not counted
     * @return array
     */
    public static function aggregate(array $related, array $attributes)
    {
        $counts = [
            'total' => 0,
            'attributes' => [],
            'objects' => [],
            'events' => [],
        ];
        foreach ($attributes as $attribute) {
            $rows = $related[$attribute['id']] ?? [];
            if (empty($rows)) {
                continue;
            }
            $n = count($rows);
            $counts['total'] += $n;
            $counts['attributes'][$attribute['uuid']] = $n;
            if (!empty($attribute['object_uuid'])) {
                $objectUuid = $attribute['object_uuid'];
                $counts['objects'][$objectUuid] =
                    ($counts['objects'][$objectUuid] ?? 0) + $n;
            }
            foreach ($rows as $row) {
                $eventId = (string)$row['id'];
                $counts['events'][$eventId] =
                    ($counts['events'][$eventId] ?? 0) + 1;
            }
        }
        return $counts;
    }
}
