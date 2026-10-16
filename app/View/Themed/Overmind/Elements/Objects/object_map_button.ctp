<?php
/**
 * "Show on map" for the objects that carry a place or a path: geolocation,
 * gpx, uav and geojson. Rendered in the card header, outside the accordion
 * button, so a click opens the map instead of collapsing the card.
 *
 * Parameters:
 *   object  array  one entry of $objects
 *   class   string extra classes for the wrapper
 */
if (!Configure::read('Plugin.Geolocation_enabled') || !empty($object['deleted'])) {
    return;
}
$byRelation = [];
foreach ($object['Attribute'] ?? [] as $attribute) {
    if (empty($attribute['deleted']) && !isset($byRelation[$attribute['object_relation']])) {
        $byRelation[$attribute['object_relation']] = $attribute;
    }
}

$data = null;
if ($object['name'] === 'geolocation') {
    if (isset($byRelation['latitude'], $byRelation['longitude'])) {
        $data = [
            'kind' => 'point',
            'lat' => $byRelation['latitude']['value'],
            'lon' => $byRelation['longitude']['value'],
            'radius' => $byRelation['accuracy-radius']['value'] ?? '',
        ];
    }
} else {
    $attachmentRelations = ['gpx' => 'attachment', 'uav' => 'flight-path', 'geojson' => 'attachment'];
    $relation = $attachmentRelations[$object['name']] ?? null;
    // A uav carries any number of flight paths.
    $files = [];
    foreach ($object['Attribute'] ?? [] as $attribute) {
        if ($relation !== null && empty($attribute['deleted'])
            && $attribute['object_relation'] === $relation
        ) {
            $files[] = ['attachment' => $attribute['id'], 'name' => $attribute['value']];
        }
    }
    if (!empty($files)) {
        $data = [
            'kind' => $object['name'] === 'geojson' ? 'geojson' : 'gpx',
            'files' => $files,
        ];
    }
}
if ($data === null) {
    return;
}

$tileUrl = Configure::read('Plugin.Geolocation_url') ?: 'https://geo.circl.lu';
?>
<div class="flex-shrink-0 <?= h($class ?? 'pe-3') ?>">
    <button type="button"
            class="btn btn-sm ov-obj-map-btn"
            data-object-map="<?= h(json_encode($data)) ?>"
            data-tile-url="<?= h($tileUrl) ?>"
            data-title="<?= h($object['name']) ?>"
            title="<?= h(__('Show on map')) ?>">
        <i class="fas fa-map-location-dot"></i>
        <?= __('Map') ?>
    </button>
</div>
