<?php
/**
 * "Show on map" for the objects that carry a place or a path: geolocation,
 * gpx, uav and geojson. An entry of the object's action menu, which
 * js/object-map.js opens from its data-object-map.
 *
 * Parameters:
 *   object  array  one entry of $objects
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
<li>
    <a class="dropdown-item justify-content-start" href="#"
       data-object-map="<?= h(json_encode($data)) ?>"
       data-tile-url="<?= h($tileUrl) ?>"
       data-title="<?= h($object['name']) ?>">
        <i class="fas fa-map-location-dot me-2"></i>
        <?= __('Show on map') ?>
    </a>
</li>
