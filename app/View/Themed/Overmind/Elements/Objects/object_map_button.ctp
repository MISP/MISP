<?php
/*
 * "Show on map" for the objects that carry a place, as the default theme's
 * row_object.ctp offers it: a geolocation (point, accuracy radius as a
 * circle), a gpx / uav track and a geojson attachment. Nothing is rendered
 * unless Plugin.Geolocation_enabled is on and the object holds what the map
 * needs. openGeoMap() in mispOvermind.js draws it.
 *
 *   object  array   the object, with its Attribute list
 *   class   string  button classes (default: the card view's small outline)
 *   label   bool    print "Map" after the glyph (default false)
 */
if (!Configure::read('Plugin.Geolocation_enabled')) {
    return;
}
$object = $object ?? [];
$attributes = $object['Attribute'] ?? [];
$valueOf = function ($relation) use ($attributes) {
    foreach ($attributes as $attribute) {
        if (($attribute['object_relation'] ?? '') === $relation) {
            return $attribute;
        }
    }
    return null;
};

$data = null;
$name = $object['name'] ?? '';
if ($name === 'geolocation') {
    $lat = $valueOf('latitude');
    $lon = $valueOf('longitude');
    if ($lat !== null && $lon !== null) {
        $radius = $valueOf('accuracy-radius');
        $data = ['kind' => 'point', 'lat' => $lat['value'], 'lon' => $lon['value'], 'radius' => $radius['value'] ?? ''];
    }
} elseif ($name === 'gpx' || $name === 'uav') {
    $file = $valueOf($name === 'gpx' ? 'attachment' : 'flight-path');
    if ($file !== null) {
        $data = ['kind' => 'gpx', 'attachment' => $file['id']];
    }
} elseif ($name === 'geojson') {
    $file = $valueOf('attachment');
    if ($file !== null) {
        $data = ['kind' => 'geojson', 'attachment' => $file['id']];
    }
}
if ($data === null) {
    return;
}
$tileUrl = Configure::read('Plugin.Geolocation_url') ?: 'https://geo.circl.lu';
$title = __('Show on map');
?>
<button type="button" class="<?= h($class ?? 'btn btn-sm btn-outline-secondary py-0 px-2') ?>"
        data-geo-map="<?= h($data['kind']) ?>"
        data-tile-url="<?= h($tileUrl) ?>"
        data-title="<?= h($name) ?>"
        <?php if ($data['kind'] === 'point'): ?>
            data-lat="<?= h($data['lat']) ?>" data-lon="<?= h($data['lon']) ?>" data-radius="<?= h($data['radius']) ?>"
        <?php else: ?>
            data-attachment-id="<?= (int)$data['attachment'] ?>"
        <?php endif; ?>
        title="<?= h($title) ?>" aria-label="<?= h($title) ?>">
    <i class="fas fa-map-location-dot"></i><?php if (!empty($label)): ?><span><?= __('Map') ?></span><?php endif; ?>
</button>
