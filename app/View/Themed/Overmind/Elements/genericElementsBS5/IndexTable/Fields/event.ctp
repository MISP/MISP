<?php
/**
 *
 * Resolves the event id / name / owner org from the row using the field's
 * data paths, then delegates all rendering to Badges/event.
 *
 * Field config:
 * - data_path      "Event.id" or "Event.id, Event.info" (id first, name second)
 * - url            URL template; %id% / %event_id% replaced with the event id
 * - org_data_path  optional path to the owner organisation
 */
$paths = array_map('trim', explode(',', $field['data_path']));
$id = Hash::get($row, $paths[0]);

if (empty($id)) {
    return;
}

$name = isset($paths[1]) ? Hash::get($row, $paths[1]) : null;

$urlTemplate = $field['url'] ?? '';
$url = str_replace(['%id%', '%event_id%'], $id, $urlTemplate);

$org = !empty($field['org_data_path'])
    ? Hash::get($row, $field['org_data_path'])
    : [];

echo $this->element('genericElementsBS5/Badges/event', [
    'id' => $id,
    'name' => $name,
    'url' => $url,
    'org' => $org,
]);
