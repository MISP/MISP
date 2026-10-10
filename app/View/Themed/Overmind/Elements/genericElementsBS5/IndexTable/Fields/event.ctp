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
 * - icon           optional Font Awesome class drawn before the "Event" eyebrow
 * - accent         optional colour override, see Badges/event. Either an array
 *                  or a callable taking the row, for a colour that is data
 *                  (an extended view's origin event, say)
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

$accent = $field['accent'] ?? [];
if (is_callable($accent)) {
    $accent = $accent($row);
}

echo $this->element('genericElementsBS5/Badges/event', [
    'id' => $id,
    'name' => $name,
    'url' => $url,
    'org' => $org,
    'icon' => $field['icon'] ?? null,
    'accent' => $accent,
]);
