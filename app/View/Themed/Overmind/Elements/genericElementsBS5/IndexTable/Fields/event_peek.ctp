<?php
/**
 * A row's event as its id and icon, with its peek on hover (Events/peek_link).
 * Give the column `'header_class' => 'idx-col-event_peek'` so its heading
 * aligns with the cells.
 *
 * Field config:
 * - data_path  "Event.id" or "Event.id, Event.info" (id first, title second)
 */
$paths = array_map('trim', explode(',', $field['data_path']));
$id = Hash::get($row, $paths[0]);
if (empty($id)) {
    return;
}
echo $this->element('Events/peek_link', [
    'id' => $id,
    'info' => isset($paths[1]) ? Hash::get($row, $paths[1]) : null,
]);
