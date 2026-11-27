<?php
/**
 * The object an attribute of a flattened list sits in: its name, opening the
 * row in the event's Objects tab, and the relation the attribute plays there.
 * Empty for a standalone attribute.
 *
 * Expected:
 *   $field['data_path']     path to ['id' => int, 'name' => string]
 *   $field['relation_path'] path to the object_relation
 *   $field['uuid_path']     path to the attribute uuid
 *   $field['event_id_path'] path to the attribute's event id
 */
$object = Hash::get($row, $field['data_path']);
if (empty($object['name'])) {
    return;
}
$relation = (string)Hash::get($row, $field['relation_path']);
$uuid = (string)Hash::get($row, $field['uuid_path']);
$eventId = (int)Hash::get($row, $field['event_id_path']);
?>
<span class="attr-object">
    <a href="<?= h($baseurl . '/events/view/' . $eventId . '/focus:' . rawurlencode($uuid)) ?>"
       class="attr-object-name text-object" data-attr-object-focus="<?= h($uuid) ?>"
       title="<?= h(__('Show it in the Objects tab')) ?>">
        <i class="misp-icon misp-icon-object misp-simple" aria-hidden="true"></i><?= h($object['name']) ?>
    </a>
    <?= $this->element('genericElementsBS5/Badges/object_relation', ['relation' => $relation]) ?>
</span>
