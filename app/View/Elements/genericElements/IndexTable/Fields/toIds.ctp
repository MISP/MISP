<?php
$object = Hash::extract($row, $field['data']['object']['value_path']);
$objectId = h($object['id']);
$mayModify = $this->Acl->canModifyEvent($row);
?>

<div id="Attribute_<?= $objectId ?>_to_ids_placeholder" class="inline-field-placeholder"></div>
<div id="Attribute_<?= $objectId ?>_to_ids_solid" class="inline-field-solid">
    <input type="checkbox" class="toids-toggle" id="toids_toggle_<?= $objectId ?>" data-attribute-id="<?= $objectId ?>" aria-label="<?= __('Toggle IDS flag') ?>" title="<?= __('Toggle IDS flag') ?>" <?= $object['to_ids'] ? ' checked' : ''; ?><?= $mayModify ? '' : ' disabled' ?>>
</div>