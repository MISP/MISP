<?php

$object = Hash::extract($row, $field['data']['object']['value_path']);
$event = $row['Event'];
$objectId = intval($object['id']);

$isNonCorrelatingType = in_array($object['type'], MispAttribute::NON_CORRELATING_TYPES, true);
$correlationDisabled = $object['disable_correlation'] || $isNonCorrelatingType;
$correlationButtonEnabled = $this->Acl->canDisableCorrelation($row) &&
    empty($event['disable_correlation']) &&
    !$isNonCorrelatingType;
?>
<input
    id="correlation_toggle_<?= $objectId ?>"
    class="correlation-toggle"
    aria-label="<?php echo __('Toggle correlation');?>"
    title="<?php echo __('Toggle correlation');?>"
    type="checkbox"
    <?php
        echo $correlationDisabled ? '' : ' checked';
        echo $correlationButtonEnabled ? '' : ' disabled';
    ?>
>
