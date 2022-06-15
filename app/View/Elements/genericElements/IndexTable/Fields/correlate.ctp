<?php

$object = Hash::extract($row, $field['data']['object']['value_path']);
$event = $row['Event'];
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));
$mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
$objectId = intval($object['id']);

$isNonCorrelatingType = in_array($object['type'], Attribute::NON_CORRELATING_TYPES, true);
$correlationDisabled = $object['disable_correlation'] || $isNonCorrelatingType;
$correlationButtonEnabled = $mayChangeCorrelation &&
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
