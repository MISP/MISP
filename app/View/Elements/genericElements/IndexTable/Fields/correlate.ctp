<?php

$object = Hash::extract($row, $field['data']['object']['value_path']);
$event = Hash::extract($row, 'Event');
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));
$mayChangeCorrelation = !Configure::read('MISP.completely_disable_correlation') && ($isSiteAdmin || ($mayModify && Configure::read('MISP.allow_disabling_correlation')));
$objectId = h($object['id']);

?>

<input
    id="correlation_toggle_<?= $objectId ?>"
    class="correlation-toggle"
    aria-label="<?php echo __('Toggle correlation');?>"
    title="<?php echo __('Toggle correlation');?>"
    type="checkbox"
    data-attribute-id="<?= $objectId ?>"
    <?php
        echo $object['disable_correlation'] ? '' : ' checked';
        echo ($mayChangeCorrelation && empty($event['disable_correlation'])) ? '' : ' disabled';
    ?>
/>