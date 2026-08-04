<?php
    $inOutCount = Hash::extract($row, $field['data_path']);
    $titleOut = __(
        'This %s %s %s other %s',
        $field['fields']['entity_name'],
        $field['fields']['outbound_action_name'],
        $inOutCount['out'],
        $inOutCount['out'] > 0 ? Inflector::pluralize($field['fields']['entity_name']) : $field['fields']['entity_name']
    );
    $titleIn = __(
        'This %s %s %s other %s',
        $field['fields']['entity_name'],
        $field['fields']['inbound_action_name'],
        $inOutCount['in'],
        $inOutCount['in'] > 0 ? Inflector::pluralize($field['fields']['entity_name']) : $field['fields']['entity_name']
    );
?>
<span>
    <span title="<?= $titleOut ?>" style="margin-right: 3px;">
        <i class="<?= $this->FontAwesome->getClass('sign-out-alt') ?> fa-sign-out-alt fa-rotate-270"></i>
        <?= isset($inOutCount['out']) ? $inOutCount['out'] : 0 ?>
    </span>
    <span title="<?= $titleIn ?>">
        <i class="<?= $this->FontAwesome->getClass('sign-in-alt') ?> fa-sign-in-alt fa-rotate-90"></i>
        <?= isset($inOutCount['in']) ? $inOutCount['in'] : 0 ?>
    </span>
</span>
