<?php
    $relationCount = Hash::extract($row, $field['data_path']);
?>
<span>
    <span title="<?= __('This cluster targets %s other clusters', $relationCount['out']) ?>" style="margin-right: 3px;">
        <i class="<?= $this->FontAwesome->getClass('sign-out-alt') ?> fa-sign-out-alt fa-rotate-270"></i>
        <?= isset($relationCount['out']) ? $relationCount['out'] : 0 ?>
    </span>
    <span title="<?= __('This cluster is being targeted by %s other clusters', $relationCount['in']) ?>">
        <i class="<?= $this->FontAwesome->getClass('sign-in-alt') ?> fa-sign-in-alt fa-rotate-90"></i>
        <?= isset($relationCount['in']) ? $relationCount['in'] : 0 ?>
    </span>
</span>
