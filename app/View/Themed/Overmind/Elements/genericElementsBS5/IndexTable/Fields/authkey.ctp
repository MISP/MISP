<?php
/*
 * authkey.ctp — masked auth key (start••••end) with the comment shown below,
 */
$authKey = Hash::get($row, $field['data_path']);
if (empty($authKey)) {
    return;
}
$start   = $authKey['authkey_start'] ?? '';
$end     = $authKey['authkey_end'] ?? '';
$comment = $authKey['comment'] ?? '';
?>
<div class="d-flex flex-column gap-1">
    <?php if (!empty($viewUrl)): ?>
        <a href="<?= h($viewUrl) ?>" class="font-monospace link-body-emphasis link-underline-opacity-0 link-underline-opacity-100-hover">
            <?= h($start) ?><span class="text-muted"><?= str_repeat('&bull;', 10) ?></span><?= h($end) ?>
        </a>
    <?php else: ?>
        <span class="font-monospace">
            <?= h($start) ?><span class="text-muted"><?= str_repeat('&bull;', 10) ?></span><?= h($end) ?>
        </span>
    <?php endif; ?>

    <?= $this->element('genericElementsBS5/Badges/comment', ['comment' => $comment]) ?>
</div>
