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
    <span class="font-monospace">
        <?= h($start) ?><span class="text-muted"><?= str_repeat('&bull;', 10) ?></span><?= h($end) ?>
    </span>

    <?php if (!empty($comment)): ?>
        <div class="card card-link-item bg-light">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i>
                <span><?= h($comment) ?></span>
            </div>
        </div>
    <?php endif; ?>
</div>
