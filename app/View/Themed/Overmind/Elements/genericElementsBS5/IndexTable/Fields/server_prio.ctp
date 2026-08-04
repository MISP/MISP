<?php
$serverId = Hash::get($row, 'Server.id');
if (empty($serverId)) {
    return;
}
?>
<div class="d-flex gap-2">
    <i
        class="fas fa-arrow-circle-up rearrange-up useCursorPointer"
        aria-label="<?= __('Move server priority up') ?>"
        title="<?= __('Move server priority up') ?>"
        data-server-id="<?= h($serverId) ?>"
    ></i>
    <i
        class="fas fa-arrow-circle-down rearrange-down useCursorPointer"
        aria-label="<?= __('Move server priority down') ?>"
        title="<?= __('Move server priority down') ?>"
        data-server-id="<?= h($serverId) ?>"
    ></i>
</div>
