<?php
$server = Hash::get($row, $field['data_path']);
if (empty($server)) {
    return;
}
?>
<div class="d-flex flex-column">
    <span class="fw-semibold"><?= h($server['name']) ?></span>
    <?php if (!empty($server['url'])): ?>
        <small class="text-muted"><?= h($server['url']) ?></small>
    <?php endif; ?>
</div>
