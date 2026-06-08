<?php
$paths = array_map('trim', explode(',', $field['data_path']));
$id = Hash::get($row, $paths[0]);
$name = isset($paths[1]) ? Hash::get($row, $paths[1]) : null;

if (empty($id)) {
    return;
}

$urlTemplate = $field['url'] ?? '';
$currentUrl = str_replace(['%id%', '%event_id%'], $id, $urlTemplate);
?>

<div class="d-flex align-items-center gap-2">
    <a class="text-decoration-underline fw-semibold mb-0 text-dark" href="<?= h($currentUrl) ?>">
        <?= sprintf('#%s', h($id)) ?>
    </a>
    <?php if (!empty($name)): ?>
        <span class="text-muted small"><?= h($name) ?></span>
    <?php endif; ?>
</div>
