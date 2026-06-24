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

<div class="rounded border">
    <div class="d-flex align-items-center gap-2 px-2 py-1" style="background:rgba(24,146,177,.07); border-bottom:1px solid rgba(24,146,177,.2);">
        <div class="d-flex align-items-center gap-2">
            <span class="fw-semibold text-uppercase" style="font-size:.6rem; letter-spacing:.08em; color:var(--primary);">
                 Event            </span>
        </div>
        <a href="<?= h($currentUrl) ?>" class="d-flex align-items-center gap-1 text-decoration-none" style="font-size:.7rem; color:var(--primary);" target="_blank">
            <span class="fw-semibold"><?= sprintf('#%s', h($id)) ?></span>
            <i class="fas fa-arrow-up-right-from-square" style="font-size:.6rem;"></i>
        </a>
    </div>
    <div class="px-2 py-1 d-flex flex-column gap-2">
    <?php if (!empty($name)): ?>
        <span class="text-muted small"><?= h($name) ?></span>
    <?php endif; ?>
    </div>
</div>