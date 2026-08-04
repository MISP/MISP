<?php
/**
 * host_port.ctp
 */
$paths = array_map('trim', explode(',', $field['data_path']));

$host        = Hash::extract($row, $paths[0])[0] ?? null;
$port = Hash::extract($row, $paths[1])[0] ?? null;

if (empty($host)) {
    echo '<span class="text-muted fst-italic small">' . __('Unknown') . '</span>';
    return;
}
if (empty($port)) {
    echo ''. __('') . '';
}
$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-inline-flex align-items-center shadow-sm rounded-pill bg-white border overflow-hidden p-1">
    <div class="px-2 d-flex align-items-center">
        <i class="fas fa-server text-primary small me-2"></i>
        <span class="fw-bold text-dark" style="font-family: 'Monaco', 'Consolas', monospace; font-size: 0.9rem;">
            <?= h($host) ?>
        </span>
    </div>

    <?php if (!empty($port)): ?>
        <div class="bg-primary text-white px-2 py-1 rounded-pill ms-1 d-flex align-items-center" style="font-size: 0.8rem;">
            <i class="fas fa-plug-circle-bolt me-1 small"></i>
            <span class="fw-bold"><?= h($port) ?></span>
        </div>
    <?php endif; ?>
</div>

<style>
.d-inline-flex.shadow-sm:hover {
    box-shadow: 0 .25rem .5rem rgba(0,0,0,.1) !important;
    border-color: var(--bs-primary) !important;
    transition: all 0.2s ease-in-out;
}
</style>