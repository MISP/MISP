<?php
$server = Hash::get($row, $field['data_path']);
if (empty($server)) {
    return;
}

$enabled = !empty($server['caching_enabled']);
$cacheTimestamp = Hash::get($server, 'cache_timestamp');
$isCard = isset($viewMode) && $viewMode === 'card';

$cacheState = null;
if ($enabled) {
    if (!empty($cacheTimestamp)) {
        $elapsed = max(0, time() - (int)$cacheTimestamp);
        $unit = 's';
        if ($elapsed >= 60) {
            $elapsed = floor($elapsed / 60);
            $unit = 'm';
        }
        if ($elapsed >= 60 && $unit === 'm') {
            $elapsed = floor($elapsed / 60);
            $unit = 'h';
        }
        if ($elapsed >= 24 && $unit === 'h') {
            $elapsed = floor($elapsed / 24);
            $unit = 'd';
        }
        $cacheState = __('Age: %s%s', $elapsed, $unit);
    } else {
        $cacheState = __('Not cached');
    }
}
?>
<div class="d-flex flex-column gap-1">
    <?= $this->element(
        'genericElementsBS5/Badges/boolean',
        [
            'boolean' => $enabled,
            'full' => $isCard,
            'true' => __('Cache enabled'),
            'false' => __('Cache disabled'),
            'trueColor' => 'success',
            'falseColor' => 'danger',
            'trueIcon' => 'fa-check-circle',
            'falseIcon' => 'fa-times-circle'
        ]
    ); ?>
    <?php if ($enabled): ?>
        <small class="<?= empty($cacheTimestamp) ? 'text-danger fw-semibold' : 'text-primary fw-semibold' ?>">
            <?= h($cacheState) ?>
        </small>
    <?php endif; ?>
</div>
