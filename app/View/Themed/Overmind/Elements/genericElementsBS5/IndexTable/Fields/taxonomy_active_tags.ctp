<?php

$current = (int)Hash::get($row, 'current_count');
$total   = (int)Hash::get($row, 'total_count');
$isCard  = isset($viewMode) && $viewMode === 'card';

if ($total === 0) {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}

$percent  = (int)round($current / $total * 100);
$complete = $current >= $total;
$variant  = $complete ? 'success' : ($current > 0 ? 'primary' : 'secondary');

$canEnable  = !$complete && !empty($isSiteAdmin) && !empty($row['Taxonomy']['enabled']);
$confirmUrl = $baseurl . '/taxonomies/addTag/' . (int)Hash::get($row, 'Taxonomy.id');
?>
<div class="d-inline-flex align-items-center gap-2">

    <div style="min-width: 5rem;"
         data-bs-toggle="tooltip"
         title="<?= h(__('%s of %s tags exist (%s%%)', $current, $total, $percent)) ?>">
        <div class="d-flex align-items-baseline gap-1 lh-1">
            <span class="fw-semibold text-<?= $variant ?>"><?= h($current) ?></span>
            <span class="text-body-secondary small">/ <?= h($total) ?></span>
        </div>
        <div class="progress mt-1" style="height: 4px;" role="progressbar"
             aria-valuenow="<?= $percent ?>" aria-valuemin="0" aria-valuemax="100">
            <div class="progress-bar bg-<?= $variant ?>" style="width: <?= $percent ?>%;"></div>
        </div>
    </div>

    <?php if ($complete): ?>
        <i class="fas fa-circle-check text-success"
           data-bs-toggle="tooltip"
           title="<?= h(__('Every tag of this taxonomy exists')) ?>"></i>
    <?php elseif ($canEnable): ?>
        <button type="button"
                class="btn btn-sm btn-outline-success py-0 px-2 lh-base"
                onclick="openModal('<?= h($confirmUrl) ?>', 'md')"
                <?= $isCard ? '' : 'data-bs-toggle="tooltip"' ?>
                title="<?= h(__('Enable all tags')) ?>">
            <i class="fas fa-bolt"></i><?= $isCard ? '<span class="ms-1">' . h(__('Enable all')) . '</span>' : '' ?>
        </button>
    <?php endif; ?>

</div>
