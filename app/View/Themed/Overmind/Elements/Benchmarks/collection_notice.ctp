<?php
/*
 * Why this screen looks the way it does.
 *
 * Benchmarks are only as good as the collection behind them, and the plugin
 * is off by default. Records also outlive it being switched off, so a screen
 * can be empty, live, or showing figures that stopped moving days ago — and
 * the last of those is the one that silently misleads. This says which.
 *
 * Expected variables:
 *   $benchmarkingEnabled  bool   Plugin.Benchmarking_enable
 *   $recordedDays         array  every day collection wrote to, oldest first
 *
 * Renders nothing at all when collection is on and has data — the numbers
 * then speak for themselves.
 */

$hasRecords = !empty($recordedDays);
$lastDay = $hasRecords ? end($recordedDays) : null;
$isStale = $hasRecords && $lastDay < date('Y-m-d');

if ($benchmarkingEnabled && $hasRecords && !$isStale) {
    return;
}

$amber = [
    'hue' => 'var(--misp-tone-yellow-solid, #F59E0B)',
    'ink' => 'var(--misp-tone-yellow-fg, #B45309)',
];
// Without theme tokens the fallback makes this mix exactly #0F6D86.
$teal = [
    'hue' => '#1892B1',
    'ink' => 'color-mix(in srgb, #1892B1 50%, var(--misp-ink, #06485B))',
];
if (!$benchmarkingEnabled) {
    $tone = $amber + ['icon' => 'fas fa-circle-pause'];
    $title = __('Benchmark collection is off');
} else if (!$hasRecords) {
    $tone = $teal + ['icon' => 'fas fa-hourglass-start'];
    $title = __('Collection is on, nothing recorded yet');
} else {
    $tone = $amber + ['icon' => 'fas fa-clock-rotate-left'];
    $title = __('These figures have stopped moving');
}
$tint = sprintf('color-mix(in srgb, %s 7.843%%, transparent)', $tone['hue']);
$edge = sprintf('color-mix(in srgb, %s 26.667%%, transparent)', $tone['hue']);
?>

<div class="container-fluid">
    <div class="rounded-3 p-3 mb-4 d-flex align-items-start gap-3"
         style="background:<?= h($tint) ?>; border:1px solid <?= h($edge) ?>;">

        <i class="<?= h($tone['icon']) ?> flex-shrink-0 mt-1"
           style="color:<?= h($tone['ink']) ?>; font-size:1rem; width:1rem;"></i>

        <div style="min-width:0;">
            <div class="fw-semibold mb-1" style="color:<?= h($tone['ink']) ?>;">
                <?= h($title) ?>
            </div>

            <p class="text-muted small mb-0">
                <?php if (!$benchmarkingEnabled): ?>
                    <?= __('MISP only measures the cost of a request while %s is on, and it is off on this instance.', '<code>Plugin.Benchmarking_enable</code>') ?>
                    <?php if ($hasRecords): ?>
                        <?= __('What you see below was collected up to %s and will not change until collection is turned back on.', '<strong>' . h($lastDay) . '</strong>') ?>
                    <?php else: ?>
                        <?= __('Nothing has ever been collected, so there is nothing to show.') ?>
                    <?php endif; ?>
                <?php elseif (!$hasRecords): ?>
                    <?= __('Collection is on, but no request has completed since it was switched on. Figures appear once traffic goes through the instance.') ?>
                <?php else: ?>
                    <?= __('Collection is on, but the most recent record is from %s — nothing has been measured since. Worth checking that requests are reaching this instance.', '<strong>' . h($lastDay) . '</strong>') ?>
                <?php endif; ?>
            </p>

            <?php if (!$benchmarkingEnabled && !empty($isSiteAdmin)): ?>
                <div class="text-muted mt-2" style="font-size:.7rem;">
                    <?= __('Turn it on under Administration → Server settings → Plugin, or with %s.', '<code>cake Admin setSetting Plugin.Benchmarking_enable 1</code>') ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>
