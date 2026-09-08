<?php
/**
 * Correlations tab of the server settings.
 *
 * The legacy view is three stacked tables. What an admin actually comes here
 * for is: which engine is live, is any table about to exhaust its ID space
 * (that silently blocks new correlations), how much disk the dormant engines
 * still hold, and the housekeeping counters. So the ID saturation — a ratio
 * against a hard limit, buried in a table cell before — is promoted to a
 * meter, and everything else hangs off it.
 *
 * Params: correlation_metrics (Correlation::collectMetrics)
 */

$engineKey = $correlation_metrics['engine'];
$engines = $correlation_metrics['db'];
$activeEngine = $engines[$engineKey];
unset($engines[$engineKey]);

$formatBytes = function ($bytes) {
    $bytes = (int)$bytes;
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    foreach (array('GB' => 1073741824, 'MB' => 1048576, 'KB' => 1024) as $unit => $scale) {
        if ($bytes >= $scale) {
            $value = $bytes / $scale;
            return number_format($value, $value >= 100 ? 0 : 1, ',', ' ') . ' ' . $unit;
        }
    }
    return $bytes . ' B';
};
$formatInt = function ($n) {
    return number_format((int)$n, 0, ',', ' ');
};

$saturationState = function ($percent) {
    if ($percent >= 80) {
        return array('level' => 0, 'icon' => 'circle-exclamation', 'label' => __('Critical'), 'colour' => 'var(--bs-danger)');
    }
    if ($percent >= 50) {
        return array('level' => 1, 'icon' => 'circle-exclamation', 'label' => __('Watch'), 'colour' => 'var(--bs-warning)');
    }
    return array('level' => 2, 'icon' => 'circle-check', 'label' => __('Healthy'), 'colour' => 'var(--bs-success)');
};

// `correlation_values` is shared by the Default and NoAcl engines and is never
// emptied by a truncate, so it must not read as reclaimable space.
$sharedTables = array();
foreach ($correlation_metrics['db'] as $engineData) {
    foreach (array_keys($engineData['tables']) as $tableName) {
        $sharedTables[$tableName] = isset($sharedTables[$tableName]) ? $sharedTables[$tableName] + 1 : 1;
    }
}

/*
 * Rows of the engine's own correlation table are the correlations;
 * the shared values table holds the deduplicated values they point at.
 * Summing the two would headline a number that is neither.
 */
$activeRows = 0;
$sharedRows = 0;
$activeSize = 0;
$worstSaturation = 0;
foreach ($activeEngine['tables'] as $tableName => $tableData) {
    if (empty($sharedTables[$tableName]) || $sharedTables[$tableName] < 2) {
        $activeRows += (int)($tableData['row_count'] ?? 0);
    } else {
        $sharedRows += (int)($tableData['row_count'] ?? 0);
    }
    $activeSize += (int)($tableData['size_on_disk'] ?? 0);
    $worstSaturation = max($worstSaturation, (float)($tableData['id_saturation'] ?? 0));
}
$worstState = $saturationState($worstSaturation);

$overCorrelations = (int)$correlation_metrics['over_correlations'];
$excluded = (int)$correlation_metrics['excluded_correlations'];

/**
 * One table row + its ID space meter.
 */
$renderTable = function ($tableName, $tableData, $isActive) use ($formatBytes, $formatInt, $saturationState, $sharedTables) {
    $percent = (float)($tableData['id_saturation'] ?? 0);
    $state = $saturationState($percent);
    $shared = !empty($sharedTables[$tableName]) && $sharedTables[$tableName] > 1;
    ob_start();
    ?>
    <div class="crl-table">
        <div class="d-flex flex-wrap align-items-baseline gap-2 mb-1">
            <span class="ss-setting-name"><?= h($tableName) ?></span>
            <?php if ($shared): ?>
                <span class="badge text-bg-secondary ss-posture"
                      title="<?= h(__('Shared with another engine — a truncate never empties it.')) ?>">
                    <?= __('shared') ?>
                </span>
            <?php endif; ?>
            <span class="ms-auto text-muted crl-figures">
                <?= $formatInt($tableData['row_count'] ?? 0) ?> <?= __('rows') ?>
                <span class="mx-1">·</span>
                <span title="<?= h($formatInt($tableData['size_on_disk'] ?? 0) . ' B') ?>">
                    <?= h($formatBytes($tableData['size_on_disk'] ?? 0)) ?>
                </span>
            </span>
        </div>

        <?php if ($isActive): ?>
            <div class="d-flex align-items-center gap-2">
                <div class="crl-meter flex-grow-1" style="--crl-fill: <?= h($state['colour']) ?>;"
                     role="meter"
                     aria-valuenow="<?= h($percent) ?>" aria-valuemin="0" aria-valuemax="100"
                     aria-label="<?= h(__('ID space used by %s', $tableName)) ?>">
                    <?php if ($percent > 0): ?>
                        <div class="crl-meter-fill" style="width: <?= h(max(0.4, min(100, $percent))) ?>%;"></div>
                    <?php endif; ?>
                </div>
                <span class="ss-prio ss-lvl-<?= (int)$state['level'] ?>">
                    <i class="fas fa-<?= h($state['icon']) ?>"></i>
                    <?= h($state['label']) ?>
                </span>
            </div>
            <div class="text-muted crl-figures mt-1">
                <?= __('%s%% of the ID space used', h($percent)) ?>
                <span class="mx-1">·</span>
                <?= __('last id %s of %s', $formatInt($tableData['last_id'] ?? 0), $formatInt($tableData['id_limit'] ?? 0)) ?>
            </div>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
};
?>
<div class="ss-scope crl-scope">

    <!-- SUMMARY -->
    <div class="card shadow-sm mb-4">
        <div class="card-body p-0">
            <div class="row g-0">

                <div class="col-6 col-lg-3 crl-stat">
                    <div class="crl-stat-label"><?= __('Active engine') ?></div>
                    <div class="crl-stat-value"><?= h($engineKey) ?></div>
                    <div class="crl-stat-sub"><?= h($activeEngine['name']) ?></div>
                </div>

                <div class="col-6 col-lg-3 crl-stat">
                    <div class="crl-stat-label"><?= __('Correlations') ?></div>
                    <div class="crl-stat-value"><?= h($formatInt($activeRows)) ?></div>
                    <div class="crl-stat-sub">
                        <?php if (empty($activeEngine['tables'])): ?>
                            <?= __('computed on demand, nothing stored') ?>
                        <?php else: ?>
                            <?= h($formatBytes($activeSize)) ?> <?= __('on disk') ?>
                            <?php if ($sharedRows): ?>
                                <span class="mx-1">·</span><?= __('%s shared values', h($formatInt($sharedRows))) ?>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="col-6 col-lg-3 crl-stat">
                    <div class="crl-stat-label"><?= __('Over-correlating values') ?></div>
                    <div class="crl-stat-value">
                        <a href="<?= h($baseurl . '/correlations/overCorrelations') ?>"
                           class="text-decoration-none"><?= h($formatInt($overCorrelations)) ?></a>
                    </div>
                    <div class="crl-stat-sub"><?= __('values blocked from correlating') ?></div>
                </div>

                <div class="col-6 col-lg-3 crl-stat">
                    <div class="crl-stat-label"><?= __('Excluded values') ?></div>
                    <div class="crl-stat-value">
                        <a href="<?= h($baseurl . '/correlation_exclusions/index') ?>"
                           class="text-decoration-none"><?= h($formatInt($excluded)) ?></a>
                    </div>
                    <div class="crl-stat-sub"><?= __('excluded by an administrator') ?></div>
                </div>

            </div>
        </div>
    </div>

    <!-- ACTIVE ENGINE -->
    <div class="card shadow-sm mb-4 ss-section" style="--ss-accent: <?= h($worstState['colour']) ?>;">
        <div class="card-header ss-section-header" style="cursor:default;">
            <span class="ss-section-icon"><i class="fas fa-diagram-project"></i></span>
            <div class="flex-grow-1">
                <div class="d-flex align-items-center gap-2">
                    <span class="fw-semibold"><?= h($activeEngine['name']) ?></span>
                    <span class="badge rounded-pill text-bg-success text-uppercase"
                          style="letter-spacing:.06em;"><?= __('Active') ?></span>
                </div>
                <div class="text-muted" style="font-size:.78rem;">
                    <?= __('The engine every new correlation is written to') ?>
                </div>
            </div>
            <?php if ($engineKey !== 'OnDemand'): ?>
                <button type="button" class="btn btn-sm btn-outline-primary"
                        onclick="openModal('<?= h($baseurl . '/attributes/generateCorrelation') ?>', 'md')">
                    <i class="fas fa-rotate me-1"></i><?= __('Recorrelate') ?>
                </button>
            <?php endif; ?>
        </div>

        <div class="card-body">
            <?php if (empty($activeEngine['tables'])): ?>
                <p class="text-muted mb-0">
                    <?= __('This engine keeps no correlation table — correlations are computed on demand, so there is no ID space to exhaust and nothing to recorrelate.') ?>
                </p>
            <?php else: ?>
                <?php foreach ($activeEngine['tables'] as $tableName => $tableData): ?>
                    <?= $renderTable($tableName, $tableData, true) ?>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- DORMANT ENGINES -->
    <div class="d-flex align-items-baseline gap-2 mb-2">
        <h2 class="h6 fw-semibold mb-0"><?= __('Dormant engines') ?></h2>
        <span class="text-muted" style="font-size:.8rem;">
            <?= __('Not receiving correlations — their tables are kept as they were left') ?>
        </span>
    </div>

    <div class="row g-3 mb-4">
        <?php foreach ($engines as $engine => $engineData): ?>
            <?php
            $dormantSize = 0;
            $reclaimable = 0;
            foreach ($engineData['tables'] as $tableName => $tableData) {
                $dormantSize += (int)($tableData['size_on_disk'] ?? 0);
                if (empty($sharedTables[$tableName]) || $sharedTables[$tableName] < 2) {
                    $reclaimable += (int)($tableData['size_on_disk'] ?? 0);
                }
            }
            ?>
            <div class="col-12 col-xl-4">
                <div class="card shadow-sm h-100 crl-dormant">
                    <div class="card-header d-flex align-items-center gap-2">
                        <span class="ss-section-icon crl-dormant-icon"><i class="fas fa-moon"></i></span>
                        <div class="flex-grow-1">
                            <div class="fw-semibold" style="font-size:.9rem;"><?= h($engineData['name']) ?></div>
                            <div class="text-muted" style="font-size:.75rem;"><?= h($engine) ?></div>
                        </div>
                    </div>

                    <div class="card-body">
                        <?php if (empty($engineData['tables'])): ?>
                            <p class="text-muted mb-0" style="font-size:.8rem;">
                                <?= __('No correlation table — nothing is stored for this engine.') ?>
                            </p>
                        <?php else: ?>
                            <?php foreach ($engineData['tables'] as $tableName => $tableData): ?>
                                <?= $renderTable($tableName, $tableData, false) ?>
                            <?php endforeach; ?>
                            <?php if ($reclaimable > 0): ?>
                                <div class="text-muted mt-2" style="font-size:.75rem;">
                                    <i class="fas fa-hard-drive me-1"></i>
                                    <?= __('%s could be reclaimed by truncating', h($formatBytes($reclaimable))) ?>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>

                    <div class="card-footer d-flex flex-wrap gap-2 bg-transparent">
                        <?php if ($engine !== 'Legacy'): ?>
                            <button type="button" class="btn btn-sm btn-outline-primary"
                                    onclick="openModal('<?= h($baseurl . '/correlations/switchEngine/' . urlencode($engine)) ?>', 'md')">
                                <i class="fas fa-toggle-on me-1"></i><?= __('Activate') ?>
                            </button>
                        <?php endif; ?>
                        <?php if ($engine !== 'OnDemand'): ?>
                            <button type="button" class="btn btn-sm btn-outline-danger"
                                    onclick="openModal('<?= h($baseurl . '/correlations/truncate/' . urlencode($engine)) ?>', 'md')">
                                <i class="fas fa-eraser me-1"></i><?= __('Truncate') ?>
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

</div>
