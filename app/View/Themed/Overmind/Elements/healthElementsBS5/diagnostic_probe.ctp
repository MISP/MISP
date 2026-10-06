<?php
/**
 * The card(s) of one health probe, answered by
 * ServersController::serverDiagnostic() and swapped into its placeholder by
 * server-settings.js. The wrapper carries the verdict (ServerHealthProbes)
 * so the navigation dot and the Overview tile can follow it.
 *
 * View variables: probe, verdict, and the data __diagnosticData() collected.
 */

App::uses('ServerHealthProbes', 'Tools');

$uid = 'dg' . dechex(mt_rand());
$selfUpdate = Configure::read('MISP.self_update') || !Configure::check('MISP.self_update');
$onlineCheck = Configure::read('MISP.online_version_check') || !Configure::check('MISP.online_version_check');
$formatBytes = array('ServerHealthProbes', 'formatBytes');

/** Status pill — a colour never travels without its icon and label. */
$pill = function ($level, $label, $icon = null) {
    $icons = array(0 => 'circle-xmark', 1 => 'triangle-exclamation', 2 => 'circle-check', 3 => 'circle-info');
    return sprintf(
        '<span class="ss-prio ss-lvl-%d"><i class="fas fa-%s"></i>%s</span>',
        (int)$level,
        h($icon ?: $icons[$level]),
        h($label)
    );
};

// The first card of the probe also carries its age and the re-run button.
$firstCard = true;
$openCard = function ($icon, $accent, $title, $subtitle = null, $badge = null) use ($pill, &$firstCard, $probe, $verdict) {
    echo '<div class="card shadow-sm mb-4 ss-section dg-card" style="--ss-accent: ' . h($accent) . ';">';
    echo '<div class="card-header ss-section-header flex-wrap" style="cursor:default;">';
    echo '<span class="ss-section-icon"><i class="fas fa-' . h($icon) . '"></i></span>';
    echo '<div class="flex-grow-1 min-w-0"><div class="fw-semibold">' . h($title) . '</div>';
    if ($subtitle !== null) {
        echo '<div class="text-muted" style="font-size:.78rem;">' . h($subtitle) . '</div>';
    }
    echo '</div>';
    if ($badge !== null) {
        echo $pill($badge['level'], $badge['label'], $badge['icon'] ?? null);
    }
    if ($firstCard) {
        printf(
            '<span class="ss-probe-age text-muted small" data-ss-age="%d"></span>'
            . '<button type="button" class="btn btn-sm btn-outline-secondary" data-ss-probe-rerun="%s" title="%s" aria-label="%s"><i class="fas fa-rotate"></i></button>',
            (int)$verdict['at'], h($probe), h(__('Run this check again')), h(__('Run this check again'))
        );
        $firstCard = false;
    }
    echo '</div><div class="card-body">';
};
$closeCard = function () {
    echo '</div></div>';
};

/** A label on the left, a verdict on the right. */
$row = function ($label, $right, $mono = false) {
    printf(
        '<div class="dg-row"><span class="%s">%s</span><span class="ms-auto d-flex align-items-center gap-2">%s</span></div>',
        $mono ? 'ss-setting-name' : 'dg-row-label',
        h($label),
        $right
    );
};
$badge = array('level' => $verdict['level'], 'label' => $verdict['label']);
?>
<div class="ss-probe dg-scope" id="<?= h($uid) ?>"
     data-ss-probe="<?= h($probe) ?>"
     data-ss-level="<?= (int)$verdict['level'] ?>"
     data-ss-label="<?= h($verdict['label']) ?>"
     data-ss-summary="<?= h($verdict['summary']) ?>"
     data-ss-at="<?= (int)$verdict['at'] ?>">
<?php
switch ($probe):
case 'version':
?>
<?php
/* ============================== VERSION ============================== */
$upToDate = isset($version['upToDate']) ? $version['upToDate'] : 'error';
$openCard('code-branch', '#0d6efd', __('Version information'),
    __('MISP ships its version in a JSON file, checked against the latest tag on GitHub'),
    $badge);
?>
    <div class="row g-3">
        <div class="col-md-6">
            <div class="dg-stat-label"><?= __('Current version') ?></div>
            <div class="dg-version"><?= h($version['current'] ?? __('Unknown')) ?></div>
            <div class="dg-figures text-muted">
                <?= $commit ? h($commit) : __('commit unknown') ?>
                <?php // A packaged/Docker install is not on a branch at all. ?>
                <?php if (!empty($branch)): ?>
                    <span class="mx-1">·</span><?= __('branch') ?> <?= h($branch) ?>
                <?php endif; ?>
            </div>
        </div>
        <div class="col-md-6">
            <div class="dg-stat-label"><?= __('Latest available') ?></div>
            <div class="dg-version">
                <?= $onlineCheck ? h($version['newest'] ?? __('Unknown')) : __('n/a') ?>
            </div>
            <div class="dg-figures text-muted">
                <?php if (!$onlineCheck): ?>
                    <?= __('online version check disabled') ?>
                <?php else: ?>
                    <?= $latestCommit ? h($latestCommit) : __('commit unknown') ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if (!empty($version['new_major']) || !empty($version['new_minor'])): ?>
        <div class="alert alert-warning d-flex gap-2 mt-3 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div>
                <strong><?= __('A new major MISP release is available: %s', h($version['new_major'] ?: $version['new_minor'])) ?></strong><br>
                <?= __('Major versions require manual intervention — check the release instructions.') ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($commit === ''): ?>
        <div class="alert alert-danger d-flex gap-2 mt-3 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('Unable to fetch the current commit ID — check the web user read privileges on the git directory.') ?></div>
        </div>
    <?php endif; ?>

    <?php if (!empty($branch) && $branch !== '2.5' && $selfUpdate): ?>
        <div class="alert alert-danger d-flex gap-2 mt-3 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('You are not on the expected branch — "Update MISP" will fail. Current branch: %s', h($branch)) ?></div>
        </div>
    <?php endif; ?>

    <?php if (!$selfUpdate): ?>
        <div class="alert alert-warning d-flex gap-2 mt-3 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div>
                <strong><?= $upToDate === 'older' ? __('Update available') : __('Self-update disabled') ?></strong><br>
                <?= __('Self-update is disabled for this installation method. Please update using Docker or your package manager.') ?>
            </div>
        </div>
    <?php else: ?>
        <hr class="my-3">
        <div class="d-flex flex-wrap gap-2 align-items-center">
            <button type="button" class="btn btn-sm btn-outline-primary"
                    onclick="openModal('<?= h($baseurl . '/servers/update') ?>', 'lg')">
                <i class="fas fa-download me-1"></i><?= __('Update MISP') ?>
            </button>
            <a href="<?= h($baseurl . '/servers/updateProgress/') ?>" class="btn btn-sm btn-outline-secondary">
                <i class="fas fa-list-check me-1"></i><?= __('View update progress') ?>
            </a>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-dg-update-json>
                <i class="fas fa-file-arrow-up me-1"></i><?= __('Load JSON into database') ?>
            </button>
            <button type="button" class="btn btn-sm btn-outline-secondary ms-auto" data-dg-submodules>
                <i class="fas fa-rotate me-1"></i><?= __('Refresh submodules') ?>
            </button>
        </div>
        <div class="dg-submodules mt-3" data-dg-submodule-target></div>
    <?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'php':
?>
<?php
/* ============================ PHP SETTINGS ============================ */
$versionLimits = compact('phpmin', 'phprec', 'phptoonew');
$webPhp = $phpversion;
$cliPhp = $extensions['cli']['phpversion'] ?? false;
$webState = ServerHealthProbes::phpVersionState($webPhp, $versionLimits);
$cliState = ServerHealthProbes::phpVersionState($cliPhp, $versionLimits);
$phpLow = ServerHealthProbes::phpLow(compact('phpSettings'));
$phpMissing = ServerHealthProbes::phpMissing(compact('extensions'));
$phpWorst = min($webState[0], $cliState[0], $phpLow ? 1 : 2);

$openCard('gauge-high', '#20c997', __('PHP settings'),
    __('Runtime versions and the limits that shape what MISP can process'),
    array('level' => $phpWorst, 'label' => $phpLow
        ? __('%s setting(s) below recommended', $phpLow)
        : ($phpWorst === 2 ? __('OK') : __('Attention needed'))));
?>
    <div class="row g-3 mb-3">
        <div class="col-md-4">
            <div class="dg-stat-label"><?= __('PHP version (web)') ?></div>
            <div class="d-flex align-items-center gap-2">
                <span class="dg-version"><?= h($webPhp ?: '?') ?></span>
                <?= $pill($webState[0], $webState[1]) ?>
            </div>
        </div>
        <div class="col-md-4">
            <div class="dg-stat-label"><?= __('PHP CLI version') ?></div>
            <div class="d-flex align-items-center gap-2">
                <span class="dg-version"><?= h($cliPhp ?: '?') ?></span>
                <?= $pill($cliState[0], $cliState[1]) ?>
            </div>
        </div>
        <div class="col-md-4">
            <div class="dg-stat-label"><?= __('INI path') ?></div>
            <div class="ss-setting-name"><?= h($php_ini ?: __('unknown')) ?></div>
            <div class="dg-figures text-muted"><?= __('%s or newer recommended', h($phprec)) ?></div>
        </div>
    </div>

    <p class="text-muted" style="font-size:.78rem;">
        <?= __('These are recommendations, not requirements — depending on usage you may want to go beyond them.') ?>
    </p>

    <?php foreach ($phpSettings as $settingName => $phpSetting): ?>
        <?php
        $unit = $phpSetting['unit'] ? ' ' . $phpSetting['unit'] : '';
        $ok = $phpSetting['value'] >= $phpSetting['recommended'];
        $right = sprintf(
            '<span class="dg-figures text-muted">%s <strong class="text-body">%s</strong><span class="mx-2">·</span>%s %s</span>%s',
            h(__('Current:')), h($phpSetting['value'] . $unit),
            h(__('Recommended:')), h($phpSetting['recommended'] . $unit),
            $ok ? $pill(2, __('OK')) : $pill(1, __('Low'))
        );
        $row($settingName, $right, true);
        ?>
    <?php endforeach; ?>
<?php $closeCard(); ?>

<?php
/* =========================== PHP EXTENSIONS =========================== */
$extMissing = $phpMissing['extensions'];
$openCard('puzzle-piece', '#6f42c1', __('PHP extensions'),
    __('Extensions MISP needs, and the optional ones that unlock features'),
    $extMissing
        ? array('level' => 0, 'label' => __('%s required missing', $extMissing))
        : array('level' => 2, 'label' => __('All required installed')));
?>
    <div class="table-responsive">
        <table class="table table-sm align-middle ss-table mb-0">
            <thead>
                <tr>
                    <th style="width:9rem;"><?= __('Extension') ?></th>
                    <th style="width:6rem;"><?= __('Required') ?></th>
                    <th><?= __('Why to install') ?></th>
                    <th style="width:11rem;"><?= __('Web') ?></th>
                    <th style="width:11rem;"><?= __('CLI') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($extensions['extensions'] as $extension => $info): ?>
                <tr class="ss-row">
                    <td><span class="ss-setting-name"><?= h($extension) ?></span></td>
                    <td>
                        <?= $info['required']
                            ? '<i class="fas fa-check text-primary" title="' . h(__('Required')) . '"></i>'
                            : '<i class="fas fa-minus text-muted" title="' . h(__('Optional')) . '"></i>' ?>
                    </td>
                    <td class="text-muted" style="font-size:.76rem;"><?= $info['info'] ?></td>
                    <?php foreach (array('web', 'cli') as $source): ?>
                        <?php
                        $ver = $info["{$source}_version"];
                        $outdated = $info["{$source}_version_outdated"];
                        ?>
                        <td>
                            <?php if ($ver && !$outdated): ?>
                                <span class="dg-figures"><i class="fas fa-check text-success me-1"></i><?= h($ver) ?></span>
                            <?php else: ?>
                                <span class="dg-figures"><i class="fas fa-xmark text-danger me-1"></i>
                                    <?= $outdated
                                        ? h(__('%s < %s required', $ver, $info['required_version']))
                                        : __('absent') ?>
                                </span>
                            <?php endif; ?>
                        </td>
                    <?php endforeach; ?>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php $closeCard(); ?>

<?php
/* ========================== PHP DEPENDENCIES ========================== */
$depMissing = $phpMissing['dependencies'];
$openCard('cubes', '#795548', __('PHP dependencies'),
    __('Composer packages under app/Vendor — install them with composer'),
    $depMissing
        ? array('level' => 0, 'label' => __('%s required missing', $depMissing))
        : array('level' => 2, 'label' => __('All required installed')));
?>
    <div class="table-responsive">
        <table class="table table-sm align-middle ss-table mb-0">
            <thead>
                <tr>
                    <th style="width:16rem;"><?= __('Dependency') ?></th>
                    <th style="width:6rem;"><?= __('Required') ?></th>
                    <th><?= __('Why to install') ?></th>
                    <th style="width:12rem;"><?= __('Installed') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($extensions['dependencies'] as $dependency => $info): ?>
                <tr class="ss-row">
                    <td><span class="ss-setting-name"><?= h($dependency) ?></span></td>
                    <td>
                        <?= $info['required']
                            ? '<i class="fas fa-check text-primary" title="' . h(__('Required')) . '"></i>'
                            : '<i class="fas fa-minus text-muted" title="' . h(__('Optional')) . '"></i>' ?>
                    </td>
                    <td class="text-muted" style="font-size:.76rem;"><?= $info['info'] ?></td>
                    <td>
                        <?php if ($info['version'] && !$info['version_outdated']): ?>
                            <span class="dg-figures"><i class="fas fa-check text-success me-1"></i><?= h($info['version']) ?></span>
                        <?php else: ?>
                            <span class="dg-figures"><i class="fas fa-xmark text-danger me-1"></i>
                                <?= $info['version_outdated']
                                    ? h(__('%s < %s required', $info['version'], $info['required_version']))
                                    : __('absent') ?>
                            </span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php $closeCard(); ?>
<?php
    break;
case 'filesystem':
?>
<?php
/* ========================== FILE PERMISSIONS ========================== */
$openCard('folder-tree', '#fd7e14', __('File system permissions'),
    __('Directories and files MISP has to be able to write to, or read from'),
    $badge);

$permGroups = array(
    array('title' => __('Directories'), 'items' => $writeableDirs, 'errors' => $writeableErrors),
    array('title' => __('Writeable files'), 'items' => $writeableFiles, 'errors' => $writeableErrors),
    array('title' => __('Readable files'), 'items' => $readableFiles, 'errors' => $readableErrors),
);
foreach ($permGroups as $group):
    if (empty($group['items'])) { continue; }
?>
    <div class="dg-block-title"><?= h($group['title']) ?></div>
    <div class="row g-2 mb-3">
        <?php foreach ($group['items'] as $path => $error): ?>
            <div class="col-lg-6">
                <div class="dg-row dg-row-boxed">
                    <span class="ss-setting-name text-truncate" title="<?= h($path) ?>"><?= h($path) ?></span>
                    <span class="ms-auto ps-2">
                        <?= $error > 0
                            ? $pill(0, $group['errors'][$error])
                            : $pill(2, __('OK')) ?>
                    </span>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endforeach; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'dbSchema':
?>
<?php if (!$dbEncodingStatus): ?>
    <div class="alert alert-danger d-flex gap-2" role="alert">
        <i class="fas fa-triangle-exclamation mt-1"></i>
        <div><?= __('Incorrect database encoding: the connection is not set to "utf8mb4 COLLATE utf8mb4_unicode_ci". Set %s in %s.',
            '<code>\'encoding\' => \'utf8mb4 COLLATE utf8mb4_unicode_ci\'</code>', '<code>' . h(APP) . 'Config/database.php</code>') ?></div>
    </div>
<?php endif; ?>
<?php
/* ============================ DATABASE SCHEMA ============================ */
$schemaTotal = ServerHealthProbes::schemaDifferences($dbSchemaDiagnostics);

// The ledger figures. db_version is frozen, so the schema-version pair below
// is the same on a healthy and on a stalled instance - these say whether
// schema work is outstanding, and a failure outranks everything else because
// the update run halts there.
$migrationsPending = (int)($dbSchemaDiagnostics['migrations_pending'] ?? 0);
$migrationsPendingIds = $dbSchemaDiagnostics['migrations_pending_ids'] ?? array();
$migrationsFailed = (int)($dbSchemaDiagnostics['migrations_failed'] ?? 0);
$migrationsFailedIds = $dbSchemaDiagnostics['migrations_failed_ids'] ?? array();
$migrationsApplied = (int)($dbSchemaDiagnostics['migrations_applied'] ?? 0);

$openCard('database', '#0dcaf0', __('Schema & migrations'),
    __('Outstanding migrations, and how the live schema compares to the expected one'),
    $badge);
?>
    <div class="row g-3 mb-3">
        <div class="col-sm-6">
            <div class="dg-stat-label"><?= __('Migrations') ?></div>
            <div class="d-flex align-items-center gap-2">
                <span class="dg-version"><?= h($migrationsApplied) ?></span>
                <?php
                if ($migrationsFailed > 0) {
                    echo $pill(0, __('%s failed', $migrationsFailed));
                } elseif ($migrationsPending > 0) {
                    echo $pill(1, __('%s pending', $migrationsPending));
                } else {
                    echo $pill(2, __('up to date'));
                }
                ?>
            </div>
            <div class="dg-figures text-muted"><?= __('applied, per the ledger') ?></div>
        </div>
        <div class="col-sm-6">
            <div class="dg-stat-label"><?= __('Schema version') ?></div>
            <div class="d-flex align-items-center gap-2">
                <span class="dg-version"><?= h($dbSchemaDiagnostics['actual_db_version']) ?></span>
                <?php
                $expected = $dbSchemaDiagnostics['expected_db_version'];
                $actual = $dbSchemaDiagnostics['actual_db_version'];
                echo $actual == $expected
                    ? $pill(2, __('expected'))
                    : $pill(1, __('expected %s', $expected));
                ?>
            </div>
            <div class="dg-figures text-muted">
                <?= h($dbSchemaDiagnostics['dataSource']) ?>
                <span class="mx-1">·</span>
                <?= !empty($dbSchemaDiagnostics['update_locked'])
                    ? __('updates locked (%ss left)', h($dbSchemaDiagnostics['remaining_lock_time']))
                    : __('updates not locked') ?>
            </div>
        </div>
    </div>

    <?php if (!empty($dbSchemaDiagnostics['error'])): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= h($dbSchemaDiagnostics['error']) ?></div>
        </div>
    <?php endif; ?>

    <?php foreach (($dbSchemaDiagnostics['warnings'] ?? array()) as $warning): ?>
        <div class="alert alert-warning d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= h($warning) ?></div>
        </div>
    <?php endforeach; ?>

    <?php if (!empty($dbSchemaDiagnostics['update_fail_number_reached'])): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('The maximum number of failed updates has been reached — updates are halted until the issue is resolved.') ?></div>
        </div>
    <?php endif; ?>

    <?php if ($migrationsFailed > 0): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div>
                <?= __('The update run halted on a failed migration. Nothing after it has been attempted; it is retried first on the next run, and the error is recorded in its ledger row.') ?>
                <div class="mt-1"><code><?= h(implode(', ', $migrationsFailedIds)) ?></code></div>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($migrationsPending > 0): ?>
        <div class="alert alert-warning d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div>
                <?= __('%s migration(s) pending, applied in this order by the next update run:', $migrationsPending) ?>
                <a href="<?= $baseurl ?>/servers/updateProgress" class="ms-1"><?= __('View update progress') ?></a>
                <ul class="mb-0 mt-1">
                <?php foreach ($migrationsPendingIds as $migrationId): ?>
                    <li>
                        <code><?= h($migrationId) ?></code>
                        <?php if (in_array($migrationId, $migrationsFailedIds, true)): ?>
                            <?= $pill(0, __('failed')) ?>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
                </ul>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($schemaTotal): ?>
        <div class="dg-block-title"><?= __('Schema differences') ?></div>
        <div class="dg-diffs">
            <?php foreach (($dbSchemaDiagnostics['diagnostic'] ?? array()) as $tableName => $diffs): ?>
                <?php foreach ($diffs as $diff): ?>
                    <div class="dg-row dg-row-boxed">
                        <span class="ss-setting-name"><?= h($tableName) ?></span>
                        <span class="text-muted ms-2" style="font-size:.76rem;"><?= h($diff['description']) ?></span>
                        <span class="ms-auto ps-2">
                            <?= !empty($diff['is_critical']) ? $pill(0, __('critical')) : $pill(1, str_replace('_', ' ', $diff['error_type'])) ?>
                        </span>
                    </div>
                <?php endforeach; ?>
            <?php endforeach; ?>
            <?php foreach (($dbSchemaDiagnostics['diagnostic_index'] ?? array()) as $tableName => $columns): ?>
                <?php foreach ($columns as $column): ?>
                    <div class="dg-row dg-row-boxed">
                        <span class="ss-setting-name"><?= h($tableName) ?></span>
                        <span class="text-muted ms-2" style="font-size:.76rem;"><?= h($column['message']) ?></span>
                        <span class="ms-auto ps-2"><?= $pill(1, __('index')) ?></span>
                    </div>
                    <?php if (!empty($column['sql'])): ?>
                        <pre class="dg-sql"><?= h($column['sql']) ?></pre>
                    <?php endif; ?>
                <?php endforeach; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'dbSpace':
?>
<?php
/* ============================ DATABASE SPACE ============================ */
$tables = array();
$dbTotal = 0;
$dbReclaimable = 0;
foreach ($dbDiagnostics as $tableData) {
    $size = (int)($tableData['data_in_bytes'] ?? 0) + (int)($tableData['index_in_bytes'] ?? 0);
    $reclaim = (int)($tableData['reclaimable_in_bytes'] ?? 0);
    $dbTotal += $size;
    $dbReclaimable += $reclaim;
    $tables[] = array('table' => $tableData['table'], 'size' => $size, 'reclaimable' => $reclaim);
}
usort($tables, function ($a, $b) {
    return $b['size'] <=> $a['size'];
});
$topTables = array_slice($tables, 0, 10);
$openCard('chart-column', '#0d6efd', __('Space usage'),
    __('Disk usage per table, and what an SQL optimize would give back'),
    null);
?>
    <div class="row g-3 mb-3">
        <div class="col-sm-6">
            <div class="dg-stat-label"><?= __('Total size') ?></div>
            <div class="dg-version"><?= h($formatBytes($dbTotal)) ?></div>
            <div class="dg-figures text-muted"><?= __('across %s tables', count($tables)) ?></div>
        </div>
        <div class="col-sm-6">
            <div class="dg-stat-label"><?= __('Reclaimable') ?></div>
            <div class="dg-version <?= $dbReclaimable > 0 ? 'text-warning-emphasis' : '' ?>">
                <?= h($formatBytes($dbReclaimable)) ?>
            </div>
            <div class="dg-figures text-muted"><?= __('freed by an SQL optimize') ?></div>
        </div>
    </div>
    <div class="dg-block-title">
        <?= __('Largest tables') ?>
        <span class="text-muted fw-normal text-lowercase" style="letter-spacing:0;">
            — <?= __('top %s of %s', count($topTables), count($tables)) ?>
        </span>
    </div>
    <div class="table-responsive mb-3">
        <table class="table table-sm align-middle ss-table mb-0">
            <thead>
                <tr>
                    <th><?= __('Table') ?></th>
                    <th style="width:9rem;" class="text-end"><?= __('Size used') ?></th>
                    <th style="width:9rem;" class="text-end"><?= __('Reclaimable') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($topTables as $tableRow): ?>
                <tr class="ss-row">
                    <td><span class="ss-setting-name"><?= h($tableRow['table']) ?></span></td>
                    <td class="text-end dg-figures"><?= h($formatBytes($tableRow['size'])) ?></td>
                    <td class="text-end dg-figures <?= $tableRow['reclaimable'] > 0 ? 'text-warning-emphasis' : 'text-muted' ?>">
                        <?= h($formatBytes($tableRow['reclaimable'])) ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <p class="text-muted" style="font-size:.76rem;">
        <?= __('Keep at least 3× the size of the largest table free on disk, so the update scripts can work as expected.') ?>
    </p>
<?php $closeCard(); ?>
<?php
    break;
case 'dbConfig':
?>
<?php
/* ======================== DATABASE CONFIGURATION ======================== */
$openCard('sliders', '#6610f2', __('Database configuration'),
    __('MySQL/MariaDB variables that shape MISP performance'),
    $badge);
if (empty($dbConfiguration)): ?>
    <p class="text-muted mb-0"><?= __('Only reported for MySQL and MariaDB.') ?></p>
<?php else:
?>
    <div class="table-responsive">
        <table class="table table-sm align-middle ss-table mb-0">
            <thead>
                <tr>
                    <th style="width:14rem;"><?= __('Setting') ?></th>
                    <th style="width:8rem;" class="text-end"><?= __('Default') ?></th>
                    <th style="width:8rem;" class="text-end"><?= __('Current') ?></th>
                    <th style="width:8rem;" class="text-end"><?= __('Recommended') ?></th>
                    <th><?= __('Explanation') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($dbConfiguration as $setting): ?>
                <?php $off = $setting['value'] != $setting['recommended']; ?>
                <tr class="ss-row <?= $off ? 'ss-row-error ss-lvl-1' : '' ?>">
                    <td><span class="ss-setting-name"><?= h($setting['name']) ?></span></td>
                    <td class="text-end dg-figures text-muted"><?= h($setting['default']) ?></td>
                    <td class="text-end dg-figures fw-semibold"><?= h($setting['value']) ?></td>
                    <td class="text-end dg-figures text-muted"><?= h($setting['recommended']) ?></td>
                    <td class="text-muted" style="font-size:.76rem;"><?= h($setting['explanation']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php
endif;
$closeCard();
?>
<?php
    break;
case 'redis':
?>
<?php
/* ================================ REDIS ================================ */
$redisOk = !empty($redisInfo['extensionVersion']) && !empty($redisInfo['connection']);
$openCard('server', '#d63384', __('Redis'),
    __('Cache, background job queues and correlation helpers'),
    $redisOk
        ? array('level' => 2, 'label' => __('Connected'))
        : array('level' => 0, 'label' => empty($redisInfo['extensionVersion']) ? __('Extension missing') : __('Unreachable')));
?>
    <?php $row(__('PHP extension version'), $redisInfo['extensionVersion']
        ? '<span class="dg-figures">' . h($redisInfo['extensionVersion']) . '</span>'
        : $pill(0, __('not installed'))); ?>

    <?php if (!empty($redisInfo['connection'])): ?>
        <?php
        $redisRows = array(
            __('Server version') => $redisInfo['redis_version'] ?? null,
            __('Server name') => $redisInfo['server_name'] ?? null,
            __('Dragonfly version') => $redisInfo['dfly_version'] ?? ($redisInfo['dragonfly_version'] ?? null),
            __('Valkey version') => $redisInfo['valkey_version'] ?? null,
            __('Memory allocator') => $redisInfo['mem_allocator'] ?? null,
            __('Fragmentation ratio') => $redisInfo['mem_fragmentation_ratio'] ?? null,
        );
        foreach ($redisRows as $label => $value) {
            if ($value === null || $value === '') { continue; }
            $row($label, '<span class="dg-figures">' . h($value) . '</span>');
        }
        $redisBytes = array(
            __('Memory usage') => $redisInfo['used_memory'] ?? null,
            __('Peak memory usage') => $redisInfo['used_memory_peak'] ?? null,
            __('Maximum memory') => $redisInfo['maxmemory'] ?? null,
            __('Total system memory') => $redisInfo['total_system_memory'] ?? null,
        );
        foreach ($redisBytes as $label => $value) {
            if ($value === null || $value === '') { continue; }
            $row($label, '<span class="dg-figures">' . h($formatBytes($value)) . '</span>');
        }
        ?>
    <?php elseif (!empty($redisInfo['extensionVersion'])): ?>
        <div class="alert alert-danger d-flex gap-2 mt-2 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('Redis is not available.') ?> <?= h($redisInfo['connection_error'] ?? '') ?></div>
        </div>
    <?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'workers':
?>
<?= $this->element('healthElementsBS5/workers', array('worker_array' => $worker_array)) ?>
<?php
    break;
case 'services':
?>
<?php
/* ==================== SERVICES & INTEGRATIONS ==================== */
$serviceLevels = ServerHealthProbes::serviceLevels(compact('gpgStatus', 'proxyStatus', 'sessionStatus', 'zmqStatus', 'yaraStatus', 'attachmentScan'));
$gpgLevel = $serviceLevels['gpg'];
$zmqLevel = $serviceLevels['zmq'];
$proxyLevel = $serviceLevels['proxy'];
$sessionLevel = $serviceLevels['session'];
$yaraLevel = $serviceLevels['yara'];

$openCard('plug', '#198754', __('Services & integrations'),
    __('External tooling MISP talks to, and the local libraries it needs'),
    $badge);
?>
    <?php
    $row(__('GnuPG'), $pill($gpgLevel, $gpgErrors[$gpgStatus['status']])
        . (!empty($gpgStatus['version']) ? '<span class="dg-figures text-muted">' . h($gpgStatus['version']) . '</span>' : ''));

    $row(__('Proxy'), $pill($proxyLevel, $proxyErrors[$proxyStatus]));

    $row(__('PHP sessions'), $pill($sessionLevel, $sessionErrors[$sessionStatus['error_code']])
        . '<span class="dg-figures text-muted">' . h($sessionStatus['handler']) . '</span>');
    ?>

    <?php if ($sessionStatus['handler'] === 'database'): ?>
        <div class="dg-row">
            <span class="dg-row-label ps-3"><?= __('Expired sessions') ?></span>
            <span class="ms-auto d-flex align-items-center gap-2">
                <span class="dg-figures"><?= h($sessionStatus['expired_count']) ?></span>
                <?php if ($sessionStatus['error_code'] === 1): ?>
                    <a href="<?= h($baseurl . '/servers/purgeSessions') ?>" class="btn btn-sm btn-outline-danger">
                        <?= __('Purge sessions') ?>
                    </a>
                <?php endif; ?>
            </span>
        </div>
    <?php endif; ?>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('ZeroMQ') ?></span>
        <span class="ms-auto d-flex align-items-center gap-2">
            <?= $pill($zmqLevel, $zmqErrors[$zmqStatus]) ?>
            <span class="btn-group">
                <button type="button" class="btn btn-sm btn-outline-secondary" data-dg-zmq="start"><?= __('Start') ?></button>
                <button type="button" class="btn btn-sm btn-outline-secondary" data-dg-zmq="stop"><?= __('Stop') ?></button>
                <button type="button" class="btn btn-sm btn-outline-secondary"
                        onclick="openModal('<?= h($baseurl . '/servers/statusZeroMQServer') ?>', 'md')"><?= __('Status') ?></button>
            </span>
        </span>
    </div>

    <?php
    $row(__('Yara (plyara library)'), $pill($yaraLevel, $yaraLevel === 2
        ? __('OK')
        : (empty($yaraStatus['test_run'])
            ? __('Failed to run the yara diagnostics tool')
            : __('plyara missing or outdated — run pip3 install plyara'))));

    $row(__('Attachment scan module'), !empty($attachmentScan['status'])
        ? $pill(2, __('OK')) . '<span class="dg-figures text-muted">' . h(implode(', ', $attachmentScan['software'])) . '</span>'
        : $pill(3, __('Not configured')) . '<span class="dg-figures text-muted">' . h($attachmentScan['error'] ?? '') . '</span>');
    ?>

    <div class="dg-block-title mt-3"><?= __('Advanced attachment handler') ?></div>
    <?php if (empty($advanced_attachments)): ?>
        <?php $row('PyMISP', $pill(0, __('Not installed or version outdated'))); ?>
    <?php else: ?>
        <?php foreach ($advanced_attachments as $tool => $problem): ?>
            <?php $row($tool, $problem === false ? $pill(2, __('OK')) : $pill(0, $problem)); ?>
        <?php endforeach; ?>
    <?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'modules':
?>
<?php
$openCard('puzzle-piece', '#6f42c1', __('misp-modules'),
    __('The module systems MISP queries misp-modules for'),
    $badge);
?>
    <?php foreach ($moduleTypes as $type): ?>
        <?php
        $status = $moduleStatus[$type];
        $message = isset($moduleErrors[$status]) ? $moduleErrors[$status] : (string)$status;
        $level = $status === 0 ? 2 : ($status === 1 ? 3 : 0);
        $row($type, $pill($level, $message));
        ?>
    <?php endforeach; ?>

<?php $closeCard(); ?>
<?php
    break;
case 'stix':
?>
<?php
/* =========================== STIX LIBRARIES =========================== */
$openCard('file-code', '#b8860b', __('STIX libraries'),
    __('Required for the STIX 1 and STIX 2 import and export — installing misp-stix pulls in the rest'),
    $badge);
?>
    <?php if ($stix['operational'] === -1): ?>
        <div class="alert alert-danger d-flex gap-2 mb-0" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('Could not run the test script (stixtest.py). Check the error logs for details.') ?></div>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-sm align-middle ss-table mb-0">
                <thead>
                    <tr>
                        <th><?= __('Library') ?></th>
                        <th style="width:11rem;"><?= __('Expected') ?></th>
                        <th style="width:11rem;"><?= __('Installed') ?></th>
                        <th style="width:8rem;"><?= __('Status') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($stix as $name => $library): ?>
                    <?php if (!is_array($library) || !isset($library['expected'])) { continue; } ?>
                    <tr class="ss-row">
                        <td><span class="ss-setting-name"><?= h($name) ?></span></td>
                        <td class="dg-figures text-muted"><?= h($library['expected']) ?></td>
                        <td class="dg-figures"><?= $library['version'] === 0 ? __('not installed') : h($library['version']) ?></td>
                        <td><?= $library['status'] ? $pill(2, __('OK')) : $pill(0, __('Incorrect')) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
case 'audit':
?>
<?php
/* =========================== SECURITY AUDIT =========================== */
$auditFindings = ServerHealthProbes::auditFindings($securityAudit);
$auditLabels = array(0 => __('Error'), 1 => __('Warning'), 3 => __('Hint'));
$openCard('shield-halved', '#dc3545', __('Security audit'),
    __('Configuration weaknesses MISP can detect on its own'),
    $badge);

if (empty($auditFindings)): ?>
    <p class="text-muted mb-0"><?= __('This instance passes every security check.') ?></p>
<?php else: ?>
    <?php foreach ($auditFindings as $finding): ?>
        <div class="dg-finding dg-lvl-<?= (int)$finding['level'] ?>">
            <div class="d-flex gap-2 align-items-start">
                <?= $pill($finding['level'], $auditLabels[$finding['level']]) ?>
                <div class="flex-grow-1">
                    <div class="fw-semibold" style="font-size:.82rem;"><?= h($finding['area']) ?></div>
                    <div class="text-muted" style="font-size:.78rem;">
                        <?= h($finding['message']) ?>
                        <?php if ($finding['link']): ?>
                            <a href="<?= h($finding['link']) ?>" target="_blank" rel="noreferrer"><?= __('More info') ?></a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
<?php $closeCard(); ?>
<?php
    break;
endswitch;
?>
</div>
