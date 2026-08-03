<?php

$uid = 'dg' . dechex(mt_rand());
$confirmations = array();

$selfUpdate = Configure::read('MISP.self_update') || !Configure::check('MISP.self_update');
$onlineCheck = Configure::read('MISP.online_version_check') || !Configure::check('MISP.online_version_check');

$formatBytes = function ($bytes, $dec = 1) {
    $bytes = (float)$bytes;
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return number_format($bytes, $i === 0 ? 0 : $dec, ',', ' ') . ' ' . $units[$i];
};

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

$openCard = function ($icon, $accent, $title, $subtitle = null, $badge = null) use ($pill) {
    echo '<div class="card shadow-sm mb-4 ss-section dg-card" style="--ss-accent: ' . h($accent) . ';">';
    echo '<div class="card-header ss-section-header" style="cursor:default;">';
    echo '<span class="ss-section-icon"><i class="fas fa-' . h($icon) . '"></i></span>';
    echo '<div class="flex-grow-1"><div class="fw-semibold">' . h($title) . '</div>';
    if ($subtitle !== null) {
        echo '<div class="text-muted" style="font-size:.78rem;">' . h($subtitle) . '</div>';
    }
    echo '</div>';
    if ($badge !== null) {
        echo $pill($badge['level'], $badge['label'], $badge['icon'] ?? null);
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
?>
<div class="ss-scope dg-scope" id="<?= h($uid) ?>">

<?php if (!$dbEncodingStatus): ?>
    <div class="alert alert-danger d-flex gap-2" role="alert">
        <i class="fas fa-triangle-exclamation mt-1"></i>
        <div><?= __('Incorrect database encoding: the connection is not set to "utf8mb4 COLLATE utf8mb4_unicode_ci". Set %s in %s.',
            '<code>\'encoding\' => \'utf8mb4 COLLATE utf8mb4_unicode_ci\'</code>', '<code>' . h(APP) . 'Config/database.php</code>') ?></div>
    </div>
<?php endif; ?>

<?php
/* ============================== VERSION ============================== */
$upToDate = isset($version['upToDate']) ? $version['upToDate'] : 'error';
$versionStates = array(
    'same' => array(2, __('Up to date')),
    'newer' => array(1, __('Development version')),
    'older' => array(1, __('Outdated')),
    'disabled' => array(3, __('Check disabled')),
    'error' => array(0, __('Check failed')),
);
$vState = isset($versionStates[$upToDate]) ? $versionStates[$upToDate] : $versionStates['error'];

$openCard('code-branch', '#0d6efd', __('Version information'),
    __('MISP ships its version in a JSON file, checked against the latest tag on GitHub'),
    array('level' => $vState[0], 'label' => $vState[1]));
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
/* ========================== FILE PERMISSIONS ========================== */
$permIssues = 0;
foreach (array($writeableDirs, $writeableFiles, $readableFiles) as $set) {
    foreach ($set as $error) {
        if ($error > 0) {
            $permIssues++;
        }
    }
}
$openCard('folder-tree', '#fd7e14', __('File system permissions'),
    __('Directories and files MISP has to be able to write to, or read from'),
    $permIssues
        ? array('level' => 0, 'label' => __('%s issue(s)', $permIssues))
        : array('level' => 2, 'label' => __('OK')));

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
/* =========================== SECURITY AUDIT =========================== */
$auditFindings = array();
foreach ($securityAudit as $area => $errors) {
    foreach ($errors as $error) {
        $auditFindings[] = array(
            'area' => $area,
            'level' => $error[0],
            'message' => $error[1],
            'link' => $error[2] ?? null,
        );
    }
}
$auditLevels = array(
    'error' => array(0, __('Error')),
    'warning' => array(1, __('Warning')),
    'hint' => array(3, __('Hint')),
);
$openCard('shield-halved', '#dc3545', __('Security audit'),
    __('Configuration weaknesses MISP can detect on its own'),
    empty($auditFindings)
        ? array('level' => 2, 'label' => __('All checks passed'))
        : array('level' => 0, 'label' => __('%s issue(s) found', count($auditFindings))));

if (empty($auditFindings)): ?>
    <p class="text-muted mb-0"><?= __('This instance passes every security check.') ?></p>
<?php else: ?>
    <?php foreach ($auditFindings as $finding): ?>
        <?php $lv = $auditLevels[$finding['level']] ?? $auditLevels['hint']; ?>
        <div class="dg-finding dg-lvl-<?= (int)$lv[0] ?>">
            <div class="d-flex gap-2 align-items-start">
                <?= $pill($lv[0], $lv[1]) ?>
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
/* ============================ PHP SETTINGS ============================ */
$phpVersionState = function ($ver) use ($phpmin, $phprec, $phptoonew) {
    if (!$ver) {
        return array(0, __('Unknown'));
    }
    if (version_compare($ver, $phptoonew) >= 0) {
        return array(0, __('Unsupported'));
    }
    if (version_compare($ver, $phpmin) < 0) {
        return array(0, __('Unsupported, update ASAP'));
    }
    if (version_compare($ver, $phprec) < 0) {
        return array(1, __('Update recommended'));
    }
    return array(2, __('Up to date'));
};
$webPhp = $phpversion;
$cliPhp = $extensions['cli']['phpversion'] ?? false;
$webState = $phpVersionState($webPhp);
$cliState = $phpVersionState($cliPhp);

$phpLow = 0;
foreach ($phpSettings as $phpSetting) {
    if ($phpSetting['value'] < $phpSetting['recommended']) {
        $phpLow++;
    }
}
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
$extMissing = 0;
foreach ($extensions['extensions'] as $info) {
    if ($info['required'] && (!$info['web_version'] || $info['web_version_outdated'])) {
        $extMissing++;
    }
}
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
$depMissing = 0;
foreach ($extensions['dependencies'] as $info) {
    if ($info['required'] && (!$info['version'] || $info['version_outdated'])) {
        $depMissing++;
    }
}
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
/* =========================== DATABASE STATUS =========================== */
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

$schemaDiffs = 0;
foreach (($dbSchemaDiagnostics['diagnostic'] ?? array()) as $diffs) {
    $schemaDiffs += count($diffs);
}
$indexDiffs = 0;
foreach (($dbSchemaDiagnostics['diagnostic_index'] ?? array()) as $columns) {
    $indexDiffs += count($columns);
}
$schemaTotal = $schemaDiffs + $indexDiffs;

$openCard('database', '#0dcaf0', __('Database status'),
    __('Disk usage per table and how the live schema compares to the expected one'),
    $schemaTotal
        ? array('level' => 1, 'label' => __('%s schema difference(s)', $schemaTotal))
        : array('level' => 2, 'label' => __('Schema matches')));
?>
    <div class="row g-3 mb-3">
        <div class="col-sm-4">
            <div class="dg-stat-label"><?= __('Total size') ?></div>
            <div class="dg-version"><?= h($formatBytes($dbTotal)) ?></div>
            <div class="dg-figures text-muted"><?= __('across %s tables', count($tables)) ?></div>
        </div>
        <div class="col-sm-4">
            <div class="dg-stat-label"><?= __('Reclaimable') ?></div>
            <div class="dg-version <?= $dbReclaimable > 0 ? 'text-warning-emphasis' : '' ?>">
                <?= h($formatBytes($dbReclaimable)) ?>
            </div>
            <div class="dg-figures text-muted"><?= __('freed by an SQL optimize') ?></div>
        </div>
        <div class="col-sm-4">
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

    <?php if (!empty($dbSchemaDiagnostics['update_fail_number_reached'])): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('The maximum number of failed updates has been reached — updates are halted until the issue is resolved.') ?></div>
        </div>
    <?php endif; ?>

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
/* ======================== DATABASE CONFIGURATION ======================== */
if (!empty($dbConfiguration)):
    $dbOff = 0;
    foreach ($dbConfiguration as $setting) {
        if ($setting['value'] != $setting['recommended']) {
            $dbOff++;
        }
    }
    $openCard('sliders', '#6610f2', __('Database configuration'),
        __('MySQL/MariaDB variables that shape MISP performance'),
        $dbOff
            ? array('level' => 1, 'label' => __('%s off recommendation', $dbOff))
            : array('level' => 2, 'label' => __('OK')));
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
    $closeCard();
endif;
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
/* ==================== SERVICES & INTEGRATIONS ==================== */
$serviceIssues = 0;

// GnuPG
$gpgLevel = $gpgStatus['status'] === 0 ? 2 : 0;
// ZeroMQ / Proxy: 0 = OK, 1 = not enabled (informational), > 1 = broken
$zmqLevel = $zmqStatus === 0 ? 2 : ($zmqStatus === 1 ? 3 : 0);
$proxyLevel = $proxyStatus === 0 ? 2 : ($proxyStatus === 1 ? 3 : 0);
$sessionLevels = array(0 => 2, 1 => 0, 2 => 1, 8 => 3, 9 => 0);
$sessionLevel = $sessionLevels[$sessionStatus['error_code']] ?? 0;
$yaraLevel = (empty($yaraStatus['test_run']) || empty($yaraStatus['operational'])) ? 0 : 2;
$scanLevel = !empty($attachmentScan['status']) ? 2 : 3;

foreach (array($gpgLevel, $zmqLevel, $proxyLevel, $sessionLevel, $yaraLevel) as $lv) {
    if ($lv === 0) {
        $serviceIssues++;
    }
}
foreach ($moduleTypes as $type) {
    if ($moduleStatus[$type] > 1) {
        $serviceIssues++;
    }
}

$openCard('plug', '#198754', __('Services & integrations'),
    __('External tooling MISP talks to, and the local libraries it needs'),
    $serviceIssues
        ? array('level' => 0, 'label' => __('%s issue(s)', $serviceIssues))
        : array('level' => 2, 'label' => __('OK')));
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
                        onclick="openModal('<?= h($baseurl . '/servers/statusZeroMQServer') ?>', 'sm')"><?= __('Status') ?></button>
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

    <div class="dg-block-title mt-3"><?= __('Module systems') ?></div>
    <?php foreach ($moduleTypes as $type): ?>
        <?php
        $status = $moduleStatus[$type];
        $message = isset($moduleErrors[$status]) ? $moduleErrors[$status] : (string)$status;
        $level = $status === 0 ? 2 : ($status === 1 ? 3 : 0);
        $row($type, $pill($level, $message));
        ?>
    <?php endforeach; ?>

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
/* =========================== STIX LIBRARIES =========================== */
if ($stix['operational'] === -1) {
    $stixBadge = array('level' => 0, 'label' => __('Test script failed'));
} elseif (empty($stix['test_run'])) {
    $stixBadge = array('level' => 0, 'label' => __('Diagnostics failed'));
} elseif ($stix['operational'] === 0) {
    $stixBadge = array('level' => 0, 'label' => __('Libraries missing'));
} elseif (!empty($stix['invalid_version'])) {
    $stixBadge = array('level' => 1, 'label' => __('Versions to update'));
} else {
    $stixBadge = array('level' => 2, 'label' => __('OK'));
}
$openCard('file-code', '#b8860b', __('STIX libraries'),
    __('Required for the STIX 1 and STIX 2 import and export — installing misp-stix pulls in the rest'),
    $stixBadge);
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
/* ========================= MAINTENANCE & TOOLS ========================= */
$confirmations[$uid . '-cache'] = array(
    'title' => __('Clean the model cache'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Rebuilds the cached database schema. Safe to run whenever fields or tables look to be missing.')) . '</p>',
    'label' => __('Clean cache'), 'cls' => 'btn-primary',
);
$confirmations[$uid . '-authkeys'] = array(
    'title' => __('Upgrade authkeys to the advanced format'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Every existing plaintext API key is converted into a hashed advanced authkey so users do not lose access when the advanced format is enabled.')) . '</p>',
    'label' => __('Upgrade authkeys'), 'cls' => 'btn-primary',
);
$confirmations[$uid . '-orphan-attr'] = array(
    'title' => __('Remove orphaned attributes'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Attributes that no longer belong to any event are deleted. Run the check first to see how many there are.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);
$confirmations[$uid . '-orphan-corr'] = array(
    'title' => __('Remove orphaned correlations'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Correlations pointing at attributes that no longer exist are deleted.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);
$confirmations[$uid . '-cull'] = array(
    'title' => __('Remove published empty events'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Published events holding no attribute, object or report are deleted.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);

$openCard('screwdriver-wrench', '#495057', __('Maintenance & tools'),
    __('One-off checks and clean-up routines for this instance'));
?>
    <div class="dg-block-title"><?= __('Consistency checks') ?></div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Orphaned attributes') ?></span>
        <span class="ms-auto d-flex align-items-center gap-2">
            <span class="dg-figures text-muted" data-dg-out="orphan-attr"><?= __('not checked') ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="orphan-attr"><?= __('Check') ?></button>
        </span>
    </div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Attachments referenced but missing on disk') ?></span>
        <span class="ms-auto d-flex align-items-center gap-2">
            <span class="dg-figures text-muted" data-dg-out="bad-attachments"><?= __('not checked') ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="bad-attachments"><?= __('Check') ?></button>
        </span>
    </div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Deprecated endpoint usage') ?></span>
        <span class="ms-auto">
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="deprecated"><?= __('View usage') ?></button>
        </span>
    </div>
    <div class="dg-raw mt-2 d-none" data-dg-out="deprecated-body"></div>

    <div class="dg-block-title mt-3"><?= __('Clean-up') ?></div>
    <div class="d-flex flex-wrap gap-2">
        <button type="button" class="btn btn-sm btn-outline-primary" onclick="dgConfirm('<?= h($uid) ?>-cache')">
            <i class="fas fa-broom me-1"></i><?= __('Clean model cache') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-primary" onclick="dgConfirm('<?= h($uid) ?>-authkeys')">
            <i class="fas fa-key me-1"></i><?= __('Upgrade authkeys') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-orphan-attr')">
            <i class="fas fa-trash me-1"></i><?= __('Remove orphaned attributes') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-orphan-corr')">
            <i class="fas fa-trash me-1"></i><?= __('Remove orphaned correlations') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-cull')">
            <i class="fas fa-trash me-1"></i><?= __('Remove published empty events') ?>
        </button>
    </div>

    <?= $this->Form->postLink('', $baseurl . '/servers/cleanModelCaches',
        array('id' => $uid . '-cache', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/users/updateToAdvancedAuthKeys',
        array('id' => $uid . '-authkeys', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/attributes/pruneOrphanedAttributes',
        array('id' => $uid . '-orphan-attr', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/servers/removeOrphanedCorrelations',
        array('id' => $uid . '-orphan-corr', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/events/cullEmptyEvents',
        array('id' => $uid . '-cull', 'class' => 'd-none', 'escape' => false)) ?>

    <div class="dg-block-title mt-3"><?= __('Other pages') ?></div>
    <div class="d-flex flex-wrap gap-2">
        <a href="<?= h($baseurl . '/servers/ondemandAction/') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-bolt me-1"></i><?= __('On-demand actions') ?>
        </a>
        <a href="<?= h($baseurl . '/events/restoreDeletedEvents') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-trash-arrow-up me-1"></i><?= __('Recover deleted events') ?>
        </a>
        <a href="<?= h($baseurl . '/pages/display/administration') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-clock-rotate-left me-1"></i><?= __('Legacy administrative tools') ?>
        </a>
    </div>
<?php $closeCard(); ?>

</div>

<script>
(function () {
    var root = document.getElementById('<?= h($uid) ?>');
    if (!root || root.dataset.dgWired) return;
    root.dataset.dgWired = '1';

    var DG = <?= json_encode($confirmations, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L = <?= json_encode(array(
        'cancel' => __('Cancel'),
        'ok' => __('OK'),
        'recommended' => __('removal recommended'),
        'badLinks' => __('bad links detected'),
        'failed' => __('The check could not be run.'),
        'zmqFailed' => __('The ZeroMQ action failed.'),
        'jsonLoaded' => __('JSON files loaded into the database.'),
        'jsonFailed' => __('Could not load the JSON files.'),
        'submodulesFailed' => __('Could not load the submodule status.'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    window.dgConfirm = function (id) {
        var conf = DG[id];
        var trigger = document.getElementById(id);
        if (!conf || !trigger) return;
        showConfirmModal({
            title: conf.title, body: conf.body, confirmLabel: conf.label,
            confirmClass: conf.cls, cancelLabel: L.cancel,
            onConfirm: function () { trigger.click(); }
        });
    };

    function out(name) { return root.querySelector('[data-dg-out="' + name + '"]'); }

    var CHECKS = {
        'orphan-attr': {
            url: baseurl + '/attributes/checkOrphanedAttributes/',
            render: function (text) {
                var zero = text.trim() === '0';
                return '<span class="ss-prio ss-lvl-' + (zero ? 2 : 0) + '">'
                    + '<i class="fas fa-' + (zero ? 'circle-check' : 'circle-xmark') + '"></i>'
                    + text.trim() + (zero ? '' : ' — ' + L.recommended) + '</span>';
            }
        },
        'bad-attachments': {
            url: baseurl + '/attributes/checkAttachments/',
            render: function (text) {
                var zero = text.trim() === '0';
                return '<span class="ss-prio ss-lvl-' + (zero ? 2 : 0) + '">'
                    + '<i class="fas fa-' + (zero ? 'circle-check' : 'circle-xmark') + '"></i>'
                    + text.trim() + (zero ? '' : ' — ' + L.badLinks) + '</span>';
            }
        }
    };

    root.querySelectorAll('[data-dg-check]').forEach(function (button) {
        button.addEventListener('click', function () {
            var name = button.dataset.dgCheck;

            if (name === 'deprecated') {
                var target = out('deprecated-body');
                button.disabled = true;
                fetch(baseurl + '/api/viewDeprecatedFunctionUse',
                      { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                    .then(function (r) { if (!r.ok) throw 0; return r.text(); })
                    .then(function (html) { target.innerHTML = html; target.classList.remove('d-none'); })
                    .catch(function () { showToast(L.failed, 'danger'); })
                    .finally(function () { button.disabled = false; });
                return;
            }

            var check = CHECKS[name];
            if (!check) return;
            var slot = out(name);
            button.disabled = true;
            slot.textContent = '…';
            fetch(check.url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, cache: 'no-store' })
                .then(function (r) { if (!r.ok) throw 0; return r.text(); })
                .then(function (text) { slot.innerHTML = check.render(text); })
                .catch(function () { slot.textContent = L.failed; showToast(L.failed, 'danger'); })
                .finally(function () { button.disabled = false; });
        });
    });

    root.querySelectorAll('[data-dg-zmq]').forEach(function (button) {
        button.addEventListener('click', function () {
            button.disabled = true;
            fetch(baseurl + '/servers/' + button.dataset.dgZmq + 'ZeroMQServer/',
                  { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    showToast(data.saved ? data.success : (data.errors || L.zmqFailed),
                              data.saved ? 'success' : 'danger');
                })
                .catch(function () { showToast(L.zmqFailed, 'danger'); })
                .finally(function () { button.disabled = false; });
        });
    });

    /* ---- self-update helpers (only rendered when MISP.self_update is on) ---- */
    var jsonButton = root.querySelector('[data-dg-update-json]');
    if (jsonButton) {
        jsonButton.addEventListener('click', function () {
            jsonButton.disabled = true;
            fetch(baseurl + '/servers/updateJSON/', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { if (!r.ok) throw 0; return r.json(); })
                .then(function () { showToast(L.jsonLoaded, 'success'); })
                .catch(function () { showToast(L.jsonFailed, 'danger'); })
                .finally(function () { jsonButton.disabled = false; });
        });
    }

    var submoduleTarget = root.querySelector('[data-dg-submodule-target]');
    if (submoduleTarget) {
        var loadSubmodules = function () {
            submoduleTarget.innerHTML = '<div class="text-center p-3"><div class="spinner-border spinner-border-sm"></div></div>';
            fetch(baseurl + '/servers/getSubmodulesStatus/', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { if (!r.ok) throw 0; return r.text(); })
                .then(function (html) { submoduleTarget.innerHTML = html; })
                .catch(function () {
                    submoduleTarget.innerHTML = '<div class="text-danger small">' + L.submodulesFailed + '</div>';
                });
        };
        root.querySelector('[data-dg-submodules]').addEventListener('click', loadSubmodules);
        loadSubmodules();

        window.submitSubmoduleUpdate = function (clicked) {
            var path = clicked.dataset.submodule;
            fetch(baseurl + '/servers/getSubmoduleQuickUpdateForm/' + (path ? btoa(path) : ''),
                  { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { return r.text(); })
                .then(function (html) {
                    var holder = document.createElement('div');
                    holder.innerHTML = html;
                    var form = holder.querySelector('form');
                    if (!form) throw 0;
                    document.body.appendChild(holder);
                    return fetch(form.getAttribute('action'), {
                        method: 'POST',
                        headers: { 'X-Requested-With': 'XMLHttpRequest' },
                        body: new URLSearchParams(new FormData(form))
                    }).finally(function () { holder.remove(); });
                })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    showToast(data.status ? (data.output || L.ok) : (data.output || L.failed),
                              data.status ? 'success' : 'danger');
                    loadSubmodules();
                })
                .catch(function () { showToast(L.failed, 'danger'); });
        };
    }
})();
</script>
