<?php
/**
 * Landing page of the server settings: what needs fixing, the health of the
 * system and the handful of settings every instance has to get right.
 *
 * The health tiles start from the last verdict each probe left in the cache;
 * server-settings.js re-runs the missing and stale ones, a few at a time.
 *
 * View variables: problems, essentials, issueCounts, healthVerdicts, destinations
 */

App::uses('ServerHealthProbes', 'Tools');

$problemLimit = 25;
$shownProblems = array_slice($problems, 0, $problemLimit);
$moreProblems = count($problems) - count($shownProblems);
$probes = ServerHealthProbes::probes();
$levelClass = function ($verdict) {
    return $verdict ? 'ss-tile-lvl-' . (int)$verdict['level'] : 'ss-tile-loading';
};
$half = (int)ceil(count($essentials) / 2);
$essentialColumns = array(array_slice($essentials, 0, $half), array_slice($essentials, $half));
?>
<div class="ss-settings" data-ss-settings>

    <div class="card shadow-sm mb-4 ss-section" style="--ss-accent: var(--bs-danger);">
        <div class="card-header ss-section-header flex-wrap" style="cursor: default;">
            <span class="ss-section-icon"><i class="fas fa-triangle-exclamation"></i></span>
            <div class="flex-grow-1 min-w-0">
                <div class="fw-semibold"><?= __('Needs attention') ?></div>
                <div class="text-muted" style="font-size:.78rem;">
                    <?= __('Critical and recommended settings whose current value fails its check. Click a value to fix it here.') ?>
                </div>
            </div>
            <div class="d-flex gap-2 flex-wrap">
                <span class="ss-count ss-count-0"><b><?= h($issueCounts[0]) ?></b> <?= __('critical') ?></span>
                <span class="ss-count ss-count-1"><b><?= h($issueCounts[1]) ?></b> <?= __('recommended') ?></span>
                <span class="ss-count ss-count-2"><b><?= h($issueCounts[2]) ?></b> <?= __('optional') ?></span>
            </div>
        </div>
        <?php if (empty($problems)): ?>
            <div class="card-body d-flex align-items-center gap-2 text-success fw-semibold">
                <i class="fas fa-circle-check"></i>
                <?= __('No critical or recommended setting left to fix.') ?>
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle ss-table mb-0">
                    <thead>
                        <tr>
                            <th class="ss-col-priority"><?= __('Priority') ?></th>
                            <th class="ss-col-setting"><?= __('Setting') ?></th>
                            <th class="ss-col-value"><?= __('Value') ?></th>
                            <th class="ss-col-description"><?= __('Description') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($shownProblems as $index => $problem): ?>
                            <?= $this->element('healthElementsBS5/setting_row', array(
                                'setting' => $problem['setting'],
                                'k' => 'p-' . $index,
                                'rowDestination' => $problem['destination'],
                                'rowDestinationTitle' => $destinations[$problem['destination']]['title'],
                            )) ?>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
        <div class="card-footer bg-transparent d-flex justify-content-between align-items-center flex-wrap gap-2 small">
            <span class="text-muted">
                <?php if ($moreProblems > 0): ?>
                    <?= h(__n('%s more setting to fix is not listed here.', '%s more settings to fix are not listed here.', $moreProblems, $moreProblems)) ?>
                <?php endif; ?>
                <?php if ($issueCounts[2] > 0): ?>
                    <?= h(__n('%s optional setting is left to its section.', '%s optional settings are left to their section.', $issueCounts[2], $issueCounts[2])) ?>
                <?php endif; ?>
            </span>
            <a href="<?= $baseurl ?>/servers/serverSettings/all#problems" data-ss-nav="all" data-ss-nav-filter="problems">
                <?= __('Every problem in All settings') ?> <i class="fas fa-arrow-right fa-xs"></i>
            </a>
        </div>
    </div>

    <div class="card shadow-sm mb-4 ss-section" style="--ss-accent: #20c997;">
        <div class="card-header ss-section-header flex-wrap" style="cursor: default;">
            <span class="ss-section-icon"><i class="fas fa-heart-pulse"></i></span>
            <div class="flex-grow-1 min-w-0">
                <div class="fw-semibold"><?= __('System health') ?></div>
                <div class="text-muted" style="font-size:.78rem;" data-ss-health-summary>
                    <?= __('Each check runs on its own; the last result is shown until it is refreshed.') ?>
                </div>
            </div>
            <button type="button" class="btn btn-sm btn-outline-primary" data-ss-rerun-tiles>
                <i class="fas fa-rotate me-1"></i><?= __('Re-run checks') ?>
            </button>
        </div>
        <div class="card-body">
            <div class="ss-tiles">
                <?php foreach (ServerHealthProbes::overviewProbes() as $probe): ?>
                    <?php
                    $meta = $probes[$probe];
                    $verdict = isset($healthVerdicts[$probe]) ? $healthVerdicts[$probe] : null;
                    ?>
                    <a class="ss-tile <?= $levelClass($verdict) ?>"
                       href="<?= $baseurl ?>/servers/serverSettings/<?= h($meta['destination']) ?>"
                       data-ss-nav="<?= h($meta['destination']) ?>"
                       data-ss-tile="<?= h($probe) ?>"
                       data-ss-at="<?= $verdict ? (int)$verdict['at'] : 0 ?>">
                        <span class="ss-tile-icon"><i class="fas fa-<?= h($meta['icon']) ?>"></i></span>
                        <span class="ss-tile-body">
                            <span class="ss-tile-title"><?= h($meta['title']) ?></span>
                            <span class="ss-tile-label" data-ss-tile-label><?= $verdict ? h($verdict['label']) : '' ?></span>
                            <span class="ss-tile-summary" data-ss-tile-summary><?= $verdict ? h($verdict['summary']) : '' ?></span>
                            <span class="ss-tile-age" data-ss-tile-age></span>
                        </span>
                        <span class="ss-tile-spinner spinner-border spinner-border-sm" aria-hidden="true"></span>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <div class="card shadow-sm mb-4 ss-section" style="--ss-accent: var(--primary);">
        <div class="card-header ss-section-header" style="cursor: default;">
            <span class="ss-section-icon"><i class="fas fa-star"></i></span>
            <div class="flex-grow-1 min-w-0">
                <div class="fw-semibold"><?= __('Essentials') ?></div>
                <div class="text-muted" style="font-size:.78rem;">
                    <?= __('The settings every instance has to get right. Click a value to change it.') ?>
                </div>
            </div>
        </div>
        <div class="row g-0">
            <?php foreach ($essentialColumns as $column => $columnSettings): ?>
                <div class="col-xl-6<?= $column === 0 ? ' ss-essentials-first' : '' ?>">
                    <table class="table table-sm align-middle ss-table ss-essentials mb-0">
                        <tbody>
                            <?php foreach ($columnSettings as $index => $setting): ?>
                                <?= $this->element('healthElementsBS5/setting_row', array(
                                    'setting' => $setting,
                                    'k' => 'e-' . $column . '-' . $index,
                                    'variant' => 'essential',
                                )) ?>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>
