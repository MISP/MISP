<?php
/**
 * Integrations hub: one card per plugin family this instance knows, each
 * opening the family's own page.
 *
 * View variables: destinations, sectionsByDestination, counters
 */

App::uses('ServerSettingGroups', 'Tools');
?>
<div class="row g-3">
    <?php foreach ($destinations as $id => $entry): ?>
        <?php
        if (!isset($entry['parent']) || $entry['parent'] !== 'integrations') {
            continue;
        }
        $sections = isset($sectionsByDestination[$id]) ? $sectionsByDestination[$id] : array();
        $settingCount = 0;
        foreach ($sections as $section) {
            $settingCount += count($section['settings']);
        }
        $toFix = isset($counters[$id]) ? $counters[$id][0] + $counters[$id][1] : 0;
        $moduleLine = null;
        if ($entry['kind'] === 'modules') {
            $grid = ServerSettingGroups::modules($sections);
            $enabled = count(array_filter(array_column($grid['modules'], 'enabled')));
            $moduleLine = __('%s modules · %s enabled', count($grid['modules']), $enabled);
        }
        ?>
        <div class="col-md-6 col-xxl-4">
            <a class="card shadow-sm h-100 ss-hub-card text-decoration-none text-body"
               href="<?= $baseurl ?>/servers/serverSettings/<?= h($id) ?>" data-ss-nav="<?= h($id) ?>"
               style="--ss-accent: <?= h($entry['accent']) ?>;">
                <div class="card-body d-flex gap-3">
                    <span class="ss-section-icon"><i class="fas fa-<?= h($entry['icon']) ?>"></i></span>
                    <div class="flex-grow-1 min-w-0">
                        <div class="fw-semibold"><?= h($entry['title']) ?></div>
                        <div class="text-muted small mb-2"><?= h($entry['description']) ?></div>
                        <div class="d-flex gap-2 flex-wrap align-items-center small">
                            <span class="text-muted"><?= h($moduleLine ?: __n('%s setting', '%s settings', $settingCount, $settingCount)) ?></span>
                            <?php if ($toFix > 0): ?>
                                <span class="ss-prio <?= $counters[$id][0] ? 'ss-lvl-0' : 'ss-lvl-1' ?>">
                                    <i class="fas fa-circle-exclamation"></i><?= h(__n('%s to fix', '%s to fix', $toFix, $toFix)) ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <i class="fas fa-chevron-right text-muted align-self-center"></i>
                </div>
            </a>
        </div>
    <?php endforeach; ?>
</div>
