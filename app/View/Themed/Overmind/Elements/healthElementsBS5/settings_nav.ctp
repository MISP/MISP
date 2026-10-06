<?php
/**
 * Navigation of the server settings page.
 *
 * Settings pages carry a badge counting their critical and recommended
 * settings in error, health pages a dot with the worst last verdict of their
 * probes; server-settings.js keeps both current as the user works.
 *
 * View variables: destination, destinations, counters, healthVerdicts, sectionsByDestination
 */

App::uses('ServerHealthProbes', 'Tools');

$groupLabels = array(
    'top' => null,
    'config' => __('Configuration'),
    'operations' => __('Operations'),
    'health' => __('System health'),
    'bottom' => null,
);
$byGroup = array();
$children = array();
foreach ($destinations as $id => $entry) {
    if (isset($entry['parent'])) {
        $children[$entry['parent']][$id] = $entry;
    } else {
        $byGroup[$entry['group']][$id] = $entry;
    }
}
$activeParent = isset($destinations[$destination]['parent']) ? $destinations[$destination]['parent'] : null;
$settingTotal = 0;
foreach ($sectionsByDestination as $sections) {
    foreach ($sections as $section) {
        $settingTotal += count($section['settings']);
    }
}
// `integrations` is the sum of its children, which are counted themselves.
$overviewCount = 0;
$overviewCritical = 0;
foreach ($counters as $id => $byLevel) {
    if ($id !== 'integrations') {
        $overviewCount += $byLevel[0] + $byLevel[1];
        $overviewCritical += $byLevel[0];
    }
}

$badge = function ($id) use ($counters, $overviewCount, $overviewCritical, $settingTotal) {
    if ($id === 'all') {
        return '<span class="ss-nav-badge ss-nav-badge-neutral">' . h(number_format($settingTotal)) . '</span>';
    }
    if ($id === 'overview') {
        $count = $overviewCount;
        $critical = $overviewCritical > 0;
    } else {
        $count = isset($counters[$id]) ? $counters[$id][0] + $counters[$id][1] : 0;
        $critical = !empty($counters[$id][0]);
    }
    return sprintf(
        '<span class="ss-nav-badge ss-nav-badge-%s%s" data-ss-badge="%s">%s</span>',
        $critical ? 'critical' : 'warning',
        $count > 0 ? '' : ' d-none',
        h($id),
        h($count)
    );
};
$dot = function ($entry) use ($healthVerdicts) {
    if (empty($entry['probes'])) {
        return '';
    }
    $known = array_intersect_key($healthVerdicts, array_flip($entry['probes']));
    $worst = ServerHealthProbes::worst($known);
    return sprintf(
        '<span class="ss-dot %s" data-ss-dot="%s" title="%s"></span>',
        $worst === null ? 'ss-dot-unknown' : 'ss-dot-' . $worst,
        h(implode(' ', $entry['probes'])),
        h($worst === null ? __('Not checked yet') : __('Last check result'))
    );
};
$link = function ($id, $entry, $extra = '') use ($baseurl, $destination, $badge, $dot) {
    $hasCount = $entry['kind'] === 'settings' || $entry['kind'] === 'modules' || $entry['kind'] === 'integrations'
        || $id === 'overview' || $id === 'all';
    return sprintf(
        '<a class="ss-nav-item%s" href="%s/servers/serverSettings/%s" data-ss-nav="%s"%s>'
        . '<i class="fas fa-%s fa-fw"></i><span class="ss-nav-label">%s</span>%s%s</a>',
        $id === $destination ? ' active' : '',
        $baseurl, h($id), h($id),
        $id === $destination ? ' aria-current="page"' : '',
        h($entry['icon']), h($entry['title']),
        $hasCount ? $badge($id) : '',
        $dot($entry) . $extra
    );
};
?>
<nav class="card shadow-sm ss-nav" aria-label="<?= h(__('Server settings')) ?>">
    <div class="card-body p-2">
        <button type="button" class="ss-nav-search" data-ss-search-open>
            <i class="fas fa-magnifying-glass"></i>
            <span><?= __('Search all settings') ?></span>
            <kbd>Ctrl K</kbd>
        </button>
        <hr class="my-2">
        <?php foreach ($groupLabels as $group => $label): ?>
            <?php if (empty($byGroup[$group])) { continue; } ?>
            <?php if (in_array($group, array('config', 'operations', 'health', 'bottom'), true)): ?><hr class="my-2"><?php endif; ?>
            <div class="ss-nav-group">
                <?php if ($label !== null): ?>
                    <div class="ss-eyebrow px-2 pt-2 pb-1"><?= h($label) ?></div>
                <?php endif; ?>
                <?php foreach ($byGroup[$group] as $id => $entry): ?>
                    <?php if (empty($children[$id])): ?>
                        <?= $link($id, $entry) ?>
                    <?php else: ?>
                        <?php $open = $destination === $id || $activeParent === $id; ?>
                        <div class="d-flex align-items-center">
                            <?= $link($id, $entry) ?>
                            <button type="button" class="ss-nav-expand<?= $open ? '' : ' collapsed' ?>"
                                    data-bs-toggle="collapse" data-bs-target="#ssNav-<?= h($id) ?>"
                                    aria-expanded="<?= $open ? 'true' : 'false' ?>"
                                    aria-label="<?= h(__('Show the pages of %s', $entry['title'])) ?>">
                                <i class="fas fa-chevron-down"></i>
                            </button>
                        </div>
                        <div class="collapse ss-nav-children<?= $open ? ' show' : '' ?>" id="ssNav-<?= h($id) ?>">
                            <?php foreach ($children[$id] as $childId => $child): ?>
                                <?= $link($childId, $child) ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>
    </div>
</nav>
