<?php
/*
 * Reusable "Analyst data" add/view control.
 * Opens the shared add modal (pre-filled + locked target) for Note/Opinion/Relationship
 * on the given object, and (optionally) the read-only thread modal. The rail's
 * card is AnalystData/rail_card.
 *
 * Params:
 *   $objectType : parent object type (Event, Attribute, Object, EventReport,
 *                 Galaxy, GalaxyCluster, SharingGroup, Note, Opinion, Relationship, …)
 *   $objectUuid : the parent object's UUID
 *   $mode       : 'dropdown' (default) | 'menu_items'
 *   $showView   : include a "View analyst data" entry (default true)
 *   $viewCount  : optional int — total analyst data, shown as "(N)" on the View entry
 */
$objectType = $objectType ?? '';
$objectUuid = $objectUuid ?? '';
$mode       = $mode ?? 'dropdown';
$showView   = !isset($showView) || $showView;
$viewCount  = empty($viewCount) ? null : (int)$viewCount;

if ($objectType === '' || empty($objectUuid)) {
    return;
}

$canAdd = !empty($me['Role']['perm_analyst_data']);
if (!$canAdd && !$showView) {
    return;
}

$types = [
    'Note'         => ['color' => 'primary',     'icon' => 'misp-icon misp-icon-analyst-note misp-simple',     'label' => __('Add note')],
    'Opinion'      => ['color' => 'success',     'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple',  'label' => __('Add opinion')],
    'Relationship' => ['color' => 'correlation', 'icon' => 'fas fa-diagram-project', 'label' => __('Add relationship')],
];

$addUrl = function ($type) use ($baseurl, $objectType, $objectUuid) {
    return $baseurl . '/analystData/add/' . $type . '/' . h($objectUuid) . '/' . h($objectType);
};
$viewUrl = $baseurl . '/analystData/viewForObject/' . h($objectType) . '/' . h($objectUuid);
$viewLabel = __('View analyst data') . ($viewCount !== null ? ' (' . (int)$viewCount . ')' : '');
?>

<?php if ($mode === 'menu_items'): ?>
    <?php if ($canAdd): ?>
        <li><hr class="dropdown-divider"></li>
        <?php foreach ($types as $type => $meta): ?>
            <li>
                <a class="dropdown-item justify-content-start" href="#"
                   onclick="event.preventDefault(); openModal('<?= $addUrl($type) ?>');">
                    <i class="<?= h($meta['icon']) ?> me-2 text-<?= h($meta['color']) ?>"></i>
                    <?= h($meta['label']) ?>
                </a>
            </li>
        <?php endforeach; ?>
    <?php endif; ?>
    <?php if ($showView): ?>
        <li>
            <a class="dropdown-item justify-content-start" href="#"
               onclick="event.preventDefault(); openModal('<?= $viewUrl ?>');">
                <i class="fas fa-eye me-2 text-secondary"></i>
                <?= __('View analyst data') ?>
            </a>
        </li>
    <?php endif; ?>

<?php else: ?>
    <div class="dropdown d-inline-block">
        <button class="btn btn-sm btn-outline-analystData dropdown-toggle" type="button"
                data-bs-toggle="dropdown" aria-expanded="false">
            <i class="fas fa-comment-dots me-1"></i><?= __('Analyst data') ?>
        </button>
        <ul class="dropdown-menu dropdown-menu-end shadow-sm">
            <?php if ($canAdd): ?>
                <?php foreach ($types as $type => $meta): ?>
                    <li>
                        <a class="dropdown-item justify-content-start" href="#"
                           onclick="event.preventDefault(); openModal('<?= $addUrl($type) ?>');">
                            <i class="<?= h($meta['icon']) ?> me-2 text-<?= h($meta['color']) ?>"></i>
                            <?= h($meta['label']) ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            <?php endif; ?>
            <?php if ($showView): ?>
                <?php if ($canAdd): ?><li><hr class="dropdown-divider"></li><?php endif; ?>
                <li>
                    <a class="dropdown-item justify-content-start" href="#"
                       onclick="event.preventDefault(); openModal('<?= $viewUrl ?>');">
                        <i class="fas fa-eye me-2 text-secondary"></i>
                        <?= h($viewLabel) ?>
                    </a>
                </li>
            <?php endif; ?>
        </ul>
    </div>
<?php endif; ?>
