<?php
$event = $data['Event'] ?? [];
$orgc = $data['Orgc'] ?? [];
$org = $data['Org'] ?? [];
$sg = $data['SharingGroup'] ?? [];
$distribution = (int)($event['distribution'] ?? 0);
$markings = $overviewMarkings ?? ['declared' => [], 'present' => [], 'absent' => []];

$meta = [];
$flagIcons = '';
foreach ([
    'protected' => ['fas fa-shield-alt', 'text-primary', __('Protected: only signatories can update this event through synchronisation')],
    'disable_correlation' => ['fas fa-unlink', 'text-warning-emphasis', __('Correlation disabled: attributes of this event are not correlated with other events')],
] as $field => [$icon, $colour, $label]) {
    if (empty($event[$field])) {
        continue;
    }
    $flagIcons .= sprintf(
        '<span class="focus-ring rounded-1 d-inline-flex align-items-center justify-content-center %s"'
        . ' style="width:1.5rem; height:1.5rem; cursor:help;" tabindex="0" role="img" title="%s" aria-label="%s">'
        . '<i class="%s" aria-hidden="true"></i></span>',
        $colour,
        h($label),
        h($label),
        $icon
    );
}
if ($flagIcons !== '') {
    $meta[] = '<span class="d-inline-flex align-items-center gap-1 border-start ps-2">' . $flagIcons . '</span>';
}

$isExtending = !empty($extending);
$children = $event['ExtendedBy'] ?? [];
$childIds = array_map('intval', array_column($children, 'id'));
sort($childIds);
$mergedChildIds = [];
foreach ($extensionEvents ?? [] as $extensionEvent) {
    if ($extensionEvent['role'] === 'extension' && in_array((int)$extensionEvent['id'], $childIds, true)) {
        $mergedChildIds[] = (int)$extensionEvent['id'];
    }
}
sort($mergedChildIds);

// Every child merged is `extended:1`, so a child added later joins the view too.
$modeUrl = function (array $mergedChildren, $extendingOn) use ($baseurl, $event, $childIds) {
    sort($mergedChildren);
    if (empty($mergedChildren)) {
        $extendedPart = '';
    } elseif ($mergedChildren === $childIds) {
        $extendedPart = '/extended:1';
    } else {
        $extendedPart = '/extendedIds:' . implode(',', $mergedChildren);
    }
    return $baseurl . '/events/view/' . (int)($event['id'] ?? 0)
        . $extendedPart . ($extendingOn ? '/extending:1' : '');
};
// The menus are spans: the header may print this inside a <p>.
$extTrigger = function ($icon, $label, $title, $on) {
    return sprintf(
        '<button type="button" class="eo-ext-rel rounded dropdown-toggle%s" data-bs-toggle="dropdown"'
        . ' aria-expanded="false" title="%s">%s%s</button>',
        $on ? ' text-primary bg-primary-subtle' : '',
        h($title),
        $icon,
        $label
    );
};
$extMenuRow = function (array $related, $merged, $toggleUrl) use ($baseurl) {
    $relatedId = (int)$related['id'];
    return sprintf(
        '<span class="d-flex align-items-center">'
        . '<a class="dropdown-item eo-ext-item min-w-0" href="%s" role="menuitemcheckbox" aria-checked="%s"'
        . ' title="%s" data-eo-keep-tab><i class="%s"></i><span class="eo-ext-id">#%d</span>'
        . '<span class="eo-ext-info">%s</span><span class="eo-muted">%s</span></a>'
        . '<a class="px-2 text-body-secondary" href="%s/events/view/%d" title="%s" aria-label="%s">'
        . '<i class="fas fa-arrow-up-right-from-square"></i></a></span>',
        h($toggleUrl),
        $merged ? 'true' : 'false',
        h($merged ? __('Remove from this view') : __('Merge into this view')),
        $merged ? 'fas fa-square-check text-primary' : 'far fa-square',
        $relatedId,
        h($related['info']),
        h($related['Orgc']['name'] ?? ''),
        h($baseurl),
        $relatedId,
        h(__('Open event #%s', $relatedId)),
        h(__('Open event #%s', $relatedId))
    );
};
$extMenuHeader = function ($text) {
    return '<span class="dropdown-header d-block">' . h($text) . '</span>';
};

if (!empty($children)) {
    $rows = $extMenuHeader(__('Extended by — tick to merge into this view'));
    foreach ($children as $child) {
        $childId = (int)$child['id'];
        $merged = in_array($childId, $mergedChildIds, true);
        $rows .= $extMenuRow($child, $merged, $modeUrl(
            $merged ? array_diff($mergedChildIds, [$childId]) : array_merge($mergedChildIds, [$childId]),
            $isExtending
        ));
    }
    if (count($children) > 1) {
        $rows .= '<span class="dropdown-divider d-block"></span>'
            . '<span class="d-flex gap-3 px-3 py-1 small">'
            . '<a href="' . h($modeUrl($childIds, $isExtending)) . '" data-eo-keep-tab>' . h(__('Merge all')) . '</a>'
            . '<a href="' . h($modeUrl([], $isExtending)) . '" data-eo-keep-tab>' . h(__('Merge none')) . '</a>'
            . '</span>';
    }
    if (count($children) === 1) {
        $label = '<span class="eo-ext-info">' . h($children[0]['info']) . '</span>';
        $title = __('Extended by #%s %s', $children[0]['id'], $children[0]['info']);
    } else {
        $label = h(__n('Extended by %s event', 'Extended by %s events', count($children), count($children)));
        $title = __('Extended by %s events', count($children));
    }
    if (!empty($mergedChildIds)) {
        $title .= "\n" . __('%s of %s merged into this view', count($mergedChildIds), count($children));
    }
    $meta[] = '<span class="eo-ext border rounded dropdown">'
        . $extTrigger('<i class="fas fa-code-branch"></i>', $label, $title, !empty($mergedChildIds))
        . '<span class="dropdown-menu eo-ext-menu">' . $rows . '</span></span>';
}
if (!empty($event['Extends']) && is_array($event['Extends'])) {
    $parent = $event['Extends'];
    $title = __('Extends #%s %s', $parent['id'], $parent['info']);
    if ($isExtending) {
        $title .= "\n" . __('Merged into this view');
    }
    $meta[] = '<span class="eo-ext border rounded dropdown">'
        . $extTrigger(
            '<i class="fas fa-code-merge"></i>',
            '<span class="eo-ext-info">' . h($parent['info']) . '</span>',
            $title,
            $isExtending
        )
        . '<span class="dropdown-menu eo-ext-menu">'
        . $extMenuHeader(__('Extends — tick to merge into this view'))
        . $extMenuRow($parent, $isExtending, $modeUrl($mergedChildIds, !$isExtending))
        . '</span></span>';
}
$this->set('headerDescription', '<span class="eo-meta">' . implode('', $meta) . '</span>');

$logo = $this->OrgImg->getOrgLogoV2($orgc, 28);
$ownerDiffers = !empty($org['id']) && (int)$org['id'] !== (int)($orgc['id'] ?? 0);
?>
<?= $this->OrgGrade->config($orgGrading ?? null) ?>
<div class="card shadow-sm mb-3 eo-band" data-tour="event-general">
    <div class="eo-band-cell eo-band-org">
        <div class="eo-org-tile<?= $this->OrgGrade->enabled($orgGrading ?? null) ? ' og-mark is-tile' : '' ?>">
            <?= $logo !== '' ? $logo : '<i class="misp-icon misp-icon-organisation misp-simple"></i>' ?>
            <?= $this->OrgGrade->badge($orgc, $orgGrading ?? null, 'large') ?>
        </div>
        <div class="min-w-0">
            <a class="eo-org-name text-truncate" href="<?= h($baseurl . '/organisations/view/' . ($orgc['id'] ?? '')) ?>"><?= h($orgc['name'] ?? '') ?></a>
            <?php if ($ownerDiffers): ?>
                <div class="eo-org-held text-truncate">
                    <?= __(
                        'held here by %s',
                        sprintf('<a href="%s">%s</a>', h($baseurl . '/organisations/view/' . (int)$org['id']), h($org['name'] ?? ''))
                    ) ?>
                </div>
            <?php endif; ?>
            <?php if (!empty($data['User']['email'])): ?>
                <div class="eo-org-held text-truncate" title="<?= h(__('Event creator')) ?>">
                    <i class="misp-icon misp-icon-user1 misp-simple"></i><?= h($data['User']['email']) ?>
                </div>
            <?php endif; ?>
        </div>
        <?php if (!empty($contributors)): ?>
            <?php $contribLabel = __n('%s contributing organisation', '%s contributing organisations', count($contributors), count($contributors)); ?>
            <div class="dropdown eo-contrib">
                <button type="button" class="btn btn-sm eo-contrib-toggle" data-bs-toggle="dropdown" aria-expanded="false"
                        title="<?= h($contribLabel) ?>" aria-label="<?= h($contribLabel) ?>">
                    <span class="eo-contrib-stack">
                        <?php foreach (array_slice($contributors, 0, 3, true) as $contribId => $contribName): ?>
                            <?php $contribLogo = $this->OrgImg->getOrgLogoV2(['id' => $contribId, 'name' => $contribName], 20, false); ?>
                            <span class="eo-contrib-avatar"><?= $contribLogo !== '' ? $contribLogo : h(strtoupper(preg_match('/^./u', $contribName, $initial) ? $initial[0] : '?')) ?></span>
                        <?php endforeach; ?>
                    </span>
                    <span class="eo-contrib-count"><?= count($contributors) ?></span>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <li><h6 class="dropdown-header"><?= __('Contributors') ?></h6></li>
                    <li><p class="px-3 mb-1 small text-muted"><?= __('Organisations that proposed changes to this event.') ?></p></li>
                    <?php foreach ($contributors as $contribId => $contribName): ?>
                        <li>
                            <a class="dropdown-item d-flex align-items-center gap-2" href="<?= h($baseurl . '/organisations/view/' . (int)$contribId) ?>">
                                <i class="misp-icon misp-icon-organisation misp-simple text-muted"></i><?= h($contribName) ?>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>

    <div class="eo-band-cell eo-band-dist">
        <div class="eo-band-label"><?= __('Distribution') ?></div>
        <div class="d-flex align-items-center gap-2 flex-wrap">
            <?= $this->element('genericElementsBS5/Badges/distribution', [
                'distribution' => $distribution,
                'full' => true,
            ]) ?>
            <?php if ($distribution === 4 && !empty($sg)): ?>
                <a class="eo-sg text-truncate" href="<?= h($baseurl . '/sharingGroups/view/' . ($sg['id'] ?? '')) ?>">
                    <span class="misp-icon misp-icon-sharing-group misp-simple"></span><?= h($sg['name'] ?? '') ?>
                </a>
                <?php if ($sharingGroupOrgCount !== null): ?>
                    <span class="eo-muted"><?= h(__n('%s org', '%s orgs', $sharingGroupOrgCount, $sharingGroupOrgCount)) ?></span>
                <?php endif; ?>
            <?php endif; ?>
            <a href="#" class="btn btn-sm btn-outline-secondary eo-narrower d-none" data-eo-narrower
               data-eo-label-one="<?= h(__('%s indicator shared more narrowly')) ?>"
               data-eo-label-many="<?= h(__('%s indicators shared more narrowly')) ?>"></a>
        </div>
    </div>

    <?php if (!empty($markings['declared'])): ?>
        <div class="eo-band-cell eo-band-marking">
            <div class="eo-band-label"><?= __('Marking') ?></div>
            <div class="d-flex align-items-center gap-1 flex-wrap">
                <?php foreach ($markings['present'] as $item): ?>
                    <?= $this->TagChip->chip($item['tag'], [
                        'searchUrl' => '',
                        'inline' => true,
                    ]) ?>
                    <?= $this->element('Events/View/extension_origin', [
                        'event_id' => $item['tag']['event_id'] ?? 0,
                        'compact' => true,
                        'only_foreign' => true,
                    ]) ?>
                <?php endforeach; ?>
                <?php foreach ($markings['absent'] as $missing): ?>
                    <span class="eo-absent" title="<?= h(__('Pinned by your analyst profile, not on this event')) ?>">
                        <i class="fas fa-thumbtack"></i><?= h($missing['key']) ?>
                    </span>
                <?php endforeach; ?>
                <?php if (empty($markings['present']) && empty($markings['absent'])): ?>
                    <span class="eo-muted"><?= __('None') ?></span>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
</div>
