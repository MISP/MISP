<?php
$event = $data['Event'] ?? [];
$orgc = $data['Orgc'] ?? [];
$org = $data['Org'] ?? [];
$sg = $data['SharingGroup'] ?? [];
$distribution = (int)($event['distribution'] ?? 0);
$markings = $overviewMarkings ?? ['declared' => [], 'present' => [], 'absent' => []];

$meta = [];
$meta[] = sprintf(
    '<span class="eo-uuid font-monospace" title="%s">%s'
    . '<button type="button" class="eo-copy" onclick="copyToClipboard(this, \'%s\')" title="%s" aria-label="%s">'
    . '<i class="fas fa-copy"></i></button></span>',
    h($event['uuid'] ?? ''),
    h(substr($event['uuid'] ?? '', 0, 8)),
    h($event['uuid'] ?? ''),
    __('Copy UUID'),
    __('Copy UUID')
);
if (!empty($event['date'])) {
    $meta[] = '<span title="' . __('Event date') . '"><i class="fas fa-calendar-day me-1 opacity-50"></i>' . h($event['date']) . '</span>';
}
if (!empty($event['timestamp'])) {
    $meta[] = '<span title="' . __('Last modified') . '"><i class="fas fa-edit me-1 opacity-50"></i>' . $this->Time->time($event['timestamp']) . '</span>';
}
if (!empty($event['published']) && !empty($event['publish_timestamp'])) {
    $meta[] = '<span title="' . __('Last published') . '"><i class="fas fa-paper-plane me-1 opacity-50"></i>' . $this->Time->time($event['publish_timestamp']) . '</span>';
}
if (!empty($event['protected'])) {
    $meta[] = '<span class="eo-flag" title="' . __('Protected events can only be updated by signatories') . '"><i class="fas fa-shield-alt"></i>' . __('Protected') . '</span>';
}
if (!empty($event['disable_correlation'])) {
    $meta[] = '<span class="eo-flag"><i class="fas fa-unlink"></i>' . __('Correlation disabled') . '</span>';
}
$isExtended = !empty($extended);
$isExtending = !empty($extending);
$modeUrl = function ($extendedOn, $extendingOn) use ($baseurl, $event) {
    return $baseurl . '/events/view2/' . (int)($event['id'] ?? 0)
        . ($extendedOn ? '/extended:1' : '')
        . ($extendingOn ? '/extending:1' : '');
};
$extSwitch = function ($on, $url, $label, $title) {
    return sprintf(
        '<a class="eo-ext-switch%s" href="%s" role="switch" aria-checked="%s" title="%s" data-eo-keep-tab>'
        . '<span class="eo-ext-knob"></span>%s</a>',
        $on ? ' is-on' : '',
        h($url),
        $on ? 'true' : 'false',
        h($title),
        h($label)
    );
};
$extEventLink = function (array $related, $class, $prefix, $suffix = '') use ($baseurl) {
    $orgName = $related['Orgc']['name'] ?? '';
    return sprintf(
        '<a class="%s" href="%s/events/view2/%d" title="%s">%s'
        . '<span class="eo-ext-id">#%d</span><span class="eo-ext-info">%s</span>%s</a>',
        $class,
        h($baseurl),
        (int)$related['id'],
        h($orgName === '' ? $related['info'] : $orgName . ' — ' . $related['info']),
        $prefix,
        (int)$related['id'],
        h($related['info']),
        $suffix
    );
};

$children = $event['ExtendedBy'] ?? [];
if (!empty($children)) {
    $childIcon = '<i class="fas fa-code-branch"></i>';
    if (count($children) === 1) {
        $relation = $extEventLink($children[0], 'eo-ext-rel', $childIcon . h(__('Extended by')));
    } else {
        $items = '';
        foreach ($children as $child) {
            $items .= $extEventLink(
                $child,
                'dropdown-item eo-ext-item',
                '',
                '<span class="eo-muted">' . h($child['Orgc']['name'] ?? '') . '</span>'
            );
        }
        $relation = '<button type="button" class="eo-ext-rel dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">'
            . $childIcon . h(__n('Extended by %s event', 'Extended by %s events', count($children), count($children)))
            . '</button><span class="dropdown-menu eo-ext-menu">' . $items . '</span>';
    }
    $meta[] = '<span class="eo-ext dropdown">' . $relation . $extSwitch(
        $isExtended,
        $modeUrl(!$isExtended, $isExtending),
        __('Extended view'),
        $isExtended
            ? __('Stop merging in the events that extend this one')
            : __n('Merge in the event that extends this one', 'Merge in the %s events that extend this one', count($children), count($children))
    ) . '</span>';
}
if (!empty($event['Extends']) && is_array($event['Extends'])) {
    $meta[] = '<span class="eo-ext">'
        . $extEventLink($event['Extends'], 'eo-ext-rel', '<i class="fas fa-code-merge"></i>' . h(__('Extends')))
        . $extSwitch(
            $isExtending,
            $modeUrl($isExtended, !$isExtending),
            __('Extending view'),
            $isExtending
                ? __('Stop merging in the event this one extends')
                : __('Merge in the event this one extends')
        ) . '</span>';
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
