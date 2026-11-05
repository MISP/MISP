<?php
/*
 * The sightings of an attribute, several attributes or an event: a summary,
 * then a journal, a timeline and, for an attribute, the add form, each a tab.
 * SightingsController::advanced() hands over the sightings already through
 * the sightings policy, their summary and timeline (SightingDigestTool), the
 * attributes they are about and the event.
 */
echo $this->element('genericElements/assetLoader', ['css' => ['sightings-modal']]);

App::uses('EventCardTool', 'Tools/EventOverview');

$isEvent = $context === 'event';
$canAdd = !$isEvent && !empty($isAclSighting);
$uid = 'sightingAdv' . substr(md5($id . $context), 0, 8);
$myOrgId = (int)$me['org_id'];
$now = time();
// The journal shows the latest; the summary and the timeline count them all.
$journalCap = 250;
$kinds = [
    0 => ['s', 'fas fa-thumbs-up', __('Sighting')],
    1 => ['f', 'fas fa-thumbs-down', __('False positive')],
    2 => ['e', 'fas fa-clock', __('Expiration')],
];

$single = !$isEvent && count($attributes) === 1 ? reset($attributes) : null;
$eventIds = array_unique(Hash::extract($attributes, '{n}.Event.id'));

// The header names what was sighted: the value, the event or the count.
if ($single !== null) {
    $eyebrow = __('Sightings · Attribute #%s', $single['Attribute']['id']);
    $titleHtml = '<span class="sg-subject" title="' . h($single['Attribute']['value']) . '">'
        . h($single['Attribute']['value']) . '</span>';
    $titleBadge = $this->element('genericElementsBS5/Badges/type', ['type' => $single['Attribute']['type']]);
} elseif ($isEvent) {
    $eyebrow = __('Sightings · Event #%s', $event['id']);
    $titleHtml = '<span class="sg-subject is-text">' . h($event['info']) . '</span>';
    $titleBadge = '';
} else {
    $eyebrow = __('Sightings');
    $titleHtml = h(__('%s attributes', count($attributes)));
    $titleBadge = '';
}
$subline = [];
if (!$isEvent && count($eventIds) === 1 && !empty($event['id'])) {
    $subline[] = sprintf(
        '<a class="sg-event" href="%s"><span class="ev-peek" aria-hidden="true"><i class="misp-icon misp-icon-event misp-simple"></i></span>'
            . '<span class="sg-event-id">#%d</span>%s</a>',
        h($baseurl . '/events/view/' . (int)$event['id']),
        (int)$event['id'],
        h($event['info'] ?? '')
    );
}
if ($single !== null && !empty($single['Attribute']['category'])) {
    $subline[] = h($single['Attribute']['category']);
}
if ($isEvent && !empty($event['date'])) {
    $subline[] = h(date('j M Y', strtotime($event['date'])));
}

// The organisations that sighted, for the summary's tiles.
$orgs = [];
foreach ($sightings as $sighting) {
    $orgs[(int)$sighting['Sighting']['org_id']] = (string)($sighting['Organisation']['name'] ?? '');
}
$orgTile = function ($orgId, $name, $size) {
    if ($name === '') {
        return '<span class="dk-logo is-mono sg-anon" title="' . h(__('Anonymised')) . '"><i class="fas fa-user-secret"></i></span>';
    }
    return $this->EventIndex->orgTile(['id' => $orgId, 'name' => $name], $size);
};
$tile = function ($label, $value, array $mods = [], $sub = '') {
    return sprintf(
        '<div class="sg-tile%s"><span class="sg-tile-label">%s</span><span class="sg-tile-value">%s</span>%s</div>',
        implode('', array_map(function ($mod) { return ' is-' . $mod; }, $mods)),
        h($label),
        $value,
        $sub === '' ? '' : '<span class="sg-tile-sub">' . $sub . '</span>'
    );
};
$count = function ($type) use ($summary, $kinds) {
    $n = (int)$summary['counts'][$type];
    return '<i class="' . $kinds[$type][1] . '"></i>' . $n;
};
?>
<div id="<?= $uid ?>" class="sg-modal">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'sighting',
        'eyebrow' => h($eyebrow),
        'title' => $titleHtml,
        'titleBadge' => $titleBadge,
        'titleIcon' => '',
        'description' => implode('<span class="sg-sep">·</span>', $subline),
        'descriptionClass' => 'sg-subline',
        'escape' => false,
        'close' => true,
    ]) ?>

    <div class="sg-tiles">
        <?php foreach ([0 => __('Sightings'), 1 => __('False positives'), 2 => __('Expirations')] as $type => $label): ?>
            <?= $tile($label, $count($type), $summary['counts'][$type] ? [$kinds[$type][0]] : [$kinds[$type][0], 'zero']) ?>
        <?php endforeach; ?>
        <?= $summary['last'] === null
            ? $tile(__('Last seen'), '&mdash;', ['small', 'zero'])
            : $tile(
                __('Last seen'),
                h(EventCardTool::ago($summary['last'], $now)),
                ['small'],
                h(gmdate('j M Y · H:i', $summary['last'])) . ' UTC'
            ) ?>
        <?php
        $orgTiles = '';
        foreach (array_slice($orgs, 0, 5, true) as $orgId => $name) {
            $orgTiles .= $orgTile($orgId, $name, 20);
        }
        if (count($orgs) > 5) {
            $orgTiles .= '<span class="sg-more">+' . (count($orgs) - 5) . '</span>';
        }
        ?>
        <?= $tile(__('Organisations'), (string)$summary['orgs'] . '<span class="sg-orgs">' . $orgTiles . '</span>', $summary['orgs'] ? ['small'] : ['small', 'zero']) ?>
    </div>

    <ul class="nav ov-view-tabs is-inline" role="tablist"
        style="--ov-view-tab-accent: var(--bs-sighting); --ov-view-tab-accent-bg: color-mix(in srgb, var(--bs-sighting) 12%, transparent);">
        <li class="nav-item" role="presentation">
            <button type="button" role="tab" class="nav-view nav-link active" data-sighting-tab="journal" aria-selected="true">
                <i class="fas fa-list"></i><span><?= __('Journal') ?></span>
                <span class="ov-tab-count"><?= h(number_format($summary['total'])) ?></span>
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button type="button" role="tab" class="nav-view nav-link" data-sighting-tab="timeline" aria-selected="false">
                <i class="fas fa-chart-column"></i><span><?= __('Timeline') ?></span>
            </button>
        </li>
        <?php if ($canAdd): ?>
        <li class="nav-item" role="presentation">
            <button type="button" role="tab" class="nav-view nav-link" data-sighting-tab="add" aria-selected="false">
                <i class="fas fa-plus"></i><span><?= __('Add sighting') ?></span>
            </button>
        </li>
        <?php endif; ?>
        <?php if ($summary['total'] > 0): ?>
        <li class="sg-scope" data-sighting-scope role="group" aria-label="<?= __('Whose sightings') ?>">
            <input type="radio" class="btn-check" name="<?= $uid ?>-scope" id="<?= $uid ?>-all" value="all" checked>
            <label class="btn btn-sm" for="<?= $uid ?>-all"><?= __('All') ?> <b><?= (int)$summary['total'] ?></b></label>
            <input type="radio" class="btn-check" name="<?= $uid ?>-scope" id="<?= $uid ?>-mine" value="mine">
            <label class="btn btn-sm" for="<?= $uid ?>-mine"><?= __('My organisation') ?> <b><?= (int)$summary['mine'] ?></b></label>
        </li>
        <?php endif; ?>
    </ul>

    <div data-sighting-pane="journal" class="sg-pane">
        <?php if (empty($sightings)): ?>
            <div class="sg-empty">
                <i class="misp-icon misp-icon-sighting misp-simple"></i>
                <span><?= $isEvent ? __('No attribute of this event has been sighted yet.') : __('Nobody has sighted this yet.') ?></span>
                <?php if ($canAdd): ?>
                    <button type="button" class="btn btn-sm btn-sighting" data-sighting-tab="add">
                        <i class="fas fa-plus me-1"></i><?= __('Add the first sighting') ?>
                    </button>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <table class="table ix-table sg-journal mb-0">
                <thead>
                    <tr>
                        <th><?= __('Type') ?></th>
                        <th><?= __('When (UTC)') ?></th>
                        <?php if ($single === null): ?><th><?= __('Attribute') ?></th><?php endif; ?>
                        <th><?= __('Organisation') ?></th>
                        <th><?= __('Source') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_slice($sightings, 0, $journalCap) as $sighting):
                        $row = $sighting['Sighting'];
                        list($key, $icon, $label) = $kinds[(int)$row['type']] ?? ['s', 'fas fa-question', (string)$row['type']];
                        $orgName = (string)($sighting['Organisation']['name'] ?? '');
                        $attr = $attributes[$row['attribute_id']]['Attribute'] ?? null;
                    ?>
                    <tr data-mine="<?= (int)$row['org_id'] === $myOrgId ? '1' : '0' ?>">
                        <td><span class="sg-kind is-<?= $key ?>"><i class="<?= $icon ?>"></i><?= h($label) ?></span></td>
                        <td>
                            <span class="sg-when"><?= h(gmdate('Y-m-d H:i:s', (int)$row['date_sighting'])) ?></span>
                            <span class="sg-ago"><?= h(EventCardTool::ago((int)$row['date_sighting'], $now)) ?></span>
                        </td>
                        <?php if ($single === null): ?>
                            <td class="sg-attr">
                                <?php if ($attr !== null): ?>
                                    <span class="sg-attr-line">
                                        <span class="sg-attr-value" title="<?= h($attr['value']) ?>"><?= h($attr['value']) ?></span>
                                        <?= $this->element('genericElementsBS5/Badges/type', ['type' => $attr['type']]) ?>
                                    </span>
                                <?php else: ?>
                                    <span class="sg-quiet">#<?= h($row['attribute_id']) ?></span>
                                <?php endif; ?>
                            </td>
                        <?php endif; ?>
                        <td>
                            <span class="sg-org">
                                <?= $orgTile((int)$row['org_id'], $orgName, 20) ?>
                                <span><?= $orgName === '' ? '<span class="sg-quiet">' . __('Anonymised') . '</span>' : h($orgName) ?></span>
                            </span>
                        </td>
                        <td class="sg-source"><?= $row['source'] === '' || $row['source'] === null ? '<span class="sg-quiet">&mdash;</span>' : h($row['source']) ?></td>
                        <td class="text-end">
                            <?php if ($this->Acl->canDeleteSighting($sighting)): ?>
                                <button type="button" class="btn sg-delete" data-sighting-delete="<?= h($row['id']) ?>"
                                        data-raw-id="<?= h($id) ?>" title="<?= __('Delete sighting') ?>" aria-label="<?= __('Delete sighting') ?>">
                                    <i class="fas fa-trash-can"></i>
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <div class="sg-empty is-mine d-none" data-sighting-mine-empty>
                <span><?= __('Your organisation has not sighted this.') ?></span>
            </div>
        <?php endif; ?>
    </div>

    <div data-sighting-pane="timeline" class="sg-pane d-none">
        <?php if ($timeline === null): ?>
            <div class="sg-empty"><span><?= __('Nothing to draw yet.') ?></span></div>
        <?php else:
            $size = $timeline['size'];
            $bins = $timeline['bins'];
            $binCount = count($bins);
            $start = $timeline['start'];
            $end = $start + $binCount * $size;
            $format = $size < 86400 ? 'H:i' : ($size < 2592000 ? 'j M' : 'M Y');
            $units = [
                60 => __('1-minute bins'), 300 => __('5-minute bins'), 900 => __('15-minute bins'),
                3600 => __('1-hour bins'), 21600 => __('6-hour bins'), 86400 => __('1-day bins'),
                604800 => __('1-week bins'), 2592000 => __('30-day bins'), 31536000 => __('1-year bins'),
            ];
            $range = gmdate('Y-m-d', $start) === gmdate('Y-m-d', $end - 1)
                ? gmdate('j M Y · H:i', $start) . ' → ' . gmdate('H:i', $end) . ' UTC'
                : gmdate($size < 86400 ? 'j M Y H:i' : 'j M Y', $start) . ' → ' . gmdate($size < 86400 ? 'j M Y H:i' : 'j M Y', $end) . ' UTC';
            $every = max(1, (int)ceil($binCount / 8));
            $max = max(1, $timeline['max']);
        ?>
            <div class="sg-timeline" style="--sg-bins: <?= $binCount ?>;">
                <div class="sg-timeline-head">
                    <span><?= h($range) ?> · <?= h($units[$size] ?? '') ?></span>
                    <span class="sg-legend">
                        <?php foreach ($kinds as $type => list($key, $icon, $label)): ?>
                            <span class="is-<?= $key ?>"><?= h($label) ?></span>
                        <?php endforeach; ?>
                    </span>
                </div>
                <div class="sg-bars">
                    <?php foreach ($bins as $i => $counts):
                        $total = array_sum($counts);
                        $from = $start + $i * $size;
                        $parts = [];
                        foreach ($kinds as $type => list($key, $icon, $label)) {
                            if ($counts[$type] > 0) {
                                $parts[] = $counts[$type] . ' ' . mb_strtolower($label);
                            }
                        }
                        $binTitle = gmdate($format, $from) . ' – ' . gmdate($format, $from + $size) . ' · '
                            . ($parts ? implode(', ', $parts) : __('none'));
                    ?>
                        <div class="sg-bin" title="<?= h($binTitle) ?>">
                            <?php if ($total > 0 && $binCount <= 24): ?><span class="sg-bin-n"><?= $total ?></span><?php endif; ?>
                            <?php foreach ([2, 1, 0] as $type): ?>
                                <?php if ($counts[$type] > 0): ?>
                                    <span class="sg-bar is-<?= $kinds[$type][0] ?>" style="height: <?= round($counts[$type] / $max * 85, 2) ?>%;"></span>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="sg-axis">
                    <?php foreach ($bins as $i => $counts): ?>
                        <span><?= $i % $every === 0 ? h(gmdate($format, $start + $i * $size)) : '' ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <div class="px-4 pb-3" data-sighting-foot>
        <?= $this->element('genericElementsBS5/Forms/modal_footer', [
            'accent' => 'sighting',
            'hint' => $summary['total'] > $journalCap
                ? __('The journal shows the latest %s of %s sightings. Times are in UTC.', $journalCap, number_format($summary['total']))
                : __('Times are in UTC.'),
            'cancel' => ['label' => __('Close')],
            'submit' => false,
        ]) ?>
    </div>

    <?php if ($canAdd): ?>
    <div data-sighting-pane="add" class="d-none">
        <?= $this->Form->create('Sighting', [
            'url' => $baseurl . '/sightings/add/' . h($id),
            'novalidate' => true,
        ]) ?>
        <div class="d-flex flex-column gap-4 px-4 py-3">
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'sighting',
                    'label' => __('Type'),
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                    'field' => 'Sighting.type',
                    'accent' => 'sighting',
                    'value' => 0,
                    'ariaLabel' => __('Sighting type'),
                    'options' => [
                        ['value' => 0, 'title' => __('Sighting'), 'sub' => __('Seen in the wild'), 'icon' => 'fas fa-thumbs-up', 'tone' => 'var(--bs-success)'],
                        ['value' => 1, 'title' => __('False positive'), 'sub' => __('Seen, but benign'), 'icon' => 'fas fa-thumbs-down', 'tone' => 'var(--bs-danger)'],
                        ['value' => 2, 'title' => __('Expiration'), 'sub' => __('No longer valid from this date'), 'icon' => 'fas fa-clock', 'tone' => 'var(--bs-warning)'],
                    ],
                ]) ?>
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'sighting',
                        'label' => __('Source'),
                        'for' => 'SightingSource',
                    ]) ?>
                    <?= $this->Form->text('source', [
                        'class' => 'form-control',
                        'placeholder' => __('honeypot, IDS sensor id, SIEM…'),
                    ]) ?>
                </div>
                <div class="col-md-6">
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'sighting',
                        'label' => __('Date'),
                        'required' => true,
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/date_field', [
                        'field' => 'Sighting.datetime',
                        'mode' => 'datetime',
                        'accent' => 'sighting',
                        'value' => gmdate('Y-m-d H:i:s'),
                        'required' => true,
                    ]) ?>
                </div>
            </div>
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'Sighting.filters',
                'label' => __('Filters'),
                'accent' => 'sighting',
                'shape' => 'object',
                'rows' => 4,
                'minHeight' => '110px',
                'gutter' => false,
                'placeholder' => '{ "to_ids": 1, "tags": ["tlp:white"] }',
                'hint' => __('Optional. Only the attributes matching these restSearch filters are sighted.'),
            ]) ?>
        </div>
        <div class="px-4 pb-3">
            <?= $this->element('genericElementsBS5/Forms/modal_footer', [
                'accent' => 'sighting',
                'hint' => __('Recorded for your organisation.'),
                'cancel' => ['label' => __('Close')],
                'submit' => ['label' => __('Add sighting'), 'icon' => 'fas fa-plus'],
            ]) ?>
        </div>
        <?= $this->Form->end() ?>
    </div>
    <?php endif; ?>
</div>

<script>
(function () {
    var root = document.getElementById(<?= json_encode($uid) ?>);
    var foot = root.querySelector('[data-sighting-foot]');
    var scope = root.querySelector('[data-sighting-scope]');
    var addPane = root.querySelector('[data-sighting-pane="add"]');
    var msg = {
        requestFailed: <?= json_encode(__('Request failed, please try again.')) ?>,
        deleted: <?= json_encode(__('Sighting deleted.')) ?>,
        confirm: <?= json_encode(__('Delete this sighting?')) ?>,
        yes: <?= json_encode(__('Delete')) ?>,
        no: <?= json_encode(__('Cancel')) ?>
    };

    function show(key) {
        root.querySelectorAll('.nav-view[data-sighting-tab]').forEach(function (el) {
            var on = el.dataset.sightingTab === key;
            el.classList.toggle('active', on);
            el.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        root.querySelectorAll('[data-sighting-pane]').forEach(function (pane) {
            pane.classList.toggle('d-none', pane.dataset.sightingPane !== key);
        });
        foot.classList.toggle('d-none', key === 'add');
        if (scope) scope.classList.toggle('invisible', key !== 'journal');
    }

    // Counts, journal and timeline all change: draw the modal again.
    function changed(detail) {
        notifySightingChange(detail);
        if (typeof reloadEventViewIndexTab === 'function') reloadEventViewIndexTab();
        openSightingDetails(<?= json_encode((string)$id) ?>, <?= json_encode($context) ?>);
    }

    if (scope) {
        scope.addEventListener('change', function (e) {
            var mine = e.target.value === 'mine';
            var shown = 0;
            root.querySelectorAll('.sg-journal tbody tr').forEach(function (tr) {
                var hide = mine && tr.dataset.mine !== '1';
                tr.classList.toggle('d-none', hide);
                if (!hide) shown++;
            });
            root.querySelector('[data-sighting-mine-empty]').classList.toggle('d-none', shown > 0);
        });
    }

    root.addEventListener('click', function (e) {
        var tab = e.target.closest('[data-sighting-tab]');
        if (tab) {
            e.preventDefault();
            show(tab.dataset.sightingTab);
            return;
        }

        var del = e.target.closest('[data-sighting-delete]');
        if (del) {
            e.preventDefault();
            var cell = del.closest('td');
            cell.dataset.original = cell.innerHTML;
            cell.innerHTML = '<span class="d-inline-flex align-items-center gap-1 small text-nowrap">'
                + msg.confirm
                + ' <button type="button" class="btn btn-danger btn-sm py-0" data-sighting-confirm="'
                + del.dataset.sightingDelete + '" data-raw-id="' + escapeHtml(del.dataset.rawId)
                + '">' + msg.yes + '</button>'
                + ' <button type="button" class="btn btn-outline-secondary btn-sm py-0" data-sighting-keep>'
                + msg.no + '</button></span>';
            return;
        }

        var keep = e.target.closest('[data-sighting-keep]');
        if (keep) {
            var keepCell = keep.closest('td');
            keepCell.innerHTML = keepCell.dataset.original;
            return;
        }

        var confirmBtn = e.target.closest('[data-sighting-confirm]');
        if (confirmBtn) {
            confirmBtn.disabled = true;
            postSighting(baseurl + '/sightings/quickDelete/' + confirmBtn.dataset.sightingConfirm
                + '/' + encodeURIComponent(confirmBtn.dataset.rawId) + '/' + <?= json_encode($context) ?>, '')
                .then(function (data) {
                    if (!data.saved) {
                        showToast(data.errors || msg.requestFailed, 'danger');
                        confirmBtn.disabled = false;
                        return;
                    }
                    showToast(msg.deleted, 'success');
                    changed({});
                })
                .catch(function () {
                    showToast(msg.requestFailed, 'danger');
                    confirmBtn.disabled = false;
                });
        }
    });

    var form = addPane ? addPane.querySelector('form') : null;
    if (form) {
        form.addEventListener('submit', function (e) {
            if (e.defaultPrevented) return;
            e.preventDefault();
            var submit = form.querySelector('[type="submit"]');
            var fd = new FormData(form);
            var when = fd.get('data[Sighting][datetime]') || '';
            fd.delete('data[Sighting][datetime]');
            var ts = Date.parse(when.replace(' ', 'T') + 'Z');
            if (!isNaN(ts)) fd.set('data[Sighting][timestamp]', Math.floor(ts / 1000));
            if (!(fd.get('data[Sighting][filters]') || '').trim()) fd.delete('data[Sighting][filters]');
            if (submit) submit.disabled = true;
            postSighting(form.getAttribute('action'), new URLSearchParams(fd).toString())
                .then(function (data) {
                    if (!data.saved) {
                        showToast(data.errors || msg.requestFailed, 'danger');
                        return;
                    }
                    showToast(data.success, 'success');
                    changed({ type: fd.get('data[Sighting][type]') });
                })
                .catch(function () {
                    showToast(msg.requestFailed, 'danger');
                })
                .finally(function () {
                    if (submit) submit.disabled = false;
                });
        });
    }
})();
</script>
