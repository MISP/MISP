<?php
/*
 * The overview's Indicator inventory card. `readOnly` draws it for an event
 * held elsewhere: its chips only name what they count.
 */
$readOnly = !empty($readOnly);
// Overmind defines the solid tones for its dark palette only.
$tones = [
    'Network' => 'var(--misp-tone-blue-solid, #0d6efd)',
    'File' => 'var(--misp-tone-orange-solid, #fd7e14)',
    'Host' => 'var(--misp-tone-purple-solid, #6f42c1)',
    'Email' => 'var(--misp-tone-teal-solid, #20c997)',
    'Detection rules' => 'var(--misp-tone-green-solid, #198754)',
    'Other' => 'var(--misp-tone-gray-solid, #6c757d)',
];
$total = (int)$inventory['total'];
$ids = (int)$inventory['ids'];
$inObjects = array_sum(array_column($inventory['groups'], 'in_objects'));
$eventId = (int)($event['Event']['id'] ?? 0);
$canEdit = !$readOnly && $this->Acl->canModifyEvent($event);
// The ways to fill an empty inventory.
$ways = [
    [
        'url' => $baseurl . '/attributes/add/' . $eventId,
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'tone' => 'var(--bs-attribute)',
        'title' => __('Add an attribute'),
        'text' => __('One value: a hash, a domain, an address.'),
    ],
    [
        'url' => $baseurl . '/objects/add/' . $eventId,
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'tone' => 'var(--bs-object)',
        'title' => __('Add an object'),
        'text' => __('Related values as one thing: a file and its hashes.'),
    ],
];
if ($this->Acl->canAccess('events', 'populateFrom')) {
    $ways[] = [
        'url' => $baseurl . '/events/populateFrom/' . $eventId,
        'icon' => 'fas fa-sign-in-alt',
        'tone' => 'var(--bs-primary)',
        'title' => __('Import from…'),
        'text' => __('Paste text and let MISP find the IOCs, or load MISP JSON.'),
    ];
}
$n = function ($value) {
    return number_format((int)$value);
};
$tabFor = function (array $group) {
    return $group['in_objects'] * 2 >= $group['total'] ? 'objects' : 'attributes';
};
// A chip opening its tab filtered to what it counts; a label when read-only.
$chip = function ($class, array $filter, $title, $inner) use ($readOnly) {
    if ($readOnly) {
        return sprintf('<span class="%s"%s>%s</span>', $class, $title === null ? '' : ' title="' . h($title) . '"', $inner);
    }
    $attributes = '';
    foreach ($filter as $name => $value) {
        $attributes .= sprintf(' data-eo-filter-%s="%s"', $name, h($value));
    }
    return sprintf('<button type="button" class="%s"%s title="%s">%s</button>', $class, $attributes, h($title), $inner);
};
?>
<div class="eo-inventory" data-eo-event-id="<?= $eventId ?>">
    <div class="eo-card-head">
        <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-attribute);--tile-bg:color-mix(in srgb, var(--bs-attribute) 12%, transparent);">
            <i class="misp-icon misp-icon-attribute misp-simple"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Indicator inventory') ?></div>
            <div class="eo-card-sub">
                <?= h(__n('%s attribute', '%s attributes', $total, $n($total))) ?>
                <?php if ($inObjects > 0): ?>· <?= h(__('%s in objects', $n($inObjects))) ?><?php endif; ?>
                <?php if ($total > 0): ?>
                    · <span title="<?= h(__('Flagged for detection (to_ids)')) ?>"><i class="fas fa-shield-halved text-warning eo-ids-icon"></i><?= h(__('%s detection-ready', $n($ids))) ?></span>
                <?php endif; ?>
            </div>
        </div>
        <?php if ($total > 0): ?>
            <div class="input-group input-group-sm eo-filter">
                <span class="input-group-text border-end-0"><i class="fas fa-search text-muted small"></i></span>
                <input type="search" class="form-control border-start-0 ps-0" data-eo-type-filter
                       placeholder="<?= h(__('Filter types…')) ?>" aria-label="<?= h(__('Filter attribute types')) ?>" autocomplete="off">
            </div>
        <?php endif; ?>
    </div>

    <?php if ($total === 0 && $canEdit): ?>
        <div class="eo-ways">
            <?php foreach ($ways as $way): ?>
                <a href="<?= h($way['url']) ?>" class="eo-way" style="--eo-way:<?= $way['tone'] ?>;"
                   onclick="event.preventDefault(); openModal('<?= h($way['url']) ?>');">
                    <span class="eo-way-tile"><i class="<?= $way['icon'] ?>"></i></span>
                    <span class="min-w-0">
                        <span class="eo-way-title"><?= h($way['title']) ?></span>
                        <span class="eo-way-text"><?= h($way['text']) ?></span>
                    </span>
                    <i class="fas fa-chevron-right eo-way-go"></i>
                </a>
            <?php endforeach; ?>
        </div>
    <?php elseif ($total === 0): ?>
        <div class="eo-empty"><span><?= __('No attributes on this event yet.') ?></span></div>
    <?php else: ?>
        <?php if (!empty($inventory['objects']['total'])): ?>
            <div class="eo-groups eo-objects-block">
                <div class="eo-group eo-group-objects">
                    <?= $chip('eo-group-name', ['object' => ''], $readOnly ? null : __('Show the objects'),
                        '<i class="misp-icon misp-icon-object misp-simple"></i>' . __('Objects')) ?>
                    <div class="eo-group-count"><b><?= $n($inventory['objects']['total']) ?></b></div>
                    <div class="eo-types">
                        <?php foreach ($inventory['objects']['by_name'] as $name => $count): ?>
                            <?= $chip('eo-type is-object', ['object' => $name], $readOnly ? null : __('Show the %s objects', $name),
                                h($name) . ' <b>' . $n($count) . '</b>') ?>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        <div class="eo-band-label eo-section-label"><?= __('Attribute types by group') ?></div>
        <div class="eo-bar" role="img" aria-label="<?= h(__('%1$s detection-ready of %2$s attributes', $ids, $total)) ?>">
            <?php foreach ($inventory['groups'] as $group): ?>
                <?php $tone = $tones[$group['group']] ?? $tones['Other']; ?>
                <?php if ($group['ids'] > 0): ?>
                    <span class="eo-bar-seg" data-eo-group="<?= h($group['group']) ?>"
                          style="flex:<?= (int)$group['ids'] ?>;--eo-tone:<?= $tone ?>;"
                          title="<?= h(__('%1$s: %2$s detection-ready', $group['group'], $group['ids'])) ?>"></span>
                <?php endif; ?>
                <?php if ($group['total'] - $group['ids'] > 0): ?>
                    <span class="eo-bar-seg is-context" data-eo-group="<?= h($group['group']) ?>"
                          style="flex:<?= (int)($group['total'] - $group['ids']) ?>;--eo-tone:<?= $tone ?>;"
                          title="<?= h(__('%1$s: %2$s context only', $group['group'], $group['total'] - $group['ids'])) ?>"></span>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>

        <div class="eo-groups">
            <?php foreach ($inventory['groups'] as $group): ?>
                <?php
                $tone = $tones[$group['group']] ?? $tones['Other'];
                $types = array_column($group['types'], 'type');
                $tab = $tabFor($group);
                ?>
                <div class="eo-group" data-eo-group="<?= h($group['group']) ?>" style="--eo-tone:<?= $tone ?>;">
                    <?= $chip('eo-group-name', ['types' => implode(',', $types), 'tab' => $tab],
                        $readOnly ? null : __('Show the %s attributes', strtolower($group['group'])),
                        '<i class="eo-swatch"></i>' . h(__($group['group']))) ?>
                    <div class="eo-group-count">
                        <b><?= $n($group['ids']) ?></b>/<?= $n($group['total']) ?>
                        <span class="eo-meter"><i style="width:<?= (int)round(100 * $group['ids'] / max(1, $group['total'])) ?>%"></i></span>
                    </div>
                    <div class="eo-types">
                        <?php foreach ($group['types'] as $type): ?>
                            <?= $chip(
                                'eo-type' . ($type['ids'] > 0 ? ' is-ids' : ''),
                                ['types' => $type['type'], 'tab' => $tab],
                                $type['ids'] > 0
                                    ? __('%1$s of %2$s flagged for detection', $type['ids'], $type['total'])
                                    : __('Context only'),
                                h($type['type']) . ' <b>' . $n($type['total']) . '</b>'
                            ) ?>
                        <?php endforeach; ?>
                        <?php if ($group['group'] === 'Detection rules'): ?>
                            <?php foreach ($inventory['detection_rules'] as $rule): ?>
                                <div class="eo-rule">
                                    <i class="fas fa-shield-halved"></i>
                                    <span class="eo-rule-name"><?= h($rule['name']) ?></span>
                                    <span class="eo-muted"><?= h($rule['type']) ?><?= $rule['object'] ? h(' · ' . __('in %s', $rule['object'])) : '' ?></span>
                                    <?= $this->element('Events/View/extension_origin', [
                                        'event_id' => $rule['event_id'] ?? 0,
                                        'compact' => true,
                                        'only_foreign' => true,
                                    ]) ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
            <div class="eo-empty d-none" data-eo-type-none><?= __('No attribute type matches.') ?></div>
        </div>

        <div class="eo-card-foot">
            <span class="eo-legend"><span class="eo-legend-swatch is-ids"></span><?= __('detection-ready') ?></span>
            <span class="eo-legend"><span class="eo-legend-swatch"></span><?= h(__('context only (%s)', $n($inventory['context']))) ?></span>
        </div>
    <?php endif; ?>
</div>
