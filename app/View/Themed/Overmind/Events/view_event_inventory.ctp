<?php
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
$eventId = (int)$event['Event']['id'];
$n = function ($value) {
    return number_format((int)$value);
};
$tabFor = function (array $group) {
    return $group['in_objects'] * 2 >= $group['total'] ? 'objects' : 'attributes';
};
?>
<div class="eo-inventory" data-eo-narrower-count="<?= (int)$inventory['narrower'] ?>"
     data-eo-narrower-tab="<?= (int)($inventory['narrower_in_objects'] ?? 0) * 2 >= (int)$inventory['narrower'] ? 'objects' : 'attributes' ?>"
     data-eo-event-id="<?= $eventId ?>">
    <div class="eo-card-head">
        <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-attribute);--tile-bg:color-mix(in srgb, var(--bs-attribute) 12%, transparent);">
            <i class="misp-icon misp-icon-attribute misp-simple"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Indicator inventory') ?></div>
            <div class="eo-card-sub">
                <?= h(__n('%s attribute', '%s attributes', $total, $n($total))) ?>
                <?php if ($inObjects > 0): ?>· <?= h(__('%s in objects', $n($inObjects))) ?><?php endif; ?>
            </div>
        </div>
        <div class="eo-figure eo-figure-ids">
            <i class="fas fa-shield-halved text-warning eo-ids-icon" title="<?= h(__('Flagged for detection (to_ids)')) ?>"></i>
            <b><?= $n($ids) ?></b> <?= __('detection-ready') ?> <span class="eo-muted"><?= h(__('of %s', $n($total))) ?></span>
        </div>
    </div>

    <?php if ($total === 0): ?>
        <div class="eo-empty"><span><?= __('No attributes on this event yet.') ?></span></div>
    <?php else: ?>
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
        <div class="eo-bar-legend">
            <span><i class="eo-key"></i><?= __('detection-ready') ?></span>
            <span><i class="eo-key is-context"></i><?= h(__('context only (%s)', $n($inventory['context']))) ?></span>
        </div>

        <div class="eo-groups">
            <?php foreach ($inventory['groups'] as $group): ?>
                <?php
                $tone = $tones[$group['group']] ?? $tones['Other'];
                $types = array_column($group['types'], 'type');
                $tab = $tabFor($group);
                ?>
                <div class="eo-group" data-eo-group="<?= h($group['group']) ?>" style="--eo-tone:<?= $tone ?>;">
                    <button type="button" class="eo-group-name"
                            data-eo-filter-types="<?= h(implode(',', $types)) ?>"
                            data-eo-filter-tab="<?= h($tab) ?>"
                            title="<?= h(__('Show the %s attributes', strtolower($group['group']))) ?>">
                        <i class="eo-swatch"></i><?= h(__($group['group'])) ?>
                    </button>
                    <div class="eo-group-count">
                        <b><?= $n($group['ids']) ?></b>/<?= $n($group['total']) ?>
                        <span class="eo-meter"><i style="width:<?= (int)round(100 * $group['ids'] / max(1, $group['total'])) ?>%"></i></span>
                    </div>
                    <div class="eo-types">
                        <?php foreach ($group['types'] as $type): ?>
                            <button type="button" class="eo-type<?= $type['ids'] > 0 ? ' is-ids' : '' ?>"
                                    data-eo-filter-types="<?= h($type['type']) ?>"
                                    data-eo-filter-tab="<?= h($tab) ?>"
                                    title="<?= h($type['ids'] > 0
                                        ? __('%1$s of %2$s flagged for detection', $type['ids'], $type['total'])
                                        : __('Context only')) ?>">
                                <?= h($type['type']) ?> <b><?= $n($type['total']) ?></b>
                            </button>
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
        </div>

        <?php if (!empty($inventory['objects']['total'])): ?>
            <div class="eo-objects">
                <b><?= h(__n('%s object', '%s objects', $inventory['objects']['total'], $inventory['objects']['total'])) ?>:</b>
                <?php
                $parts = [];
                foreach ($inventory['objects']['by_name'] as $name => $count) {
                    $parts[] = sprintf('%d %s', $count, h($name));
                }
                echo implode(' · ', $parts);
                ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>

</div>
