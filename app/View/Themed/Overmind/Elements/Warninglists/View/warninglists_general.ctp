<?php
$warninglist = $data['Warninglist'] ?? [];
$types = array_column($data['WarninglistType'] ?? [], 'type');
$categories = $possibleCategories ?? [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

// How Warninglist::checkValue() compares an attribute value with this list.
$matching = [
    'string' => ['fas fa-equals', __('Exact match'), __('The value must equal an entry')],
    'substring' => ['fas fa-magnifying-glass', __('Substring'), __('The value must contain an entry')],
    'hostname' => ['fas fa-sitemap', __('Hostname'), __('The host or one of its parent domains must be an entry')],
    'cidr' => ['fas fa-network-wired', __('CIDR'), __('The address must fall in one of the ranges')],
    'regex' => ['fas fa-code', __('Regular expression'), __('The value must match one of the patterns')],
];
$match = $matching[$warninglist['type'] ?? ''] ?? ['fas fa-question', (string)($warninglist['type'] ?? ''), ''];

// What a hit on this list tells the analyst about the attribute.
$categoryGlosses = [
    'false_positive' => ['fas fa-shield-halved', __('A hit flags the value as a likely false positive')],
    'known' => ['fas fa-fingerprint', __('A hit names the value as a known identifier')],
];
$categoryKey = (string)($warninglist['category'] ?? '');
$category = [
    $categoryGlosses[$categoryKey][0] ?? 'fas fa-tag',
    $categories[$categoryKey] ?? $categoryKey,
    $categoryGlosses[$categoryKey][1] ?? '',
];

$flags = [
    [
        'on' => !empty($warninglist['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Enabled'), __('Disabled')],
        'sub' => [__('Attribute values are checked against it'), __('Nothing is checked against it')],
    ],
    [
        'on' => !empty($warninglist['default']),
        'colour' => 'primary',
        'icon' => 'fas fa-box',
        'label' => [__('Default'), __('Custom')],
        'sub' => [__('Shipped with MISP, updated from the warninglist library'), __('Created on this instance')],
    ],
];
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-triangle-exclamation me-1" style="color:var(--warninglist);"></i><?= __('Warninglist') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($warninglist['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($warninglist['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 rounded-end px-3 py-2 text-break"
                     style="border-color:var(--warninglist) !important;background:color-mix(in srgb, var(--warninglist) 7%, transparent);">
                    <?= nl2br(h($warninglist['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <?php if ($categoryKey !== ''): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Category') ?></div>
                <div class="d-inline-flex rounded-pill border bg-body-tertiary p-1 gap-1 mw-100" role="group" aria-label="<?= h(__('Category')) ?>">
                    <?php foreach ($categoryGlosses as $key => list($icon)): ?>
                        <?php $active = $key === $categoryKey; ?>
                        <span class="d-inline-flex align-items-center gap-1 rounded-pill px-3 py-1 small text-nowrap<?= $active ? ' fw-semibold shadow-sm' : ' text-body-secondary opacity-50' ?>"
                              <?= $active ? 'style="background:var(--warninglist);color:#fff;" aria-current="true"' : '' ?>>
                            <i class="<?= h($icon) ?>"></i><?= h($categories[$key] ?? $key) ?>
                        </span>
                    <?php endforeach; ?>
                </div>
                <?php if ($category[2] !== ''): ?>
                    <div class="small text-body-secondary mt-1"><?= h($category[2]) ?></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Matching') ?></div>
            <div class="d-flex flex-column flex-md-row gap-2 gap-md-3">
                <div class="d-flex align-items-center gap-2 min-w-0 flex-shrink-0" style="min-width:13rem;">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                          style="<?= $tileStyle ?>background:color-mix(in srgb, var(--warninglist) 14%, transparent);color:var(--warninglist);">
                        <i class="<?= h($match[0]) ?>"></i>
                    </span>
                    <div class="min-w-0">
                        <div class="fw-semibold lh-sm"><?= h($match[1]) ?></div>
                        <div class="small text-body-secondary"><?= h($match[2]) ?></div>
                    </div>
                </div>
                <div class="min-w-0">
                    <div class="small text-body-secondary mb-1"><?= __('Checked on these attribute types') ?></div>
                    <?php if (empty($types)): ?>
                        <span class="small text-body-secondary fst-italic"><?= __('None') ?></span>
                    <?php else: ?>
                        <div class="d-flex flex-wrap gap-1">
                            <?php foreach ($types as $type): ?>
                                <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal font-monospace"><?= h($type) ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Settings') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['on']
                            ? 'bg-' . $flag['colour'] . '-subtle text-' . $flag['colour'] . '-emphasis'
                            : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['on'] ? '' : ' text-body-secondary' ?>"><?= h($flag['label'][$state]) ?></div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['sub'][$state]) ?>"><?= h($flag['sub'][$state]) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>
</div>
