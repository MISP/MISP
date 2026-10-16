<?php
App::uses('GalaxyMatrixLayout', 'Tools');
$iconClass = !empty($data['icon']) ? $this->FontAwesome->getClass($data['icon']) : 'fas fa-shapes';
$palette = $this->GalaxyColour->palette($data['name'] ?? '');
$connectorPrefix = 'misp-galaxy:' . ($data['type'] ?? '') . '=';
$killChains = is_array($data['kill_chain_order'] ?? null) ? array_filter($data['kill_chain_order']) : [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$formatDate = function ($value) {
    $digits = preg_replace('/\D/', '', (string)$value);
    if ($digits === '' || (int)$digits === 0) {
        return '<span class="text-muted">' . __('N/A') . '</span>';
    }
    return $this->Time->time($value);
};
$this->set(
    'headerDescription',
    '<span class="d-inline-flex align-items-center gap-3 flex-wrap">'
    . '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-day me-1 opacity-50"></i>' . $formatDate($data['created'] ?? null) . '</span>'
    . '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>' . $formatDate($data['modified'] ?? null) . '</span>'
    . '</span>'
);

$flags = [
    [
        'on' => !empty($data['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Enabled'), __('Disabled')],
        'sub' => [__('Its clusters can be attached'), __('Its clusters cannot be attached')],
    ],
    [
        'on' => !empty($data['default']),
        'colour' => 'primary',
        'icon' => 'fas fa-box',
        'label' => [__('Default'), __('Custom')],
        'sub' => [__('Shipped with MISP, updated from the galaxy library'), __('Created on a MISP instance')],
    ],
    [
        'on' => !empty($data['local_only']),
        'colour' => 'warning',
        'icon' => 'fas fa-house-lock',
        'label' => [__('Local only'), __('Shareable')],
        'sub' => [__('Never leaves this instance'), __('Synchronised with its distribution')],
    ],
];
?>
<div class="card mb-3 shadow-sm" data-tour="galaxy-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="<?= h($iconClass) ?> me-1" style="color:<?= h($palette['tintIcon']) ?>;"></i><?= __('Galaxy') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($data['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($data['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 rounded-end px-3 py-2 text-break"
                     style="border-color:<?= h($palette['tintIcon']) ?> !important;background:<?= h($palette['sectionBg']) ?>;">
                    <?= nl2br(h($data['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Tagging') ?></div>
            <div class="d-flex flex-wrap align-items-center gap-2">
                <span class="d-inline-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100">
                    <span class="d-inline-flex align-items-center gap-1 px-2 text-body-secondary" title="<?= h(__('Type')) ?>">
                        <i class="fas fa-shapes opacity-50"></i><?= h($data['type'] ?? '') ?>
                    </span>
                    <span class="vr my-1"></span>
                    <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center gap-1 border-0 bg-transparent text-body-secondary px-2 mb-0 text-truncate"
                            title="<?= h(__('Clusters of this galaxy are attached as tags of this form — click to copy')) ?>"
                            data-copy-value="<?= h($connectorPrefix) ?>"
                            data-copy-msg="<?= h(__('Connector copied to clipboard')) ?>"
                            onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                        <i class="fas fa-tag opacity-50"></i><?= h($connectorPrefix) ?><span class="opacity-50">"&hellip;"</span><i class="fas fa-copy fa-xs"></i>
                    </button>
                </span>
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Category') ?></div>
            <?php if (empty($data['category'])): ?>
                <span class="text-body-secondary fst-italic small"><?= __('Not classified') ?></span>
            <?php else: ?>
                <div class="d-inline-flex align-items-center gap-2">
                    <span class="badge rounded-pill bg-body-tertiary text-body border fw-normal"><?= h($data['category']) ?></span>
                    <?php if (!empty($data['sub_category'])): ?>
                        <span class="text-body-secondary small"><?= h($data['sub_category']) ?></span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
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

        <?php if (!empty($killChains)): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Kill chain') ?></div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($killChains as $chain => $phases): ?>
                        <div class="d-flex flex-wrap align-items-center gap-1">
                            <?php if (count($killChains) > 1): ?>
                                <span class="small fw-semibold me-1"><?= h(GalaxyMatrixLayout::formatTactic($chain)) ?></span>
                            <?php endif; ?>
                            <?php foreach (array_values((array)$phases) as $i => $phase): ?>
                                <?php if ($i > 0): ?>
                                    <i class="fas fa-chevron-right fa-xs text-body-secondary opacity-50"></i>
                                <?php endif; ?>
                                <span class="badge rounded-pill fw-normal border"
                                      style="background:<?= h($palette['badgeBg']) ?>;color:<?= h($palette['badgeText']) ?>;border-color:<?= h($palette['badgeBorder']) ?> !important;">
                                    <span class="opacity-50 me-1"><?= $i + 1 ?></span><?= h(GalaxyMatrixLayout::formatTactic($phase)) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>
</div>
