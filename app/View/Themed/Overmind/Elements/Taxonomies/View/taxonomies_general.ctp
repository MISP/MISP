<?php
$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$flags = [
    [
        'on' => !empty($data['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Enabled'), __('Disabled')],
        'sub' => [__('Its tags can be attached'), __('Its tags cannot be attached')],
    ],
    [
        'on' => !empty($data['required']),
        'colour' => 'danger',
        'icon' => 'fas fa-asterisk',
        'label' => [__('Required'), __('Optional')],
        'sub' => [
            !empty($data['enabled'])
                ? __('An event needs one of its tags to be published')
                : __('Enforced once the taxonomy is enabled'),
            __('Not needed to publish an event'),
        ],
    ],
    [
        'on' => !empty($data['highlighted']),
        'colour' => 'warning',
        'icon' => 'fas fa-highlighter',
        'label' => [__('Highlighted'), __('Not highlighted')],
        'sub' => [__('Its tags stand out on the event view'), __('Its tags show like any other')],
    ],
    [
        'on' => !empty($data['exclusive']),
        'colour' => 'info',
        'icon' => 'fas fa-circle-dot',
        'label' => [__('Exclusive'), __('Not exclusive')],
        'sub' => [__('Only one of its tags per element'), __('Several of its tags can be combined')],
    ],
];
?>
<div class="card mb-3 shadow-sm" data-tour="taxonomy-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-sitemap text-primary me-1"></i><?= __('Taxonomy') ?>
                </span>
                <span class="d-flex flex-wrap align-items-center gap-1">
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                        v<?= h((int)($data['version'] ?? 0)) ?>
                    </span>
                </span>
            </div>
            <?php if (trim($data['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($data['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
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

    </div>
</div>
