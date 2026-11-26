<?php

$feed = $data['Feed'] ?? [];
$isParsedFeed = in_array($feed['source_format'] ?? '', ['freetext', 'csv'], true);


$ruleLines = [];
$urlParams = null;
if (!empty($feed['rules'])) {
    $decoded = is_array($feed['rules']) ? $feed['rules'] : json_decode($feed['rules'], true);
    if (is_array($decoded)) {
        $booleanColours = ['OR' => 'text-bg-success', 'NOT' => 'text-bg-danger'];
        foreach (['tags', 'orgs'] as $scope) {
            if (empty($decoded[$scope]['OR']) && empty($decoded[$scope]['NOT'])) {
                continue;
            }
            $pills = '';
            foreach (['OR', 'NOT'] as $booleanScope) {
                foreach (($decoded[$scope][$booleanScope] ?? []) as $ruleValue) {
                    $pills .= sprintf(
                        '<span class="badge rounded-pill fw-normal %s me-1">%s</span>',
                        $booleanColours[$booleanScope],
                        h($ruleValue)
                    );
                }
            }
            $ruleLines[] = sprintf(
                '<span class="fw-semibold me-1">%s:</span>%s',
                h(ucfirst($scope)),
                $pills
            );
        }
        if (!empty($decoded['url_params'])) {
            $urlParams = $decoded['url_params'];
        }
    }
}

$settingsDecoded = null;
if (!empty($feed['settings'])) {
    $settingsDecoded = is_array($feed['settings'])
        ? $feed['settings']
        : json_decode($feed['settings'], true);
}
$hasSettings = !empty($settingsDecoded);

$flags = [
    [
        'label' => __('Publish pulled events'),
        'icon' => 'fas fa-upload',
        'value' => !empty($feed['publish']),
        'help' => __('Events created by this feed are published automatically.'),
    ],
    [
        'label' => __('Delta merge'),
        'icon' => 'fas fa-code-merge',
        'value' => !empty($feed['delta_merge']),
        'help' => __('Align the local copy with the remote state instead of only adding.'),
    ],
    [
        'label' => __('Override IDS flag'),
        'icon' => 'fas fa-shield-cat',
        'value' => !empty($feed['override_ids']),
        'help' => __('Force every derived attribute to IDS off.'),
    ],
    [
        'label' => __('Force to IDS'),
        'icon' => 'fas fa-shield-halved',
        'value' => !empty($feed['force_to_ids']),
        'help' => __('Force every derived attribute to IDS on.'),
    ],
    [
        'label' => __('Visible to all orgs'),
        'icon' => 'fas fa-eye',
        'value' => !empty($feed['lookup_visible']),
        'help' => __('Organisations other than the host org can see this feed and its correlations.'),
    ],
    [
        'label' => __('Lock pulled events'),
        'icon' => 'fas fa-lock',
        'value' => !empty($feed['lock_events']),
        'help' => __('Events created by this feed cannot be edited locally.'),
    ],
];
if (($feed['input_source'] ?? '') === 'local') {
    $flags[] = [
        'label' => __('Delete local file'),
        'icon' => 'fas fa-file-circle-xmark',
        'value' => !empty($feed['delete_local_file']),
        'help' => __('Remove the source file from disk once it has been ingested.'),
    ];
}
$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="fas fa-sliders text-primary me-1"></i><?= __('Pull behaviour') ?>
            </div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['value'] ? '' : ' opacity-75' ?>" style="flex:1 1 15rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['value'] ? 'bg-success-subtle text-success-emphasis' : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['value'] ? '' : ' text-body-secondary' ?>">
                                <?= h($flag['label']) ?>
                                <span class="badge rounded-pill fw-normal ms-1 <?= $flag['value'] ? 'text-bg-success' : 'border bg-body text-body-secondary' ?>">
                                    <?= $flag['value'] ? __('On') : __('Off') ?>
                                </span>
                            </div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['help']) ?>"><?= h($flag['help']) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if ($isParsedFeed): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Target event') ?></div>
                <?php if (empty($feed['fixed_event'])): ?>
                    <div class="d-flex gap-2 p-2 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning small">
                        <i class="fas fa-triangle-exclamation mt-1"></i>
                        <div>
                            <strong><?= __('New event each pull') ?></strong> &middot;
                            <?= __('This can grow the correlation table without bound. Only use it when the data is mostly distinct between pulls; a fixed event is otherwise recommended.') ?>
                        </div>
                    </div>
                <?php elseif (!empty($feed['event_id'])): ?>
                    <a href="<?= h($baseurl . '/events/view2/' . $feed['event_id']) ?>"
                       class="d-inline-flex align-items-center gap-2 p-2 rounded-3 border bg-body-tertiary text-decoration-none link-body-emphasis ov-mini-card">
                        <i class="misp-icon misp-icon-event misp-simple text-primary"></i>
                        <span class="small"><?= __('Fixed event') ?></span>
                        <span class="fw-semibold">#<?= h($feed['event_id']) ?></span>
                        <i class="fas fa-arrow-right text-body-secondary"></i>
                    </a>
                <?php else: ?>
                    <span class="small text-body-secondary"><i class="fas fa-calendar-plus me-1 opacity-50"></i><?= __('New fixed event, created on the first pull') ?></span>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Filter rules') ?></div>
            <?php if (!empty($ruleLines)): ?>
                <div class="d-flex flex-column gap-1 small">
                    <?php foreach ($ruleLines as $line): ?>
                        <div><?= $line ?></div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <span class="small text-body-secondary fst-italic"><?= __('No filtering — everything the feed offers is pulled.') ?></span>
            <?php endif; ?>
        </div>

        <?php if (!empty($urlParams)): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Event index parameters') ?></div>
                <?= $this->element('genericElementsBS5/Badges/json', [
                    'json' => $urlParams,
                    'full' => true,
                ]) ?>
            </div>
        <?php endif; ?>

        <?php if ($hasSettings): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Format settings') ?></div>
                <?= $this->element('genericElementsBS5/Badges/json', [
                    'json' => $settingsDecoded,
                    'full' => true,
                ]) ?>
            </div>
        <?php endif; ?>

    </div>
</div>
