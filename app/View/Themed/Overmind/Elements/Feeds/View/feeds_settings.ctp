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
                        '<span class="badge %s me-1">%s</span>',
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
        'value' => !empty($feed['publish']),
        'help' => __('Events created by this feed are published automatically.'),
    ],
    [
        'label' => __('Delta merge'),
        'value' => !empty($feed['delta_merge']),
        'help' => __('Align the local copy with the remote state instead of only adding.'),
    ],
    [
        'label' => __('Override IDS flag'),
        'value' => !empty($feed['override_ids']),
        'help' => __('Force every derived attribute to IDS off.'),
    ],
    [
        'label' => __('Force to IDS'),
        'value' => !empty($feed['force_to_ids']),
        'help' => __('Force every derived attribute to IDS on.'),
    ],
    [
        'label' => __('Visible to all orgs'),
        'value' => !empty($feed['lookup_visible']),
        'help' => __('Organisations other than the host org can see this feed and its correlations.'),
    ],
    [
        'label' => __('Lock pulled events'),
        'value' => !empty($feed['lock_events']),
        'help' => __('Events created by this feed cannot be edited locally.'),
    ],
];
if (($feed['input_source'] ?? '') === 'local') {
    $flags[] = [
        'label' => __('Delete local file'),
        'value' => !empty($feed['delete_local_file']),
        'help' => __('Remove the source file from disk once it has been ingested.'),
    ];
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <div class="fw-bold mb-3 d-flex align-items-center gap-2">
            <i class="fas fa-sliders text-muted"></i>
            <?= __('Pull behaviour') ?>
        </div>

        <!-- FLAGS -->
        <div class="row g-3">
            <?php foreach ($flags as $flag): ?>
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= h($flag['label']) ?></div>
                    <div class="py-1">
                        <?= $this->element('genericElementsBS5/Badges/boolean', [
                            'boolean' => $flag['value'],
                            'full' => true,
                            'true' => __('Yes'),
                            'false' => __('No'),
                            'trueColor' => 'success',
                            'falseColor' => 'secondary',
                            'trueIcon' => 'fa-check',
                            'falseIcon' => 'fa-xmark',
                        ]) ?>
                    </div>
                    <div class="text-muted" style="font-size:0.75rem;"><?= h($flag['help']) ?></div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- TARGET EVENT (freetext/CSV only — MISP feeds carry their own events) -->
        <?php if ($isParsedFeed): ?>
        <hr class="my-4">
        <div>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Target event') ?></div>
            <?php if (empty($feed['fixed_event'])): ?>
                <div class="alert alert-warning d-flex mb-0" role="alert">
                    <i class="fas fa-triangle-exclamation me-2 mt-1"></i>
                    <div>
                        <strong><?= __('New event each pull') ?></strong><br>
                        <?= __('This can grow the correlation table without bound. Only use it when the data is mostly distinct between pulls; a fixed event is otherwise recommended.') ?>
                    </div>
                </div>
            <?php elseif (!empty($feed['event_id'])): ?>
                <div class="bg-light rounded px-2 py-1 border d-inline-block">
                    <?= __('Fixed event') ?>:
                    <a href="<?= h($baseurl . '/events/view/' . $feed['event_id']) ?>"
                       class="text-decoration-none fw-semibold">#<?= h($feed['event_id']) ?></a>
                </div>
            <?php else: ?>
                <div class="bg-light rounded px-2 py-1 border d-inline-block">
                    <?= __('New fixed event, created on the first pull') ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- FILTER RULES -->
        <hr class="my-4">
        <div>
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Filter rules') ?></div>
            <?php if (!empty($ruleLines)): ?>
                <div class="bg-light border rounded p-3">
                    <?php foreach ($ruleLines as $line): ?>
                        <div class="mb-1"><?= $line ?></div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="text-muted"><?= __('No filtering — everything the feed offers is pulled.') ?></div>
            <?php endif; ?>
        </div>

        <!-- EVENT INDEX PARAMETERS -->
        <?php if (!empty($urlParams)): ?>
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Event index parameters') ?></div>
            <?= $this->element('genericElementsBS5/Badges/json', [
                'json' => $urlParams,
                'full' => true,
            ]) ?>
        </div>
        <?php endif; ?>

        <!-- FORMAT-SPECIFIC SETTINGS -->
        <?php if ($hasSettings): ?>
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Settings') ?></div>
            <?= $this->element('genericElementsBS5/Badges/json', [
                'json' => $settingsDecoded,
                'full' => true,
            ]) ?>
        </div>
        <?php endif; ?>

    </div>
</div>
