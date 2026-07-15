<?php
// view_layout only forwards `data` to the partial. $data is the Feed record.
$feed = $data['Feed'] ?? [];

// Decode the pull filter rules (tags/orgs OR/NOT) for a read-only summary,
// mirroring the legacy view.ctp Rules row.
$ruleLines = [];
if (!empty($feed['rules'])) {
    $decoded = json_decode($feed['rules'], true);
    if (is_array($decoded)) {
        $booleanColours = ['OR' => 'text-bg-success', 'NOT' => 'text-bg-danger'];
        foreach (['tags', 'orgs'] as $scope) {
            if (empty($decoded[$scope])) {
                continue;
            }
            $ruleData = $decoded[$scope];
            if (empty($ruleData['OR']) && empty($ruleData['NOT'])) {
                continue;
            }
            $pills = '';
            foreach (['OR', 'NOT'] as $booleanScope) {
                if (empty($ruleData[$booleanScope])) {
                    continue;
                }
                foreach ($ruleData[$booleanScope] as $ruleValue) {
                    $pills .= sprintf(
                        '<span class="badge %s me-1">%s</span>',
                        $booleanColours[$booleanScope],
                        h($ruleValue)
                    );
                }
            }
            $ruleLines[] = sprintf('<span class="fw-semibold me-1">%s:</span>%s', h(ucfirst($scope)), $pills);
        }
    }
}

// Pretty-print the settings JSON blob.
$settingsPretty = '';
if (!empty($feed['settings'])) {
    $settingsDecoded = is_array($feed['settings']) ? $feed['settings'] : json_decode($feed['settings'], true);
    if ($settingsDecoded !== null) {
        $settingsPretty = json_encode($settingsDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME + SOURCE FORMAT -->
        <div class="d-flex align-items-start justify-content-between mb-4">
            <div>
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Name') ?></div>
                <div class="fw-semibold fs-5 d-flex align-items-center gap-2">
                    <?= h($feed['name'] ?? '') ?>
                    <?php if (!empty($feed['source_format'])): ?>
                        <span class="badge text-bg-light border"><?= h($feed['source_format']) ?></span>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- URL -->
        <?php if (!empty($feed['url'])): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('URL') ?></div>
            <?= $this->element('genericElementsBS5/Badges/links', [
                'links' => [$feed['url']],
                'object' => $feed,
            ]); ?>
        </div>
        <?php endif; ?>

        <!-- TAGS -->
        <?php if (!empty($data['Tag']['id'])): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Default tag') ?></div>
            <?= $this->element('genericElementsBS5/Badges/tag', [
                'tag' => $data['Tag'],
                'local' => false,
                'showFavourite' => false,
            ]); ?>
        </div>
        <?php endif; ?>

        <!-- FILTER RULES -->
        <?php if (!empty($ruleLines)): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Filter rules') ?></div>
            <div class="bg-light border rounded p-3">
                <?php foreach ($ruleLines as $line): ?>
                    <div class="mb-1"><?= $line ?></div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- SETTINGS -->
        <?php if ($settingsPretty !== '' && $settingsPretty !== '[]' && $settingsPretty !== 'null'): ?>
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Settings') ?></div>
            <pre class="bg-light border rounded p-3 mb-0" style="white-space:pre-wrap;"><?= h($settingsPretty) ?></pre>
        </div>
        <?php endif; ?>

        <!-- META GRID -->
        <div class="row g-3">
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1">ID</div>
                <div class="bg-light rounded px-2 py-1 border"><?= h($feed['id'] ?? '') ?></div>
            </div>
            <?php if (!empty($feed['provider'])): ?>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Provider') ?></div>
                <div class="bg-light rounded px-2 py-1 border text-truncate"><?= h($feed['provider']) ?></div>
            </div>
            <?php endif; ?>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Enabled') ?></div>
                <div class="py-1">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => !empty($feed['enabled']),
                        'full' => true,
                        'true' => __('Yes'), 'false' => __('No'),
                        'trueColor' => 'success', 'falseColor' => 'secondary',
                        'trueIcon' => 'fa-check', 'falseIcon' => 'fa-xmark',
                    ]); ?>
                </div>
            </div>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Caching enabled') ?></div>
                <div class="py-1">
                    <?= $this->element('genericElementsBS5/Badges/boolean', [
                        'boolean' => !empty($feed['caching_enabled']),
                        'full' => true,
                        'true' => __('Yes'), 'false' => __('No'),
                        'trueColor' => 'success', 'falseColor' => 'secondary',
                        'trueIcon' => 'fa-check', 'falseIcon' => 'fa-xmark',
                    ]); ?>
                </div>
            </div>
        </div>

        <!-- COVERAGE BY OTHER FEEDS (read-only percentage; interactive compare tool is OUT) -->
        <?php if (isset($feed['coverage_by_other_feeds'])): ?>
        <div class="mt-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Coverage by other feeds') ?></div>
            <div class="progress" style="height:1.25rem;">
                <div class="progress-bar" role="progressbar"
                     style="width: <?= h($feed['coverage_by_other_feeds']) ?>;"
                     aria-valuenow="<?= h(rtrim($feed['coverage_by_other_feeds'], '%')) ?>"
                     aria-valuemin="0" aria-valuemax="100">
                    <?= h($feed['coverage_by_other_feeds']) ?>
                </div>
            </div>
        </div>
        <?php endif; ?>

    </div>
</div>
