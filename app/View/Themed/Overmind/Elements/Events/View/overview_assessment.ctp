<?php
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');

$eventUuid = $data['Event']['uuid'] ?? '';
$confidence = [];
foreach ($data['EventTag'] ?? [] as $eventTag) {
    $namespace = ValueLabelPriority::namespaceOf($eventTag['Tag']['name'] ?? '');
    if (in_array($namespace, ['admiralty-scale', 'estimative-language'], true)) {
        $confidence[] = $eventTag;
    }
}
$opinions = $data['Opinion'] ?? [];
$notes = $data['Note'] ?? [];
$relationships = $data['Relationship'] ?? [];
$hasAnalystData = !empty($opinions) || !empty($notes) || !empty($relationships);
$canAdd = !empty($me['Role']['perm_analyst_data']) && $eventUuid !== '';
$addUrl = function ($type) use ($baseurl, $eventUuid) {
    return $baseurl . '/analystData/add/' . $type . '/' . rawurlencode($eventUuid) . '/Event';
};
$scores = array_filter(array_map(function ($opinion) {
    return isset($opinion['opinion']) ? (int)$opinion['opinion'] : null;
}, $opinions), 'is_int');

$facts = [];
if (!empty($opinions)) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-opinion misp-simple"></i>'
        . h(__n('%s opinion', '%s opinions', count($opinions), count($opinions)))
        . (empty($scores) ? '' : ' <span class="eo-muted">' . h(__('avg. %s/100', (int)round(array_sum($scores) / count($scores)))) . '</span>')
        . '</span>';
}
if (!empty($notes)) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-note misp-simple"></i>'
        . h(__n('%s note', '%s notes', count($notes), count($notes))) . '</span>';
}
if (!empty($relationships)) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-diagram-project"></i>'
        . h(__n('%s relationship', '%s relationships', count($relationships), count($relationships))) . '</span>';
}
?>
<div class="card shadow-sm eo-card eo-assessment" id="analyst-data-card">
    <div class="eo-card-head">
        <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-analystData);--tile-bg:color-mix(in srgb, var(--bs-analystData) 12%, transparent);">
            <i class="fas fa-scale-balanced"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Assessment') ?></div>
            <div class="eo-card-sub eo-assessment-facts">
                <?php if (empty($facts) && empty($confidence)): ?>
                    <?= __('No assessment yet') ?>
                <?php elseif (empty($facts)): ?>
                    <?= __('No analyst data yet') ?>
                <?php else: ?>
                    <?= implode('', $facts) ?>
                <?php endif; ?>
            </div>
        </div>
        <?php if ($hasAnalystData): ?>
            <button type="button" class="btn btn-sm btn-outline-analystData flex-shrink-0 d-inline-flex align-items-center gap-1" data-bs-toggle="collapse" data-bs-target="#eo-analyst-data" aria-expanded="false" title="<?= __('Show analyst data') ?>">
                <i class="fas fa-comment-dots"></i><span class="eo-btn-label"><?= __('Show analyst data') ?></span>
            </button>
        <?php endif; ?>
    </div>

    <?php if (!empty($confidence)): ?>
        <div class="eo-assessment-chips">
            <?php foreach ($confidence as $eventTag): ?>
                <?= $this->TagChip->chip($eventTag, ['searchUrl' => '']) ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($hasAnalystData): ?>
        <div class="collapse" id="eo-analyst-data">
            <div class="border-top" data-eo-fragment-lazy="<?= h($baseurl . '/analystData/viewForObject/Event/' . rawurlencode($eventUuid) . '?embedded=1') ?>">
                <div class="text-center text-muted py-3"><div class="misp-loader misp-loader-sm" role="status"></div></div>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($canAdd): ?>
        <div class="eo-card-foot eo-assessment-foot">
            <span class="eo-muted small"><?= __('Add') ?></span>
            <span class="btn-group btn-group-sm" role="group" aria-label="<?= h(__('Add analyst data')) ?>">
                <button type="button" class="btn btn-outline-analystData" onclick="openModal('<?= h($addUrl('Note')) ?>')">
                    <i class="misp-icon misp-icon-analyst-note misp-simple me-1"></i><?= __('Note') ?>
                </button>
                <button type="button" class="btn btn-outline-analystData" onclick="openModal('<?= h($addUrl('Opinion')) ?>')">
                    <i class="misp-icon misp-icon-analyst-opinion misp-simple me-1"></i><?= __('Opinion') ?>
                </button>
                <button type="button" class="btn btn-outline-analystData" onclick="openModal('<?= h($addUrl('Relationship')) ?>')">
                    <i class="fas fa-diagram-project me-1"></i><?= __('Relationship') ?>
                </button>
            </span>
        </div>
    <?php endif; ?>
</div>
