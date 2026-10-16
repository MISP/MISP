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
<div class="card shadow-sm eo-card eo-assessment w-100" id="analyst-data-card">
    <div class="eo-card-head">
        <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-analystData);--tile-bg:color-mix(in srgb, var(--bs-analystData) 12%, transparent);">
            <i class="fas fa-scale-balanced"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Assessment') ?></div>
            <?php if (!empty($facts)): ?>
                <div class="eo-card-sub eo-assessment-facts"><?= implode('', $facts) ?></div>
            <?php endif; ?>
        </div>
        <?php if ($canAdd): ?>
            <div class="dropdown flex-shrink-0">
                <button type="button" class="btn btn-sm btn-outline-analystData dropdown-toggle d-inline-flex align-items-center gap-1" data-bs-toggle="dropdown" aria-expanded="false" title="<?= h(__('Add analyst data')) ?>">
                    <i class="fas fa-plus"></i><span class="eo-btn-label"><?= __('Add') ?></span>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center gap-2" onclick="openModal('<?= h($addUrl('Note')) ?>')">
                            <i class="misp-icon misp-icon-analyst-note misp-simple"></i><?= __('Note') ?>
                        </button>
                    </li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center gap-2" onclick="openModal('<?= h($addUrl('Opinion')) ?>')">
                            <i class="misp-icon misp-icon-analyst-opinion misp-simple"></i><?= __('Opinion') ?>
                        </button>
                    </li>
                    <li>
                        <button type="button" class="dropdown-item d-flex align-items-center gap-2" onclick="openModal('<?= h($addUrl('Relationship')) ?>')">
                            <i class="fas fa-diagram-project"></i><?= __('Relationship') ?>
                        </button>
                    </li>
                </ul>
            </div>
        <?php endif; ?>
    </div>

    <?php if (!empty($confidence)): ?>
        <div class="eo-assessment-chips">
            <?php foreach ($confidence as $eventTag): ?>
                <?= $this->TagChip->chip($eventTag, ['searchUrl' => '']) ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php
    $thread = $this->element('AnalystData/thread', [
        'objectType' => 'Event',
        'objectUuid' => $eventUuid,
        'peek' => true,
        'showEmpty' => false,
    ]);
    ?>
    <?php if (trim($thread) !== ''): ?>
        <div class="eo-assessment-thread" data-collapse-tall="350" data-collapse-peek="[data-collapse-peek-label]"><?= $thread ?></div>
    <?php else: ?>
        <?= $this->element('AnalystData/empty', ['class' => 'flex-grow-1']) ?>
    <?php endif; ?>
</div>
