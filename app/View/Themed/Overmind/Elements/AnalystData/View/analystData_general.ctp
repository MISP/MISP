<?php
App::uses('AnalystData', 'Model');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/*
 * What a Note / Opinion / Relationship says, and what it is about. Its id,
 * UUID, organisations and distribution are drawn by the page header and the
 * ownership card, so they are not repeated here.
 *
 * $analystTargets (address => label, meta) comes from AnalystData::describeTargets();
 * a target missing from it is not on this instance or not visible to the user.
 */
$m = $modelSelection ?? 'Note';
$record = $data[$m] ?? [];
$analystTargets = $analystTargets ?? [];

$styles = [
    'Note'         => ['color' => 'primary', 'icon' => 'misp-icon misp-icon-analyst-note misp-simple',    'label' => __('Note')],
    'Opinion'      => ['color' => 'success', 'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple', 'label' => __('Opinion')],
    'Relationship' => ['color' => 'info',    'icon' => 'fas fa-diagram-project',                          'label' => __('Relationship')],
];
$s = $styles[$m] ?? $styles['Note'];
$color = $s['color'];
$labelStyle = 'font-size:.7rem;';
$labelClass = 'text-body-secondary text-uppercase fw-bold';

$descParts = [];
if (!empty($record['created'])) {
    $descParts[] = '<span title="' . h(__('Created')) . '">'
        . '<i class="fas fa-calendar-day me-1 opacity-50"></i>' . h($record['created']) . '</span>';
}
if (!empty($record['modified'])) {
    $descParts[] = '<span title="' . h(__('Last modified')) . '">'
        . '<i class="fas fa-edit me-1 opacity-50"></i>' . h($record['modified']) . '</span>';
}
$this->set(
    'headerDescription',
    '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $descParts) . '</span>'
);

$targetGlyphs = [
    'Event' => 'misp-icon misp-icon-event misp-simple',
    'Attribute' => 'fas fa-cube',
    'Object' => 'fas fa-cubes',
    'EventReport' => 'misp-icon misp-icon-report misp-simple',
    'GalaxyCluster' => 'fas fa-atom',
    'Galaxy' => 'fas fa-globe',
    'Organisation' => 'fas fa-building',
    'SharingGroup' => 'misp-icon misp-icon-sharing-group misp-simple',
    'AttributeValue' => 'misp-icon misp-icon-value-intelligence misp-simple',
];

$target = function ($type, $end) use ($baseurl, $record, $analystTargets, $styles, $targetGlyphs) {
    $uuid = $record[AnalystData::addressColumn($type, $end)] ?? '';
    if (empty($uuid)) {
        return '<span class="text-body-secondary fst-italic small">' . __('Nothing') . '</span>';
    }
    $isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
    $known = $analystTargets[$isValue ? strtolower($uuid) : $uuid] ?? null;
    if ($isValue) {
        $url = isset($known['value']) ? $baseurl . '/values/view/' . ValueUrlTool::encode($known['value']) : '';
        $glyph = $targetGlyphs[$type];
    } elseif (isset($styles[$type])) {
        $url = $baseurl . '/analystData/view/' . $type . '/' . $uuid;
        $glyph = $styles[$type]['icon'];
    } else {
        $url = $type === 'Event'
            ? $baseurl . '/events/view/' . $uuid
            : $baseurl . '/' . Inflector::tableize($type) . '/view/' . $uuid;
        $glyph = $targetGlyphs[$type] ?? 'fas fa-link';
    }
    $tile = sprintf(
        '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 %s"'
        . ' style="width:2.5rem;height:2.5rem;"><i class="%s fs-5"></i></span>',
        $known ? 'bg-primary-subtle text-primary' : 'bg-body-secondary text-body-secondary',
        h($glyph)
    );
    $meta = '<span class="badge rounded-pill border bg-body text-body-secondary fw-normal">' . h($isValue ? __('Value') : $type) . '</span>';
    foreach ($known['meta'] ?? [] as $part) {
        $meta .= '<span class="text-truncate">' . h($part) . '</span>';
    }
    $meta .= '<span class="font-monospace text-truncate opacity-75">' . h($uuid) . '</span>';
    $body = sprintf(
        '<div class="min-w-0 flex-grow-1"><div class="fw-semibold lh-sm text-break">%s</div>'
        . '<div class="d-flex flex-wrap align-items-center column-gap-3 row-gap-1 small text-body-secondary mt-1">%s</div></div>',
        $known
            ? h($known['label'] !== '' ? $known['label'] : $type)
            : '<span class="text-body-secondary fst-italic">' . h($isValue
                ? __('This value could not be resolved, so it is shown by the SHA-256 of its text.')
                : __('Not on this instance, or not visible to you')) . '</span>',
        $meta
    );
    if (!$known) {
        return '<div class="d-flex align-items-center gap-3 p-2 rounded-3 border bg-body-tertiary" style="border-style:dashed !important;">'
            . $tile . $body . '</div>';
    }
    return sprintf(
        '<a href="%s" class="d-flex align-items-center gap-3 p-2 rounded-3 border bg-body-tertiary'
        . ' text-decoration-none link-body-emphasis ov-mini-card">%s%s'
        . '<i class="fas fa-arrow-right flex-shrink-0 text-body-secondary"></i></a>',
        h($url),
        $tile,
        $body
    );
};

$chips = [];
if (!empty($record['note_type_name']) && $record['note_type_name'] !== $m) {
    $chips[] = ['icon' => 'fas fa-tag', 'text' => $record['note_type_name']];
}
if (isset($record['authors']) && $record['authors'] !== '') {
    $chips[] = ['icon' => 'fas fa-user-pen', 'text' => $record['authors']];
}
if ($m === 'Note' && !empty($record['language'])) {
    $chips[] = ['icon' => 'fas fa-language', 'text' => $record['language']];
}

$opinion = isset($record['opinion']) ? max(0, min(100, (int)$record['opinion'])) : null;
if ($opinion !== null) {
    $opLabel = $opinion >= 81 ? __('Strongly Agree')
        : ($opinion >= 61 ? __('Agree')
        : ($opinion >= 41 ? __('Neutral')
        : ($opinion >= 21 ? __('Disagree') : __('Strongly Disagree'))));
    $opColor = $opinion === 50 ? 'secondary' : ($opinion > 50 ? 'success' : 'danger');
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="<?= h($s['icon']) ?> text-<?= $color ?> me-1"></i><?= h($s['label']) ?>
                </span>
                <?php if (!empty($chips)): ?>
                    <span class="d-flex flex-wrap gap-1">
                        <?php foreach ($chips as $chip): ?>
                            <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal">
                                <i class="<?= h($chip['icon']) ?> me-1 opacity-50"></i><?= h($chip['text']) ?>
                            </span>
                        <?php endforeach; ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if ($m === 'Note'): ?>
                <div class="border-start border-3 border-<?= $color ?> bg-<?= $color ?>-subtle bg-opacity-25 rounded-end px-3 py-2 text-break"
                     style="white-space:pre-wrap;"><?= h($record['note'] ?? '') ?></div>

            <?php elseif ($m === 'Opinion'): ?>
                <?php if ($opinion !== null): ?>
                    <div class="d-flex align-items-center gap-3">
                        <span class="fs-4 fw-bold text-<?= $opColor ?>-emphasis lh-1"><?= $opinion ?><span class="fs-6 text-body-secondary fw-normal">/100</span></span>
                        <div class="flex-grow-1">
                            <div class="fw-semibold small text-<?= $opColor ?>-emphasis mb-1"><?= h($opLabel) ?></div>
                            <div class="progress" style="height:.4rem;" role="progressbar"
                                 aria-valuenow="<?= $opinion ?>" aria-valuemin="0" aria-valuemax="100">
                                <div class="progress-bar bg-<?= $opColor ?>" style="width:<?= $opinion ?>%;"></div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                <?php if (!empty($record['comment'])): ?>
                    <div class="border-start border-3 border-<?= $opColor ?? 'secondary' ?> bg-body-tertiary rounded-end px-3 py-2 mt-2 text-break"
                         style="white-space:pre-wrap;"><?= h($record['comment']) ?></div>
                <?php endif; ?>

            <?php elseif ($m === 'Relationship'): ?>
                <div class="d-flex flex-column gap-1">
                    <?= $target($record['object_type'] ?? '', 'object') ?>
                    <div class="d-flex align-items-center gap-2 ps-3">
                        <i class="fas fa-arrow-down text-body-secondary"></i>
                        <span class="badge rounded-pill bg-<?= $color ?>-subtle text-<?= $color ?>-emphasis border border-<?= $color ?>-subtle">
                            <?= h($record['relationship_type'] ?? __('related to')) ?>
                        </span>
                    </div>
                    <?= $target($record['related_object_type'] ?? '', 'related_object') ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($m !== 'Relationship'): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('About') ?></div>
                <?= $target($record['object_type'] ?? '', 'object') ?>
            </div>
        <?php endif; ?>

    </div>
</div>
