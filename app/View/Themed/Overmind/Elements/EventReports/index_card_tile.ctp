<?php
/**
 * One report in the card view of the reports indexes (/event_reports/index and
 * the event's Reports tab), wired in through `card_element` (see
 * genericElementsBS5/IndexTable/index_card).
 *
 * Handled as the attribute and object cards are: the report icon leads and
 * gives way to the selection box on hover, the menu shows on hover. Then the
 * distribution and the name over the report's id and length, the last change
 * at the top right; the opening of the report (rendered on the event page, as
 * plain text elsewhere); the event and its creator org when the list spans
 * several events; at the foot, the way into the report (the event page's
 * reader, or the report's own page) and the analyst data.
 *
 * The selection box, the preview, the analyst badges and the menu are the
 * sections Elements/EventReports/index configures; the rest is read from the
 * row and its `ctx`.
 */
$report = $row['EventReport'] ?? [];
if (empty($report['id'])) {
    return;
}
$ctx = $row['ctx'];
$section = function ($name) use ($sections) {
    return implode('', $sections[$name] ?? []);
};
$dist = $this->DistributionLevel->get((int)($report['distribution'] ?? 0));
$distTitle = __('Distribution: %s', $dist['label'])
    . (empty($row['SharingGroup']['name']) ? '' : ' (' . $row['SharingGroup']['name'] . ')');
$timestamp = (int)($report['timestamp'] ?? 0);
$excerpt = $ctx['digest']['excerpt'];

$facts = [];
if ($ctx['origin']) {
    $facts[__('Event')] = $this->element('EventReports/index_event', ['row' => $row]);
    if (!empty($row['Event']['Orgc'])) {
        $facts[__('Creator org')] = $this->element('genericElementsBS5/IndexTable/Fields/organisation', [
            'row' => $row,
            'field' => ['data_path' => 'Event.Orgc'],
        ]);
    }
}
$facts = array_filter($facts, function ($html) {
    return trim($html) !== '';
});
?>
<div class="card-body er-tile">
    <div class="er-tile-head">
        <span class="er-tile-lead">
            <i class="misp-icon misp-icon-report misp-simple text-report" aria-hidden="true"></i>
            <?php if (!empty($sections['selector'])): ?>
                <span class="er-tile-sel"><?= $section('selector') ?></span>
            <?php endif; ?>
        </span>
        <span class="ov-obj-dist"
              style="--ov-dist-bg:<?= h($this->DistributionLevel->themed($dist, 'bg')) ?>;--ov-dist-ink:<?= h($this->DistributionLevel->themed($dist, 'fg')) ?>;"
              title="<?= h($distTitle) ?>">
            <i class="<?= h($dist['icon']) ?>"></i>
        </span>
        <div class="er-tile-title">
            <div class="er-tile-name">
                <?= $this->element('genericElementsBS5/IndexTable/Fields/report_value', [
                    'row' => $row,
                    'field' => ['data_path' => 'EventReport.name', 'reader' => $ctx['reader']],
                    'viewMode' => 'card',
                    'viewUrl' => $baseurl . '/event_reports/view/' . (int)$report['id'],
                ]) ?>
                <?php if ($timestamp > 0): ?>
                    <span class="er-tile-modified"><?= $this->element('genericElementsBS5/Badges/timestamp_pill', [
                        'record' => ['timestamp' => $timestamp],
                    ]) ?></span>
                <?php endif; ?>
            </div>
            <div class="er-tile-sub">
                <span class="er-tile-id">#<?= (int)$report['id'] ?></span>
                <?php if (!empty($report['deleted'])): ?>
                    <span class="ov-obj-deleted"><i class="fas fa-trash"></i><?= __('Deleted') ?></span>
                <?php endif; ?>
                <?= $this->element('EventReports/index_stats', ['digest' => $ctx['digest'], 'long' => true]) ?>
            </div>
        </div>
        <?php if (!empty($sections['actions'])): ?>
            <div class="er-tile-actions"><?= $section('actions') ?></div>
        <?php endif; ?>
    </div>

    <?php if (!empty($sections['preview'])): ?>
        <div class="er-tile-preview"><?= $section('preview') ?></div>
    <?php elseif ($excerpt === ''): ?>
        <p class="er-tile-excerpt is-empty"><?= __('This report has no content yet.') ?></p>
    <?php else: ?>
        <p class="er-tile-excerpt"><?= h($excerpt) ?></p>
    <?php endif; ?>

    <?php if (!empty($facts)): ?>
        <dl class="er-tile-facts">
            <?php foreach ($facts as $label => $html): ?>
                <dt><?= h($label) ?></dt>
                <dd><?= $html ?></dd>
            <?php endforeach; ?>
        </dl>
    <?php endif; ?>

    <div class="er-tile-foot">
        <?php if ($ctx['reader']): ?>
            <button type="button" class="er-tile-open" data-report-read="<?= (int)$report['id'] ?>">
                <i class="fas fa-book-open" aria-hidden="true"></i><?= __('Read') ?>
            </button>
        <?php else: ?>
            <a class="er-tile-open" href="<?= h($baseurl . '/event_reports/view/' . (int)$report['id']) ?>">
                <i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i><?= __('Open') ?>
            </a>
        <?php endif; ?>
        <?php if (!empty($sections['analyst'])): ?>
            <div class="er-tile-analyst"><?= $section('analyst') ?></div>
        <?php endif; ?>
    </div>
</div>
