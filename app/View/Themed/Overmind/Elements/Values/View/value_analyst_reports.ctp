<?php
/**
 * The Collaboration tab's Event reports: the reports on the events this
 * value appears in, newest change first. Each one is the reports index's
 * card tile (EventReports/index_card_tile) in its compact form:
 * distribution, name (which opens the report), last change, the event
 * reference, length and references, then two lines of the text.
 *
 * A report is written about an event, never about the value.
 *
 * Lazily loaded from ValuesController::viewAnalystReports.
 *
 * @var array $valueIntelligence
 */
$reports = $valueIntelligence['analyst_reports'];
$rows = $reports['rows'];

$facts = array();
if (!empty($rows)) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-report misp-simple"></i>'
        . h(sprintf(__n('%s report', '%s reports', $reports['total']), number_format($reports['total']))) . '</span>';
    // The events carrying the listed reports, out of the value's events read.
    $onEvents = count(array_unique(array_map(function ($report) {
        return $report['event']['id'];
    }, $rows)));
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-event misp-simple"></i>'
        . h(sprintf(__n('on %1$s of its %2$s event', 'on %1$s of its %2$s events', $reports['events']),
            number_format($onEvents), number_format($reports['events']))) . '</span>';
    if ($reports['withdrawn'] > 0) {
        $facts[] = '<span class="eo-fact"><i class="fas fa-trash" aria-hidden="true"></i>'
            . h(sprintf(__n('%s withdrawn', '%s withdrawn', $reports['withdrawn']), $reports['withdrawn'])) . '</span>';
    }
}

// Past these, the tiles wait behind "Show N more"; the search reads them all.
$fold = 3;

$notes = array();
if (!empty($reports['capped'])) {
    $notes[] = sprintf(__('The %1$s most recently changed of %2$s.'), count($rows), number_format($reports['total']));
}
if (!empty($reports['occurrence_capped'])) {
    $notes[] = __('Only the events of its most recent occurrences are read: a report on an older one is not listed.');
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-entries-card" style="--vp-panel-color: var(--report);" data-vp-entries>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Event reports'),
        'panelIcon' => 'misp-icon misp-icon-report misp-simple',
        'panelColor' => 'var(--report)',
        'panelSub' => empty($facts)
            ? h(__('No report on its events'))
            : '<span class="eo-assessment-facts">' . implode('', $facts) . '</span>',
    )) ?>

    <?php if (empty($rows)): ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-report misp-simple"></span>
            <span><?= __('Nobody has written a report on an event this value appears in.') ?></span>
        </div>
    <?php else: ?>
        <?= $this->element('Values/View/value_entries_search', array(
            'count' => count($rows),
            'placeholder' => __('Filter reports…'),
        )) ?>
        <div class="vp-entries">
            <?php foreach ($rows as $i => $report): ?>
                <?php
                // The row as the reports index hands it to its card tile.
                $row = array(
                    'EventReport' => array(
                        'id' => $report['id'],
                        'name' => $report['name'] === '' || $report['name'] === null
                            ? __('(untitled report)') : $report['name'],
                        'event_id' => $report['event']['id'],
                        'distribution' => $report['distribution'],
                        'timestamp' => $report['timestamp'],
                        'deleted' => $report['withdrawn'],
                    ),
                    'SharingGroup' => array('name' => $report['sharing_group']),
                    'Event' => ($report['event_peek'] ?? array()) + array(
                        'id' => $report['event']['id'],
                        'info' => $report['event']['info'],
                    ),
                    'ctx' => array(
                        'digest' => $report['digest'],
                        'reader' => false,
                        'origin' => false,
                    ),
                );
                ?>
                <?php $folded = $i >= $fold; ?>
                <div class="vp-entry vp-report-entry<?= $report['withdrawn'] ? ' er-deleted' : '' ?><?= $folded ? ' d-none' : '' ?>"
                     data-vp-entry<?= $folded ? ' data-vp-entry-fold' : '' ?>>
                    <?= $this->element('EventReports/index_card_tile', array(
                        'row' => $row,
                        'sections' => array(),
                        'compact' => true,
                    )) ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?= $this->element('Values/View/value_entries_more', array('count' => count($rows), 'fold' => $fold)) ?>
        <div class="vp-empty d-none" data-vp-entries-none><?= __('No report matches.') ?></div>
    <?php endif; ?>

    <?php if (!empty($notes)): ?>
        <div class="eo-card-foot">
            <span class="eo-legend"><i class="fas fa-circle-info" aria-hidden="true"></i><?= h(implode(' ', $notes)) ?></span>
        </div>
    <?php endif; ?>
</div>
