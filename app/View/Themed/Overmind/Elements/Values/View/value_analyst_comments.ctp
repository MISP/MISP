<?php
/**
 * The Collaboration tab's Attribute comments: the distinct `comment` values
 * of this value's occurrences, newest written first. Each one is the
 * sentence over one meta line: the event reference (Attributes/event_ref),
 * the organisation, how many occurrences carry it (when more than one) and
 * its last write.
 *
 * A comment has no author and no date of its own: its organisations are the
 * creating organisations of the events its rows sit in, and its dates are
 * the attribute rows' writes. The same sentence written in events of several
 * organisations is one entry naming them all.
 *
 * Lazily loaded from ValuesController::viewAnalystComments.
 *
 * @var array $valueIntelligence
 */
$comments = $valueIntelligence['analyst_comments'];

// Rows come per (comment, organisation), newest first.
$entries = array();
foreach ($comments['rows'] as $row) {
    $key = $row['comment'];
    if (!isset($entries[$key])) {
        $entries[$key] = array(
            'comment' => $row['comment'],
            'orgs' => array(),
            'occurrences' => 0,
            'events' => 0,
            'last_at' => $row['last_at'],
            'event' => $row['event'],
            'deleted' => true,
        );
    }
    $entry = &$entries[$key];
    $entry['orgs'][] = array('id' => $row['org_id'], 'name' => $row['org']);
    $entry['occurrences'] += (int)$row['occurrences'];
    // An event has one creator org, so the per-org counts never overlap.
    $entry['events'] += (int)$row['events'];
    $entry['deleted'] = $entry['deleted'] && $row['deleted'];
    unset($entry);
}

$facts = array();
if (!empty($entries)) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-comment-dots" aria-hidden="true"></i>'
        . h(sprintf(__n('%s comment', '%s comments', $comments['total']), number_format($comments['total']))) . '</span>';
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-attribute misp-simple"></i>'
        . h(sprintf(__n('on %s occurrence', 'on %s occurrences', $comments['occurrences']), number_format($comments['occurrences']))) . '</span>';
}

// Past these, the entries wait behind "Show N more"; the search reads them all.
$fold = 5;

?>
<div class="card shadow-sm mb-3 vp-panel vp-entries-card" style="--vp-panel-color: var(--analystData);" data-vp-entries>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Attribute comments'),
        'panelIcon' => 'fas fa-comment-dots',
        'panelColor' => 'var(--analystData)',
        'panelSub' => empty($facts)
            ? h(__('No occurrence carries one'))
            : '<span class="eo-assessment-facts">' . implode('', $facts) . '</span>',
    )) ?>

    <?php if (empty($entries)): ?>
        <div class="vp-empty">
            <i class="fas fa-comment-dots" aria-hidden="true"></i>
            <span><?= __('No occurrence of this value carries a comment.') ?></span>
        </div>
    <?php else: ?>
        <?= $this->element('Values/View/value_entries_search', array(
            'count' => count($entries),
            'placeholder' => __('Filter comments…'),
        )) ?>
        <div class="vp-entries">
            <?php $i = 0; ?>
            <?php foreach ($entries as $entry): ?>
                <?php
                $orgs = $entry['orgs'];
                $lead = array_shift($orgs);
                $spread = sprintf(
                    __('%1$s in %2$s'),
                    sprintf(__n('%s occurrence', '%s occurrences', $entry['occurrences']), number_format($entry['occurrences'])),
                    sprintf(__n('%s event', '%s events', $entry['events']), number_format($entry['events']))
                );
                ?>
                <?php $folded = $i++ >= $fold; ?>
                <article class="vp-entry vp-cmt<?= $entry['deleted'] ? ' is-deleted' : '' ?><?= $folded ? ' d-none' : '' ?>"
                         data-vp-entry<?= $folded ? ' data-vp-entry-fold' : '' ?>>
                    <p class="vp-cmt-text" title="<?= h($entry['comment']) ?>"><?= h($entry['comment']) ?></p>
                    <div class="vp-cmt-meta">
                        <?php if ($entry['event'] !== null): ?>
                            <?php // With several events, the one it was last written in. ?>
                            <?= $this->element('Attributes/event_ref', array('event' => $entry['event'])) ?>
                        <?php endif; ?>
                        <span class="vp-cmt-org">
                            <?= $this->element('Values/View/value_org_link', array('org' => $lead, 'small' => true)) ?>
                            <?php if (!empty($orgs)): ?>
                                <span class="vp-cmt-more" title="<?= h(implode(', ', array_column($orgs, 'name'))) ?>">+<?= count($orgs) ?></span>
                            <?php endif; ?>
                        </span>
                        <?php if ($entry['occurrences'] > 1): ?>
                            <span class="vp-cmt-count" title="<?= h($spread) ?>">
                                <i class="misp-icon misp-icon-attribute misp-simple"></i><?= h(number_format($entry['occurrences'])) ?>
                            </span>
                        <?php endif; ?>
                        <?php if ($entry['deleted']): ?>
                            <span class="ov-obj-deleted" title="<?= h(__('Every occurrence carrying it is deleted')) ?>"><i class="fas fa-trash"></i><?= __('Deleted') ?></span>
                        <?php endif; ?>
                        <span class="vp-cmt-when"><?= $this->element('genericElementsBS5/Badges/timestamp_pill', array(
                            'record' => array('timestamp' => $entry['last_at']),
                        )) ?></span>
                    </div>
                </article>
            <?php endforeach; ?>
        </div>
        <?= $this->element('Values/View/value_entries_more', array('count' => count($entries), 'fold' => $fold)) ?>
        <div class="vp-empty d-none" data-vp-entries-none><?= __('No comment matches.') ?></div>
    <?php endif; ?>

    <?php if (!empty($comments['capped'])): ?>
        <div class="eo-card-foot">
            <span class="eo-legend"><i class="fas fa-circle-info" aria-hidden="true"></i><?= h(sprintf(
                __('The %1$s most recently written of %2$s distinct comments.'),
                count($comments['rows']),
                number_format($comments['total'])
            )) ?></span>
        </div>
    <?php endif; ?>
</div>
