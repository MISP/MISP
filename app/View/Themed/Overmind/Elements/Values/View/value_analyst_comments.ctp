<?php
/**
 * What analysts typed into the `comment` column of this value's
 * occurrences.
 *
 * **The one panel on this tab whose subject is the value itself.**
 * Every other item here is anchored to a uuid — a note on an event, an
 * opinion on a note, a report on an event — and each spends a chip
 * saying which, because analyst data cannot address a value. A comment
 * is a column on the occurrence, so the sentence *somebody wrote this
 * about this value* needs no qualification for once. It is also by far
 * the most common analyst writing MISP holds: 2.1M attributes on this
 * instance carry a comment, against 75 notes and 43 opinions.
 *
 * **A table, and one row per distinct sentence.** `94.98.224.81` carries
 * *Xtreme RAT botnet C2 server (confidence level: 100%)* on 1,459
 * occurrences — one thing somebody wrote, stamped onto every row by a
 * feed. A row per occurrence would have been 1,459 identical lines; the
 * count belongs in a column, and it is the most interesting thing on
 * the row.
 *
 * **Three things the panel refuses to imply:**
 *
 * - **Who wrote it.** A comment has no author. Its only attribution is
 *   the creating organisation of the event its attribute sits in, and
 *   the column says *Event's org* rather than *Author*.
 * - **When it was written.** Its only date is `attributes.timestamp`,
 *   a row write that any later edit to any other column moves. The
 *   column says *Row last written*.
 * - **That two spellings are one sentence.** `attributes.comment` is
 *   `utf8mb3_bin`, the grouping is byte-exact, and `Blocked` and
 *   `blocked` are two rows here.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewAnalystComments.
 *
 * @var array $valueIntelligence
 */
$comments = $valueIntelligence['analyst_comments'];
$rows = $comments['rows'];

/**
 * How long ago, in the coarsest unit still true — the standing panel's
 * scale, so one tab does not date two things two ways.
 *
 * @param int|null $at Unix seconds
 * @return string|null
 */
$age = function ($at) {
    if (empty($at)) {
        return null;
    }
    $days = (int)floor((time() - (int)$at) / 86400);
    if ($days <= 0) {
        return __('today');
    }
    if ($days === 1) {
        return __('yesterday');
    }
    if ($days < 31) {
        return sprintf(__n('%d day ago', '%d days ago', $days), $days);
    }
    $months = max(1, (int)round($days / 30.44));
    return sprintf(__n('%d month ago', '%d months ago', $months), $months);
};

/*
 * Nothing to count is a state, not a zero. `0 comments on 0 of 26
 * occurrences` is a sentence about an empty panel and reads as a
 * broken one.
 */
$subtitle = empty($rows)
    ? h(__('No occurrence of this value carries a comment'))
    : implode(' &nbsp;·&nbsp; ', array_filter(array(
        h(sprintf(
            __('%1$s on %2$s'),
            __n('%s distinct comment', '%s distinct comments',
                $comments['total'], $comments['total']),
            __n('%s occurrence', '%s occurrences',
                $comments['occurrences'], $comments['occurrences'])
        )),
        $comments['events'] > 0
            ? h(sprintf(
                __n('in %s event', 'in %s events', $comments['events'],
                    $comments['events'])
            ))
            : null,
        h(__('most recently written first')),
    )));
?>
<?php
/*
 * `vp-ctable-panel` makes the card a query container. The table's five
 * sized columns are the sentence's width, and this panel is full width
 * when it is stacked and half width when it sits beside the report list
 * — so what they should be is a question about the card, not about the
 * window.
 */
?>
<div class="card shadow-sm mb-3 vp-panel vp-dense vp-ctable-panel"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-comments>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Attribute comments'),
        'panelIcon' => 'fas fa-comment-dots',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if (empty($rows)): ?>
        <div class="vp-empty">
            <i class="fas fa-comment-dots"></i>
            <span><?= h(__(
                'No occurrence of this value carries a comment. The'
                . ' column is free text on the attribute and most rows'
                . ' leave it empty.'
            )) ?></span>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-sm mb-0 vp-table vp-ctable">
                <thead>
                    <tr>
                        <th><?= h(__('Comment')) ?></th>
                        <th class="vp-ctable-num"
                            title="<?= h(__(
                                'How many of this value\'s occurrences'
                                . ' carry this exact comment. Counted'
                                . ' over every occurrence you can see,'
                                . ' never over the rows in this table.'
                            )) ?>"><?= h(__('Rows')) ?></th>
                        <th class="vp-ctable-num"><?= h(__('Events')) ?></th>
                        <th class="vp-ctable-event"><?=
                            h(__('Latest in')) ?></th>
                        <th title="<?= h(__(
                            'A comment has no author — it is a column on'
                            . ' the attribute. This is the creating'
                            . ' organisation of the event that'
                            . ' attribute sits in.'
                        )) ?>"><?= h(__('Event\'s org')) ?></th>
                        <th class="vp-ctable-when" title="<?= h(__(
                            'A comment has no date of its own. This is'
                            . ' the attribute row\'s last write, which'
                            . ' any later edit to any other column'
                            . ' moves.'
                        )) ?>"><?= h(__('Row last written')) ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $row): ?>
                        <tr<?= $row['deleted']
                            ? ' class="vp-ctable-gone"' : '' ?>>
                            <td class="vp-ctable-text">
                                <?php if ($row['deleted']): ?>
                                    <?php
                                    /*
                                     * Every occurrence carrying this
                                     * sentence is soft-deleted. Drawn
                                     * anyway — somebody wrote it and
                                     * somebody withdrew the rows, and
                                     * both are part of what happened
                                     * to this value.
                                     */
                                    ?>
                                    <i class="fas fa-trash me-1
                                              text-body-tertiary"
                                       title="<?= h(__(
                                           'Every occurrence carrying'
                                           . ' this comment is deleted.'
                                       )) ?>"></i>
                                <?php endif; ?>
                                <span title="<?= h($row['comment']) ?>"><?=
                                    h($row['comment'])
                                ?></span>
                            </td>
                            <td class="vp-ctable-num"><?=
                                h(number_format($row['occurrences']))
                            ?></td>
                            <td class="vp-ctable-num"><?=
                                h(number_format($row['events']))
                            ?></td>
                            <td class="vp-ctable-event">
                                <?php if ($row['event'] === null): ?>
                                    <span class="vpa-chip
                                                 vpa-chip-unresolved"
                                          title="<?= h(__(
                                              'The event this comment'
                                              . ' was last written on'
                                              . ' did not resolve.'
                                          )) ?>"><?= h(__('—')) ?></span>
                                <?php else: ?>
                                    <a class="vpa-chip vpa-chip-link"
                                       href="<?= h($baseurl)
                                           ?>/events/view/<?=
                                           (int)$row['event']['id'] ?>"
                                       title="<?= h(sprintf(
                                           __('The event holding the most'
                                               . ' recently written of'
                                               . ' these rows: %s'),
                                           $row['event']['info'] === null
                                               ? __('(no title)')
                                               : $row['event']['info']
                                       )) ?>">
                                        <span class="misp-icon
                                                     misp-icon-event
                                                     misp-simple"></span>
                                        <?= h('#' . $row['event']['id']) ?>
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td class="vp-ctable-org">
                                <?php
                                /*
                                 * `.vpa-orglink` — the same affordance
                                 * the thread's meta line and the report
                                 * list already use for an organisation:
                                 * inherited colour, underlined on
                                 * hover, so a column of them is not a
                                 * column of blue. Unlinked where the
                                 * organisation no longer resolves,
                                 * which is the report list's guard.
                                 */
                                ?>
                                <?php if ($row['org_id'] === null): ?>
                                    <?= h($row['org']) ?>
                                <?php else: ?>
                                    <a class="vpa-orglink"
                                       href="<?= h($baseurl)
                                           ?>/organisations/view/<?=
                                           (int)$row['org_id'] ?>"
                                       title="<?= h(sprintf(
                                           __('%s — the creating'
                                               . ' organisation of the'
                                               . ' events these rows sit'
                                               . ' in. Opens it.'),
                                           $row['org']
                                       )) ?>"><?= h($row['org']) ?></a>
                                <?php endif; ?>
                            </td>
                            <td class="vp-ctable-when"
                                title="<?= h(sprintf(
                                    __('Oldest of these rows: %s'),
                                    gmdate('Y-m-d', $row['first_at'])
                                )) ?>"><?=
                                h(gmdate('Y-m-d', $row['last_at']))
                            ?><span class="vp-ctable-age"><?=
                                h($age($row['last_at']))
                            ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if (!empty($comments['capped'])): ?>
            <p class="vp-aside-note px-3 pb-2"><?= h(sprintf(
                __('Showing the %1$s most recently written of %2$s'
                    . ' distinct comments. There is no page control'
                    . ' here: the counts beside each row are over every'
                    . ' occurrence whatever this list shows.'),
                count($rows),
                $comments['total']
            )) ?></p>
        <?php endif; ?>
    <?php endif; ?>

</div>
