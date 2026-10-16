<?php
/**
 * The proposals that propose *adding* this value.
 *
 * **`value-intelligence-coverage.md` §2.2's defect made visible.** A
 * proposal with `old_id = 0` proposes a new attribute rather than a
 * change to an existing one, so nothing in `attributes` holds the value
 * yet and every occurrence read on this page returns nothing for it.
 * `123.123.123.1` is proposed on event 195 and was rendering as §2.12's
 * unknown page; this block is what the tab was missing.
 *
 * **Beside the table and never inside it.** §5.1's counting question
 * has one answer — a proposal is not an attribute row and the header
 * should not say it is — and the table above states *N attribute rows
 * across M events*, counts facets over those rows in the rail, and
 * sorts and pages them in script. Folding these in would have had all
 * three counting a row of a table it is not a row of. Every number the
 * table prints is the number it printed before this block existed.
 *
 * **No distribution badge, and that is not an omission.**
 * `shadow_attributes` has no distribution column: a proposal's audience
 * is exactly its event's, and the event is named and linked on every
 * row here. A badge would restate what the link already leads to.
 *
 * **Withdrawn proposals stay, struck through**, the way phase 26's
 * report list keeps withdrawn reports — somebody wrote it and somebody
 * discarded it, and both are part of what happened to this value.
 *
 * Rendered from `value_occurrence_table.ctp`, off the same
 * `forOccurrenceTable` read, so the block and the table cannot be
 * answering two different fetches.
 *
 * @var array $proposals From `ValueIntelligence::forOccurrenceTable`
 */
$rows = $proposals['rows'];

$subtitle = implode(' &nbsp;·&nbsp; ', array_filter(array(
    h(sprintf(
        __n(
            '%s proposed addition',
            '%s proposed additions',
            (int)$proposals['total']
        ),
        (int)$proposals['total']
    )),
    (int)$proposals['withdrawn'] > 0
        ? h(sprintf(
            __n('%s withdrawn', '%s withdrawn', $proposals['withdrawn']),
            (int)$proposals['withdrawn']
        ))
        : null,
    h(__('newest first')),
)));
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--vp-tl-proposal);"
     data-vp-standalone-proposals>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Proposed additions'),
        'panelIcon' => 'fas fa-code-pull-request',
        'panelColor' => 'var(--vp-tl-proposal)',
        'panelSub' => $subtitle,
    )) ?>

    <div class="p-3 d-flex flex-column gap-2">

        <?php
        /*
         * The sentence the block exists to make, and it is made once
         * rather than per row: these are not occurrences, and what
         * makes them worth a panel is precisely that no occurrence read
         * can reach them.
         */
        ?>
        <div class="vp-filter-note mb-1">
            <i class="fas fa-circle-info"></i>
            <span><?= h(__(
                'These are pending attributes, not occurrences. Nothing'
                . ' has been added to the events below — an'
                . ' organisation has asked for it.'
            )) ?></span>
        </div>

        <?php foreach ($rows as $row): ?>
            <div class="vp-sap<?= $row['deleted'] ? ' vp-sap-gone' : '' ?>">

                <div class="d-flex align-items-center gap-2 flex-wrap">
                    <?php
                    /*
                     * No *Proposed* badge, though the occurrence table's
                     * State column carries one. There a badge marks the
                     * rows that are not ordinary among rows that are;
                     * here every row is a proposed addition and the
                     * heading says so, so a badge on each would be the
                     * panel title repeated once per row — and repeated
                     * directly beside *Withdrawn*, which is the one
                     * word on the row that does distinguish anything.
                     */
                    ?>
                    <?php if ($row['deleted']): ?>
                        <span class="badge d-inline-flex align-items-center
                                     gap-1 bg-secondary-subtle
                                     text-secondary-emphasis
                                     border border-secondary-subtle"
                              title="<?= h(__(
                                  'Withdrawn — the proposal was'
                                  . ' discarded, not accepted'
                              )) ?>">
                            <i class="fas fa-trash"></i>
                            <?= h(__('Withdrawn')) ?>
                        </span>
                    <?php endif; ?>
                    <span class="vp-sap-value"><?= h($row['value']) ?></span>
                    <span class="vp-sap-type"><?= h($row['type']) ?></span>
                    <?php
                    /*
                     * The flag the proposal asks for, stated only when
                     * it is set: `to_ids` defaults to 1 on most types
                     * and a badge on every row would carry no signal,
                     * where its absence on a row that could have had it
                     * does.
                     */
                    ?>
                    <?php if ($row['to_ids']): ?>
                        <span class="badge bg-body-secondary
                                     text-body-secondary
                                     border border-secondary-subtle"
                              title="<?= h(__(
                                  'The proposal asks for this to be'
                                  . ' actionable by an IDS'
                              )) ?>">
                            <?= h(__('IDS')) ?>
                        </span>
                    <?php endif; ?>
                </div>

                <?php if ((string)$row['comment'] !== ''): ?>
                    <div class="vp-sap-comment"><?= h($row['comment']) ?></div>
                <?php endif; ?>

                <div class="vp-sap-meta">
                    <span class="misp-icon misp-icon-organisation
                                 misp-simple me-1"></span>
                    <?php if (empty($row['org_id'])): ?>
                        <?= h($row['org']) ?>
                    <?php else: ?>
                        <a class="vpa-orglink"
                           href="<?= h($baseurl) ?>/organisations/view/<?=
                               (int)$row['org_id'] ?>"><?=
                            h($row['org']) ?></a>
                    <?php endif; ?>
                    &nbsp;·&nbsp;
                    <i class="fas fa-calendar-days me-1"></i>
                    <a href="<?= h($baseurl) ?>/events/view/<?=
                           (int)$row['event']['id'] ?>"><?= h(
                        $row['event']['info'] === null
                            ? sprintf(__('Event %s'), $row['event']['id'])
                            : $row['event']['info']
                    ) ?></a>
                    &nbsp;·&nbsp;
                    <i class="fas fa-tag me-1"></i>
                    <?= h($row['category']) ?>
                    <?php if ($row['timestamp'] > 0): ?>
                        &nbsp;·&nbsp;
                        <i class="fas fa-clock me-1"></i>
                        <?= h(gmdate('Y-m-d', (int)$row['timestamp'])) ?>
                    <?php endif; ?>
                </div>

            </div>
        <?php endforeach; ?>

    </div>

    <?php if (!empty($proposals['capped'])): ?>
        <div class="vp-acl-note">
            <i class="fas fa-layer-group"></i>
            <span><?= h(sprintf(
                __(
                    'Showing the %1$s most recent of %2$s proposed'
                    . ' additions you can see.'
                ),
                count($rows),
                $proposals['total']
            )) ?></span>
        </div>
    <?php endif; ?>

</div>
