<?php
/**
 * The most recent analyst notes and opinions on this value.
 *
 * A preview: the thread, the replies, the proposals, the event reports
 * and the full opinion distribution belong to the Collaboration tab.
 * `AnalystData/thread` is not reused here because it carries the add /
 * edit / delete controls, and nothing on this page writes.
 *
 * Off `ValueIntelligence::forAnalystPreview` and therefore off the same
 * union the tab reads, so the counts here and one tab across agree.
 *
 * **Newest first across both kinds**, so a card headed *the most
 * recent* never puts a two-year-old note above yesterday's opinion.
 *
 * **The event-report count lands here** rather than as a seventh fact
 * cell, which is where `29-overview.md` §10 recommended it and §14.8
 * deferred it: this card already mirrors the tab that holds the list,
 * and the fact strip is full at six. It is a count and never a row —
 * the documents are the tab's third panel.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewAnalystPreview.
 *
 * @var array $valueIntelligence
 */
$analyst = $valueIntelligence['analyst'];
$counts = $analyst['counts'];
$items = $analyst['preview'];
$written = (int)$counts['notes'] + (int)$counts['opinions'];
$shown = count($items);

/*
 * **The split, borrowed whole from the Collaboration tab.** Phase 31
 * §5 left *investigate other small widgets you could bring from other
 * panes* open, and this is the one that costs nothing to take: the
 * union behind this card already builds the ledger the tab's standing
 * panel draws, and `forAnalystPreview` used to throw it away.
 *
 * Only the bar comes over, and not the lane ledger under it. The bar
 * is *how many fall each way*, which is a shape a reader takes in
 * without reading anything; the ledger is one lane, one score, one
 * organisation and one date per opinion, which is a table — and the
 * Overview already sent its tables to the tabs that own them.
 *
 * **It is also the only thing on this card that is not capped.** The
 * list under it is the newest four items of any kind, so a value with
 * two notes and six opinions can fill it with notes and show no
 * opinion at all; the bar counts every opinion that rates the value.
 * That is what earns it the ~72px rather than merely the fact that it
 * was free.
 *
 * Absent on a value nobody has rated — which on the verification
 * instance is four values of five. A bar over no opinions would be an
 * empty state inside a card that already has one.
 */
$standing = isset($analyst['standing']) ? $analyst['standing'] : null;
$split = ($standing === null || empty($standing['orgs']))
    ? null
    : $standing['orgs'];

$subtitle = implode(' &nbsp;·&nbsp; ', array_filter(array(
    h(sprintf(
        __n('%s note', '%s notes', (int)$counts['notes']),
        (int)$counts['notes']
    )),
    h(sprintf(
        __n('%s opinion', '%s opinions', (int)$counts['opinions']),
        (int)$counts['opinions']
    )),
    /*
     * Proposals are counted here and drawn on the tab. The card says
     * they exist because the alternative is a subtitle that reads
     * `0 notes · 0 opinions` over a value three organisations have
     * proposed edits to.
     */
    (int)$counts['proposals'] > 0
        ? h(sprintf(
            __n('%s proposal', '%s proposals', (int)$counts['proposals']),
            (int)$counts['proposals']
        ))
        : null,
    /*
     * **On its events, and the phrase is the point.** Notes and
     * opinions reach this value through five kinds of anchor; an event
     * report attaches to an event and to nothing smaller, so a bare
     * `8 reports` beside `3 notes` would read as eight documents about
     * the value. The tab's panel spends a header saying so, and this
     * chip says it in three words.
     *
     * The number is the panel's headline total — withdrawn reports
     * included, because that is what the panel counts before it
     * qualifies itself.
     */
    (int)$counts['reports'] > 0
        ? h(sprintf(
            __n(
                '%s report on its events',
                '%s reports on its events',
                (int)$counts['reports']
            ),
            (int)$counts['reports']
        ))
        : null,
    $shown > 0 && $shown < $written
        ? h(sprintf(__('showing the %s most recent'), $shown))
        : null,
)));

/**
 * One item's organisation, author and date.
 *
 * The organisation opens, under §18.1's rule that a chip naming a
 * record is a link to that record — the thread's meta line, the report
 * rows and the ledger already follow it.
 *
 * @param array $item
 * @return string
 */
$meta = function ($item) use ($baseurl) {
    $bits = array();
    $bits[] = '<span class="misp-icon misp-icon-organisation'
        . ' misp-simple me-1"></span>'
        . (empty($item['org_id'])
            ? h($item['org'])
            : '<a class="vpa-orglink" href="' . h($baseurl)
                . '/organisations/view/' . (int)$item['org_id'] . '">'
                . h($item['org']) . '</a>');
    // Free text on the row and not a user reference, so it is printed
    // and never linked.
    if (!empty($item['author'])) {
        $bits[] = '<i class="fas fa-user me-1"></i>' . h($item['author']);
    }
    if (!empty($item['date'])) {
        $bits[] = '<i class="fas fa-clock me-1"></i>' . h($item['date']);
    }
    return implode(' &nbsp;·&nbsp; ', $bits);
};

/*
 * Nothing written is a state, and which state depends on what else the
 * tab found. A value nobody has written about, a value three
 * organisations have proposed edits to, and a value whose events carry
 * eight reports are not the same emptiness, and this card previews a
 * tab that holds all three.
 *
 * The clauses are composed rather than enumerated because there are now
 * four cases and the fourth — both — is the one a pair of ternaries
 * would have dropped.
 */
$elsewhere = array_filter(array(
    (int)$counts['proposals'] > 0 ? __('proposals on it') : null,
    (int)$counts['reports'] > 0
        ? __('event reports on its events')
        : null,
));
$emptyText = empty($elsewhere)
    ? __('No analyst has written about this value.')
    : sprintf(
        __(
            'Nobody has written a note or an opinion about this value,'
            . ' but there are %s.'
        ),
        implode(__(' and '), $elsewhere)
    );

// Nothing on the tab means nothing to open, so the affordance goes too.
$hasTab = $written > 0 || !empty($elsewhere);
$headerExtra = !$hasTab ? null : '<a href="#tab-analyst"'
    . ' class="btn btn-sm btn-outline-secondary d-flex align-items-center'
    . ' gap-1" title="' . h(__('The full thread')) . '">'
    . h(__('Open thread')) . '<i class="fas fa-arrow-right"></i></a>';
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-preview>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Analyst data'),
        'panelIcon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if ($split !== null): ?>
        <?php
        /*
         * Above the items and never beside them: the split is what the
         * four rows under it add up to, and a summary that follows its
         * own evidence is a summary a reader has already done without.
         *
         * **The lead carries the denominator, where the tab's does
         * not.** This card's sub-line is headed *2 notes · 4 opinions
         * · 1 proposal*, and those opinions are counted by
         * `analystCounts` — top-level items of any anchor — while the
         * bar is over `analystStanding`'s, which are opinions at any
         * depth that rate the value. On the flagship both are 4 and on
         * `127.0.0.1` both are 1; they are not the same set and
         * nothing guarantees they agree, so the bar states its own.
         */
        ?>
        <div class="vp-analyst-split">
            <?= $this->element('Values/View/value_analyst_tug', array(
                'tugOrgs' => $split,
                'tugLead' => sprintf(
                    __n(
                        'The split — %d opinion on the value',
                        'The split — %d opinions on the value',
                        count($split)
                    ),
                    count($split)
                ),
            )) ?>
        </div>
    <?php endif; ?>

    <?php if ($shown === 0): ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-analyst-note misp-simple"></span>
            <span><?= h($emptyText) ?></span>
        </div>
    <?php else: ?>
        <div class="p-3 d-flex flex-column gap-2">

            <?php foreach ($items as $item):
                $isOpinion = $item['kind'] === 'opinion';
                ?>
                <div class="vp-analyst vp-analyst-<?=
                    $isOpinion ? 'opinion' : 'note' ?>">
                    <div class="vp-analyst-kind">
                        <span class="misp-icon misp-icon-analyst-<?=
                            $isOpinion ? 'opinion' : 'note'
                        ?> misp-simple"></span>
                        <?= $isOpinion ? __('Opinion') : __('Note') ?>
                    </div>
                    <div class="vp-analyst-body">
                        <?php if ($isOpinion): ?>
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <?php
                                /*
                                 * **Coloured by the score against 50,
                                 * never by the band word.** That is
                                 * MISP's own rule, not this page's:
                                 * `Analyst_data/opinion_scale.ctp`
                                 * computes `$opinion > 50 ? green :
                                 * red`, greys exactly 50, and paints
                                 * the band word and the numeral with
                                 * it. The five words split at
                                 * 20/40/60/80 and agreement splits at
                                 * 50, so the word is not what carries
                                 * the side — the score is, and a
                                 * `Neutral` at 45 is red where a
                                 * `Neutral` at 55 is green.
                                 *
                                 * The card used to colour by *band*:
                                 * 61+ green, 41-60 grey, 40 and below
                                 * red. That is what made it half of
                                 * `05-analyst.md` §11's contradiction —
                                 * it painted a disagreeing 45 the same
                                 * grey as an agreeing 60. The fix is
                                 * the pivot, not the absence of colour.
                                 *
                                 * `reads` is resolved in the facade off
                                 * the same 50, so this badge and the
                                 * tab's ledger take one side per score.
                                 */
                                $side = array(
                                    'malicious' => 'agree',
                                    'benign' => 'dispute',
                                );
                                $side = isset($side[$item['reads']])
                                    ? $side[$item['reads']]
                                    : 'neither';
                                ?>
                                <span class="vpa-reading vpa-s-<?=
                                          h($side) ?>"
                                      title="<?= h(__(
                                          'MISP colours an opinion by'
                                          . ' its score against 50 —'
                                          . ' above it agrees with what'
                                          . ' the record asserts, below'
                                          . ' it disagrees, and exactly'
                                          . ' 50 takes no side.'
                                      )) ?>">
                                    <i></i><?= h($item['label']) ?>
                                    &middot;
                                    <?= (int)$item['score'] ?>/100
                                </span>
                                <?php
                                /*
                                 * An opinion the ledger leaves out, in
                                 * the tab's own words rather than in
                                 * this card's. Only one of the two
                                 * cases can reach a preview — these are
                                 * roots, so nothing here hangs off the
                                 * item above it — but a root whose
                                 * anchor no longer resolves is D5's row
                                 * and is drawn because somebody wrote
                                 * it. Saying *rates a note* over one of
                                 * those would be this card inventing a
                                 * target the row does not have.
                                 */
                                ?>
                                <?php if ($item['rates'] !== 'value'): ?>
                                    <span class="vpa-chip"><?= h(
                                        $item['attached_to']['kind']
                                            === 'unresolved'
                                            ? __(
                                                'the row this hangs off'
                                                . ' does not resolve —'
                                                . ' not in the aggregate'
                                            )
                                            : __(
                                                'about the item above,'
                                                . ' not about the value'
                                                . ' — not in the'
                                                . ' aggregate'
                                            )
                                    ) ?></span>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                        <?php if ($item['body'] !== ''): ?>
                            <div class="vp-analyst-text"><?=
                                h($item['body'])
                            ?></div>
                        <?php endif; ?>
                        <div class="vp-analyst-meta"><?= $meta($item) ?></div>
                    </div>
                </div>
            <?php endforeach; ?>

        </div>
    <?php endif; ?>

</div>
