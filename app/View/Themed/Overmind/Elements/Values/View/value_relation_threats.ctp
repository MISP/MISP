<?php
/**
 * The rail's third card: which named threats this value sits next to.
 *
 * The only thing on this tab that answers *what does this mean* rather
 * than *what is related*. Every section beside it lists edges; this
 * names the actors, campaigns, malware and tooling reachable through
 * the value, which is the read every peer platform leads with.
 *
 * **A named threat is a galaxy cluster**, and the card says so in the
 * subtitle by naming the four kinds rather than by using the phrase
 * and leaving it to be guessed. `GalaxyCategory` holds the rule and
 * the evidence — in short, freetext tags cannot carry the claim (the
 * two most-used on the verification instance are the word `malware`
 * and ` C2`, and one malware family appears under seven spellings)
 * and no installed taxonomy names an individual threat, they classify
 * one.
 *
 * **Clusters wear MISP's own cluster chip**, in their galaxy's hue, so a
 * Threat Actor cluster is the same colour here as on the event page.
 * That is a galaxy hue, not one of this tab's seven notion hues, so the
 * notion grammar is untouched.
 *
 * **The counts at the top are the filter.** They were a static
 * composition line first, which told a reader the neighbourhood held
 * 63 malware and then gave them no way to see them. As pills they
 * answer the same question and act on it: picking a kind shows every
 * cluster of that kind rather than the eight the card opens with, and
 * the per-row kind label goes away while it is picked because the
 * pill already says it.
 *
 * **A second group under them: where in the intrusion.** The same
 * events' attack-pattern clusters, folded to their tactics and laid
 * out in kill-chain order — what stage, where the list above says who.
 * It is a group on this card rather than a card of its own because the
 * two are folded from the same events and the tab does not grow, and a
 * strip rather than a list because the *order* is the finding: the
 * chips are not ranked by count, they run the chain.
 *
 * Three things it has to keep saying, all in the note under it. A
 * technique filed under two tactics counts in both, so the chips total
 * more than the techniques folded. A technique whose galaxy ships no
 * kill chain is in none of them and is counted separately. And a value
 * whose techniques span two galaxies gets two chains laid end to end,
 * which the single run of chips would otherwise pass off as one — so
 * the note says how many, and each chip's hover names its own.
 *
 * Lazily loaded from ValuesController::viewRelationThreats.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$relations = $profile['relationships'];
$threats = $relations['threats'];

$rows = isset($threats['rows']) ? $threats['rows'] : array();
$total = isset($threats['total']) ? (int)$threats['total'] : 0;
$cap = isset($threats['cap']) ? (int)$threats['cap'] : 8;

/*
 * The card's second group, which answers *what stage* where the list
 * above answers *who* — the same events' attack-pattern clusters folded
 * to their tactics and laid out in kill-chain order. Defaulted rather
 * than assumed: a scan cached before this group existed carries no
 * `tactics` key, and §6.2's rule retires those payloads at the deploy
 * while the template has to survive the one read that beats it.
 */
$tactics = isset($relations['tactics']) ? $relations['tactics'] : array();
$tacticRows = isset($tactics['rows']) ? $tactics['rows'] : array();
$techniques = isset($tactics['techniques'])
    ? (int)$tactics['techniques']
    : 0;
$unplaced = isset($tactics['unplaced']) ? (int)$tactics['unplaced'] : 0;
$multi = isset($tactics['multi']) ? (int)$tactics['multi'] : 0;
$frameworks = isset($tactics['frameworks'])
    ? (int)$tactics['frameworks']
    : 0;
$eventsRead = isset($threats['events_read'])
    ? (int)$threats['events_read']
    : 0;
$eventCap = isset($threats['event_cap'])
    ? (int)$threats['event_cap']
    : 0;

$kindWords = array(
    'actor' => __('actor'),
    'campaign' => __('campaign'),
    'malware' => __('malware'),
    'tool' => __('tool'),
);
/* Pill labels, which count them. */
$kindLabels = array(
    'actor' => __('Actors'),
    'campaign' => __('Campaigns'),
    'malware' => __('Malware'),
    'tool' => __('Tools'),
);
/*
 * The two attachments worth a word on the row. `event` is the ordinary
 * case and gets none — a mark on every row is not a mark. `neighbour`
 * arrived with §10.2: the card reads the co-occurrence fold now, and
 * that fold sees a cluster tagged on an attribute *beside* this value
 * as well as on the value and on the event. It is a real third way in
 * and the reader should be told which one they are looking at.
 *
 * Same words as the co-occurrence table's own `$attachMark`, because
 * this card is a slice of that table.
 */
$marks = array(
    'value' => __('on the value'),
    'neighbour' => __('on a neighbour'),
);

/*
 * What a claim was written on. The card counts a claim about the
 * occurrence, about the event it is in, and about the object it sits
 * in — so the hover has to say which, or *Human claim* is two words
 * that hide the difference between a statement about this address and
 * one about a report containing it.
 */
$anchorWords = array(
    'Attribute' => __('on this value'),
    'Event' => __('on an event it appears in'),
    'Object' => __('on the object it sits in'),
    'AttributeValue' => __('on this value'),
);

/*
 * The hover card's heading word, and the same map the asserted section
 * passes, because it is the same element. Only the cluster entry is
 * ever reached from here — a row on this card is always a cluster —
 * but the element takes the map, not the word.
 */
$targetKindWords = array(
    'Event' => __('event'),
    'GalaxyCluster' => __('galaxy cluster'),
    'Object' => __('object'),
    'Attribute' => __('attribute'),
);

/* The hover card element renders itself through the view. */
$view = $this;

/**
 * Who asserted a cluster, how, and when — one line per claim.
 *
 * The row has room for two words, so this goes in the hover beside the
 * figures. The asserted section is where the whole claim, with its
 * author and its direction, is laid out properly; this is the peek.
 *
 * Returns the lines rather than a joined string, because a `\n` inside
 * markup is whitespace: joined, two claims render as one run-on
 * sentence.
 *
 * @param array $claims As `neighbourhoodThreats` recorded them
 * @return array
 */
$claimLines = function (array $claims) use ($anchorWords) {
    $lines = array();
    foreach ($claims as $claim) {
        $where = isset($anchorWords[$claim['anchor']])
            ? $anchorWords[$claim['anchor']]
            : '';
        $lines[] = trim(sprintf(
            __('%s claimed "%s" %s'),
            $claim['org'],
            $claim['type'],
            $where
        )) . ($claim['date'] === '' ? '' : ' · ' . $claim['date']);
    }
    return $lines;
};

/*
 * Names that more than one cluster carries, and they are real: MITRE
 * ships APT28 as an intrusion set in the enterprise, mobile and
 * pre-attack galaxies, so `Malicious` draws `APT28 - G0007` three
 * times with near-identical counts and it reads as a duplicated row
 * rather than as three records. Those rows name their galaxy; the
 * rest do not, because on every other row it would be a word that
 * never varies.
 */
$nameCounts = array();
foreach ($rows as $threat) {
    $key = mb_strtolower($threat['name']);
    $nameCounts[$key] = isset($nameCounts[$key])
        ? $nameCounts[$key] + 1
        : 1;
}

/* Kinds present, in the order they are worth reading. */
$kindCounts = array();
foreach (array('actor', 'campaign', 'malware', 'tool') as $kind) {
    $n = 0;
    foreach ($rows as $threat) {
        if ($threat['sub_category'] === $kind) {
            $n++;
        }
    }
    if ($n > 0) {
        $kindCounts[$kind] = $n;
    }
}

/**
 * One cluster's row.
 *
 * @param array $threat
 * @param bool $folded Beyond the opening cut, hidden until asked for
 */
$row = function (array $threat, $folded) use (
    $kindWords, $marks, $baseurl, $nameCounts, $claimLines, $view,
    $targetKindWords
) {
    $kind = isset($threat['sub_category']) ? $threat['sub_category'] : '';
    $word = isset($kindWords[$kind])
        ? $kindWords[$kind]
        : str_replace('-', ' ', $kind);
    $attachment = isset($threat['attachment'])
        ? $threat['attachment']
        : 'event';
    $key = mb_strtolower($threat['name']);
    $galaxy = !empty($nameCounts[$key]) && $nameCounts[$key] > 1
        ? $threat['galaxy']
        : null;
    $claimed = $attachment === 'claim' && !empty($threat['claims']);
    $extra = isset($marks[$attachment]) || $claimed || $galaxy !== null;
    $figures = array();
    if (!empty($threat['orgs'])) {
        $figures[] = '<span class="vp-threat-n">'
            . (int)$threat['orgs'] . '</span> '
            . h(__n('org', 'orgs', (int)$threat['orgs']));
    }
    if (!empty($threat['events'])) {
        $figures[] = '<span class="vp-threat-n">'
            . (int)$threat['events'] . '</span> '
            . h(__n('event', 'events', (int)$threat['events']));
    }
    ?>
    <li class="vp-threat<?= $folded ? ' vp-threat-folded' : '' ?>"
        data-vp-threat-kind="<?= h($kind) ?>">
        <span class="vp-threat-cell">
            <?= $this->TagChip->cluster([
                'id' => $threat['id'],
                'value' => $threat['name'],
                'galaxy' => $threat['galaxy'],
            ], ['display' => 'leaf']) ?>
            <?php if (!empty($threat['target'])): ?>
                <?php /*
                 * The asserted section's own hover card, rendered
                 * from the same element and the same target shape —
                 * everything recorded about the cluster, its tag
                 * name, its description, its audience.
                 *
                 * It is a CSS card on `:hover`/`:focus-within` rather
                 * than a `title`, which is the element's own reason
                 * and applies here twice over: this fragment arrives
                 * through `loadAjaxContainer`, so a Bootstrap tooltip
                 * declared in it would never bind, and a native
                 * `title` is not reachable from the keyboard.
                 */ ?>
                <?= $view->element(
                    'Values/View/value_claim_target_card',
                    array(
                        'target' => $threat['target'],
                        'url' => $url,
                        'kindWords' => $targetKindWords,
                    )
                ) ?>
            <?php endif; ?>
        </span>
        <?php /*
         * The figures name their own sources on hover. `2 orgs · 3
         * events` is the right size for the rail and says nothing
         * about *which*, and which is the question a reader checking
         * corroboration actually has — one organisation reporting a
         * cluster three times is not three organisations agreeing.
         *
         * Built from the shared card's classes rather than from its
         * element: that element is documented as being about a claim's
         * target and nothing else, and this is about the row's
         * evidence. Same look, different subject.
         */ ?>
        <span class="vp-threat-right vp-claim-tipwrap">
            <span class="vp-threat-kind"><?= h($word) ?></span>
            <span class="vp-threat-figs"><?= implode(
                ' <span class="vp-threat-sep">·</span> ',
                $figures
            ) ?></span>
            <?php if (!empty($threat['org_names'])
                || !empty($threat['event_list'])
            ): ?>
                <span class="vp-claim-tip" role="tooltip">
                    <span class="vp-claim-tiphead"><?=
                        h(__('Where this comes from')) ?></span>
                    <?php if (!empty($threat['org_names'])): ?>
                        <span class="vp-claim-tiprow">
                            <b><?= h(__('Organisations')) ?></b>
                            <span><?= h(implode(', ',
                                $threat['org_names'])) ?></span>
                        </span>
                    <?php endif; ?>
                    <?php if (!empty($threat['event_list'])): ?>
                        <span class="vp-claim-tiprow">
                            <b><?= h(sprintf(
                                __('Events (%d)'),
                                count($threat['event_list'])
                            )) ?></b>
                            <span class="vp-threat-tipevents">
                                <?php foreach (array_slice(
                                    $threat['event_list'], 0, 6
                                ) as $event): ?>
                                    <span class="vp-threat-tipevent">
                                        <a class="vp-claim-link"
                                           href="<?= $baseurl
                                               ?>/events/view2/<?=
                                               h($event['id']) ?>">#<?=
                                               h($event['id']) ?></a>
                                        <?= h($event['info'] === ''
                                            ? $event['date']
                                            : $event['info']) ?>
                                    </span>
                                <?php endforeach; ?>
                                <?php $spare = count(
                                    $threat['event_list']
                                ) - 6; ?>
                                <?php if ($spare > 0): ?>
                                    <span class="vp-threat-tipevent">
                                        <?= h(sprintf(
                                            __('and %d more'),
                                            $spare
                                        )) ?>
                                    </span>
                                <?php endif; ?>
                            </span>
                        </span>
                    <?php endif; ?>
                    <?php if (!empty($threat['claims'])): ?>
                        <span class="vp-claim-tiprow">
                            <b><?= h(sprintf(
                                __('Claims (%d)'),
                                count($threat['claims'])
                            )) ?></b>
                            <span class="vp-threat-tiplines">
                                <?php foreach ($claimLines(
                                    $threat['claims']
                                ) as $line): ?>
                                    <span><?= h($line) ?></span>
                                <?php endforeach; ?>
                            </span>
                        </span>
                    <?php endif; ?>
                </span>
            <?php endif; ?>
        </span>
        <?php if ($extra): ?>
            <span class="vp-threat-extra">
                <?php if ($claimed): ?>
                    <?php /*
                     * The tab's own human-claim mark, **word
                     * included**: `.vp-rel-prov-human`, `fa-user-pen`
                     * and the words *Human claim* are what the
                     * asserted and references panels already use to
                     * say *a person wrote this*, and `--vp-rel-human`
                     * is that notion's colour.
                     *
                     * This card first said *claimed by an analyst*,
                     * which is the same notion under a second name.
                     * The separation rule this tab carries four times
                     * over — colour, form, **word**, place — only
                     * works if the word is the same word everywhere,
                     * so a synonym weakens the thing the styling was
                     * borrowed to reinforce.
                     */ ?>
                    <?php /*
                     * No `title` on the mark any more: who claimed
                     * what is in the figures hover beside it, which
                     * is findable and keyboard-reachable where a
                     * native tooltip was neither.
                     */ ?>
                    <span class="vp-rel-prov vp-rel-prov-human">
                        <i class="fas fa-user-pen" aria-hidden="true"></i>
                        <?= h(__('Human claim')) ?>
                    </span>
                <?php endif; ?>
                <?php if (isset($marks[$attachment])): ?>
                    <span class="vp-threat-mark"><?=
                        h($marks[$attachment]) ?></span>
                <?php endif; ?>
                <?php if ($galaxy !== null): ?>
                    <span class="vp-threat-galaxy"><?=
                        h($galaxy) ?></span>
                <?php endif; ?>
            </span>
        <?php endif; ?>
    </li>
    <?php
};
?>
<div class="card shadow-sm mb-3 vp-panel" data-vp-threats
     data-vp-threat-view="top"
     style="--vp-panel-color: var(--bs-secondary-color);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Named threats in this neighbourhood'),
        'panelIcon' => 'misp-icon misp-icon-galaxy misp-simple',
        'panelColor' => 'var(--bs-secondary-color)',
        /*
         * The subtitle is where *named threat* gets defined, by naming
         * the four kinds. It also carries the scope and the age, so
         * the card needs no footer — the first cut had one that
         * repeated the scope already stated here.
         */
        'panelSub' => h(__('Actors, campaigns, malware or tools'))
            . '&nbsp;·&nbsp;' . h(sprintf(
                __n('%d event', '%d events', $eventsRead),
                $eventsRead
            )) . '&nbsp;·&nbsp;' . $this->element(
            'Values/View/value_read_age',
            array(
                'readAt' => isset($relations['read_at'])
                    ? $relations['read_at'] : 0,
                'prefix' => __('read %s'),
            )
        ),
    )) ?>

    <div class="p-3">
        <?php if (empty($rows)): ?>
            <div class="vp-threat-none">
                <?php if ($eventsRead === 0): ?>
                    <?= h(__(
                        'This value is in no event you may read, so'
                        . ' there is no neighbourhood to name.'
                    )) ?>
                <?php elseif (!empty($tacticRows)): ?>
                    <?php /*
                     * The neighbourhood names no threat but does name
                     * behaviour, so the card is not empty and the long
                     * form below would be the wrong length: the group
                     * under it is about to say what *was* found, and
                     * this only has to say what was not.
                     */ ?>
                    <?= h(sprintf(
                        __n(
                            'No actor, campaign, malware or tool is'
                            . ' named in this value\'s %d event.',
                            'No actor, campaign, malware or tool is'
                            . ' named in this value\'s %d events.',
                            $eventsRead
                        ),
                        $eventsRead
                    )) ?>
                <?php else: ?>
                    <?= h(sprintf(
                        __n(
                            'Nothing in this value\'s %d event names an'
                            . ' actor, a campaign, malware or a tool.',
                            'Nothing in this value\'s %d events names an'
                            . ' actor, a campaign, malware or a tool.',
                            $eventsRead
                        ),
                        $eventsRead
                    )) ?>
                <?php endif; ?>
            </div>
        <?php else: ?>

            <?php if (count($kindCounts) > 1 || $total > $cap): ?>
                <div class="vp-pillgroup vp-threat-filters" role="group"
                     aria-label="<?= h(__('Show one kind of threat')) ?>">
                    <button type="button" class="vp-pill active"
                            data-vp-threat-filter="top"
                            aria-pressed="true">
                        <?= h(__('All')) ?>
                        <span class="vp-pill-n"><?= (int)$total ?></span>
                    </button>
                    <?php foreach ($kindCounts as $kind => $n): ?>
                        <button type="button" class="vp-pill"
                                data-vp-threat-filter="<?= h($kind) ?>"
                                aria-pressed="false">
                            <?= h($kindLabels[$kind]) ?>
                            <span class="vp-pill-n"><?= (int)$n ?></span>
                        </button>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <ul class="vp-threat-list">
                <?php foreach ($rows as $i => $threat) {
                    $row($threat, $i >= $cap);
                } ?>
            </ul>

            <?php if ($total > $cap): ?>
                <button type="button" class="vp-threat-more"
                        data-vp-threat-expand>
                    <?= h(sprintf(
                        __('Show %d more'),
                        $total - $cap
                    )) ?>
                </button>
            <?php endif; ?>
        <?php endif; ?>

        <?php if (!empty($tacticRows)): ?>
            <?php /*
             * **Where in the intrusion**, and it is a group rather than
             * more rows above because it answers a different question:
             * what stage, not who. The two share the card because they
             * are folded from the same events, and the tab's own rule
             * is that a new element lands inside an existing panel.
             *
             * Chips in kill-chain order, not ranked by count — the
             * order is the reading. Every other list on this tab ranks
             * by corroboration, and a tactic mix sorted that way would
             * still say which tactics dominate while losing the one
             * thing that makes it a *chain*: that a value ringed by
             * discovery and defence evasion sits somewhere different
             * from one ringed by exfiltration and impact.
             */ ?>
            <div class="vp-tactics">
                <div class="vp-subhead">
                    <?= h(__('Where in the intrusion')) ?>
                </div>
                <ul class="vp-tactic-list">
                    <?php foreach ($tacticRows as $tactic): ?>
                        <li class="vp-tactic vp-claim-tipwrap<?=
                            $tactic['position'] === null
                                ? ' vp-tactic-unplaced'
                                : '' ?>">
                            <span class="vp-tactic-name"><?=
                                h($tactic['name']) ?></span>
                            <span class="vp-tactic-n"><?=
                                (int)$tactic['techniques'] ?></span>
                            <?php /*
                             * The card's own hover, same classes as the
                             * figures above it: a chip has room for a
                             * name and a number, and *which techniques*
                             * is the question the number raises.
                             *
                             * No `placeThreatTip` call for these, and
                             * none needed — that function exists for
                             * the rows inside the scrolling list, whose
                             * card has to go `fixed` to escape an
                             * `overflow` ancestor. This group sits
                             * outside that box in every view, so the
                             * stylesheet places it.
                             */ ?>
                            <span class="vp-claim-tip" role="tooltip">
                                <span class="vp-claim-tiphead"><?=
                                    h(sprintf(
                                        __n(
                                            '%d technique in this'
                                                . ' tactic',
                                            '%d techniques in this'
                                                . ' tactic',
                                            (int)$tactic['techniques']
                                        ),
                                        (int)$tactic['techniques']
                                    )) ?></span>
                                <span class="vp-claim-tiprow">
                                    <span class="vp-threat-tipevents">
                                        <?php foreach (array_slice(
                                            $tactic['technique_names'],
                                            0,
                                            6
                                        ) as $name): ?>
                                            <span
                                                class="vp-threat-tipevent"
                                            ><?= h($name) ?></span>
                                        <?php endforeach; ?>
                                        <?php $spare = count(
                                            $tactic['technique_names']
                                        ) - 6; ?>
                                        <?php if ($spare > 0): ?>
                                            <span
                                                class="vp-threat-tipevent"
                                            ><?= h(sprintf(
                                                __('and %d more'),
                                                $spare
                                            )) ?></span>
                                        <?php endif; ?>
                                    </span>
                                </span>
                                <?php /*
                                 * A plain line rather than one of the
                                 * card's labelled rows: that label
                                 * column is a fixed 5.9rem so the
                                 * claim card's four sections line up
                                 * as one table, and a single `Seen on`
                                 * against it is a label stranded from
                                 * its own figures.
                                 */ ?>
                                <?php if (!empty($tactic['galaxies'])): ?>
                                    <?php /*
                                     * Whose kill chain this tactic is
                                     * on. The strip is one ordered run
                                     * of chips, so a value carrying
                                     * two frameworks' techniques would
                                     * otherwise read as one chain
                                     * running past `Impact` — which
                                     * none of them claims.
                                     */ ?>
                                    <span class="vp-tactic-tipfoot"><?=
                                        h(sprintf(
                                            __('From the %s galaxy'),
                                            implode(
                                                ', ',
                                                $tactic['galaxies']
                                            )
                                        )) ?></span>
                                <?php endif; ?>
                                <span class="vp-tactic-tipfoot"><?=
                                    h(sprintf(
                                        __('Seen on %s · %s'),
                                        sprintf(
                                            __n(
                                                '%d event',
                                                '%d events',
                                                (int)$tactic['events']
                                            ),
                                            (int)$tactic['events']
                                        ),
                                        sprintf(
                                            __n(
                                                '%d organisation',
                                                '%d organisations',
                                                (int)$tactic['orgs']
                                            ),
                                            (int)$tactic['orgs']
                                        )
                                    )) ?></span>
                                <?php if ($tactic['position'] === null): ?>
                                    <span class="vp-tactic-tipfoot"><?=
                                        h(__(
                                            'Its galaxy states no kill'
                                            . ' chain, so this tactic'
                                            . ' has no place in the'
                                            . ' order.'
                                        )) ?></span>
                                <?php endif; ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <?php
                /*
                 * The chips are not a partition of what they count: a
                 * reader adding them up gets more than the techniques
                 * folded, and one whose galaxy ships no kill chain is
                 * in none of them. Both belong on the card, neither is
                 * worth a line of a rail this narrow — so the count
                 * stays and the qualifiers hang off its glyph.
                 */
                $tacticMore = array();
                if ($multi > 0) {
                    $tacticMore[] = sprintf(
                        __n(
                            '%d of them sits in more than one tactic'
                            . ' and counts in each.',
                            '%d of them sit in more than one tactic'
                            . ' and count in each.',
                            $multi
                        ),
                        $multi
                    );
                }
                if ($unplaced > 0) {
                    $tacticMore[] = sprintf(
                        __n(
                            '%d names no tactic and is in none of'
                            . ' these counts.',
                            '%d name no tactic and are in none of'
                            . ' these counts.',
                            $unplaced
                        ),
                        $unplaced
                    );
                }
                if ($frameworks > 1) {
                    $tacticMore[] = sprintf(
                        __(
                            'They come from %d galaxies, each ordered'
                            . ' by its own kill chain — hover a tactic'
                            . ' for which.'
                        ),
                        $frameworks
                    );
                }
                ?>
                <p class="vp-tactic-note">
                    <?= h(sprintf(
                        __n(
                            'Folded from %d technique on these events.',
                            'Folded from %d techniques on these events.',
                            $techniques
                        ),
                        $techniques
                    )) ?>
                    <?php if (!empty($tacticMore)): ?>
                        <i class="fas fa-circle-info vp-cap-more"
                           title="<?= h(implode(' ', $tacticMore)) ?>"
                        ></i>
                    <?php endif; ?>
                </p>
            </div>
        <?php endif; ?>

        <?php /*
         * The event cap applies to both groups and to the empty state's
         * own count, so it sits outside them. Inside the named-threat
         * branch it was a note a value with no named threats never got
         * to see, over a sentence already quoting the capped number.
         */ ?>
        <?php if ($eventCap > 0 && $eventsRead >= $eventCap): ?>
            <p class="vp-threat-note">
                <?= h(sprintf(
                    __(
                        'This value is in more than %d events, and'
                        . ' these are the most recent.'
                    ),
                    $eventCap
                )) ?>
            </p>
        <?php endif; ?>
    </div>
</div>
