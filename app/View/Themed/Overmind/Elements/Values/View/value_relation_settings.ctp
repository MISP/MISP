<?php
/**
 * The rail's second card: what MISP is configured to count.
 *
 * Every number on this tab is conditional on rules the reader cannot see
 * from the page, and a count whose rules are invisible is a count nobody
 * should trust. This card is where those rules are written down — which
 * is also why it is the one panel on the tab that still renders for a
 * value with nothing at all: what MISP counts is true whether or not
 * this value has anything to count.
 *
 * **A rule earns a row by bounding a number below it that nothing else
 * on the page states.** Two do, and both are the feed cache's: how many
 * sources have caching switched on and how many events are listed per
 * source. Everything else was dropped over three passes.
 *
 * The correlation limit and the exclusion list went first: no section
 * on this tab reads `default_correlations`, so neither bounds a number
 * here. They are named only when this value is on the wrong side of
 * one — see `$alerts`. The ssdeep threshold went next, for the
 * opposite reason: it does bound the near-match count, and that panel
 * already prints it *with* what it did — *"M pairs cleared the
 * threshold of 40"* — so the rail's shorter telling taught less than
 * the one two columns over.
 *
 * **And three sections answer to no setting at all**: the two object
 * joins and the typed references read attributes and
 * `object_references` directly. A card that lists what governs this
 * tab has to say where nothing does, which is the `†` under the
 * breakdown.
 *
 * **A settings value is not a finding.** The card printed five
 * mechanisms as bordered `.vp-fact-line` boxes and measured 1,278px
 * against a rail whose other two panels are 380px and 427px. Prose is
 * spent on the exceptions now — a value past the correlation limit, a
 * value in `correlation_exclusions`, an instance with nothing cached —
 * because those are the readings that change what the reader does.
 *
 * **Nothing explains a mechanism here any more.** A fold held those
 * paragraphs for one pass; every one of them turned out to be a
 * shorter retelling of something the panel that owns the rule already
 * says in context — the md5-membership caveat is the external panel's
 * opening line, the threshold is the near-match caption, and the `†`
 * note restates itself two lines below. A rail card is the wrong place
 * to explain a section that is on the same screen.
 *
 * The breakdown at the foot is the tab's arithmetic, stated rather than
 * left to be inferred. **Eight notions and five units** — values,
 * relations, remote events, references, claims — so each row names its
 * own unit and nothing is summed into one strength.
 *
 * **This is still the only panel on the page that reads the correlation
 * engine's state live.** Section one is an event join, section two
 * re-derives its own matches and section four reads a cache; the
 * Overview's Lifecycle card only flags an over-correlating value. So
 * what the engine did
 * or refused to do for this value is reported in this card's warn lines
 * or nowhere — which is why they survived the rows.
 * prd/value-intelligence-live/24-relationships.md §3.
 *
 * Lazily loaded from ValuesController::viewRelationSettings.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$relations = $profile['relationships'];
$settings = $relations['settings'];

/*
 * The value is past the limit when MISP recorded it in
 * `over_correlating_values` rather than correlating it. That is a
 * property of this value against this setting, not of the setting —
 * and it is a different question from whether the pane beside this one
 * could read the value's events, which is what `suppressed` means
 * since phase 24.
 *
 * Read straight off `relationSettings`, which asks
 * `OverCorrelatingValue` for this value every time this panel is
 * fetched. It used to fall back to the neighbourhood fold's
 * `suppressed` flag, which was the last thing holding this card to a
 * 20,000-row scan — and a fallback for a question the live read always
 * answers.
 */
$suppressed = !empty($settings['over_correlating']);

$external = $settings['external'];
$nothingCached = empty($external['cached']['feeds'])
    && empty($external['cached']['servers']);
$restricted = !empty($external['restricted']['feeds'])
    || !empty($external['restricted']['servers']);

/*
 * The three readings worth a paragraph on the face of the card, and —
 * for the first two — the only reason the correlation engine is
 * mentioned here at all.
 *
 * **Neither the correlation limit nor the exclusion list bounds a
 * single number on this tab.** `default_correlations` links two
 * attributes carrying the *same* value, so the engine never returns a
 * different one: section one is an event join, section two re-derives
 * CIDR and ssdeep from the engine's own inputs, and the rest read
 * `object_references`, a feed cache or an analyst's claim.
 * `OverCorrelatingValue` and `Correlation::isValueExcluded` are each
 * read in exactly one place in `ValueIntelligence` — `relationSettings`,
 * for this card — and nothing consults them again. The Occurrences tab
 * is not bounded by them either; it queries `attributes` directly, so
 * a value past the limit still lists every occurrence it has.
 *
 * So they are not rules of this card and no longer get a row. `Limit
 * 20` beside a value nowhere near 20 teaches nothing, and stating it
 * under a heading promising *the settings these sections depend on*
 * teaches something false.
 *
 * They stay as exceptions because *this value is past the limit* is a
 * real fact with real consequences elsewhere in MISP, and beside the
 * Overview's Lifecycle flag this card is the page's only statement of
 * it. The co-occurrence panel's `suppressed` state is a different
 * condition — `0.0.0.0` is past the limit and renders a full
 * neighbourhood table.
 * Each says plainly that the sections beside it are unaffected.
 */
$alerts = array();
if ($suppressed) {
    $alerts[] = array(
        'icon' => 'fas fa-triangle-exclamation',
        'title' => __('This value is past the correlation limit.'),
        'body' => sprintf(
            __('MISP stored no correlations for it and recorded it in'
                . ' %s instead. No count on this tab is affected —'
                . ' none of them reads the correlation table — but'
                . ' every other page in MISP that offers to show you'
                . ' what this value relates to will come back empty.'),
            '<span class="font-monospace">over_correlating_values</span>'
        ),
    );
}
if (!empty($settings['excluded'])) {
    $alerts[] = array(
        'icon' => 'fas fa-ban',
        'title' => __('This value is excluded from correlation.'),
        'body' => sprintf(
            __('It matches an entry in %s, so MISP does not correlate'
                . ' it at all — but no count on this tab is affected,'
                . ' because none of them reads the correlation table.'),
            '<span class="font-monospace">correlation_exclusions</span>'
        ),
    );
}
if ($nothingCached) {
    $alerts[] = array(
        'icon' => 'fas fa-cloud-arrow-down',
        'title' => __('Nothing is cached for lookup.'),
        'body' => __(
            'A feed or server needs caching switched on and a completed'
            . ' caching job before anything outside this instance can be'
            . ' looked up, so Outside this instance is empty for every'
            . ' value.'
        ),
    );
}

/*
 * One row per rule: its name, and where this instance stands.
 *
 * **Only the two nothing else on the page states.** A rule already
 * printed by the panel it governs does not need a second, shorter
 * telling in the rail: the near-match panel says *"M pairs cleared the
 * threshold of 40"*, which is the threshold plus what it did to this
 * value, so an `ssdeep threshold · 40` row here was the same fact with
 * the context removed. The cached-source count and the per-source cap
 * are not printed anywhere else, so they stay.
 *
 * `state` is the reading a warn line above has already spelled out, so
 * the row can mark itself without repeating the sentence.
 */
$rules = array();
/*
 * The cached-source rules only when there is a cache. With nothing
 * cached both rows read zero and the warn line above already says so
 * once; two rows restating it is the density this card was losing.
 */
if (!$nothingCached) {
    /*
     * §21.6's role disclosure, in the row rather than a sentence under
     * it: `5 of 6 feeds` names the difference the reader is on the
     * wrong side of, and collapses to `5 feeds` when there is none.
     * It is a statement about the instance and their own role, not
     * about any value — vary the value and it does not move.
     */
    $feedText = $external['visible']['feeds'] < $external['cached']['feeds']
        ? sprintf(
            __n('%1$d of %2$d feed', '%1$d of %2$d feeds',
                $external['cached']['feeds']),
            $external['visible']['feeds'],
            $external['cached']['feeds']
        )
        : sprintf(
            __n('%d feed', '%d feeds', $external['cached']['feeds']),
            $external['cached']['feeds']
        );
    $serverText = $external['visible']['servers']
            < $external['cached']['servers']
        ? sprintf(
            __n('%1$d of %2$d server', '%1$d of %2$d servers',
                $external['cached']['servers']),
            $external['visible']['servers'],
            $external['cached']['servers']
        )
        : sprintf(
            __n('%d server', '%d servers', $external['cached']['servers']),
            $external['cached']['servers']
        );
    $rules[] = array(
        'label' => __('Cached for lookup'),
        'value' => sprintf(__('%1$s · %2$s'), $feedText, $serverText),
        'state' => $restricted ? __('some withheld') : '',
    );
    $rules[] = array(
        'label' => __('Listed per source'),
        'value' => sprintf(
            __n('%d event', '%d events', $external['event_cap']),
            $external['event_cap']
        ),
        'state' => '',
    );
}

/*
 * One entry per section on the tab, in the order they are read, each
 * carrying the unit it counts.
 *
 * **All of them.** It listed four until the object-mediated sections
 * were split out into panels of their own — leaving a card whose whole
 * claim is *this is the tab's arithmetic* silently missing three of
 * the numbers the tab prints. The section names are the panels' own,
 * so this card, the contents strip at the top of the tab and the panel
 * headers all say the same thing in the same words.
 *
 * The units differ — values, relations, remote events, references,
 * claims — so each row names its own rather than letting eight bars in
 * one group imply they are the same thing. Nothing here is summed.
 *
 * `capped` marks a count the section itself prints with a `≥`: a join
 * bounded by how many of this value's objects the scan read is a floor,
 * and a rail stating a bare number beside a panel qualifying it would
 * be the two disagreeing about how much they saw.
 *
 * **The `≥` is dropped on a zero.** `0.0.0.0`'s reference read is
 * capped and finds nothing, and `≥ 0` is both vacuous — *at least none*
 * — and indistinguishable from a rendering fault. A capped zero says
 * `0` and carries the bound in its tooltip instead.
 *
 * `ungoverned` is the fourth rule — that three sections have none —
 * carried by the rows it applies to rather than by a paragraph above
 * them. The footnote under the list spells the marker out once.
 */
$split = array(
    array(
        'key' => 'siblings',
        'label' => __('In the same object'),
        'unit' => __('siblings'),
        'colour' => 'var(--vp-rel-co)',
        'ungoverned' => true,
    ),
    array(
        'key' => 'cooccurrence',
        'label' => __('In the same events'),
        'unit' => __('values'),
        'colour' => 'var(--vp-rel-co)',
        'ungoverned' => false,
    ),
    array(
        'key' => 'dated',
        'label' => __('Dated relations'),
        'unit' => __('relations'),
        'colour' => 'var(--vp-rel-object)',
        'ungoverned' => true,
    ),
    array(
        'key' => 'near',
        'label' => __('Near-matches'),
        'unit' => __('values'),
        'colour' => 'var(--vp-rel-near)',
        'ungoverned' => false,
    ),
    array(
        'key' => 'external',
        'label' => __('Outside this instance'),
        'unit' => __('remote events'),
        'colour' => 'var(--vp-rel-external)',
        'ungoverned' => false,
    ),
    array(
        'key' => 'references',
        'label' => __('Object relationships'),
        'unit' => __('references'),
        'colour' => 'var(--vp-rel-reference)',
        'ungoverned' => true,
    ),
    array(
        'key' => 'asserted',
        'label' => __('Asserted by analysts'),
        'unit' => __('claims'),
        'colour' => 'var(--vp-rel-human)',
        'ungoverned' => false,
    ),
    /*
     * §10.2's label neighbours, in their own unit.
     *
     * **Its own row because it is its own unit**, which is this card's
     * one rule: a galaxy cluster is not a value, so it cannot be added
     * to the row above it any more than a remote event or a reference
     * can. The co-occurrence table carries both and `relationSummary`
     * splits them for exactly this reason.
     *
     * Declared with the rest now rather than appended on a non-zero
     * count, because this card no longer holds the counts to test. A
     * value whose events carry no clusters and no tags draws no
     * `labels` section, so the panel stamps no such key and the row is
     * dropped on arrival — the same treatment, decided by the panel
     * that knows rather than by a fold this card would have to read.
     */
    array(
        'key' => 'labels',
        'label' => __('Labels in this neighbourhood'),
        'unit' => __('clusters and tags'),
        'colour' => 'var(--vp-rel-co)',
        'ungoverned' => false,
    ),
);
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--bs-secondary-color);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('What is counted'),
        'panelIcon' => 'fas fa-sliders',
        'panelColor' => 'var(--bs-secondary-color)',
        /*
         * No age beside the title any more. Everything this card reads
         * itself is live, and the counts at the foot are copied from
         * the panels as they land — each of which discloses its own
         * age. One figure here would have to date eight readings taken
         * at eight different moments, which §16.7 asks for the
         * opposite of.
         */
        'panelSub' => __('The settings and caches these sections depend on'),
    )) ?>

    <div class="p-3">

        <?php foreach ($alerts as $alert): ?>
            <div class="vp-fact-line vp-fact-line-warn mb-2">
                <i class="<?= h($alert['icon']) ?>"></i>
                <div>
                    <span class="fw-semibold">
                        <?= h($alert['title']) ?>
                    </span>
                    <div class="vp-fact-line-sub">
                        <?= $alert['body'] ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>

        <div class="vp-rules">
            <?php foreach ($rules as $rule): ?>
                <div class="vp-rule-row">
                    <span class="vp-rule-name">
                        <?= h($rule['label']) ?>
                    </span>
                    <span class="vp-rule-value">
                        <?= h($rule['value']) ?>
                        <?php if ($rule['state'] !== ''): ?>
                            <span class="vp-rule-state">
                                <?= h($rule['state']) ?>
                            </span>
                        <?php endif; ?>
                    </span>
                </div>
            <?php endforeach; ?>
        </div>


    </div>

    <?php
    /*
     * **Always rendered, and empty until the panels land.** The counts
     * are no longer here to test for — `forRelationSettings` reads no
     * fold — so the block cannot decide up front whether it has
     * anything to draw. It starts hidden and `layoutRelationSplit` in
     * `value-intelligence.js` reveals it once a panel has stamped a figure
     * on it, which is the same discipline the contents strip keeps:
     * *not yet read* and *nothing there* are different answers, and a
     * row of zeroes would claim the second while the first is true.
     */
    ?>
    <div class="px-3 pb-3 d-none" data-vp-relsum-split-block>
        <?php
        /*
         * Both plural forms from here rather than a string in the
         * script, for the reason every other label this page fills in
         * comes from a `data-` attribute: `__()` runs in PHP and a
         * translation is free to disagree with English about where the
         * number goes.
         */
        ?>
        <div class="vp-subhead" data-vp-relsum-split-head
             data-vp-split-one="<?= h(__('%d notion, counted apart')) ?>"
             data-vp-split-many="<?= h(__('%d notions, counted apart')) ?>"
             ></div>

        <?php
        /*
         * Two lines per notion rather than the rail's usual
         * name-bar-count row. `.vp-reporter` gives its label 40% of
         * a card that is a quarter of the page, which is about
         * twenty characters — enough for an organisation's acronym
         * in the Sightings rail, and not enough for `Outside this
         * instance` beside the unit it counts. Here the name and
         * its figure take a line and the bar takes the next.
         *
         * The figure, the bar's width and the `≥` a bounded section
         * prints are all filled in from the panel that owns the
         * section. The `†` is not: which notions answer to none of
         * the rules above is a property of this card's own list, so
         * it is written here and stays put.
         */
        ?>
        <?php foreach ($split as $part): ?>
            <div class="vp-split-row vp-split-none d-none"
                 data-vp-relsum-split="<?= h($part['key']) ?>"
                 style="--vp-split-colour: <?= h($part['colour']) ?>;">
                <span class="vp-split-dot"></span>
                <span class="vp-split-label" data-vp-relsum-split-label>
                    <?= h($part['label']) ?><?php
                    if (!empty($part['ungoverned'])): ?><span
                        class="vp-split-mark"
                        title="<?= h(__('Answers to none of the rules'
                            . ' above.')) ?>">&#8224;</span><?php
                    endif; ?>
                </span>
                <span class="vp-split-figure" data-vp-relsum-split-figure>
                    <span class="vp-split-count"
                          data-vp-relsum-split-count></span>
                    <span class="vp-split-unit">
                        <?= h($part['unit']) ?>
                    </span>
                </span>
                <span class="vp-split-track">
                    <span class="vp-split-fill"
                          data-vp-relsum-split-fill
                          style="width: 0%;"></span>
                </span>
            </div>
        <?php endforeach; ?>

        <?php
        /*
         * The two markers the rows use, spelled out once. This is
         * what the two paragraphs at the foot cost 189px to say
         * less clearly — the sentences restated every figure the
         * bars had just printed, so the card said each number
         * three times and the tab's contents strip said it a
         * fourth.
         */
        ?>
        <div class="vp-split-footnote">
            <span class="vp-split-mark">&#8224;</span>
            <?= sprintf(
                __('Read straight from attributes and %s — none of'
                    . ' the rules above governs it.'),
                '<span class="font-monospace">object_references'
                    . '</span>'
            ) ?>
            <span class="d-none" data-vp-relsum-split-capped>
                <?= sprintf(
                    __('%s marks a floor: the scan did not reach'
                        . ' every object this value sits in.'),
                    '<span class="font-monospace">&#8805;</span>'
                ) ?>
            </span>
        </div>
    </div>

</div>
