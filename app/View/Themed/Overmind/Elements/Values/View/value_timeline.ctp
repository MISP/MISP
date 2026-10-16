<?php
/**
 * The Timeline tab — candidate `T-final`.
 *
 * One window, three depths. The spine says *when* the value was busy,
 * the source lanes say *which sources say so*, and the chronology says
 * *what exactly happened* — and all three are the same selection, which
 * is the whole design. Each of the four candidates the deck opened with
 * answered one of those three questions and lost the other two.
 *
 * The tab's placeholder note promised a merged chronology of seven
 * sources. Of those seven, one is fully dated and addressable by value,
 * one needs an assembled union, two are truncated to first-and-last,
 * one is a nullable per-occurrence span, and two carry no timestamp in
 * MISP on any instance. So the design problem was never how to draw a
 * chronology — it was how to draw one that admits its own holes without
 * becoming unreadable. Every hatched lane and every precision chip
 * below is that admission, put in the reading path rather than in a
 * margin a reader can skip.
 *
 * Three cards in one panel, and one endpoint behind them, because the
 * brush is a single control driving two regions that must already exist
 * when it fires (`06-timeline.md` §4).
 *
 * The spine is Chart.js, per `00-shared.md` §7. The lanes are inline
 * SVG and deliberately not: a lane has no axis of its own, no legend
 * and no scale, so seven Chart.js instances would be seven canvases for
 * a shape that needs marks and a `<title>`.
 *
 * Lazily loaded from ValuesController::viewTimeline.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');

/*
 * The spine's grain, chosen from the value's own range.
 *
 * A value first seen last week needs finer bins and one held since 2020
 * needs coarser, so the rule is the range's — and it is this tab's own
 * rule rather than `ValueIntelligenceBuckets`' default, because a bar here
 * means something different from a bar on the Sightings navigator. A
 * sighting has a timestamp to the second; a bar here is a density over
 * sources MISP dates unevenly, so the finest grain it offers is a day
 * and it reaches for it only when the whole range is short enough that
 * a day is what the reader is asking about.
 *
 * Deliberately not `plan()`. That ships every grain and lets the
 * browser re-aggregate, which is right for a chart with one series and
 * wrong here: this spine is stacked per source, so a grain is a matrix
 * rather than a row, and the counts it stacks are already server-side.
 */
$spineRule = array(
    array('days' => 45, 'unit' => ValueIntelligenceBuckets::DAY),
    array('days' => 400, 'unit' => ValueIntelligenceBuckets::WEEK),
    array('days' => null, 'unit' => ValueIntelligenceBuckets::MONTH),
);

$timeline = isset($valueIntelligence['timeline'])
    ? $valueIntelligence['timeline']
    : null;

/*
 * ------------------------------------------------------------------
 * The vocabularies
 * ------------------------------------------------------------------
 * One table per axis of meaning, so a source's colour, its glyph and
 * its label are decided once and read by all three cards. §11's rule is
 * that a lane mark and its stack segment must be the same colour, and
 * the only way to keep that true is for both to read the same token.
 */
$sourceMeta = array(
    'sighting' => array(
        'label' => __('Sighting'),
        'plural' => __('sightings'),
        'icon' => 'fas fa-eye',
        'token' => 'var(--vp-tl-sighting)',
    ),
    'false_positive' => array(
        'label' => __('False positive'),
        'plural' => __('false positives'),
        'icon' => 'fas fa-thumbs-down',
        'token' => 'var(--vp-tl-false_positive)',
    ),
    'expiration' => array(
        'label' => __('Expiration'),
        'plural' => __('expirations'),
        'icon' => 'fas fa-hourglass-end',
        'token' => 'var(--vp-tl-expiration)',
    ),
    'publication' => array(
        'label' => __('Published'),
        'plural' => __('publications'),
        'icon' => 'fas fa-paper-plane',
        'token' => 'var(--vp-tl-publication)',
    ),
    'note' => array(
        'label' => __('Note'),
        'plural' => __('notes'),
        'icon' => 'fas fa-note-sticky',
        'token' => 'var(--vp-tl-note)',
    ),
    'opinion' => array(
        'label' => __('Opinion'),
        'plural' => __('opinions'),
        'icon' => 'fas fa-comment-dots',
        'token' => 'var(--vp-tl-opinion)',
    ),
    /*
     * MISP's own icon for an event report, the one `EventReports/view`
     * puts in its header — a report on this axis should be the glyph a
     * reader has already met on the page the row links to.
     */
    'report' => array(
        'label' => __('Report'),
        'plural' => __('event reports'),
        'icon' => 'fas fa-file-lines',
        'token' => 'var(--vp-tl-report)',
    ),
    /*
     * Not MISP's own, and that is a collision rather than a
     * disagreement: the product draws a proposal as `fa-comment-dots`
     * (`NavbarHelper.php:221`), which is the glyph an opinion already
     * wears two rows up. A pull request is what a proposal is — a
     * change offered for someone else to accept or discard.
     */
    'proposal' => array(
        'label' => __('Proposal'),
        'plural' => __('proposals'),
        'icon' => 'fas fa-code-pull-request',
        'token' => 'var(--vp-tl-proposal)',
    ),
    'edit' => array(
        'label' => __('Edit'),
        'plural' => __('edits'),
        'icon' => 'fas fa-pencil',
        'token' => 'var(--vp-tl-edit)',
    ),
    /*
     * Attaching a tag is the one audit action whose subject is not the
     * record it names, and on this instance it is also the most common
     * row in `audit_logs` by two orders of magnitude — so it is its own
     * source rather than an edit. The two colours are MISP's own
     * `--tag` and `--galaxy`, which is what a tag is drawn in
     * everywhere else in the product.
     */
    'tag' => array(
        'label' => __('Tag'),
        'plural' => __('tag changes'),
        'icon' => 'fas fa-tag',
        'token' => 'var(--vp-tl-tag)',
    ),
    'cluster' => array(
        'label' => __('Galaxy cluster'),
        'plural' => __('cluster changes'),
        'icon' => 'fas fa-atom',
        'token' => 'var(--vp-tl-cluster)',
    ),
    'seen' => array(
        'label' => __('First seen'),
        'plural' => __('first-seen dates'),
        'icon' => 'far fa-clock',
        'token' => 'var(--vp-tl-seen)',
    ),
    /*
     * The same date one level up. MISP keeps `first_seen` and
     * `last_seen` on the object as well as on the attribute and copies
     * the object's down at save time — but only on the add path, so
     * the two drift and the object's is usually the only one set. It
     * is a weaker claim than the attribute's, which is why it is its
     * own source rather than more rows in the one above: the key can
     * name it, the spine can stack it apart, and a reader can press it
     * away.
     */
    'seen_object' => array(
        'label' => __('First seen (object)'),
        'plural' => __('object-level spans'),
        'icon' => 'far fa-clock',
        'token' => 'var(--vp-tl-seen_object)',
    ),
    /*
     * A date an object template records in a field of its own, which is
     * a different kind of evidence from the two above: those are MISP's
     * `first_seen`/`last_seen` columns, this is whatever the template
     * decided to call a date. The glyph is the one the Relationships
     * tab's *Dated relations* section already wears, because these are
     * the rows that section folds — a reader meeting the same dates on
     * two tabs should meet the same mark.
     */
    'objdate' => array(
        'label' => __('Object date'),
        'plural' => __('dates recorded by objects'),
        'icon' => 'fas fa-clock-rotate-left',
        'token' => 'var(--vp-tl-objdate)',
    ),
);

/*
 * How well a row is dated, and which bucket the chronology's tally
 * counts it in. Two buckets and not three: a `no date` bucket in a list
 * of dated entries would be a number describing nothing, and the facts
 * it would count are in the lanes and on the off-axis strip instead
 * (§8.3).
 */
$precisionMeta = array(
    'exact' => array(
        'label' => __('exact'),
        'bucket' => 'exact',
        'class' => 'vp-prec-exact',
    ),
    'first_last' => array(
        'label' => __('first & last only'),
        'bucket' => 'partial',
        'class' => 'vp-prec-part',
    ),
    'latest' => array(
        'label' => __('latest only'),
        'bucket' => 'partial',
        'class' => 'vp-prec-part',
    ),
);

/**
 * Where an entry opens.
 *
 * **To the event's own tab and not to `/attributes/view` or
 * `/objects/view`**, which is the choice `value_relation_asserted` and
 * the sightings table already made and recorded: this theme's event view
 * takes no `focus:` parameter, and the two flat views redirect to the
 * event and lose which record they were asked about. So the anchor is as
 * close as a link can get, and the title carries the record.
 *
 * The anchor comes from `ref['kind']`, which the facade sets per entry
 * and not per lane — the distinction matters in the tag lane, where an
 * audit row about an Object is drawn beside one about an Attribute and
 * the two open different tabs.
 *
 * Null where there is nowhere to send the reader. Two entries can be in
 * that state and both are honest: an analyst note whose target this
 * viewer cannot resolve to an event, and any row on an instance where
 * the audit log recorded no `event_id`.
 *
 * @param array $entry
 * @return string|null
 */
$entryUrl = function (array $entry) use ($baseurl) {
    $ref = $entry['ref'];
    if (empty($ref['event'])) {
        return null;
    }
    $anchors = array(
        'attribute' => '#tab-attributes',
        'object' => '#tab-objects',
        'report' => '#tab-reports',
    );
    $kind = isset($ref['kind']) ? $ref['kind'] : 'event';
    return $baseurl . '/events/view/' . (int)$ref['event']
        . (isset($anchors[$kind]) ? $anchors[$kind] : '');
};

/**
 * What that link promises, since the anchor cannot promise the record.
 *
 * @param array $entry
 * @return string
 */
$entryLinkTitle = function (array $entry) {
    $ref = $entry['ref'];
    $kind = isset($ref['kind']) ? $ref['kind'] : 'event';
    if ($kind === 'attribute' && !empty($ref['attribute'])) {
        return sprintf(
            __('Open event %1$s — attribute %2$s is on its Attributes tab'),
            $ref['event'],
            $ref['attribute']
        );
    }
    if ($kind === 'object') {
        return sprintf(
            __('Open event %s — the object is on its Objects tab'),
            $ref['event']
        );
    }
    if ($kind === 'report') {
        return sprintf(
            __('Open event %s — the report is on its Event reports tab'),
            $ref['event']
        );
    }
    return sprintf(__('Open event %s'), $ref['event']);
};

/*
 * The cut band's own sentence, held in one variable because both
 * renderers of the band need it: the template for the window the
 * fragment arrives with, and the script for every window after it. The
 * script substitutes rather than composes, so the words stay
 * translatable and there is no second sentence to keep in step.
 */
$cutTitle = __(
    'Not fetched. %1$s of this lane\'s entries in this span are older'
    . ' than the newest %2$s rows this fetch carries, so nothing here'
    . ' is drawn. Brush this span to fetch it.'
);

$utc = new DateTimeZone('UTC');
$entries = $timeline === null ? array() : $timeline['entries'];
$undated = $timeline === null ? array() : $timeline['undated'];
$window = $timeline === null ? null : $timeline['window'];
$auditRecorded = $timeline !== null && $timeline['audit_recorded'];
/*
 * When the instance first held this value, or the bound the records
 * support — `ValueIntelligence::timelineFirstHere` decides which and this
 * only picks the sentence. Null on a value with no trace at all, which
 * is the panel that has no axis either.
 */
$firstHere = $timeline === null || empty($timeline['first_here'])
    ? null
    : $timeline['first_here'];
/*
 * The tag set with each tag's first attach. Oldest first, and the ones
 * the audit log cannot place carry a null `at` — they are counted in
 * the lane's own sentence and listed on the off-axis strip.
 */
$tagState = $timeline === null || empty($timeline['tags'])
    ? array()
    : $timeline['tags'];
$tagsDated = array();
foreach ($tagState as $tag) {
    if ($tag['at'] !== null) {
        $tagsDated[] = $tag;
    }
}

/*
 * ------------------------------------------------------------------
 * The counts arrive; they are no longer all derived here
 * ------------------------------------------------------------------
 * The tab's rule was that every number in the panel is an aggregate
 * over `entries`, so two of them could not disagree. That holds only
 * while `entries` is all of them, and on a value like `443` — 174,299
 * dated things, 172,426 of them audit rows — it is not: the array is
 * the newest few hundred and the panel would be charting a fortnight
 * under a year's axis.
 *
 * So the counts come from aggregates over the whole set the viewer may
 * see, and `entries` is what the chronology lists. The invariant is
 * kept, in the stronger form: **no number below is tallied from the
 * rows unless the rows are all of them.** `by_day` bins the spine,
 * `in_window` fills the lane grid, `total` and `shown` are what the
 * panel says out loud.
 */
$counts = $timeline === null
    ? array(
        'total' => 0,
        'shown' => 0,
        'by_source' => array(),
        'by_day' => array(),
        'spans' => array(),
        'in_window' => array('total' => 0),
        'first' => null,
        'last' => null,
        'first_record' => null,
        'capped' => false,
        'cap' => 0,
    )
    : $timeline['counts'];
$countsByDay = $counts['by_day'];
$inWindow = $counts['in_window'];
/*
 * The intervals, kept beside the day map rather than folded into it.
 * A month a `passive-dns` pair runs straight through holds no *date*
 * and is not empty, and only these can say so.
 */
$spanRanges = isset($counts['spans']) ? $counts['spans'] : array();
$spans = $timeline === null
    ? array(
        'occurrences' => 0, 'with' => 0, 'shown' => 0, 'cap' => 0,
        'covered' => 0, 'objects' => 0, 'objects_shown' => 0,
    )
    : $timeline['spans'];

/*
 * The seen lane's sub-label, composed here because it has two halves
 * and either can be absent.
 *
 * The first is what the lane has always said: how many occurrences
 * carry a span of their own, of how many the viewer can see, and — when
 * the cap bites — how many were drawn. The second is the object half,
 * and it appears only when there is one, because *0 dated by their
 * object* on a value whose occurrences are all dated is a number
 * answering a question nobody asked.
 *
 * `covered` rather than `objects` leads the second clause: a reader
 * counting bars wants to know how many *occurrences* the fallback
 * rescued, and one object can hold several.
 */
$seenSub = $spans['shown'] < $spans['with']
    ? sprintf(
        __('%1$s of %2$s occurrences carry one · drawing %3$s'),
        $spans['with'],
        $spans['occurrences'],
        $spans['shown']
    )
    : sprintf(
        __('%1$s of %2$s occurrences carry one'),
        $spans['with'],
        $spans['occurrences']
    );
if (!empty($spans['objects'])) {
    $seenSub .= ' · ' . __n(
        '%1$s more dated by its object',
        '%1$s more dated by their objects (%2$s)',
        $spans['covered'],
        $spans['covered'],
        $spans['objects']
    );
    if ($spans['objects_shown'] < $spans['objects']) {
        $seenSub .= ' ' . sprintf(
            __('· drawing %s of those'),
            $spans['objects_shown']
        );
    }
}

/*
 * The object-date lane's sub-label: how many dates the objects record,
 * and — the half that matters — what they are called.
 *
 * The relation names are the point of printing anything here at all. A
 * lane saying *32,893 dates* over a value in 32,922 objects has told
 * the reader nothing; *time_generated, first-seen, last-seen* tells
 * them whether this lane is about being seen or about something else
 * entirely, which is the one question the lane cannot answer for them.
 *
 * From the aggregate and never from the drawn rows — the rows are the
 * newest 1,000, and on `0.0.0.0` all 1,000 of them would be
 * `time_generated`.
 */
$objdates = $timeline === null
    ? array('total' => 0, 'shown' => 0, 'relations' => array())
    : $timeline['objdates'];
$objdateSub = __('nothing recorded');
if (!empty($objdates['total'])) {
    $names = array_keys($objdates['relations']);
    $head = array_slice($names, 0, 3);
    $objdateSub = sprintf(
        __('%1$s · %2$s'),
        __n('%s date', '%s dates', $objdates['total'],
            number_format($objdates['total'])),
        implode(', ', $head) . (count($names) > count($head)
            ? sprintf(__(' +%s more'), count($names) - count($head))
            : '')
    );
    if ($objdates['shown'] < $objdates['total']) {
        $objdateSub .= ' · ' . sprintf(
            __('drawing %s'),
            number_format($objdates['shown'])
        );
    }
}

$windowFrom = $window === null ? null : $window['from'] . ' 00:00:00';
$windowTo = $window === null ? null : $window['to'] . ' 23:59:59';

/*
 * Whether the endpoint was asked for this window or chose it.
 *
 * The panel says different things about the two. Asked, the rows are
 * everything the viewer may see in the window (up to the cap), so the
 * list's numbers are the window's; unasked, they are the newest of the
 * whole value and the numbers are the value's. It also decides whether
 * `Reset window` is offered before any script runs — a fragment fetched
 * for a window is already off the default, and a reader who arrived by
 * following the URL needs the way back.
 */
$windowRequested = $window !== null && !empty($window['requested']);

/*
 * What the list carries, against what it could have carried, and the
 * second number is the whole of what `$windowRequested` decides.
 *
 * Asked for a window, the rows are the newest cap-many *in it*, so the
 * set they are a sample of is the window's — and when the whole window
 * fits, which is the usual case, there is no cap to mention at all.
 * Unasked, they are the newest cap-many of the value.
 */
$listShown = $counts['shown'];
$listOf = $windowRequested ? $inWindow['total'] : $counts['total'];
$listCapped = $listShown < $listOf;

/*
 * Which of the *listed* rows fall in the window. This is the
 * chronology's own business — which rows to show — and never a count
 * the panel prints: the numbers come from `$inWindow`, which was summed
 * over every day the viewer may see rather than over the rows that fit.
 */
$windowed = array();
foreach ($entries as $entry) {
    /*
     * Overlap and not start — `ValueIntelligence::timelineTouches`' rule,
     * and this is the copy of it the lane marks read. A span whose two
     * ends both sit outside the window still crosses it and the lane
     * still draws a bar right across; tested on its start alone it was
     * dropped here, and the bar the reader was looking at came with a
     * precision tally and a count that had both forgotten it.
     */
    $end = empty($entry['span_to']) ? $entry['at'] : $entry['span_to'];
    if ($end >= $windowFrom && $entry['at'] <= $windowTo) {
        $windowed[] = $entry;
    }
}

/*
 * ------------------------------------------------------------------
 * Where the rows stop
 * ------------------------------------------------------------------
 * The oldest listed row in the window, and the panel's most useful
 * number when the cap has bitten: the rows are the newest cap-many, so
 * **nothing older than this moment has a row**, in any lane, and the
 * span between it and the window's start is one the lanes can count and
 * cannot draw.
 *
 * A single boundary and not one per lane, because the cap is applied
 * once to the merged array: every lane's rows are newer than the 300th
 * newest of the union, so one cut line is true for all of them.
 *
 * `null` means no row at all falls in the window, and the whole window
 * is then the span the lanes cannot draw.
 *
 * **Where a row starts, not where a span reaches back to.** A
 * `passive-dns` pair crossing the window is in `$windowed` and belongs
 * there — the lane draws it — but its 2013 start is not evidence that
 * the cap left anything from 2013 alone. Reading it as the boundary
 * would put the cut line before the window and erase a band that is
 * describing real rows the cap took.
 */
$boundary = null;
foreach ($windowed as $entry) {
    if ($entry['at'] < $windowFrom) {
        continue;
    }
    if ($boundary === null || $entry['at'] < $boundary) {
        $boundary = $entry['at'];
    }
}

/*
 * ------------------------------------------------------------------
 * The spine's bins
 * ------------------------------------------------------------------
 * Over the value's whole dated range, at whatever grain the range
 * asks for, and binned from `by_day` rather than from the rows — so a
 * value whose chronology is capped still gets its whole history
 * charted. That is the difference between this chart and a chart of
 * the last fortnight labelled as a year.
 *
 * `$before` therefore stays at zero and the notice under the chart no
 * longer fires: the spine now begins where the value does, so there is
 * nothing older than it to count. The branch is kept because a future
 * ceiling on the axis would need it back, and removing it would take
 * the wording with it.
 *
 * **The axis ends at today and not at the value's last entry.** It
 * used to end where the value did, which made a value that went quiet
 * two months ago and one seen this morning the same picture — the
 * difference between them was in the tick labels, which is the half of
 * a chart a reader skims. Running the series on to today puts *how
 * long since* back into the shape, and §27 has why that is worth the
 * empty space it costs.
 *
 * **The grain is still chosen from `$rangeDays`, which is the data's
 * own span**, and that is deliberate rather than incidental. Choosing
 * it from the drawn range would let the emptiness after a value decide
 * how finely the value itself is drawn: `yovtube.co` has one dated
 * day, and measured against the range now drawn it would fall from
 * days to weeks — its whole record redrawn as a week, *because of the
 * eleven months of silence that followed it*.
 */
$bins = array();
$before = 0;
$earliest = null;
$spineUnit = ValueIntelligenceBuckets::MONTH;
$today = (new DateTimeImmutable('now', $utc))->format('Y-m-d');
$rangeFrom = $counts['first'] === null
    ? null
    : substr($counts['first'], 0, 10);
$rangeTo = $counts['last'] === null
    ? null
    : substr($counts['last'], 0, 10);
if ($window !== null && $rangeFrom !== null) {
    $rangeDays = 1 + (int)(new DateTimeImmutable($rangeFrom, $utc))
        ->diff(new DateTimeImmutable($rangeTo, $utc))
        ->days;
    $spineUnit = ValueIntelligenceBuckets::unitForSpan($rangeDays, $spineRule);
    $bins = ValueIntelligenceBuckets::series(
        $rangeFrom,
        max($rangeTo, $today),
        $spineUnit
    );
    foreach ($bins as $i => $bin) {
        $bins[$i]['counts'] = array();
        $bins[$i]['total'] = 0;
    }
    $index = ValueIntelligenceBuckets::locate($bins);
    foreach ($countsByDay as $day => $bySource) {
        if (!isset($index[$day])) {
            continue;
        }
        $at = $index[$day];
        foreach ($bySource as $source => $n) {
            if (!isset($bins[$at]['counts'][$source])) {
                $bins[$at]['counts'][$source] = 0;
            }
            $bins[$at]['counts'][$source] += $n;
            $bins[$at]['total'] += $n;
        }
    }
}

/*
 * ------------------------------------------------------------------
 * The cap on the empty end
 * ------------------------------------------------------------------
 * The bins above already run to today, so a dormant value has empty
 * ones after its last entry. Left alone that is the whole of the
 * change and it is wrong for the values it matters most to: one busy
 * through 2016 and dead since would spend nine tenths of its axis on
 * nothing and draw its actual history as a sliver.
 *
 * So **the empty end may take half the width of the data and no
 * more**, which is a third of the drawn axis. Past that the bins
 * nearest today are the ones kept and the rest fold into a single
 * elided bin — a real date range like any other, so `locate()` still
 * covers the axis and a reader can brush it and get the empty window
 * it honestly describes. What it is not is to scale, and the axis
 * says so with a break rather than with a texture (§27.4).
 *
 * Its title is written and currently unreadable: the brush overlay
 * takes the pointer before the canvas does, so this chart's tooltip
 * has never fired. §27.8 has why that is left alone and why the span
 * the break stands for is in the sentence under the chart instead.
 *
 * The floor of two is for the values with almost no width to halve.
 * A value whose whole history is one bin has no resolution inside it
 * to protect, so the fraction has nothing to say and the tail gets
 * the break and the one bin holding today.
 */
$tail = null;
if ($bins !== array() && $rangeTo !== null && isset($index[$rangeTo])) {
    $tailAt = $index[$rangeTo] + 1;
    $tailOf = count($bins) - $tailAt;
    if ($tailOf > 0) {
        $tailCap = max(2, (int)ceil($tailAt / 2));
        $fold = $tailOf - ($tailCap - 1);
        if ($fold > 1) {
            $foldFrom = $bins[$tailAt];
            $foldTo = $bins[$tailAt + $fold - 1];
            array_splice($bins, $tailAt, $fold, array(array(
                'key' => 'elided',
                'label' => '⋯',
                'title' => '',
                'from' => $foldFrom['from'],
                'to' => $foldTo['to'],
                'elided' => $fold,
                'counts' => array(),
                'total' => 0,
            )));
        } else {
            $fold = 0;
        }
        /*
         * Whether the silence is worth a sentence.
         *
         * The band is drawn for any tail at all, because the axis
         * reaching today is now simply true and needs no excuse.
         * *Quiet for n* is a claim, and a claim needs a floor:
         * `193.161.193.99` was last seen four days ago and was
         * getting a box telling the reader it had gone quiet.
         *
         * The floor is one bin of the spine's own grain, which makes
         * it proportionate rather than absolute. The grain is chosen
         * from the value's range, so a value with five years behind
         * it has to go a month silent before the panel says so and
         * one with three weeks has to go two days — where a flat
         * thirty days would call the first quiet at a fraction of
         * its own rhythm and never say anything about the second.
         */
        $grainDays = array(
            ValueIntelligenceBuckets::DAY => 1,
            ValueIntelligenceBuckets::WEEK => 7,
            ValueIntelligenceBuckets::MONTH => 30,
        );
        $tailDays = (int)(new DateTimeImmutable($rangeTo, $utc))
            ->diff(new DateTimeImmutable($today, $utc))
            ->days;
        $tail = array(
            'at' => $tailAt,
            'elided' => $fold,
            'since' => $rangeTo,
            'days' => $tailDays,
            'quiet' => $tailDays > $grainDays[$spineUnit],
        );
    }
}

/*
 * ------------------------------------------------------------------
 * Which bins a span runs through
 * ------------------------------------------------------------------
 * A bin's `total` counts the dates that fall *in* it, and an interval
 * has dates only at its two ends. So on `8.8.8.8` — a `passive-dns`
 * pair running 2013-01-15 to 2018-09-30 — sixty-seven months between
 * those two ends held a total of zero, and the panel went on to name
 * the run and call it empty. It is not empty; a feed observed the
 * value throughout it, which is the one thing a bar spanning five
 * years exists to say.
 *
 * Counted after the tail fold rather than before it, so the elided bin
 * is measured as the range it actually stands for instead of
 * inheriting a sum from bins that no longer exist.
 *
 * This is a coverage flag and never a count: the bin's height stays
 * the number of dates it holds. Smearing one span across sixty-seven
 * columns would draw one observation as sixty-seven of them, which is
 * the opposite mistake and a louder one.
 */
foreach ($bins as $i => $bin) {
    $covered = 0;
    foreach ($spanRanges as $span) {
        if ($span['to'] >= $bin['from'] && $span['from'] <= $bin['to']) {
            $covered++;
        }
    }
    $bins[$i]['covered'] = $covered;
}

/*
 * Which sources the value actually has, in the vocabulary's order. A
 * stack segment for a source nobody ever filed is a legend entry
 * teaching the reader a colour they will never meet again.
 *
 * From the counts and not from the rows, which is the same correction
 * as everywhere else on this page: a source whose every row was capped
 * away still has entries, and a legend that dropped it would be
 * hiding a stack segment the chart above is drawing.
 */
$present = array();
foreach ($sourceMeta as $key => $meta) {
    if (!empty($counts['by_source'][$key])) {
        $present[] = $key;
    }
}

/*
 * The longest empty run *between* two months that do carry entries.
 * Named rather than left to be read as a quiet period: this is T3's own
 * objection answered rather than ignored — a density chart cannot tell
 * a quiet month from an unrecorded one, so the strip says which it is
 * and the lanes underneath say which sources could have recorded it.
 *
 * A leading run is not a gap; it is the time before the value existed.
 * A trailing one is not a gap either; it is the present.
 *
 * **A month a span crosses is not empty**, whether or not a date lands
 * in it. This sentence is the panel's strongest claim about silence —
 * it tells the reader the lanes below will say whether the value was
 * quiet or the record was not kept — and on a value carrying a
 * multi-year `passive-dns` observation it was neither: the record was
 * kept, and it says the value was there the whole time.
 */
$gap = null;
$run = null;
$seen = false;
foreach ($bins as $bin) {
    if ($bin['total'] > 0 || $bin['covered'] > 0) {
        if ($run !== null
            && ($gap === null || $run['len'] > $gap['len'])) {
            $gap = $run;
        }
        $run = null;
        $seen = true;
        continue;
    }
    if (!$seen) {
        continue;
    }
    if ($run === null) {
        $run = array('from' => $bin, 'to' => $bin, 'len' => 1);
    } else {
        $run['to'] = $bin;
        $run['len']++;
    }
}

/*
 * ------------------------------------------------------------------
 * Geometry
 * ------------------------------------------------------------------
 * The lane axis is one viewBox stretched to whatever width the panel
 * has, so every mark is placed in its coordinates and every word about
 * a mark is placed in HTML over it. `preserveAspectRatio="none"`
 * stretches glyphs with the box and turns an explanation into a smear,
 * which is what `.vp-lane-fill` and `.vp-lane-tag` exist to avoid
 * (§8.2).
 */
$LANE_W = 740;
$LANE_H = 38;
$MARK_W = 5;

/*
 * What a `.vp-lane-tag` costs, so the seen lane can tell whether two of
 * them would land on each other.
 *
 * The labels are HTML at a fixed `font-size`, positioned in *percent*
 * of a plot whose pixel width is responsive — so whether two collide
 * depends on a number the server does not have. Measured: 6.22px per
 * digit at 0.68rem, and the plot runs 1,078px at a 1500px viewport
 * down to 570px at 992px.
 *
 * **The reference is the narrow end, deliberately.** Sizing the test
 * for the widest plot would let labels collide on a narrow one, which
 * is the defect; sizing it for the narrowest drops a label here and
 * there on a wide screen that would in fact have fitted. One direction
 * is a bug and the other is a lane that says slightly less than it
 * could, so the rule is conservative and the script uses the same two
 * numbers rather than measuring — §24.6's vocabulary, extended to the
 * one lane that places words rather than columns.
 */
$TAG_CHAR = 6.22;
$TAG_REF = 560;

$t0 = $window === null
    ? 0
    : (new DateTimeImmutable($windowFrom, $utc))->getTimestamp();
$t1 = $window === null
    ? 1
    : (new DateTimeImmutable($windowTo, $utc))->getTimestamp();
$span = max(1, $t1 - $t0);

/**
 * How far along the window a moment sits, 0 to 1.
 *
 * Its own function because two things need it at two scales: a mark is
 * placed in viewBox units and inset by its own width, and the cut band
 * is a CSS width over the same box that must land on the moment itself.
 *
 * @param string $at `Y-m-d H:i:s`
 * @return float
 */
$fractionFor = function ($at) use ($t0, $span, $utc) {
    $t = (new DateTimeImmutable($at, $utc))->getTimestamp();
    return max(0, min(1, ($t - $t0) / $span));
};

/**
 * Where a moment sits on the lane axis, in viewBox units.
 *
 * @param string $at `Y-m-d H:i:s`
 * @return float
 */
$xFor = function ($at) use ($fractionFor, $LANE_W, $MARK_W) {
    return round($fractionFor($at) * ($LANE_W - $MARK_W), 1);
};

/*
 * ------------------------------------------------------------------
 * The lane's columns
 * ------------------------------------------------------------------
 * A lane used to draw one 5×13 rect per row at that row's moment, and
 * a rect like that says only *something happened near here*. It cannot
 * say how much — the count column has one number for the whole window
 * — it cannot say which of a two-source lane's sources, and two rows
 * at one moment are one rect. On `193.161.193.99` that drew 204
 * publications, 952 edits and 1,100 tag changes as the same eighteen
 * squares, three rows apart, and a reader comparing those lanes read
 * three equal rows.
 *
 * So a lane is a density profile: one column per calendar bin, height
 * on the lane's own scale, sources stacked inside the column. What was
 * lost is the exact moment — a row is now somewhere inside its bin —
 * and the chronology under the panel is where an exact moment was
 * always read.
 *
 * The bins are `ValueIntelligenceBuckets`, the same helper the spine uses,
 * at a grain chosen for this axis rather than for the spine's: 740
 * viewBox units wide, so past about 120 columns a column is thinner
 * than the gap beside it.
 */
$laneRule = array(
    array('days' => 120, 'unit' => ValueIntelligenceBuckets::DAY),
    array('days' => 730, 'unit' => ValueIntelligenceBuckets::WEEK),
    array('days' => null, 'unit' => ValueIntelligenceBuckets::MONTH),
);
$laneBins = array();
$laneAt = array();
if ($window !== null) {
    $laneDays = 1 + (int)(new DateTimeImmutable($window['from'], $utc))
        ->diff(new DateTimeImmutable($window['to'], $utc))
        ->days;
    $laneBins = ValueIntelligenceBuckets::series(
        $window['from'],
        $window['to'],
        ValueIntelligenceBuckets::unitForSpan($laneDays, $laneRule)
    );
    $laneAt = ValueIntelligenceBuckets::locate($laneBins);
}

/*
 * The column geometry, in the axis's own viewBox units — which are
 * pixels vertically, because the SVG is 38 units tall and 38px high,
 * and stretch horizontally with the panel, which is what makes a bin
 * keep its share of the width at any width.
 *
 * The bars stop at 25 so the 12 units above them stay clear for the
 * one direct label this lane carries. That label is HTML over the
 * axis and not SVG text, for the reason `.vp-lane-tag` is:
 * `preserveAspectRatio="none"` would smear a word along with the box.
 */
$BAR_BASE = $LANE_H - 1;
$BAR_MAX = 25;
$BIN_GAP = 1;

/**
 * Where a bin sits on the axis, and how wide it is.
 *
 * The full width and not `LANE_W - MARK_W`: that inset exists so a
 * *point* drawn at the window's end still fits inside the box, and a
 * bin is a span that already ends there.
 *
 * @param array $bin From `ValueIntelligenceBuckets::series()`
 * @return array x and width, in viewBox units
 */
$binBox = function (array $bin) use ($fractionFor, $LANE_W, $BIN_GAP) {
    $x = $fractionFor($bin['from'] . ' 00:00:00') * $LANE_W;
    $to = $fractionFor($bin['to'] . ' 23:59:59') * $LANE_W;
    return array(
        round($x, 2),
        round(max(1.0, $to - $x - $BIN_GAP), 2)
    );
};

/**
 * A lane's binned rows as columns.
 *
 * Both subjects this lane grid has go through here, and the only
 * difference between them is what a segment *is*: a source, in the
 * vocabulary's order, or a single tag in the colour an analyst gave
 * it. Same geometry, same scale, one code path — a second one would
 * be a second set of rounding rules.
 *
 * @param array $byBin bin index => `n`, `parts` (`hue`, `n`), `title`
 * @param bool $own Whether the hues are analyst-chosen rather than
 *                  this panel's own tokens
 * @return array `svg` and `peak`
 */
$columnsFor = function (array $byBin, $own, $ground = false) use (
    $laneBins, $binBox, $BAR_BASE, $BAR_MAX
) {
    $max = 0;
    foreach ($byBin as $bin) {
        $max = max($max, $bin['n']);
    }
    if ($max === 0) {
        return array('svg' => '', 'peak' => null);
    }
    $svg = '';
    $peak = null;
    foreach ($byBin as $i => $bin) {
        if (!isset($laneBins[$i])) {
            continue;
        }
        list($x, $w) = $binBox($laneBins[$i]);
        $h = max(2.0, round($BAR_MAX * $bin['n'] / $max, 1));
        if ($peak === null || $bin['n'] > $peak['n']) {
            $peak = array(
                'n' => $bin['n'],
                'at' => $x + $w / 2,
                'title' => $bin['title'],
            );
        }
        /*
         * A column on a hatched lane needs a ground, for the reason a
         * mark did: the one recorded edit against an unrecorded
         * background is that lane's whole point, and a bar the colour
         * of the hatch behind it loses it (§8.2).
         */
        if ($ground) {
            $svg .= '<rect class="vp-lane-ground" x="' . ($x - 1)
                . '" y="' . round($BAR_BASE - $h - 1, 2) . '" width="'
                . ($w + 2) . '" height="' . round($h + 2, 2)
                . '" rx="2"></rect>';
        }
        /*
         * And a column wearing a colour an analyst chose needs an
         * outline: nine tags on this instance are `#ffffff` and
         * fourteen are `#000000`, each of which is the lane's own
         * ground in one of the two themes, so without it a white tag
         * at the top of a stack is a shorter column.
         */
        if ($own) {
            $svg .= '<rect class="vp-lane-bar-own" x="' . $x
                . '" y="' . round($BAR_BASE - $h, 2) . '" width="' . $w
                . '" height="' . $h . '" rx="1.5"></rect>';
        }
        /*
         * A hairline between segments while a segment is tall enough
         * to have one. Below that it is most of the segment, and a
         * column of hairlines is a column of nothing.
         */
        /*
         * Segments off shared boundaries, not off independently
         * rounded heights. A tag column can hold 41 segments in 25
         * units — `193.161.193.99` does — and rounding each one on its
         * own leaves a sub-pixel crack between every pair, which at
         * that count turns the column into a barcode. Taking each
         * rect's edges from the same two rounded numbers its
         * neighbours use makes them tile exactly.
         */
        $gap = count($bin['parts']) > 1 && $h >= 6 ? 1 : 0;
        $inner = $h - $gap * (count($bin['parts']) - 1);
        $bottom = $BAR_BASE;
        $acc = 0;
        foreach ($bin['parts'] as $k => $part) {
            $acc += $part['n'];
            $top = $BAR_BASE - $inner * $acc / $bin['n'] - $gap * $k;
            $y0 = round($top, 2);
            $ph = max(0.5, round($bottom, 2) - $y0);
            $svg .= '<rect class="vp-lane-bar'
                . ($own && $ph >= 3 ? ' vp-lane-bar-edge' : '')
                . '" x="' . $x . '" y="' . $y0
                . '" width="' . $w . '" height="' . round($ph, 2)
                . '" style="--vp-tl-hue: ' . h($part['hue']) . ';">'
                . '<title>' . h($bin['title']) . '</title></rect>';
            $bottom = $top - $gap;
        }
    }
    return array('svg' => $svg, 'peak' => $peak);
};

/**
 * The peak label, as HTML over the axis.
 *
 * One direct label and not a figure on every column: a number beside
 * every bar is the thing nobody reads. It is what turns a height into
 * a quantity, so it is only worth printing where the height is a
 * quantity worth having — a lane whose busiest bin holds two rows is
 * telling the reader nothing they cannot see.
 *
 * @param array|null $peak
 * @return string
 */
$peakTag = function ($peak) use ($LANE_W) {
    if ($peak === null || $peak['n'] < 3) {
        return '';
    }
    $at = 100 * $peak['at'] / $LANE_W;
    $side = $at > 86 ? ' vp-lane-peak-r' : ($at < 6
        ? ' vp-lane-peak-l' : '');
    return '<span class="vp-lane-peak' . $side . '" style="left: '
        . round($at, 2) . '%;" title="' . h($peak['title']) . '">'
        . h(sprintf(__('peak %s'), number_format($peak['n'])))
        . '</span>';
};

/*
 * The month names the ruler and the spine's axis both read. Formatted
 * once here and shipped, because the ruler is redrawn client-side for
 * every brush and a second formatter in JavaScript would be a second
 * vocabulary — `toLocaleString` follows the browser's locale, `M`
 * follows PHP's, and the two disagree the moment they differ.
 */
$months = array();
for ($m = 1; $m <= 12; $m++) {
    $months[] = (new DateTimeImmutable(sprintf('2001-%02d-01', $m), $utc))
        ->format('M');
}

/**
 * What a lane column's bin is called, out of the same twelve names.
 *
 * One rule for all three grains rather than a name per unit —
 * `ValueIntelligenceBuckets::describe()` writes *November 2025* for a month
 * and the script has only the abbreviations, so reusing its title
 * would put the two renderers a word apart on every month bin.
 *
 * @param array $bin `from` and `to`, `Y-m-d`
 * @return string
 */
$binTitle = function (array $bin) use ($months, $utc) {
    $a = new DateTimeImmutable($bin['from'] . ' 00:00:00', $utc);
    $b = new DateTimeImmutable($bin['to'] . ' 00:00:00', $utc);
    if ($bin['from'] === $bin['to']) {
        return $a->format('j') . ' '
            . $months[(int)$a->format('n') - 1] . ' ' . $a->format('Y');
    }
    return $a->format('j') . ' ' . $months[(int)$a->format('n') - 1]
        . ' – ' . $b->format('j') . ' '
        . $months[(int)$b->format('n') - 1] . ' ' . $b->format('Y');
};
foreach ($laneBins as $i => $bin) {
    $laneBins[$i]['title'] = $binTitle($bin);
}

/*
 * The elided bin's title, written here because it is written out of
 * `$binTitle` — the twelve names the ruler and the lanes already use,
 * rather than `describe()`'s, for §16's reason: two spellings of one
 * month is two vocabularies.
 *
 * It says the span and it says the axis is not to scale across it,
 * because those are the two things a reader cannot get from a bin
 * with no bar in it.
 */
if ($tail !== null && $tail['elided'] > 0) {
    $bins[$tail['at']]['title'] = sprintf(
        __('%s — nothing recorded, and not drawn to scale'),
        $binTitle($bins[$tail['at']])
    );
}

/**
 * One ruler label: the day, plus whatever the tick before it has not
 * already said.
 *
 * @param DateTimeImmutable $at
 * @param DateTimeImmutable|null $prev The tick to its left, if any
 * @return string
 */
$rulerLabel = function ($at, $prev) use ($months) {
    $day = $at->format('j');
    if ($prev !== null && $prev->format('Y-m') === $at->format('Y-m')) {
        return $day;
    }
    $label = $day . ' ' . $months[(int)$at->format('n') - 1];
    if ($prev === null || $prev->format('Y') !== $at->format('Y')) {
        $label .= ' ' . $at->format('Y');
    }
    return $label;
};

/*
 * Five ticks across the window. Enough for a reader to place a mark
 * without turning the lane header into a ruler.
 *
 * Each one names its month where the month changed and its year where
 * the year did, which the first four never did before: the window is
 * the reader's to set and a brush over the whole spine is years wide,
 * so a ruler of bare day numbers put four of its five ticks in the
 * first tick's month and never named a year at all.
 */
$ticks = array();
if ($window !== null) {
    $prev = null;
    for ($i = 0; $i < 5; $i++) {
        $at = $t0 + (int)round(($span * $i) / 4);
        $tick = (new DateTimeImmutable('@' . $at))->setTimezone($utc);
        $ticks[] = $rulerLabel($tick, $prev);
        $prev = $tick;
    }
}

/*
 * ------------------------------------------------------------------
 * The lanes
 * ------------------------------------------------------------------
 * Seven, and every one of them can now put something on the axis.
 *
 * §8.2's rule — a full-size hatched lane for a source MISP cannot date,
 * so a reader scanning the lanes cannot miss what is missing — no
 * longer has a lane to apply to, and that is progress rather than a
 * regression: §22.6 removed the feed lane because there was no date to
 * be had, and §22.7 dated the tag set from the audit log. What is left
 * unplaceable is a *subset* of the tag set, and the lane that holds
 * those tags states its own gap — *4 of 7 datable* — which is the
 * visibility the rule was buying, said by the row that has the facts.
 *
 * The two tag lanes are not a duplication. Tags is the set the value
 * carries now, one mark at each tag's first attach; Tag changes is
 * every attach and detach, including tags since removed. State and
 * activity.
 */
$lanes = array(
    array(
        'key' => 'sightings',
        'label' => __('Sightings'),
        'sub' => __('date_sighting, exact'),
        'sources' => array('sighting', 'false_positive', 'expiration'),
        'draw' => 'marks',
    ),
    array(
        'key' => 'publications',
        'label' => __('Publications'),
        'sub' => __('first & last only'),
        'sources' => array('publication'),
        'draw' => 'marks',
    ),
    array(
        'key' => 'analyst',
        'label' => __('Notes / Opinions'),
        'sub' => __('created, exact'),
        'sources' => array('note', 'opinion'),
        'draw' => 'marks',
    ),
    /*
     * Beside the analyst lane because it is the same union's other
     * half: a report is written about an event, exactly as an
     * event-level note is, and nothing in MISP addresses a value. The
     * sub-label says which date it is, because `event_reports` has no
     * `created` and a reader who assumes one would read every mark as
     * the day the report was filed.
     */
    array(
        'key' => 'reports',
        'label' => __('Event reports'),
        'sub' => __('last edited, on this value\'s events'),
        'sources' => array('report'),
        'draw' => 'marks',
    ),
    /*
     * Beside Edits, because a proposal is an edit that has not
     * happened — and the pair reads as one question: what changed, and
     * what was asked to change.
     */
    array(
        'key' => 'proposals',
        'label' => __('Proposals'),
        'sub' => __('last moved; a resolved one sits at its resolution'),
        'sources' => array('proposal'),
        'draw' => 'marks',
    ),
    array(
        'key' => 'edits',
        'label' => __('Edits'),
        /*
         * Which of the lane's two shapes it is in. `latest per
         * occurrence` is the fallback's description — one point from
         * `attributes.timestamp` — and it was printed over the audit
         * branch too, where the lane draws one mark per logged change
         * and the phrase is simply false.
         */
        'sub' => $auditRecorded
            ? __('every logged change')
            : __('latest per occurrence'),
        'sources' => array('edit'),
        'draw' => 'marks',
        /*
         * A lane state, not a whole-tab state. One point per occurrence
         * is still a point, so the lane keeps its mark and the hatch
         * behind it names the setting that would fill in the rest.
         */
        'hatch' => $auditRecorded ? null : __(
            'Nothing before each occurrence\'s latest edit is recorded'
            . ' — MISP.log_new_audit is off.'
        ),
    ),
    /*
     * The lane the Edits lane used to carry. `audit_logs` is the only
     * place a tag on this value is dated, and its tag rows were being
     * filed as edits — so a tagged value read as a value that had been
     * edited hundreds of times, three feet below a Tags lane saying
     * that only an audit row could date a tag.
     *
     * Attach *and* detach, and the mark says which: a tag that was
     * taken off is as much a dated fact about this value as one that
     * was put on.
     */
    array(
        'key' => 'tagging',
        'label' => __('Tag changes'),
        'sub' => $auditRecorded
            ? __('attach & detach, exact')
            : __('nothing recorded'),
        'sources' => array('tag', 'cluster'),
        'draw' => 'marks',
        'hatch' => $auditRecorded ? null : __(
            'An audit row is the only thing that dates a tag, and'
            . ' MISP.log_new_audit is off.'
        ),
    ),
    array(
        'key' => 'seen',
        'label' => __('Seen spans'),
        /*
         * Three numbers and not two, when the cap bites: how many
         * occurrences carry a span, of how many the viewer can see, and
         * how many of those this lane drew. A cap is not a permission,
         * so the third is said out loud for every reader.
         */
        'sub' => $seenSub,
        'sources' => array('seen', 'seen_object'),
        'draw' => 'spans',
    ),
    /*
     * Directly under Seen spans, because it is the same question asked
     * of a third source and the reader should meet the three together:
     * the attribute's column, the object's column, and the field the
     * object's template chose to put a date in.
     *
     * Not folded into that lane, because the vocabulary is not one
     * notion — `compilation-timestamp` and `send-date` are `datetime`
     * fields that say nothing about when anything was *seen*. The
     * sub-label prints the vocabulary this value actually has, so the
     * reader knows which of the two they are looking at before they
     * read a single mark.
     */
    array(
        'key' => 'objdates',
        'label' => __('Object dates'),
        'sub' => $objdateSub,
        'sources' => array('objdate'),
        'draw' => 'spans',
        'absent' => __(
            'No object holding this value records a date of its own.'
        ),
    ),
    array(
        'key' => 'tags',
        'label' => __('Tags'),
        /*
         * Three numbers where the cap or the log's reach bites, and the
         * middle one is the point: how many tags the value carries, how
         * many of those the audit log can place, and — where they
         * differ — that the rest are on the strip.
         */
        'sub' => count($tagsDated) < count($tagState)
            ? sprintf(
                __('first attached · %1$s of %2$s datable'),
                count($tagsDated),
                count($tagState)
            )
            : __('first attached, in the tag\'s own colour'),
        'draw' => 'tagfirst',
        'tags' => $tagState,
        'dated' => $tagsDated,
        'absent' => __('Nothing has tagged this value.'),
    ),
    /*
     * **No feed lane.** It had a full-size row and nothing to put in
     * it: the feed cache holds one timestamp for the whole feed,
     * rewritten on every refresh, so there is no date for *this value
     * in that feed* to be right or wrong about — and unlike the tag
     * set, which is a fact the reader wants from this tab, which feeds
     * hold the value is answered in full by the External sources panel
     * on the Relationships tab, names included.
     *
     * §8.2's rule bought visibility for an absence that a reader might
     * otherwise mistake for a quiet period. Feeds are not that: there
     * is no period to be quiet in. The one-line chip on the off-axis
     * strip above keeps the fact on the tab, which is all it was
     * worth.
     */
);

/**
 * How many of a lane's entries in the window have no row to be drawn
 * from — its aggregate less the rows the fragment carries.
 *
 * Only the mark lanes are asked. The seen lane's own cap cuts the
 * *newest* of its spans, not the oldest, so a band anchored to the
 * window's start would be exactly backwards there — and its sub-label
 * already states all three of its numbers. The undated lanes have no
 * time axis to band.
 *
 * @param array $lane
 * @return int
 */
$laneCut = function (array $lane) use ($inWindow, $windowed) {
    if ($lane['draw'] !== 'marks') {
        return 0;
    }
    $n = 0;
    foreach ($lane['sources'] as $source) {
        $n += isset($inWindow[$source]) ? (int)$inWindow[$source] : 0;
    }
    foreach ($windowed as $entry) {
        if (in_array($entry['source'], $lane['sources'], true)) {
            $n--;
        }
    }
    return max(0, $n);
};

/*
 * The whole grid's share of it, for the one sentence that explains the
 * bands. Summed over the lanes that can carry a band rather than taken
 * as *window total less rows carried*, so the seen lane's own
 * truncation is not counted into a claim about the row cap.
 */
$cutTotal = 0;
foreach ($lanes as $lane) {
    $cutTotal += $laneCut($lane);
}

/*
 * ------------------------------------------------------------------
 * The chronology
 * ------------------------------------------------------------------
 * Newest first, grouped by day. Runs of one source inside one day
 * collapse to a summary row: forty-seven sightings must not be
 * forty-seven rows. A day is wholly inside the window or wholly outside
 * it, so a run's shape never changes when the brush moves — which is
 * what lets the grouping be done once, here, rather than again in
 * JavaScript every time the window changes.
 */
$RUN_MIN = 3;
$SHOWN_MAX = 14;

$rowsByDay = array();
foreach (array_reverse($entries) as $entry) {
    $day = substr($entry['at'], 0, 10);
    if (!isset($rowsByDay[$day])) {
        $rowsByDay[$day] = array();
    }
    $rowsByDay[$day][] = $entry;
}

$days = array();
foreach ($rowsByDay as $day => $rows) {
    $units = array();
    $current = array();
    foreach ($rows as $entry) {
        if (!empty($current)
            && $current[0]['source'] !== $entry['source']) {
            $units[] = $current;
            $current = array();
        }
        $current[] = $entry;
    }
    if (!empty($current)) {
        $units[] = $current;
    }
    $days[] = array(
        'day' => $day,
        'label' => (new DateTimeImmutable($day, $utc))
            ->format('l, j F Y'),
        'units' => $units,
    );
}

/*
 * The precision tally, over the window and only over the window. It
 * sums to the number of entries in the list beneath it, which is the
 * property that makes it worth printing at all — and it is therefore
 * a tally over the *listed* rows rather than over the value, which is
 * the one place on this panel where that is the right choice.
 */
$tally = array('exact' => 0, 'partial' => 0);
foreach ($windowed as $entry) {
    $meta = $precisionMeta[$entry['precision']];
    $tally[$meta['bucket']]++;
}

/*
 * What the spine needs, and nothing else. The lanes and the chronology
 * re-scope from the rows already in the DOM rather than from a second
 * copy of them here — one array, three readings, and only one of the
 * three needs a canvas.
 */
$payload = null;
if ($window !== null) {
    $datasets = array();
    foreach ($present as $source) {
        $data = array();
        foreach ($bins as $bin) {
            $data[] = isset($bin['counts'][$source])
                ? $bin['counts'][$source]
                : 0;
        }
        $datasets[] = array(
            'source' => $source,
            'label' => $sourceMeta[$source]['label'],
            'colour' => $sourceMeta[$source]['token'],
            'data' => $data,
        );
    }
    $payload = array(
        'bins' => array_map(function ($bin) {
            return array(
                'key' => $bin['key'],
                'label' => $bin['label'],
                'title' => $bin['title'],
                'from' => $bin['from'],
                'to' => $bin['to'],
                /*
                 * How many bins this one stands in for. Zero on every
                 * bin but the elided one, and the script reads it for
                 * two things: where to draw the break, and which bin
                 * to keep out of the year ticks — a `⋯` under a year
                 * would date the break to its far end.
                 */
                'elided' => isset($bin['elided']) ? $bin['elided'] : 0,
            );
        }, $bins),
        'datasets' => $datasets,
        /*
         * Where the value stops and the wait begins, or null for a
         * value that has not stopped. The script needs the index
         * rather than a date: the tail is a band over whole bin
         * slots, and the bins are equal-width categories whose date
         * spans are not.
         */
        'tail' => $tail,
        /*
         * The day map travels with the chart, so a brushed window is
         * counted the same way the default one was: summed over every
         * day the viewer may see. Without it the script would fall back
         * to tallying the rows in the DOM, which are capped — and the
         * lane counts would drop the moment a reader brushed a value
         * whose chronology did not fit, which is the disagreement this
         * panel exists to make impossible. A day is a date and a small
         * object; `443`'s whole history is 49 of them.
         */
        'by_day' => $countsByDay,
        /*
         * And the intervals beside it, for the half of the same
         * problem a day map cannot hold. A brushed window that lands
         * between a span's two ends shares no day with it, so counting
         * from `by_day` alone reported a lane the reader can see a bar
         * in as holding nothing — the exact disagreement the note
         * above says this map exists to make impossible.
         */
        'spans' => $spanRanges,
        'window' => array(
            'from' => $window['from'],
            'to' => $window['to'],
            /*
             * Whether this window was asked for. The script needs it
             * for the two gestures that go back to the server: a click
             * clearing the brush, and `Reset window`, both of which are
             * a repaint on a default fragment and a request on one
             * fetched for a window.
             */
            'requested' => $windowRequested,
        ),
        'lane' => array(
            'width' => $LANE_W,
            'height' => $LANE_H,
            'mark' => $MARK_W,
            /*
             * The column geometry and the grain rule, shipped rather
             * than restated in the script. The brush rebins client-side
             * and a second copy of these thresholds would be a second
             * vocabulary — the same reason `months` is formatted here:
             * two renderers of one lane have to round identically or
             * the lane moves when the reader lets go of the brush.
             */
            'base' => $BAR_BASE,
            'bar' => $BAR_MAX,
            'gap' => $BIN_GAP,
            'rule' => $laneRule,
            /*
             * The seen lane's label-collision rule, for the same reason
             * as the rest of this block: the script rebuilds those
             * labels on every brush, and a second copy of these two
             * numbers would let the two renderers disagree about which
             * labels a window can hold.
             */
            'tag_char' => $TAG_CHAR,
            'tag_ref' => $TAG_REF,
        ),
        // For the ruler over the lanes, which moves with the brush.
        'months' => $months,
        /*
         * The Tags lane's marks, which are the tag set rather than the
         * entry set — the script redraws them for every window from
         * here. Datable ones only: a tag with no first attach has no
         * position to be redrawn at, and it is named on the strip.
         */
        'tags' => array_map(function ($tag) {
            return array(
                'name' => $tag['name'],
                'colour' => $tag['colour'],
                'at' => $tag['at'],
            );
        }, $tagsDated),
        'labels' => array(
            'entries' => __('entries'),
            'cut' => $cutTitle,
            'axis' => __('Dated entries per month, stacked by source'),
            /*
             * Printed at the right-hand end of the empty band, where
             * there is room for it. The axis already ends at today —
             * `series()` clamps its last bin there — so this names an
             * edge the reader can otherwise only infer from a tick.
             */
            'today' => __('today'),
            /*
             * The note over the chronology names the filter either way
             * round, because shift-clicking a key drops one source and
             * *showing* the six that are left is the same fact written
             * six times.
             */
            'showing' => __('Showing'),
            'hiding' => __('Hiding'),
            // A tag column's tooltip, substituted rather than composed
            // so the words stay translatable in one place.
            'tag_first' => __('%1$s — first attached %2$s'),
            'tag_more' => __(' +%s more'),
            // The lane's one direct label: what its tallest column
            // holds.
            'peak' => __('peak %s'),
        ),
    );
}

$subtitle = $timeline === null
    ? h(__('Nothing to place on an axis'))
    : h(sprintf(
        __('%1$s dated · %2$s named but undatable'),
        $counts['total'],
        array_sum(array_column($undated, 'count'))
    ));
?>
<?php
/*
 * The endpoint, without the window: what the brush asks again for when
 * it lands past the rows this fragment carries, and what `Reset window`
 * asks for to get back. The same shape `value_history.ctp` ships as
 * `data-vp-audit-base`, because it is the same gesture — a control that
 * has reached the edge of what it was sent.
 */
$timelineBase = $baseurl . '/values/viewTimeline/' . $valueB64;
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--bs-info);"
     data-vp-tl-base="<?= h($timelineBase) ?>"
     <?= $timeline === null ? '' : 'data-vp-tl' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Timeline'),
        'panelIcon' => 'fas fa-clock',
        'panelColor' => 'var(--bs-info)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if ($timeline === null): ?>

        <?php
        /*
         * Not an empty timeline — no timeline. An axis, empty bins and
         * seven lanes over a value with no occurrence to date would be
         * inventing a period of silence that never happened.
         *
         * **The sentence says nothing about why.** *Because MISP has
         * never held it* is one of the two cases: the other is a value
         * held only in events this reader cannot open. Naming the first
         * would be false for the second,
         * and naming either would make the panel answer *does this exist
         * on the instance* — on a page whose URL takes any value the
         * reader types. So one sentence, true both ways, identical for
         * every reader.
         */
        ?>
        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-clock"></i>
                <span><?= __('There is no occurrence of this value here'
                    . ' to place on an axis.') ?></span>
            </div>
        </div>

    <?php else: ?>

        <script type="application/json" data-vp-tl-data><?=
            json_encode($payload) ?></script>

        <div class="p-3 vp-tl">

            <?php
            /*
             * ------------------------------------------------------
             * 1. The spine
             * ------------------------------------------------------
             * A control, not a second chart. Every count below it is
             * scoped to what is brushed here, which is what stops the
             * spine and the lanes from being two encodings of the same
             * thing sitting next to each other.
             */
            ?>
            <section class="vp-tl-card">
                <div class="vp-tl-head">
                    <div class="vp-min-w-0">
                        <div class="fw-semibold">
                            <?= __('Activity on this value') ?>
                        </div>
                        <div class="vp-tl-why">
                            <?php
                            /*
                             * The grain is named rather than assumed:
                             * it is chosen from the value's range, so
                             * two values on this page can carry two
                             * different bar widths and a reader who is
                             * not told will read one as the other.
                             */
                            $grainWord = array(
                                ValueIntelligenceBuckets::DAY => __('by day'),
                                ValueIntelligenceBuckets::WEEK => __('by week'),
                                ValueIntelligenceBuckets::MONTH =>
                                    __('by month'),
                            );
                            ?>
                            <?= h(sprintf(
                                __(
                                    '%1$s %2$s, stacked by source.'
                                    . ' Drag to set the window — the'
                                    . ' lanes and the chronology below'
                                    . ' both follow it. Press a source'
                                    . ' in the key to narrow the chart'
                                    . ' to it.'
                                ),
                                __n(
                                    '%s dated entry',
                                    '%s dated entries',
                                    $counts['total'],
                                    $counts['total']
                                ),
                                isset($grainWord[$spineUnit])
                                    ? $grainWord[$spineUnit]
                                    : __('by month')
                            )) ?>
                        </div>
                    </div>
                    <?php
                    /*
                     * The key is a control, not a caption. A stacked
                     * bar whose bottom segment is three orders of
                     * magnitude taller than the rest — `193.161.193.99`
                     * files 1,256 sightings against 111 publications —
                     * draws the other sources as a hairline, and the
                     * only way to read them was to squint. Pressing a
                     * key narrows the chart *and* the chronology to
                     * that source, which is the same selection the lane
                     * buttons below set: one filter, two ways in.
                     *
                     * `aria-pressed` here means *this source is drawn*
                     * and starts true, which is the opposite of the
                     * lane buttons' *this lane is the whole filter*.
                     * They are two gestures — a visibility toggle and
                     * a solo — and each one's title says which.
                     *
                     * Disabled until the script arrives, for the
                     * brush's reason: without it these would offer a
                     * gesture that cannot do anything.
                     */
                    ?>
                    <div class="vp-tl-legend" data-vp-tl-legend>
                        <?php foreach ($present as $source): ?>
                            <button type="button" class="vp-tl-key"
                                    data-vp-tl-key="<?= h($source) ?>"
                                    aria-pressed="true" disabled
                                    title="<?= h(sprintf(
                                        __('%1$s · %2$s dated. Click to'
                                            . ' show only this source,'
                                            . ' shift-click to drop it.'),
                                        $sourceMeta[$source]['label'],
                                        number_format(
                                            $counts['by_source'][$source]
                                        )
                                    )) ?>">
                                <span class="vp-tl-swatch"
                                      style="--vp-tl-hue: <?=
                                          h($sourceMeta[$source]['token'])
                                      ?>;"></span>
                                <?= h($sourceMeta[$source]['label']) ?>
                            </button>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="vp-tl-spine" data-vp-tl-spine>
                    <?php
                    /*
                     * Named from the grain and the range: the spine
                     * covers the value's whole history at whichever of
                     * three grains the range asks for.
                     */
                    ?>
                    <canvas id="vp-tl-spine" role="img"
                            aria-label="<?= h(sprintf(
                                __('Dated entries %1$s from %2$s to'
                                    . ' %3$s, stacked by source'),
                                isset($grainWord[$spineUnit])
                                    ? $grainWord[$spineUnit]
                                    : __('by month'),
                                $rangeFrom === null ? '-' : $rangeFrom,
                                /*
                                 * The drawn end and not the value's,
                                 * because those are two dates now and
                                 * a label naming the wrong one would
                                 * tell a screen reader the axis stops
                                 * where the bars do.
                                 */
                                $bins === array()
                                    ? '-'
                                    : $bins[count($bins) - 1]['to']
                            )) ?>"></canvas>
                    <?php
                    /*
                     * Hidden until the chart it controls exists. A
                     * brush framing an empty canvas offers a gesture
                     * that cannot do anything, which is worse than
                     * offering none.
                     */
                    ?>
                    <?= $this->element(
                        'genericElementsBS5/brush',
                        ['hidden' => true]
                    ) ?>
                </div>

                <?php if ($tail !== null && $tail['quiet']): ?>
                    <?php
                    /*
                     * The wait, in words, under the chart that draws
                     * it as a length.
                     *
                     * Both, and not one or the other. The empty band
                     * is what a reader sees without looking — it is
                     * the thing that makes a dormant value and a live
                     * one different pictures — and a length read off
                     * an axis is an estimate. The sentence is the
                     * number, and it is also the only form the wait
                     * takes for a reader on a screen reader or with
                     * no script at all.
                     */
                    $sinceWord = function ($days) {
                        if ($days < 31) {
                            return sprintf(
                                __n('%d day', '%d days', $days),
                                $days
                            );
                        }
                        if ($days < 730) {
                            $n = max(1, (int)round($days / 30.44));
                            return sprintf(
                                __n('%d month', '%d months', $n),
                                $n
                            );
                        }
                        $n = max(2, (int)round($days / 365.25));
                        return sprintf(
                            __n('%d year', '%d years', $n),
                            $n
                        );
                    };
                    ?>
                    <div class="vp-tl-quiet">
                        <i class="fas fa-hourglass-end"></i>
                        <div class="vp-min-w-0">
                            <div class="fw-semibold">
                                <?= h(sprintf(
                                    __('Quiet for %s'),
                                    $sinceWord($tail['days'])
                                )) ?>
                            </div>
                            <div class="vp-tl-why">
                                <?= h(sprintf(
                                    __(
                                        'Nothing dated against this'
                                        . ' value since %s. The axis'
                                        . ' runs to today, so the'
                                        . ' empty stretch at its'
                                        . ' right-hand end is that'
                                        . ' silence.'
                                    ),
                                    $binTitle(array(
                                        'from' => $tail['since'],
                                        'to' => $tail['since'],
                                    ))
                                )) ?>
                            </div>
                            <?php if ($tail['elided'] > 0): ?>
                                <div class="vp-tl-why">
                                    <?= h(sprintf(
                                        __(
                                            'The break in the axis'
                                            . ' stands for %s. The'
                                            . ' chart is to scale on'
                                            . ' either side of the'
                                            . ' break and not across'
                                            . ' it.'
                                        ),
                                        $binTitle($bins[$tail['at']])
                                    )) ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>

                <noscript>
                    <?php
                    /*
                     * The counts below are already right — they were
                     * computed for the default window before this page
                     * was sent. It is only the chart and the brush that
                     * need a script, so that is all this says.
                     */
                    ?>
                    <div class="vp-tl-why">
                        <?= h(sprintf(
                            __(
                                'The chart and its window control need'
                                . ' JavaScript. Everything below is the'
                                . ' window %1$s to %2$s, and its counts'
                                . ' are correct without it.'
                            ),
                            $window['from'],
                            $window['to']
                        )) ?>
                    </div>
                </noscript>

                <?php if ($before > 0): ?>
                    <?php
                    /*
                     * The spine holds twelve months and this value is
                     * older. Said out loud rather than left as a chart
                     * that silently begins after the beginning.
                     */
                    ?>
                    <div class="vp-tl-why pt-1">
                        <?= h(sprintf(
                            __(
                                '%1$s older than this chart, the'
                                . ' earliest on %2$s. They are in the'
                                . ' chronology and not on the axis.'
                            ),
                            __n(
                                '%s entry is',
                                '%s entries are',
                                $before,
                                $before
                            ),
                            substr($earliest, 0, 10)
                        )) ?>
                    </div>
                <?php endif; ?>

                <?php if ($firstHere !== null): ?>
                    <?php
                    /*
                     * The question a reader asks before any of the
                     * others, and the tab answered it nowhere: the
                     * axis's left edge is where the *record* starts,
                     * which is a different fact and one this panel is
                     * in a position to be precise about.
                     *
                     * One sentence in two prepositions, and they are the
                     * whole point: *since* is a date the audit log
                     * holds, *by* is a bound the records support. The
                     * clause after it says which row it came from, so
                     * the distinction is never left to the preposition
                     * alone.
                     *
                     * Never the words *first seen*. That phrase is
                     * taken, by the lane three rows down that draws
                     * what an analyst claimed about the world rather
                     * than anything about this instance.
                     */
                    $firstDay = substr($firstHere['at'], 0, 10);
                    if ($firstHere['exact']) {
                        $firstWhy = __('The oldest creation the audit'
                            . ' log holds for these records.');
                    } elseif ($firstHere['from'] === 'timestamp') {
                        $firstWhy = __('From an occurrence\'s'
                            . ' last-modified stamp — MISP records no'
                            . ' creation date for an attribute, so it'
                            . ' may be older.');
                    } else {
                        $firstWhy = __('The oldest dated thing here.'
                            . ' MISP records no creation date for an'
                            . ' attribute, so it may be older.');
                    }
                    ?>
                    <div class="vp-tl-firsthere">
                        <i class="fas fa-flag"></i>
                        <span>
                            <b><?= h(sprintf(
                                $firstHere['exact']
                                    ? __('On this instance since %s')
                                    : __('On this instance by %s'),
                                $firstDay
                            )) ?></b>
                            <span class="vp-tl-why"><?= h($firstWhy) ?></span>
                        </span>
                    </div>
                <?php endif; ?>

                <?php
                /*
                 * The off-axis strip. Not conditional on the brush, and
                 * that is the point: nothing on it is in any window,
                 * because nothing on it has a date to be in one with.
                 *
                 * These same facts also keep a full-size lane below, so
                 * neither a reader who scans the chart nor one who
                 * scans the lanes can miss them (§8.7).
                 */
                ?>
                <?php if (!empty($undated) || $gap !== null): ?>
                    <div class="vp-tl-offaxis">
                        <?php if (!empty($undated)): ?>
                            <i class="fas fa-circle-info"></i>
                            <span class="fw-semibold">
                                <?= __('Never on this axis:') ?>
                            </span>
                            <?php foreach ($undated as $row): ?>
                                <span class="vp-tl-undated-chip"
                                      title="<?= h($row['reason']) ?>">
                                    <?= h($row['kind']) ?>
                                    <strong><?= h($row['count']) ?></strong>
                                    <?php if ($row['as_of'] !== null): ?>
                                        — <?= h(sprintf(
                                            __('as of %s'),
                                            substr($row['as_of'], 0, 16)
                                        )) ?>
                                    <?php elseif (!empty($row['suffix'])): ?>
                                        — <?= h($row['suffix']) ?>
                                    <?php else: ?>
                                        — <?= __('no date column') ?>
                                    <?php endif; ?>
                                </span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        <?php if ($gap !== null): ?>
                            <span class="ms-auto vp-tl-why">
                                <?= h($gap['len'] === 1
                                    ? sprintf(
                                        __(
                                            '%s is empty here. Whether'
                                            . ' the value was quiet or'
                                            . ' the record was not kept'
                                            . ' is what the lanes below'
                                            . ' answer.'
                                        ),
                                        $gap['from']['title']
                                    )
                                    : sprintf(
                                        __(
                                            '%1$s to %2$s is empty here.'
                                            . ' Whether the value was'
                                            . ' quiet or the record was'
                                            . ' not kept is what the'
                                            . ' lanes below answer.'
                                        ),
                                        $gap['from']['title'],
                                        $gap['to']['title']
                                    )) ?>
                            </span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </section>

            <?php
            /*
             * ------------------------------------------------------
             * 2. The lanes
             * ------------------------------------------------------
             */
            ?>
            <section class="vp-tl-card">
                <div class="vp-tl-head">
                    <div class="vp-min-w-0">
                        <div class="fw-semibold">
                            <?= __('Sources in this window') ?>
                        </div>
                        <div class="vp-tl-why">
                            <span data-vp-tl-window-label><?= h(sprintf(
                                __('%1$s to %2$s'),
                                $window['from'],
                                $window['to']
                            )) ?></span>
                            ·
                            <span data-vp-tl-window-count><?=
                                (int)$inWindow['total'] ?></span>
                            <?php
                            /*
                             * The noun agrees with the number, and it
                             * is a node the script can rewrite because
                             * the number is one the script rewrites. A
                             * brush landing on a single entry — which
                             * a narrow window over one span now
                             * routinely is — was reading *1 entries*.
                             */
                            ?>
                            <span data-vp-tl-window-noun
                                  data-vp-tl-one="<?= h(__('entry')) ?>"
                                  data-vp-tl-many="<?= h(__('entries')) ?>"
                            ><?= h((int)$inWindow['total'] === 1
                                ? __('entry')
                                : __('entries')) ?></span>
                            ·
                            <?php
                            /*
                             * The bands' one sentence, and the reason
                             * they are not left to be read as a
                             * texture. It is in the reading path rather
                             * than in a tooltip for §8.2's rule: a
                             * lane's admission that it is incomplete
                             * has to be as visible as the lane.
                             *
                             * The advice is real now. Brushing the
                             * hatched span fetches it, because the
                             * newest cap-many of a narrower window
                             * reaches further back.
                             */
                            ?>
                            <span data-vp-tl-cut-note
                                  <?= $cutTotal > 0 ? '' : 'hidden' ?>>
                                <span class="vp-lane-cut-key"></span>
                                <?= sprintf(
                                    __('%s in no column — brush the'
                                        . ' hatched span to fetch'
                                        . ' them'),
                                    '<b data-vp-tl-cut-n>'
                                        . h(number_format($cutTotal))
                                        . '</b>'
                                ) ?>
                                ·
                            </span>
                            <?= __('a lane per dated source, and the tag'
                                . ' set at each tag\'s first attach') ?>
                        </div>
                    </div>
                    <?php
                    /*
                     * Hidden unless the window is already off the
                     * default — which the server knows when it was
                     * asked for one, and the script takes over from
                     * there.
                     */
                    ?>
                    <button type="button"
                            class="btn btn-sm btn-outline-secondary"
                            data-vp-tl-reset
                            <?= $windowRequested ? '' : 'hidden' ?>>
                        <?= __('Reset window') ?>
                    </button>
                </div>

                <div class="vp-lanes">
                    <div class="vp-lane-head"><?= __('Source') ?></div>
                    <div class="vp-lane-head vp-lane-ticks"
                         data-vp-tl-ticks>
                        <?php foreach ($ticks as $tick): ?>
                            <span><?= h($tick) ?></span>
                        <?php endforeach; ?>
                    </div>
                    <div class="vp-lane-head text-end">
                        <?= __('In window') ?>
                    </div>

                    <?php foreach ($lanes as $lane): ?>
                        <?php
                        $tagLane = $lane['draw'] === 'tagfirst';
                        $sources = isset($lane['sources'])
                            ? $lane['sources']
                            : array();

                        /*
                         * The lane's own share of the window, from the
                         * summed day map rather than from the rows the
                         * chronology happens to be carrying. On a value
                         * whose chronology is capped these differ, and
                         * the row tally is the one that is wrong: `443`
                         * ships 1,000 rows inside three days, so tallying
                         * them would report a window of 11 entries as
                         * 300 and every quiet lane as busy.
                         */
                        $laneCount = 0;
                        $parts = array();
                        foreach ($sources as $source) {
                            $n = isset($inWindow[$source])
                                ? (int)$inWindow[$source]
                                : 0;
                            $laneCount += $n;
                            if ($n > 0) {
                                $parts[] = $n . ' '
                                    . $sourceMeta[$source]['label'];
                            }
                        }
                        // What the lane draws, which is still the rows:
                        // marks come from entries, counts do not.
                        $mine = array();
                        foreach ($windowed as $entry) {
                            if (in_array($entry['source'], $sources)) {
                                $mine[] = $entry;
                            }
                        }

                        /*
                         * A lane whose sources this value has nothing
                         * dated of gets no button. Narrowing to it can
                         * only empty the chart and the chronology
                         * together — the filter reaches both now — and
                         * an empty spine under a note naming a source
                         * that was never here reads as a broken panel
                         * rather than as an answer. The lane still
                         * renders, because §8.2's rule is that what is
                         * missing must be as visible as what is not.
                         */
                        $laneDead = true;
                        foreach ($sources as $source) {
                            if (!empty($counts['by_source'][$source])) {
                                $laneDead = false;
                            }
                        }
                        ?>

                        <div class="vp-lane-label">
                            <?php if ($laneDead): ?>
                                <span class="vp-tl-src vp-tl-src-<?=
                                        h($lane['key']) ?>"
                                      title="<?= h(sprintf(
                                          __('Nothing dated of %s on'
                                              . ' this value, so there'
                                              . ' is nothing to narrow'
                                              . ' to'),
                                          $lane['label']
                                      )) ?>">
                                    <?= h($lane['label']) ?>
                                </span>
                            <?php else: ?>
                                <button type="button" class="vp-tl-src-btn"
                                        data-vp-tl-lane="<?= h($lane['key'])
                                            ?>"
                                        data-vp-tl-sources="<?=
                                            h(implode(',', $sources)) ?>"
                                        aria-pressed="false"
                                        title="<?= h(sprintf(
                                            __('Show only %s in the'
                                                . ' chart and the'
                                                . ' chronology'),
                                            $lane['label']
                                        )) ?>">
                                    <span class="vp-tl-src vp-tl-src-<?=
                                        h($lane['key']) ?>">
                                        <?= h($lane['label']) ?>
                                    </span>
                                </button>
                            <?php endif; ?>
                            <div class="vp-tl-why"><?= h($lane['sub']) ?>
                            </div>
                        </div>

                        <?php if ($tagLane): ?>
                            <?php
                            /*
                             * One mark per tag, at the first time it
                             * was attached — the fact a reader wants
                             * out of a tag set, and one the raw stream
                             * cannot give: a tag is re-attached on
                             * every re-import.
                             *
                             * The mark takes the tag's **own** colour,
                             * not a source token. There is one source
                             * here and eight marks, and what
                             * distinguishes them is which tag they are.
                             *
                             * The readable half is the chip row below,
                             * and it is deliberately not on the axis:
                             * first attaches cluster at the beginning
                             * of a value's history while the window
                             * defaults to the last month, so a lane
                             * that said this only in marks would say
                             * nothing at all until the reader brushed
                             * back two years.
                             */
                            $tagWindowed = array();
                            foreach ($lane['dated'] as $tag) {
                                $day = substr($tag['at'], 0, 10);
                                if ($day >= $window['from']
                                    && $day <= $window['to']
                                ) {
                                    $tagWindowed[] = $tag;
                                }
                            }
                            ?>
                            <div class="vp-lane-axis"
                                 data-vp-tl-axis="<?= h($lane['key']) ?>"
                                 data-vp-tl-draw="tagfirst">
                                <?php if (empty($lane['tags'])): ?>
                                    <?php
                                    /*
                                     * Nothing has tagged it, which is a
                                     * fact rather than an empty lane —
                                     * and there is no *of 0 tags* to
                                     * count against.
                                     */
                                    ?>
                                    <div class="vp-lane-fill">
                                        <span class="vp-lane-fill-text">
                                            <?= h($lane['absent']) ?>
                                        </span>
                                    </div>
                                <?php endif; ?>
                                <?php
                                /*
                                 * One column per bin, and a segment per
                                 * tag **in that tag's own colour** —
                                 * which is the whole reason this lane
                                 * is worth drawing rather than counting.
                                 * A source lane's segments answer *which
                                 * source*; this one's answer *which
                                 * tag*, and the chip row below spells
                                 * the names.
                                 */
                                $tagByBin = array();
                                foreach ($tagWindowed as $tag) {
                                    $day = substr($tag['at'], 0, 10);
                                    if (!isset($laneAt[$day])) {
                                        continue;
                                    }
                                    $i = $laneAt[$day];
                                    if (!isset($tagByBin[$i])) {
                                        $tagByBin[$i] = array(
                                            'n' => 0,
                                            'parts' => array(),
                                            'names' => array(),
                                        );
                                    }
                                    $tagByBin[$i]['n']++;
                                    $tagByBin[$i]['parts'][] = array(
                                        'hue' => $tag['colour']
                                            ? $tag['colour']
                                            : 'var(--vp-tl-tag)',
                                        'n' => 1,
                                    );
                                    $tagByBin[$i]['names'][] = $tag['name'];
                                }
                                foreach ($tagByBin as $i => $bin) {
                                    $names = array_slice($bin['names'], 0, 6);
                                    $rest = $bin['n'] - count($names);
                                    $tagByBin[$i]['title'] = sprintf(
                                        __('%1$s — first attached %2$s'),
                                        implode(', ', $names)
                                            . ($rest > 0 ? sprintf(
                                                __(' +%s more'),
                                                $rest
                                            ) : ''),
                                        $laneBins[$i]['title']
                                    );
                                }
                                $tagCols = $columnsFor($tagByBin, true);
                                ?>
                                <div class="vp-lane-plot">
                                    <?= $peakTag($tagCols['peak']) ?>
                                    <svg viewBox="0 0 <?= (int)$LANE_W ?> <?=
                                             (int)$LANE_H ?>"
                                         preserveAspectRatio="none"
                                         class="vp-lane-svg"
                                         data-vp-tl-marks><?=
                                        $tagCols['svg'] ?></svg>
                                </div>
                            </div>
                            <div class="vp-lane-count"
                                 data-vp-tl-count="<?= h($lane['key']) ?>">
                                <span data-vp-tl-count-n><?=
                                    count($tagWindowed) ?></span>
                                <div class="vp-tl-why"
                                     data-vp-tl-count-why><?= empty(
                                    $lane['tags']
                                ) ? '' : h(sprintf(
                                    __('of %s'),
                                    __n(
                                        '%s tag',
                                        '%s tags',
                                        count($lane['tags']),
                                        count($lane['tags'])
                                    )
                                )) ?></div>
                            </div>

                        <?php else: ?>
                            <div class="vp-lane-axis"
                                 data-vp-tl-axis="<?= h($lane['key']) ?>"
                                 data-vp-tl-draw="<?= h($lane['draw']) ?>"
                                 data-vp-tl-sources="<?=
                                     h(implode(',', $sources)) ?>">
                                <?php if (!empty($lane['hatch'])): ?>
                                    <div class="vp-lane-fill">
                                        <span class="vp-lane-fill-text">
                                            <?= h($lane['hatch']) ?>
                                        </span>
                                    </div>
                                <?php endif; ?>
                                <?php
                                /*
                                 * The span this lane counts and cannot
                                 * draw, banded from the window's start
                                 * to the oldest row the fragment
                                 * carries.
                                 *
                                 * **A different hatch from
                                 * `.vp-lane-fill`'s, deliberately.**
                                 * That one is grey and means *MISP
                                 * cannot date this, ever*; this one is
                                 * warning-toned and means *these are
                                 * dated and this fetch did not bring
                                 * them*. One is a hole in the record
                                 * and the other is a hole in the
                                 * request, and a reader who cannot tell
                                 * them apart learns the wrong thing
                                 * about the instance.
                                 */
                                $cut = $laneCut($lane);
                                ?>
                                <?php if ($cut > 0): ?>
                                    <div class="vp-lane-cut"
                                         style="--vp-cut: <?= h($boundary
                                             === null
                                                 ? 1
                                                 : round(
                                                     $fractionFor($boundary),
                                                     4
                                                 )) ?>;"
                                         data-vp-tl-cut="<?=
                                             h($lane['key']) ?>"
                                         title="<?= h(sprintf(
                                             $cutTitle,
                                             number_format($cut),
                                             number_format(
                                                 count($windowed)
                                             )
                                         )) ?>"></div>
                                <?php endif; ?>
                                <?php
                                /*
                                 * `style="--vp-tl-hue: …"` and not a
                                 * `fill` attribute: a presentation
                                 * attribute does not resolve a custom
                                 * property, and the whole palette here
                                 * is custom properties so that a lane
                                 * bar and its stack segment cannot
                                 * drift apart.
                                 *
                                 * The seen lane is the exception to all
                                 * of this and keeps its rects. It draws
                                 * intervals, not instants: a first-seen
                                 * span binned into a column would be a
                                 * bar saying *something lasted a while
                                 * somewhere in here*, which is a worse
                                 * sentence than the one it says now.
                                 */
                                $barSvg = '';
                                if ($lane['draw'] === 'spans') {
                                    foreach ($mine as $entry) {
                                        $x = $xFor($entry['at']);
                                        $to = $entry['span_to'] === null
                                            ? $entry['at']
                                            : $entry['span_to'];
                                        $barSvg .= '<rect'
                                            . ' class="vp-lane-span" x="'
                                            . h($x) . '" y="19" width="'
                                            . h(max($MARK_W, $xFor($to) - $x))
                                            . '" height="7" rx="3"'
                                            . ' style="--vp-tl-hue: '
                                            . h($sourceMeta[$entry['source']]
                                                ['token'])
                                            . ';"><title>'
                                            . h($entry['title'])
                                            . '</title></rect>';
                                    }
                                    $peak = null;
                                } else {
                                    $byBin = array();
                                    foreach ($mine as $entry) {
                                        $day = substr($entry['at'], 0, 10);
                                        if (!isset($laneAt[$day])) {
                                            continue;
                                        }
                                        $i = $laneAt[$day];
                                        if (!isset($byBin[$i])) {
                                            $byBin[$i] = array(
                                                'n' => 0,
                                                'by' => array(),
                                            );
                                        }
                                        $byBin[$i]['n']++;
                                        $s = $entry['source'];
                                        $byBin[$i]['by'][$s] = 1 + (
                                            isset($byBin[$i]['by'][$s])
                                                ? $byBin[$i]['by'][$s]
                                                : 0
                                        );
                                    }
                                    /*
                                     * Segments in the vocabulary's
                                     * order and not in arrival order,
                                     * so a source is in the same place
                                     * in every column of the lane —
                                     * otherwise a stack that happened
                                     * to start with a cluster reads as
                                     * a different lane from the one
                                     * beside it.
                                     */
                                    foreach ($byBin as $i => $bin) {
                                        $parts2 = array();
                                        $words = array();
                                        foreach ($sourceMeta as $s => $m) {
                                            if (empty($bin['by'][$s])) {
                                                continue;
                                            }
                                            $parts2[] = array(
                                                'hue' => $m['token'],
                                                'n' => $bin['by'][$s],
                                            );
                                            $words[] = $bin['by'][$s] . ' '
                                                . $m['label'];
                                        }
                                        $byBin[$i]['parts'] = $parts2;
                                        $byBin[$i]['title'] =
                                            $laneBins[$i]['title'] . ' — '
                                            . implode(', ', $words);
                                    }
                                    $cols = $columnsFor(
                                        $byBin,
                                        false,
                                        !empty($lane['hatch'])
                                    );
                                    $barSvg = $cols['svg'];
                                    $peak = $cols['peak'];
                                }
                                ?>
                                <div class="vp-lane-plot">
                                    <?= $peakTag($peak) ?>
                                    <?php
                                    /*
                                     * **A label is drawn only where it
                                     * clears the last one drawn.**
                                     * Every span used to get one at the
                                     * same `top`, so any two starting
                                     * near each other printed over each
                                     * other: `143.14.244.37` put eight
                                     * of them on the same pixel and the
                                     * result was one unreadable smear
                                     * of digits.
                                     *
                                     * Bars may overlap — two spans that
                                     * ran at once is a fact, and the
                                     * composite says it. Words may not:
                                     * overlapping text is not a denser
                                     * reading of anything, it is a
                                     * thing nobody can read.
                                     *
                                     * Greedy and left to right, over
                                     * rows already ordered by span
                                     * start (§7's D3), so which label
                                     * survives a cluster is the
                                     * earliest span in it and not
                                     * whichever the loop reached first.
                                     * The dropped ones lose nothing a
                                     * reader could have read; their
                                     * `<title>` still names them, and
                                     * it is on the bar rather than on
                                     * the word.
                                     */
                                    $tagEnd = null;
                                    /*
                                     * **Sorted here, and by two keys.**
                                     * The script builds its copy of
                                     * these rows out of the chronology,
                                     * which is newest first, so a
                                     * greedy pass in arrival order runs
                                     * the other way there and keeps a
                                     * different label. And `at` alone
                                     * does not order them: twenty-four
                                     * of `45.178.180.13`'s spans share
                                     * one instant, so the tie-break has
                                     * to be a value both sides hold —
                                     * the attribute id, ascending.
                                     * Without it the two agree on where
                                     * every label goes and disagree
                                     * about which one it names, which
                                     * is a label that changes identity
                                     * when the reader lets go of the
                                     * brush.
                                     */
                                    $labelled = $mine;
                                    usort($labelled, function ($a, $b) {
                                        if ($a['at'] !== $b['at']) {
                                            return strcmp($a['at'], $b['at']);
                                        }
                                        return (int)$a['ref']['attribute']
                                            - (int)$b['ref']['attribute'];
                                    });
                                    ?>
                                    <?php foreach ($labelled as $entry): ?>
                                        <?php
                                        if ($lane['draw'] !== 'spans') {
                                            continue;
                                        }
                                        $label = (string)$entry['ref']
                                            ['attribute'];
                                        if ($label === '') {
                                            continue;
                                        }
                                        $at = round(
                                            100 * $xFor($entry['at'])
                                                / $LANE_W,
                                            2
                                        );
                                        $wide = 100 * strlen($label)
                                            * $TAG_CHAR / $TAG_REF;
                                        if ($tagEnd !== null
                                            && $at < $tagEnd
                                        ) {
                                            continue;
                                        }
                                        $tagEnd = $at + $wide;
                                        ?>
                                        <?php $tagHref = $entryUrl($entry); ?>
                                        <?php if ($tagHref === null): ?>
                                            <span class="vp-lane-tag"
                                                  style="left: <?= h($at)
                                                      ?>%;">
                                                <?= h($label) ?>
                                            </span>
                                        <?php else: ?>
                                            <a class="vp-lane-tag"
                                               href="<?= h($tagHref) ?>"
                                               title="<?=
                                                   h($entryLinkTitle($entry))
                                               ?>"
                                               style="left: <?= h($at)
                                                   ?>%;">
                                                <?= h($label) ?>
                                            </a>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                    <svg viewBox="0 0 <?= (int)$LANE_W ?> <?=
                                             (int)$LANE_H ?>"
                                         preserveAspectRatio="none"
                                         class="vp-lane-svg"
                                         data-vp-tl-marks><?= $barSvg
                                        ?></svg>
                                </div>
                            </div>
                            <div class="vp-lane-count"
                                 data-vp-tl-count="<?= h($lane['key']) ?>">
                                <span data-vp-tl-count-n><?=
                                    (int)$laneCount ?></span>
                                <div class="vp-tl-why"
                                     data-vp-tl-count-why><?=
                                    h(implode(', ', $parts)) ?></div>
                            </div>
                        <?php endif; ?>

                        <?php if ($tagLane && !empty($lane['dated'])): ?>
                            <?php
                            /*
                             * The tags themselves, in the order they
                             * arrived, each with the day it did. A full
                             * grid row rather than something inside the
                             * axis cell: a tag name is
                             * `misp:threat-level="medium-risk"` and a
                             * dozen of them need the card's width, not
                             * a lane's fifteen-rem label column.
                             *
                             * Window-independent, unlike the marks
                             * above it. This is the sentence the lane
                             * exists to say and it has to be true on
                             * arrival.
                             */
                            $shown = array_slice($lane['dated'], 0, 12);
                            $rest = count($lane['dated']) - count($shown);
                            $unplaceable = count($lane['tags'])
                                - count($lane['dated']);
                            /*
                             * Grouped by day, because a value is
                             * usually tagged in bursts:
                             * `193.161.193.99` took 77 tags on one
                             * afternoon, so a date per chip printed
                             * *26 Nov 2025* twelve times and buried
                             * the one thing it was there to say.
                             */
                            $byDay = array();
                            foreach ($shown as $tag) {
                                $day = substr($tag['at'], 0, 10);
                                if (!isset($byDay[$day])) {
                                    $byDay[$day] = array();
                                }
                                $byDay[$day][] = $tag;
                            }
                            ?>
                            <div class="vp-lane-tagchips">
                                <span class="vp-lane-tagchips-head">
                                    <?= __('First attached') ?>
                                </span>
                                <?php foreach ($byDay as $day => $group): ?>
                                    <span class="vp-tagfirst">
                                        <span class="vp-tagfirst-at"><?=
                                            h((new DateTimeImmutable(
                                                $day,
                                                $utc
                                            ))->format('j M Y')) ?></span>
                                        <?php foreach ($group as $tag): ?>
                                            <?= $this->element(
                                                'genericElementsBS5/'
                                                    . 'Badges/tag',
                                                array(
                                                    'tag' => array(
                                                        'name' =>
                                                            $tag['name'],
                                                        'colour' =>
                                                            $tag['colour'],
                                                    ),
                                                    'local' => false,
                                                    'hiddenClass' => '',
                                                )
                                            ) ?>
                                        <?php endforeach; ?>
                                    </span>
                                <?php endforeach; ?>
                                <?php if ($rest > 0): ?>
                                    <span class="vp-tl-why"><?= h(sprintf(
                                        __n(
                                            '+%s more, newer',
                                            '+%s more, newer',
                                            $rest,
                                            $rest
                                        ),
                                        $rest
                                    )) ?></span>
                                <?php endif; ?>
                                <?php if ($unplaceable > 0): ?>
                                    <span class="vp-tl-why">·
                                        <?= h(sprintf(
                                            __n(
                                                '%s the audit log cannot'
                                                    . ' place, named on the'
                                                    . ' strip above',
                                                '%s the audit log cannot'
                                                    . ' place, named on the'
                                                    . ' strip above',
                                                $unplaceable,
                                                $unplaceable
                                            ),
                                            $unplaceable
                                        )) ?>
                                    </span>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>

                <div class="vp-tl-why pt-2">
                    <?= h(__('Height is that bin\'s share of the'
                        . ' lane, on the lane\'s own scale · one'
                        . ' lane is truncated and says where · what'
                        . ' nothing dates is named on the strip'
                        . ' above')) ?>
                </div>
            </section>

            <?php
            /*
             * ------------------------------------------------------
             * 3. The chronology
             * ------------------------------------------------------
             */
            ?>
            <section class="vp-tl-card" data-vp-tl-list>
                <div class="vp-tl-head">
                    <div class="vp-min-w-0">
                        <div class="fw-semibold">
                            <?= __('Chronology') ?>
                        </div>
                        <div class="vp-tl-why">
                            <?php if ($listCapped): ?>
                                <?php
                                /*
                                 * Two numbers about the same query at
                                 * two grains, and not a disagreement:
                                 * the aggregates above describe every
                                 * dated thing the viewer may see, and
                                 * this list carries the newest of them
                                 * that fit. A cap is not a permission,
                                 * so it reads the same for every
                                 * reader.
                                 *
                                 * Which set the cap bit into is named,
                                 * because a fragment fetched for a
                                 * window holds the newest of *it*:
                                 * *the newest 1,000 of 2,256* over a
                                 * chronology that is 24 rows of one
                                 * February would be arithmetic about
                                 * the wrong pair of numbers.
                                 */
                                ?>
                                <b><?= h(sprintf(
                                    $windowRequested
                                        ? __('Showing the newest %1$s'
                                            . ' of %2$s entries in this'
                                            . ' window.')
                                        : __('Showing the newest %1$s'
                                            . ' of %2$s entries.'),
                                    number_format($listShown),
                                    number_format($listOf)
                                )) ?></b>
                            <?php endif; ?>
                            <?= __('Newest first. Click a source in the'
                                . ' key or a lane above to narrow to'
                                . ' it, or an entry to open the record'
                                . ' behind it.') ?>
                            <span data-vp-tl-filter-note hidden>
                                <span data-vp-tl-filter-verb><?=
                                    __('Showing') ?></span>
                                <b data-vp-tl-filter-name></b>
                                <button type="button"
                                        class="btn btn-link btn-sm p-0"
                                        data-vp-tl-filter-clear>
                                    <?= __('clear') ?>
                                </button>
                            </span>
                        </div>
                    </div>
                    <div class="d-flex gap-1 align-items-center">
                        <span class="vp-prec vp-prec-exact">
                            <?= __('exact') ?>
                            <b data-vp-tl-tally-exact><?=
                                h($tally['exact']) ?></b>
                        </span>
                        <span class="vp-prec vp-prec-part">
                            <?= __('partial') ?>
                            <b data-vp-tl-tally-part><?=
                                h($tally['partial']) ?></b>
                        </span>
                    </div>
                </div>

                <?php foreach ($days as $group): ?>
                    <?php
                    /*
                     * A day is wholly inside the window or wholly
                     * outside it, so the whole chronology can be
                     * rendered once and the days outside simply
                     * hidden. Without JavaScript that leaves exactly
                     * the default window on screen, with counts that
                     * were computed for it (§10).
                     */
                    $dayIn = $group['day'] >= $window['from']
                        && $group['day'] <= $window['to'];
                    ?>
                    <div class="vp-tl-day" data-vp-tl-day-head="<?=
                        h($group['day']) ?>"<?= $dayIn ? '' : ' hidden'
                        ?>><?= h($group['label']) ?></div>

                    <?php foreach ($group['units'] as $unit): ?>
                        <?php $collapse = count($unit) >= $RUN_MIN; ?>

                        <?php if ($collapse): ?>
                            <?php
                            $by = array();
                            foreach ($unit as $entry) {
                                $org = $entry['org'] === null
                                    ? __('unattributed')
                                    : $entry['org'];
                                if (!isset($by[$org])) {
                                    $by[$org] = 0;
                                }
                                $by[$org]++;
                            }
                            $summary = array();
                            foreach ($by as $org => $n) {
                                $summary[] = $org . ' ' . $n;
                            }
                            $meta = $sourceMeta[$unit[0]['source']];
                            ?>
                            <div class="vp-tl-collapsed"
                                 data-vp-tl-row
                                 data-vp-tl-day="<?= h($group['day']) ?>"
                                 data-vp-tl-source="<?=
                                     h($unit[0]['source']) ?>"
                                 data-vp-tl-run="<?= h($group['day'] . ':'
                                     . $unit[0]['source'] . ':'
                                     . $unit[0]['at']) ?>"
                                 <?= $dayIn ? '' : 'hidden' ?>>
                                <i class="<?= h($meta['icon']) ?> me-1"></i>
                                <?= h(sprintf(
                                    __('%1$s %2$s collapsed — %3$s'),
                                    count($unit),
                                    $meta['plural'],
                                    implode(', ', $summary)
                                )) ?>
                                <button type="button"
                                        class="btn btn-link btn-sm p-0 ms-1"
                                        data-vp-tl-expand>
                                    <?= __('expand') ?>
                                </button>
                            </div>
                        <?php endif; ?>

                        <?php foreach ($unit as $entry): ?>
                            <?php
                            $meta = $sourceMeta[$entry['source']];
                            $prec = $precisionMeta[$entry['precision']];
                            $href = $entryUrl($entry);
                            ?>
                            <div class="vp-audit-row"
                                 data-vp-tl-row
                                 data-vp-tl-day="<?= h($group['day']) ?>"
                                 data-vp-tl-at="<?= h($entry['at']) ?>"
                                 data-vp-tl-source="<?=
                                     h($entry['source']) ?>"
                                 data-vp-tl-precision="<?=
                                     h($prec['bucket']) ?>"
                                 data-vp-tl-ref="<?=
                                     h($entry['ref']['attribute']) ?>"
                                 <?php
                                 /*
                                  * The mark's tooltip, carried on the
                                  * row rather than read back out of it.
                                  * The script rebuilds every mark on
                                  * every window and was taking this
                                  * from the row's `textContent`, which
                                  * is the source label, the title, the
                                  * precision chip and the template's
                                  * own indentation — so one paint after
                                  * arriving, a clean tooltip became a
                                  * dump of the row. Same string, one
                                  * source.
                                  */
                                 ?>
                                 data-vp-tl-title="<?=
                                     h($entry['title']) ?>"
                                 <?php
                                 /*
                                  * Carried on the row so the script can
                                  * link the span labels it rebuilds on
                                  * every window — it works from these
                                  * rows and has no other way to reach
                                  * the URL the server composed.
                                  */
                                 ?>
                                 <?php if ($href !== null): ?>
                                     data-vp-tl-href="<?= h($href) ?>"
                                 <?php endif; ?>
                                 <?php if ($collapse): ?>
                                     data-vp-tl-in-run="<?=
                                         h($group['day'] . ':'
                                             . $unit[0]['source'] . ':'
                                             . $unit[0]['at']) ?>"
                                 <?php endif; ?>
                                 <?php if ($entry['span_to'] !== null): ?>
                                     data-vp-tl-span-to="<?=
                                         h($entry['span_to']) ?>"
                                 <?php endif; ?>
                                 <?= $dayIn && !$collapse ? '' : 'hidden'
                                     ?>>
                                <div class="vp-tl-time"><?=
                                    h(substr($entry['at'], 11, 5)) ?></div>
                                <div class="vp-tl-dot">
                                    <i class="<?= h($meta['icon']) ?>"></i>
                                </div>
                                <div class="vp-min-w-0">
                                    <div class="vp-tl-main">
                                        <span class="vp-tl-src vp-tl-src-<?=
                                            h($entry['source']) ?>"><?=
                                            h($meta['label']) ?></span>
                                        <?php
                                        /*
                                         * The title is the link, not the
                                         * whole row: the row is a grid
                                         * of four parts and one of them
                                         * is a source chip that already
                                         * means *press to filter*. Two
                                         * gestures in one box, one of
                                         * which navigates away, is how
                                         * a reader loses their window.
                                         *
                                         * An entry with nowhere to go
                                         * renders the same words as
                                         * plain text rather than a dead
                                         * link — 8.2's rule about
                                         * absences applies to
                                         * affordances too.
                                         */
                                        ?>
                                        <?php if ($href === null): ?>
                                            <?= h($entry['title']) ?>
                                        <?php else: ?>
                                            <a class="vp-tl-link"
                                               href="<?= h($href) ?>"
                                               title="<?=
                                                   h($entryLinkTitle($entry))
                                               ?>"><?=
                                                h($entry['title']) ?></a>
                                        <?php endif; ?>
                                        <span class="vp-prec <?=
                                            h($prec['class']) ?>"><?=
                                            h($prec['label']) ?></span>
                                    </div>
                                    <?php if ($entry['note'] !== null): ?>
                                        <div class="vp-tl-why"><?=
                                            h($entry['note']) ?></div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                <?php endforeach; ?>

                <?php if (empty($entries)): ?>
                    <?php
                    /*
                     * The state that justifies the design. Nothing is
                     * dated, and the tab still says something true:
                     * the lanes above name every source that could
                     * have carried a date and did not, and the two
                     * that never could.
                     */
                    ?>
                    <div class="vp-empty">
                        <i class="fas fa-clock"></i>
                        <span><?= __('Nothing about this value carries a'
                            . ' date. The lanes above say which sources'
                            . ' could have supplied one.') ?></span>
                    </div>
                <?php endif; ?>

                <div class="vp-tl-foot" data-vp-tl-foot hidden>
                    <button type="button"
                            class="btn btn-sm btn-outline-secondary"
                            data-vp-tl-more>
                        <span data-vp-tl-more-n>0</span>
                        <?= __('more in this window') ?>
                    </button>
                </div>

                <div class="vp-empty vp-tl-blank" data-vp-tl-blank hidden>
                    <i class="fas fa-clock"></i>
                    <span><?= __('Nothing dated falls in this window.') ?>
                    </span>
                </div>

                <?php
                /*
                 * The other reason this list can be empty, and the one
                 * it used to deny: the window *does* hold entries and
                 * none of them are rows the fragment carries.
                 *
                 * A reader who brushes the first active bar of a value
                 * with years of history hits it every time — the spine
                 * is binned from the aggregate and covers the whole
                 * range, while the rows are the newest cap-many. Saying
                 * *nothing dated falls in this window* there is not a
                 * softer answer than this one, it is the opposite of
                 * what the number beside the window label says, so a
                 * reader can only conclude the panel is broken.
                 *
                 * Two caps can put a day in the aggregate with no row
                 * to show for it, and the sentence names whichever
                 * applies: `TIMELINE_ROW_CAP` over the merged
                 * chronology, whose numbers are worth printing, and
                 * `TIMELINE_SPAN_CAP` inside the seen lane, which bites
                 * on values whose chronology fits whole.
                 *
                 * It is a state the brush passes *through* rather than
                 * lands in: releasing the drag fetches the window, so
                 * what a reader normally sees here is the sentence for
                 * as long as they hold the pointer. The last clause is
                 * the script's — it is the only party that knows
                 * whether the fetch is available — and this state is
                 * hidden entirely once one is on its way.
                 */
                ?>
                <div class="vp-empty vp-tl-blank"
                     data-vp-tl-blank-capped hidden>
                    <i class="fas fa-clock"></i>
                    <span>
                        <?= sprintf(
                            __('%s dated entries fall in this window,'
                                . ' and none of them are among the'
                                . ' rows this list carries.'),
                            '<b data-vp-tl-blank-n>0</b>'
                        ) ?>
                        <?php if ($listCapped): ?>
                            <?= h(sprintf(
                                __('It holds the newest %1$s of %2$s.'),
                                number_format($listShown),
                                number_format($listOf)
                            )) ?>
                        <?php else: ?>
                            <?= h(__('A lane caps the rows it draws;'
                                . ' the counts above are over all of'
                                . ' them.')) ?>
                        <?php endif; ?>
                        <span data-vp-tl-blank-fetch hidden>
                            <?= h(__('Release the brush to fetch this'
                                . ' window.')) ?>
                        </span>
                    </span>
                </div>

                <?php
                /*
                 * **No ACL band here, deliberately.** A note such as
                 * *four of this value's nine occurrences are on events
                 * you cannot see* is itself the disclosure, and cannot
                 * ship on a page whose URL takes any value the reader
                 * types: it turns the page
                 * into an oracle for what exists on the instance. The
                 * panel where everything is hidden therefore renders as
                 * the panel where nothing is dated, which is a real
                 * loss and the cheaper of the two.
                 *
                 * Cap notices are a different thing and stay: a cap is
                 * a property of the fragment, not of the reader, so it
                 * reads identically for everyone and discloses nothing.
                 */
                ?>
            </section>

        </div>

    <?php endif; ?>
</div>
