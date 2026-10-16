<?php
App::uses('ValueFieldKind', 'Tools/ValueIntelligence');
App::uses('ValueRelationTool', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/**
 * Section one of the Relationships tab: what the correlation engine
 * stored about this value.
 *
 * Machine-derived, statistical, and the only section that grows without
 * bound — so it is the only one that carries `R3`'s narrowing bar and
 * pages rather than caps. The cut is always stated in words above the
 * rows: a table that silently shows the top eight of 1,462 is a table
 * that lies by omission.
 *
 * Three things share this panel and are not the same thing:
 *
 *   object siblings   a join on `Attribute.object_id` over occurrences
 *                     the page already holds. Structural, not
 *                     statistical, and bounded by how many objects the
 *                     value sits in rather than by how large its events
 *                     are — which is why it still renders under a
 *                     suppressed band.
 *   the roll-ups      the neighbourhood, counted three ways.
 *   the facet bar     folded from every row read, not from the page.
 *                     Its counts do not move when the list pages, and
 *                     saying so is the whole reason the bar is here.
 *
 * **Not the correlation engine.** A `default_correlations` row links
 * two attributes carrying the *same* value, so for one value the engine
 * returns other occurrences of it — the Occurrences tab — and its
 * CIDR/ssdeep partners, which are the section below. It never returns a
 * different value. What is counted here is an event join, and the
 * engine's own state is reported on the rail instead.
 * prd/value-intelligence-live/24-relationships.md §3.
 *
 * Lazily loaded from ValuesController::viewRelationCooccurrence.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$relations = $profile['relationships'];
$co = $relations['cooccurrence'];
$siblings = $co['siblings'];
$facets = $co['facets'];
$scan = $co['scan'];

$view = $this;

/*
 * The narrowing the fold applied, so the controls come back set the way
 * the reader left them. The panel re-requests itself for a facet its
 * own markup cannot answer, and a re-request that arrived with every
 * box cleared would undo the click that caused it.
 */
$active = isset($co['filters']) ? $co['filters'] : array();
$activeSelects = isset($active['select']) ? $active['select'] : array();

/**
 * @param string $key
 * @return array Tokens ticked in this facet group
 */
$activeFacet = function ($key) use ($active) {
    return isset($active[$key]) ? (array)$active[$key] : array();
};

/**
 * @param string $text
 * @return string
 */
$slug = function ($text) {
    return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($text)), '-');
};

/*
 * A row's tokens are the fold's, not this template's — both tables'.
 * They decide what a facet matches, and the fold has to be able to
 * apply the same narrowing over rows this table never received, so one
 * place builds them and both ends agree by construction.
 *
 * The sibling rows' were the exception until the bar started counting
 * how much of each entry the carried rows reach: a count derived from
 * one rule against markup written by another is a count that can be
 * wrong without either side changing.
 */

/**
 * A row's two orderings, as numbers the sort can read without parsing
 * a date out of a cell.
 *
 * @param int $weight
 * @param string $date
 * @return string
 */
$numbers = function ($weight, $date) {
    return 'shared:' . (int)$weight
        . ' recent:' . str_replace('-', '', substr($date, 0, 10));
};

/**
 * Column-sort tokens, compared lexicographically by the script, so a
 * number has to be zero-padded and a date reduced to its digits before
 * it gets here — `9` after `10` and `2026-01-14` before `2025-12-15`
 * are the two mistakes this exists to stop.
 *
 * @param array $data `vp-sort-<column>` => token
 * @param int $index The row's place in the order the model sent
 * @return string Attributes, ready to print inside a `<tr>`
 */
$sortAttrs = function (array $data, $index) {
    // Reordering moves the rows, so "unsorted" has to be restorable
    // rather than merely stoppable: the third click sorts by this.
    $data['vp-sort-default'] = str_pad((string)$index, 6, '0',
        STR_PAD_LEFT);
    $out = '';
    foreach ($data as $key => $token) {
        $out .= ' data-' . $key . '="' . h($token) . '"';
    }
    return $out;
};

/**
 * @param int $n
 * @return string A count that sorts as a number
 */
$sortNum = function ($n) {
    return str_pad((string)(int)$n, 12, '0', STR_PAD_LEFT);
};

/**
 * Whether the spread was read for this fold at all.
 *
 * A scan cached before the prevalence lookup existed carries none, and
 * for those five minutes the rank would sort by nothing and the column
 * would print empty cells down the page. Neither renders without this.
 */
$spreadRead = !empty($co['spread_read']);

/**
 * How specific a neighbour is to this value, as a sentence.
 *
 * A ratio is what sorts the column and a fraction is what the reader
 * needs: *"in 8 of its 204 events"* says both that the neighbour is
 * frequent here and that it is frequent everywhere, which is the whole
 * distinction the rank exists to draw. A bare score would say neither,
 * and a percentage would invite comparison between two values whose
 * denominators are nothing alike.
 *
 * `null` prints nothing rather than a zero — that is the difference
 * between a spread nobody read and a value that appears nowhere else.
 *
 * Two units, because the two tables count different things: the ranked
 * table's rows are events and the sibling table's are objects. The
 * sentence names whichever the row beside it does.
 *
 * @param int $shared Events or objects shared with this value
 * @param int|null $spread The neighbour's own count, same unit
 * @param string $unit `event` or `object`
 * @return string
 */
$specificRead = function ($shared, $spread, $unit = 'event',
    $least = false
) {
    if ($spread === null) {
        return '';
    }
    $spread = (int)$spread;
    $shared = (int)$shared;
    $object = $unit === 'object';
    /*
     * **A floor names the unit it was measured in, which is not this
     * row's.** The lookup stops after `Value::PREVALENCE_ROW_CAP`
     * *occurrences* of a value, and what it can say afterwards is only
     * about occurrences: `flood` is 65,717 of them across **two**
     * events, so a capped read rendered as a fraction of events would
     * print *in 2 of its 500+ events* about a value that is in two of
     * its two. The rows a truncated read saw cannot be sampled for the
     * answer either — they arrive in index order, which for one value
     * is insertion order, so the events they name are the earliest ones
     * rather than a spread of them.
     *
     * So the fraction is dropped and the one measured fact is printed.
     * It is still the fact worth having: a value seen this many times
     * is one this table exists to push down the page, whichever unit
     * that many were counted in.
     */
    if ($least) {
        return sprintf(
            __('in %s+ occurrences'),
            number_format($spread)
        );
    }
    if ($spread === 1) {
        return $object
            ? __('in its only object')
            : __('in its only event');
    }
    if ($shared >= $spread) {
        return sprintf(
            $object
                ? __('in all %s of its objects')
                : __('in all %s of its events'),
            number_format($spread)
        );
    }
    return sprintf(
        $object
            ? __('in %1$s of its %2$s objects')
            : __('in %1$s of its %2$s events'),
        number_format($shared),
        number_format($spread)
    );
};

/**
 * The column's sort token, and it is the pill's key exactly.
 *
 * Two padded numbers concatenated — shared count, then the ratio —
 * because the rank leads with frequency and settles ties on the
 * fraction, and because the script compares these lexicographically. A
 * single number could not express a two-level order, and clicking the
 * heading has to reproduce the pill's order rather than approximate
 * it: on a page whose whole claim is that the reader can see why a row
 * won, a heading that sorts *nearly* like the pill is worse than one
 * that sorts differently on purpose.
 *
 * An unread spread returns the empty token, which the comparator sorts
 * last whichever way the heading is pointing — the same treatment it
 * gives a missing date, and for the same reason: the row has no value
 * for this column, and a zero would claim it had the lowest one.
 *
 * **The two tables sort this column by different keys**, because they
 * rank by different keys, and the reason is in
 * `ValueRelationTool::compareSpecificity` and beside the sibling sort.
 * The ranked table leads with frequency; the sibling table divides
 * outright, so `$squared` selects which of the two a heading click
 * reproduces. A heading that sorted *nearly* like its own table would
 * be worse than one that sorted differently on purpose.
 *
 * @param int $shared Events or objects shared with this value
 * @param int|null $spread The neighbour's own count, same unit
 * @param bool $squared The sibling table's key rather than the
 *                      ranked table's
 * @return string
 */
$specificSort = function ($shared, $spread, $squared = false)
    use ($sortNum)
{
    if ($spread === null || (int)$spread < 1) {
        return '';
    }
    $shared = (int)$shared;
    if ($squared) {
        return $sortNum(
            intdiv($shared * $shared * 1000000, (int)$spread)
        );
    }
    return $sortNum($shared) . ' '
        . $sortNum(intdiv($shared * 1000000, (int)$spread));
};

/**
 * A list of organisation names, ordered by how many there are and then
 * alphabetically. How many reported a thing is the question the column
 * answers when it says `+3 more`, so it leads.
 *
 * @param array $names
 * @param int $total
 * @return string
 */
$sortOrgs = function (array $names, $total) use ($sortNum) {
    $first = empty($names) ? '' : mb_strtolower($names[0]);
    return $sortNum($total) . ' ' . $first;
};

/**
 * MISP's own distribution badge, once per audience the row has.
 *
 * A value roll-up row folds many occurrences, and they state between
 * them as many audiences as they state — so the cell is a set and not
 * a badge. Two occurrences at `Your organisation only` are one pill;
 * two different sharing groups are two, told apart by the name beside
 * each, because `Sharing group` alone does not say which one. An event
 * row has a single audience and renders through the same cell.
 *
 * @param array $row
 * @return string
 */
$distributionBadge = function ($row) use ($view, $baseurl) {
    $audiences = empty($row['distributions'])
        ? array(array(
            'level' => (int)$row['distribution'],
            'sharing_group' => array('id' => null, 'name' => null),
        ))
        : $row['distributions'];
    $shown = array_slice($audiences, 0, 3);
    $out = '<span class="vp-dist-set">';
    foreach ($shown as $audience) {
        $out .= $view->element(
            'genericElementsBS5/Badges/distribution',
            array(
                'distribution' => (int)$audience['level'],
                'full' => false,
            )
        );
        $group = $audience['sharing_group'];
        /*
         * Safe to link, for the reason the Occurrences tab gives: a
         * name is only ever set from `fetchAllAuthorised`, so a name
         * that resolved is a group this viewer may open. Where it did
         * not, the badge stands alone and there is nothing to link.
         */
        if ((int)$audience['level'] === 4 && !empty($group['name'])) {
            $out .= '<a class="vp-dist-sg" href="' . h($baseurl)
                . '/sharing_groups/view/' . h($group['id'])
                . '" title="' . h(sprintf(
                    __('%s — who this is shared with'),
                    $group['name']
                )) . '">' . h($group['name']) . '</a>';
        }
    }
    $rest = array_slice($audiences, 3);
    if (!empty($rest)) {
        $names = array();
        foreach ($rest as $audience) {
            $label = $view->DistributionLevel
                ->get((int)$audience['level']);
            $names[] = empty($audience['sharing_group']['name'])
                ? $label['label']
                : $label['label'] . ' — '
                    . $audience['sharing_group']['name'];
        }
        $out .= '<span class="text-muted small" title="'
            . h(implode(', ', $names)) . '">'
            . h(sprintf(__('+%d more'), count($rest)))
            . '</span>';
    }
    return $out . '</span>';
};

/**
 * @param array $tags
 * @return string
 */
$tagChips = function ($tags) use ($view) {
    if (empty($tags)) {
        return '<span class="text-muted">&mdash;</span>';
    }
    $out = '';
    foreach ($tags as $tag) {
        $out .= $view->element(
            'genericElementsBS5/Badges/tag',
            array(
                'tag' => $tag,
                'local' => false,
                'hiddenClass' => '',
                'showFavourite' => false,
            )
        );
    }
    return $out;
};

/**
 * The mark on a value MISP already knows to be benign, for the two
 * tables in this panel that carry one.
 *
 * The markup is `value_warninglist_mark`, shared with the dated panel
 * so one mark is not drawn three ways. What stays here is the guard:
 * an unlisted row costs no element render, and gets **nothing at all**
 * in its cell.
 *
 * That second part is load-bearing. §7 asks that a value with no listed
 * neighbours render byte-identically to what it did before B5, so the
 * call sites default the key inline rather than in a statement of their
 * own — a `<?php ?>` block inside a row loop leaves its indentation in
 * the markup of every row on the tab.
 *
 * @param array $lists id, name, category, matched, comment
 * @return string
 */
$listedMark = function ($lists) use ($view) {
    return empty($lists) ? '' : $view->element(
        'Values/View/value_warninglist_mark',
        array('lists' => $lists)
    );
};

/**
 * A neighbour's value cell opens its own hover card where the instance
 * has the card on, and is left exactly as it was where it has not.
 *
 * @param string $value
 * @return string the trigger's attribute, or nothing
 */
$hoverCardOn = (bool)Configure::read('MISP.value_hover_card');
$hoverCard = function ($value) use ($hoverCardOn) {
    return $hoverCardOn
        ? ' data-vp-hc-value="' . h(ValueUrlTool::encode($value)) . '"'
        : '';
};
$hoverClass = $hoverCardOn ? ' vp-hc-trigger' : '';

/**
 * The type, through MISP's own badge, re-flowed for a dense row by
 * `.vp-rel-type` rather than by a second rendering of the same fact.
 *
 * @param string $type
 * @return string
 */
$typeBadge = function ($type) use ($view) {
    return '<span class="vp-rel-type">'
        . $view->element(
            'genericElementsBS5/Badges/type',
            array('type' => $type, 'full' => true)
        )
        . '</span>';
};

/**
 * A weight, on the page's own bar. Strengths are only ever compared
 * inside one roll-up, never across the three notions.
 *
 * `$prefix` is markup rather than text, because the one caller that
 * passes it passes the floor marker the section already prints.
 *
 * @param int $weight
 * @param int $max
 * @param string $prefix
 * @return string
 */
$weightBar = function ($weight, $max, $prefix = '') {
    $share = $max > 0 ? round(($weight / $max) * 100) : 0;
    return '<span class="vp-rel-bar"'
        . ' style="--vp-seg-color: var(--vp-rel-co);">'
        . '<span class="vp-weight-track"><span class="vp-weight-fill"'
        . ' style="width: ' . h($share) . '%;"></span></span>'
        . '<span class="vp-rel-bar-read">' . $prefix
        . h(number_format($weight)) . '</span></span>';
};

/*
 * The seven groups, in the order the bar prints them. A key with no
 * values renders nothing at all, which is what `value_facet_group`
 * already enforces for a group of zeroes — which is also why the
 * sharing-group dropdown is absent from every value whose neighbours
 * are distributed by level alone.
 */
$facetGroups = array(
    array('key' => 'event', 'title' => __('Event'),
        'icon' => 'misp-icon misp-icon-event misp-simple'),
    array('key' => 'organisation', 'title' => __('Organisation'),
        'icon' => 'fas fa-building'),
    array('key' => 'type', 'title' => __('Type'),
        'icon' => 'misp-icon misp-icon-attribute misp-simple'),
    array('key' => 'object', 'title' => __('Object'),
        'icon' => 'misp-icon misp-icon-object misp-simple'),
    array('key' => 'tag', 'title' => __('Tag'),
        'icon' => 'misp-icon misp-icon-tag misp-simple'),
    array('key' => 'distribution', 'title' => __('Distribution'),
        'icon' => 'fas fa-globe'),
    array('key' => 'sharing_group', 'title' => __('Sharing group'),
        'icon' => 'misp-icon misp-icon-sharing-group misp-simple'),
);

/*
 * Eighth, and appended rather than declared, because the bar's render
 * loop prints its own indentation on every pass — including the ones
 * that `continue` past an empty group. A neighbourhood no enabled list
 * reaches must come out byte-identical to what it did before B5, so
 * there the group is not in the array at all.
 *
 * A dropdown and not a second switch: a switch has no count, and the
 * useful half of this is being told that five of these neighbours are
 * RFC 5735 private ranges before deciding to cut them. The switch
 * beside the filters does the cutting.
 */
if (!empty($facets['warninglist'])) {
    $facetGroups[] = array('key' => 'warninglist',
        'title' => __('Warninglist'),
        'icon' => 'fas fa-list-check');
}

/*
 * The sibling table's own bar. Five keys and not seven: a sibling row
 * has no tag column and no single distribution to name, and Relation
 * is the dimension that only exists here — it is what separates the
 * `domain` in a `domain-ip` object from the timestamps beside it.
 *
 * Field kind leads, because it is the cut this table is worst without.
 * It is also the only group here whose two entries are a vocabulary
 * rather than a census, so it is the only one that can show a zero.
 */
$sibFacets = isset($siblings['facets']) ? $siblings['facets'] : array();
/*
 * Descriptive siblings the fold counted and the table could not carry.
 * Worth its own sentence rather than only the greyed facet entry it
 * also produces: linking rows now sort first, so on a value whose
 * siblings run past the hundred the table holds, the cut lands on the
 * descriptive ones by construction. That is the intended trade and it
 * is still a cut, so the panel states it in the same breath as the
 * order that caused it.
 */
$sibUnreached = 0;
foreach ($sibFacets['siblink'] ?? array() as $sibKind) {
    if ($sibKind['value'] === ValueFieldKind::DESCRIPTIVE
        && isset($sibKind['listed'])
    ) {
        $sibUnreached = (int)$sibKind['count'] - (int)$sibKind['listed'];
    }
}
/**
 * A field list as the caption prints it.
 *
 * @param array $fields Relation names
 * @return string
 */
$sibFieldList = function ($fields) {
    $out = array();
    foreach ($fields as $field) {
        $out[] = '<code>' . h($field) . '</code>';
    }
    return implode(__(' and '), $out);
};
$sibExamples = isset($siblings['examples'])
    ? $siblings['examples']
    : array(
        ValueFieldKind::LINKING => array(),
        ValueFieldKind::DESCRIPTIVE => array(),
    );
$sibLinkEg = $sibExamples[ValueFieldKind::LINKING];
$sibDescEg = $sibExamples[ValueFieldKind::DESCRIPTIVE];

$sibFacetGroups = array(
    array('key' => 'siblink', 'title' => __('Field kind'),
        'icon' => 'fas fa-share-nodes'),
    array('key' => 'sibobject', 'title' => __('Object'),
        'icon' => 'misp-icon misp-icon-object misp-simple'),
    array('key' => 'sibrelation', 'title' => __('Relation'),
        'icon' => 'fas fa-diagram-project'),
    array('key' => 'sibtype', 'title' => __('Type'),
        'icon' => 'misp-icon misp-icon-attribute misp-simple'),
    array('key' => 'siborg', 'title' => __('Reported by'),
        'icon' => 'fas fa-building'),
);

/*
 * Sixth, appended rather than declared, for the reason the ranked
 * bar's own eighth group is: the render loop prints its indentation on
 * every pass, including the ones that `continue` past an empty group,
 * and a value whose siblings no enabled list names must come out
 * byte-identical to what it did before.
 */
if (!empty($sibFacets['sibwarninglist'])) {
    $sibFacetGroups[] = array('key' => 'sibwarninglist',
        'title' => __('Warninglist'),
        'icon' => 'fas fa-list-check');
}
$sibListsHit = isset($siblings['warninglists_listed'])
    ? (int)$siblings['warninglists_listed']
    : 0;

/*
 * The sibling table's own sentence.
 *
 * This bar has no narrowing endpoint behind it, so its Warninglist
 * group filters the hundred rows the panel holds rather than fetching a
 * fresh hundred — unlike the ranked table's, which re-ranks the fold.
 * The note says which, because a cut that silently reaches only part of
 * what it counted is the one thing this section's bar already promises
 * not to be.
 *
 * Buffered and echoed against a closing tag: an `if` in the markup
 * would leave its indentation behind on every value that has nothing
 * listed, and those must render byte-identically to what they did
 * before.
 */
$sibWarninglistNote = '';
if ($sibListsHit > 0) {
    ob_start();
    ?>
 <?= sprintf(
        __n(
            '<strong>One sibling value</strong> is on a warninglist and'
            . ' dimmed here. <strong>Warninglist</strong> below keeps or'
            . ' drops it, and narrows the rows this table carries rather'
            . ' than the fold behind them.',
            '<strong>%d sibling values</strong> are on a warninglist and'
            . ' dimmed here. <strong>Warninglist</strong> below keeps or'
            . ' drops them, and narrows the rows this table carries'
            . ' rather than the fold behind them.',
            $sibListsHit
        ),
        $sibListsHit
    ) ?>
    <?php
    $sibWarninglistNote = ob_get_clean();
}

/*
 * A distribution row carries MISP's own badge and a tag row its own
 * chip, because `value_facet_group` renders `html` where a caller
 * supplies one and the bare `label` otherwise — and neither of those
 * two facets has a label to fall back on. The Occurrences rail has
 * built these since phase 22; this pane never did, so its Distribution
 * and Tag dropdowns have been rendering rows with an empty name and a
 * count beside it since phase 11.
 */
foreach ($facets['distribution'] as &$facet) {
    $facet['html'] = $this->element(
        'genericElementsBS5/Badges/distribution',
        array('distribution' => (int)$facet['level'], 'full' => true)
    );
}
unset($facet);
foreach ($facets['tag'] as &$facet) {
    $facet['html'] = $this->element(
        'genericElementsBS5/Badges/tag',
        array(
            'tag' => $facet['tag'],
            'local' => !empty($facet['local']),
            'hiddenClass' => '',
            'showFavourite' => false,
        )
    );
}
unset($facet);

$valueRows = $co['rollups']['value']['rows'];
$eventRows = $co['rollups']['event']['rows'];
$objectRows = $co['rollups']['object']['rows'];
$hasRows = !empty($valueRows);

$maxShared = 0;
foreach ($valueRows as $row) {
    $maxShared = max($maxShared, (int)$row['shared_events']);
}
$maxEventShared = 0;
foreach ($eventRows as $row) {
    $maxEventShared = max($maxEventShared, (int)$row['shared_values']);
}

$labels = $co['labels'];
/*
 * The fold holds every label because the rail's named-threat card
 * filters them itself and a cluster reaching this value through one
 * event ranks nowhere near the top. The table shows a page's worth and
 * says so — the no-silent-caps rule, and the reason `cap` travels with
 * the rows rather than being spelled here.
 */
/*
 * The reader's own order over the fold's, and it runs **before** the
 * cut below. The table lists a page of a neighbourhood that can hold
 * hundreds, ranked by shared events, so the question the profile
 * answers here is which labels are listed at all — a desk that pins
 * `tlp` and prefers `threat-actor` was seeing neither on a value whose
 * top rows are `type:OSINT` and a dozen pieces of tooling.
 *
 * **One pass over both dimensions**, because this is one list: a
 * cluster row and a tag row compete for the same rows above the cut,
 * and ranking them in two passes gives two lists and no way to
 * interleave them. Each row says which dimension it is in and
 * `across()` does the rest, keeping the shared-event order among
 * everything the profile has no opinion about.
 */
$labelPlan = ValueLabelPriority::planFor($profile['label_plan']);
$labelOrdered = $labels['rows'];
if (ValueLabelPriority::declares($labelPlan)) {
    foreach ($labelOrdered as $labelAt => $labelRow) {
        $kind = $labelRow['kind'];
        if ($kind === ValueRelationTool::KIND_CLUSTER) {
            $labelOrdered[$labelAt]['scope'] = ValueLabelPriority::GALAXIES;
        } elseif ($kind === ValueRelationTool::KIND_TAG) {
            $labelOrdered[$labelAt]['scope']
                = ValueLabelPriority::TAXONOMIES;
            /*
             * The tag string, which is where the handling order inside
             * `tlp` and `pap` is read from — `label` prints a
             * cluster's name and `value` is the tag either way.
             */
            $labelOrdered[$labelAt]['name'] = $labelRow['value'];
        }
    }
    unset($labelAt, $labelRow, $kind);
    $labelOrdered = ValueLabelPriority::across($labelOrdered, $labelPlan);
}
$labelRows = empty($labels['cap'])
    ? $labelOrdered
    : array_slice($labelOrdered, 0, (int)$labels['cap']);
$labelCapped = count($labelRows) < (int)$labels['total'];
$labelFacets = $labels['facets'];
$labelByKind = $labels['by_kind'];

/*
 * The scope sentence's two numbers. Labels are read over every event
 * the value is in; the value table over the events its attribute budget
 * afforded. Equal on most values, and the section only draws the
 * distinction where it arose.
 */
$labelScope = (int)$scan['events_seen'];
$labelScopeDiffers = $scan['events_read'] !== $scan['events_seen'];

/*
 * The header sub-line: what the section counts, in its own two units.
 * Both named even where one is zero would read as a claim about a kind
 * the value has none of, so each is printed only where it is there.
 */
$labelTally = array();
if (!empty($labelByKind['cluster'])) {
    $labelTally[] = sprintf(
        __n('%s cluster', '%s clusters', $labelByKind['cluster']),
        number_format($labelByKind['cluster'])
    );
}
if (!empty($labelByKind['tag'])) {
    $labelTally[] = sprintf(
        __n('%s tag', '%s tags', $labelByKind['tag']),
        number_format($labelByKind['tag'])
    );
}
ob_start();
?>
    <span class="vp-rel-tag me-1">
        <i class="misp-icon misp-icon-galaxy misp-simple"></i><?=
            h(__('Labels')) ?>
    </span>
    <?php /*
     * Escaped per part and joined with the raw entity: `h()` over the
     * joined string turns the separator into the five characters that
     * spell it.
     */ ?>
    <?= implode(' &middot; ', array_map('h', $labelTally)) ?>
    &nbsp;·&nbsp;<?= h(__('shared events')) ?>&nbsp;·&nbsp;
    <?php /*
     * `Tagged`, not `Applied by hand`. A cluster reaches an event
     * through whoever wrote it — and that is as often a feed or a sync
     * from another instance as it is a person at a keyboard, which the
     * join tables record nothing about either way. The chip beside the
     * co-occurrence table says `Machine-derived` because an event join
     * is; this one says what happened and not who did it.
     */ ?>
    <span class="vp-rel-prov"><i class="fas fa-tag"></i><?=
        h(__('Tagged')) ?></span>
<?php
$labelHeaderSub = ob_get_clean();

/**
 * The six groups on the labels bar, in the order it prints them.
 *
 * The first three are the ones the value bar cannot have and the reason
 * this section exists; the last three are the dimensions both sections
 * genuinely share. There is no Type, no Object and no Warninglist,
 * because a cluster has none of them and a control that can only empty
 * the table under it is not a control.
 */
$labelFacetGroups = array(
    array('key' => 'kind', 'title' => __('Kind'),
        'icon' => 'fas fa-shapes'),
    array('key' => 'family', 'title' => __('Family'),
        'icon' => 'misp-icon misp-icon-galaxy misp-simple'),
    array('key' => 'attachment', 'title' => __('Attached to'),
        'icon' => 'fas fa-paperclip'),
    array('key' => 'event', 'title' => __('Event'),
        'icon' => 'misp-icon misp-icon-event misp-simple'),
    array('key' => 'organisation', 'title' => __('Organisation'),
        'icon' => 'fas fa-building'),
    array('key' => 'distribution', 'title' => __('Distribution'),
        'icon' => 'fas fa-globe'),
);
/*
 * A distribution row carries MISP's own badge, for the reason the value
 * bar's does: `value_facet_group` renders `html` where a caller supplies
 * one and the bare `label` otherwise, and this facet has no label to
 * fall back on.
 */
foreach ($labelFacets['distribution'] ?? array() as &$labelFacet) {
    $labelFacet['html'] = $this->element(
        'genericElementsBS5/Badges/distribution',
        array(
            'distribution' => (int)$labelFacet['level'],
            'full' => true,
        )
    );
}
unset($labelFacet);

/*
 * One scale for this table, and it is this table's own. The bar beside
 * a label counts events over every event the value is in, and the one
 * above counts the events the budget read — scaling both against the
 * larger drew every value neighbour on `443` as a stub, which is a
 * picture of the scope difference rather than of which neighbours are
 * strong. Strengths are only ever compared inside one roll-up here
 * already; two tables are two roll-ups.
 */
$maxLabelShared = 0;
foreach ($labelRows as $row) {
    $maxLabelShared = max($maxLabelShared, (int)$row['shared_events']);
}

/*
 * The words for how a label reached this value, and the digit that
 * sorts them. Tightest first, so the column sorted ascending reads as
 * the scale the words are.
 */
$attachWords = array(
    'value' => __('on this value'),
    'neighbour' => __('on a neighbour'),
    'event' => __('on the event'),
);
$attachOrder = array('value' => '0', 'neighbour' => '1', 'event' => '2');

/**
 * @param array $row
 * @return string
 */
$attachSort = function (array $row) use ($attachOrder) {
    $at = isset($row['attachment']) ? $row['attachment'] : null;
    return isset($attachOrder[$at]) ? $attachOrder[$at] : '9';
};

/**
 * How a label reached this value, as its own cell.
 *
 * @param array $row
 * @return string
 */
$attachCell = function (array $row) use ($attachWords) {
    $at = isset($row['attachment']) ? $row['attachment'] : null;
    if (!isset($attachWords[$at])) {
        return '<span class="text-muted">&mdash;</span>';
    }
    return '<span class="vp-rel-attach">'
        . h($attachWords[$at]) . '</span>';
};

/**
 * The first cell: what this label is called.
 *
 * A cluster is MISP's cluster chip, linked to its page and in its
 * galaxy's colour; a tag is MISP's own tag chip, because a taxonomy
 * tag's colour *is* its identity to a reader who has seen it on an
 * event.
 *
 * @param array $row
 * @return string
 */
$labelCell = function (array $row) use ($view) {
    if ($row['kind'] === ValueRelationTool::KIND_CLUSTER) {
        $cluster = isset($row['cluster']['GalaxyCluster'])
            ? $row['cluster']['GalaxyCluster']
            : array();
        return $view->TagChip->cluster([
            'id' => $cluster['id'] ?? null,
            'value' => $row['label'],
            'galaxy' => $row['family'],
        ], ['inline' => true]);
    }
    return empty($row['tag'])
        ? '<span class="vp-rel-cell">' . h($row['label']) . '</span>'
        : $view->element(
            'genericElementsBS5/Badges/tag',
            array(
                'tag' => $row['tag'],
                'local' => !empty($row['tag']['local']),
                'hiddenClass' => '',
                'showFavourite' => false,
                'inline' => true,
            )
        );
};

/**
 * The second cell: the galaxy a cluster belongs to, or the taxonomy a
 * tag was written under. Plain text rather than a badge, because the
 * chip beside it already carries that colour and two coloured things on
 * one row compete for the same glance.
 *
 * @param array $row
 * @return string
 */
$labelFamilyCell = function (array $row) {
    if ($row['family'] === '') {
        return '<span class="vp-rel-family text-muted">'
            . h(__('freetext')) . '</span>';
    }
    return '<span class="vp-rel-family">' . h($row['family'])
        . '</span>';
};
$maxObjectValues = 0;
foreach ($objectRows as $row) {
    $maxObjectValues = max($maxObjectValues, (int)$row['values']);
}
/*
 * The sibling table's own spread flag. Separate from the ranked
 * table's because the two lookups are separate reads over separate row
 * sets — a value can sit in an object that survived an event the
 * co-occurrence scan skipped for being oversized, which is the same
 * reason the sibling warninglist probe cannot reuse the other one.
 */
$sibSpreadRead = !empty($siblings['spread_read']);

$maxSibObjects = 0;
foreach ($siblings['rows'] as $sibling) {
    $maxSibObjects = max($maxSibObjects, (int)$sibling['objects']);
}

/**
 * A pill group: every option on screen, the current one filled.
 *
 * A select hides its alternatives behind a click, which is how the
 * roll-up came to be the least-used control on the tab — nothing about
 * `Group by value` says that grouping by event is a thing the panel can
 * do. Three pills say it without being opened.
 *
 * The container carries the same `data-vp-sort` / `data-vp-group` hook
 * the select did and keeps its choice in `data-vp-value`, so the script
 * reads one or the other through `controlValue()` and every panel still
 * using a select is untouched.
 *
 * @param string $key `sort` or `group`
 * @param string $label
 * @param string $current
 * @param array $options value => label
 * @return string
 */
$pillGroup = function ($key, $label, $current, array $options) {
    $out = '<div class="vp-pillgroup" data-vp-' . h($key) . ' '
        . 'data-vp-value="' . h($current) . '" role="group" '
        . 'aria-label="' . h($label) . '">';
    $out .= '<span class="vp-pillgroup-label">' . h($label) . '</span>';
    foreach ($options as $value => $text) {
        $on = (string)$value === (string)$current;
        $out .= '<button type="button" class="vp-pill'
            . ($on ? ' active' : '') . '" data-vp-pill="' . h($value)
            . '" aria-pressed="' . ($on ? 'true' : 'false') . '">'
            . h($text) . '</button>';
    }
    return $out . '</div>';
};

/*
 * The warninglist read, in words — and only where it found something.
 * A neighbourhood no enabled list reaches produces no dimmed rows, no
 * facet, no switch and no sentence, which is §7's requirement that this
 * task be inert where it has nothing to say rather than print a
 * reassuring zero.
 *
 * Buffered into a string rather than written as an `if` block in the
 * markup below, and that is the whole reason: an `if` leaves its own
 * indentation behind on the values it skips, and the requirement is
 * *byte*-identical. Echoed against the closing tag of the caption above
 * it, so an empty string adds nothing at all.
 *
 * Three things have to be in the sentence. **What was read**: the whole
 * fold, not the carried page, so the count agrees with the facet's and
 * with every other count in that bar. **Against what**: a hit means
 * nothing without how many lists were consulted, which is why the fact
 * strip has printed *"84 lists checked"* since phase 7. **What it did
 * not do**: a reader who sees dimmed rows at the top of a ranked table
 * will otherwise assume the rank has already accounted for them. It has
 * not — that is B6.
 */
$listsHit = isset($co['warninglists_listed'])
    ? (int)$co['warninglists_listed']
    : 0;
$warninglistCap = '';
if ($listsHit > 0) {
    ob_start();
    ?>
        <div class="vp-rel-cap" data-vp-group-only="value">
            <i class="fas fa-list-check"
               title="<?= h(__(
                   'The Warninglist facet names the lists, and its first'
                   . ' two entries keep or drop the lot. The ranking'
                   . ' does not account for them.'
               )) ?>"></i>
            <span>
                <?= sprintf(
                    __('%1$s, checked against %2$s, and dimmed here.'),
                    '<strong>' . h(sprintf(
                        __('%1$s of %2$s are on a warninglist'),
                        number_format($listsHit),
                        number_format($co['distinct_values'])
                    )) . '</strong>',
                    h(sprintf(
                        __n(
                            '%d enabled list',
                            '%d enabled lists',
                            (int)($co['warninglists_checked'] ?? 0),
                            (int)($co['warninglists_checked'] ?? 0)
                        ),
                        (int)($co['warninglists_checked'] ?? 0)
                    ))
                ) ?>
            </span>
        </div>
    <?php
    $warninglistCap = ob_get_clean();
}

ob_start();
?>
    <?= $pillGroup('group', __('Group by'), 'value', array(
        'value' => __('Value'),
        'event' => __('Event'),
        'object' => __('Object'),
    )) ?>
    <?php
    /*
     * **Most specific** joins the group only where the spread was read.
     * A pill that sorts by a number nobody fetched would reorder the
     * table into the fold's fallback and look like a bug.
     */
    $rankPills = array(
        'shared' => __('Most shared'),
        'recent' => __('Most recent'),
    );
    if ($spreadRead) {
        $rankPills['specific'] = __('Most specific');
    }
    ?>
    <?= $pillGroup('sort', __('Rank by'), $co['rank'], $rankPills) ?>
<?php
$headerExtra = ob_get_clean();
if (!$hasRows) {
    // Ranking and rolling up nothing is a control that cannot do
    // anything, which is worse than one that is absent.
    $headerExtra = null;
}

ob_start();
?>
    <span class="vp-rel-tag me-1">
        <i class="fas fa-link"></i><?= h(__('Co-occurrence')) ?>
    </span>
    <?php if ($co['suppressed']): ?>
        <?= h(__n(
            'the one event this value is in is too large to read',
            'all %d events this value is in are too large to read',
            $scan['events_seen'],
            $scan['events_seen']
        )) ?>
    <?php elseif ($hasRows): ?>
        <span data-vp-list-shown><?= h(count($valueRows)) ?></span>
        <?= h(sprintf(
            __n(
                'of %1$s distinct values in %2$d event',
                'of %1$s distinct values across %2$d events',
                $co['events'],
                number_format($co['distinct_values']),
                $co['events']
            )
        )) ?>
    <?php else: ?>
        <?= h(__('Nothing else in the events this value is in')) ?>
    <?php endif; ?>
    &nbsp;·&nbsp;<?= h(__('shared events')) ?>&nbsp;·&nbsp;
    <span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
        h(__('Machine-derived')) ?></span>
<?php
$headerSub = ob_get_clean();
?>
    <?php if (!empty($siblings['rows'])): ?>

        <?php
        /*
         * Listed above the ranked table because it is the only
         * co-occurrence here that is structural rather than
         * statistical, and because it survives everything: the object
         * join reads attributes rather than correlations, so it is
         * unaffected by the correlation limit that suppressed the
         * section above it.
         *
         * Its own `data-vp-list` rather than a second control inside
         * the panel's: it pages on a different set of rows than the
         * ranked table, and one pager over the union of the two would
         * print a range belonging to neither.
         *
         * The section scales on how many objects the value sits in,
         * which is a function of the occurrence count and not of the
         * correlation count — so it can be the longest thing on the
         * tab on exactly the value whose correlations were suppressed.
         * Everything below states its own bound for that reason.
         */
        $sibCapped = !empty($siblings['cap']['applied']);
        // A count taken over a capped join is a floor, and says so.
        $sibFloor = $sibCapped ? '≥&nbsp;' : '';
        ?>
        <?php
        /*
         * Its own panel, because the tab said `Co-occurrence` over both
         * tables and two tables under one heading read as one answer in
         * two halves. These are two answers: this one is what somebody
         * put in a box with this value, the one below is what happened
         * to be written up near it. They are also bounded differently
         * and can disagree about how much they saw, which a single
         * header cannot state twice.
         */
        ob_start();
        ?>
            <span class="vp-rel-tag me-1">
                <i class="fas fa-link"></i><?= h(__('Co-occurrence')) ?>
            </span>
            <?= $sibFloor ?><?= h(sprintf(
                __n('%s sibling', '%s siblings', $siblings['total'],
                    number_format($siblings['total']))
            )) ?>
            <?= h(sprintf(
                __n('in %s object', 'in %s objects',
                    $siblings['objects'],
                    number_format($siblings['objects']))
            )) ?>
            &nbsp;·&nbsp;<?= h(__('same object')) ?>&nbsp;·&nbsp;
            <span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
                h(__('Machine-derived')) ?></span>
        <?php
        $sibHeaderSub = ob_get_clean();
        ?>
        <div class="card shadow-sm mb-3 vp-panel vp-rel-k-co"
             style="--vp-panel-color: var(--vp-rel-co);"
             data-vp-rel-summary="siblings"
             data-vp-rel-count="<?= h(($sibCapped ? "\u{2265}\u{00A0}" : '')
                 . number_format($siblings['total'])) ?>"
             <?php if ($sibCapped): ?>
                 data-vp-rel-note="<?= h(__('a floor — the join was capped')) ?>"
             <?php endif; ?>>

        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('In the same object'),
            'panelIcon' => 'misp-icon misp-icon-object misp-simple',
            'panelColor' => 'var(--vp-rel-co)',
            'panelSub' => $sibHeaderSub,
        )) ?>

        <div data-vp-list>

            <div class="px-3 pt-3">
                <?php
                /*
                 * No sub-heading of its own any more. It used to name
                 * the section inside a panel called `Co-occurrence` and
                 * carry the sibling count as a badge; the panel is now
                 * called `In the same object` and its header states the
                 * count in words, so a heading here would say the same
                 * thing twice in eight words less.
                 */
                ?>
                <?php
                /*
                 * One sentence, and it spends its length on what the
                 * reader is looking at rather than on how it was built.
                 * The two examples do the work a definition of a MISP
                 * object used to do here and do it faster, because a
                 * reader recognises the pair before they can parse the
                 * category it belongs to.
                 */
                ?>
                <div class="small mb-2">
                    <?= __('What else was recorded alongside this value'
                        . ' in the same object — a file\'s other hashes,'
                        . ' an IP\'s resolved domains.') ?>
                </div>
                <?php
                /*
                 * The order, stated. Ranked on count alone this table
                 * opens on whichever template captured the value most
                 * often, and for an address that is a screen of capture
                 * bookkeeping. Saying which fields come first, and how
                 * a row is put in one bucket or the other, is the same
                 * bargain the dated panel strikes over its pair rule:
                 * a rule the reader can check beats an order they have
                 * to infer.
                 */
                ?>
                <div class="small text-muted mb-2">
                    <?= __('Linking fields first, then the descriptive'
                        . ' ones — dimmed in the Relation column, not'
                        . ' hidden.') ?>
                    <?php
                    /*
                     * The example names two fields off this table
                     * rather than two the author had in mind. Written
                     * by hand it said *a file's other hashes and its
                     * filename*, and `filename` is a field MISP does
                     * not correlate on — so the sentence promised a
                     * pivot the rows beneath it were dimming, on the
                     * file objects where the flag happens to be set.
                     * Pointing at the table cannot go stale.
                     */
                    ?>
                    <?php if ($sibLinkEg && $sibDescEg): ?>
                        <?= sprintf(
                            __('Here %1$s link, %2$s describe.'),
                            $sibFieldList($sibLinkEg),
                            $sibFieldList($sibDescEg)
                        ) ?>
                    <?php elseif ($sibLinkEg): ?>
                        <?= __('Every field this table carries is a'
                            . ' linking one.') ?>
                    <?php elseif ($sibDescEg): ?>
                        <?= __('No field this table carries is one the'
                            . ' engine links on.') ?>
                    <?php endif; ?>
                    <?php if ($sibUnreached > 0): ?>
                        <?= sprintf(
                            __n(
                                'One descriptive sibling is counted'
                                . ' below but not listed — linking ones'
                                . ' fill the table\'s %2$s rows.',
                                '%1$s descriptive siblings are counted'
                                . ' below but not listed — linking ones'
                                . ' fill the table\'s %2$s rows.',
                                $sibUnreached
                            ),
                            '<strong>' . h(number_format($sibUnreached))
                                . '</strong>',
                            '<strong>' . h(number_format(
                                count($siblings['rows'])
                            )) . '</strong>'
                        ) ?>
                    <?php endif; ?><?= $sibWarninglistNote ?>
                </div>
            </div>

            <?php if ($sibCapped): ?>
                <?php
                /*
                 * §9.6's resolution, stated rather than inferred. The
                 * aggregate is over the viewer's whole occurrence set
                 * and not over the Occurrences tab's current page, so
                 * it needs a ceiling — and an aggregate over a
                 * truncated set that does not say so is the one thing
                 * this section must not produce.
                 */
                ?>
                <div class="vp-rel-cap">
                    <i class="fas fa-circle-info"
                       title="<?= h(__(
                           'Every count in this section is a floor'
                           . ' rather than a total, and is written ≥'
                           . ' to say so.'
                       )) ?>"></i>
                    <span>
                        <?= sprintf(
                            __(
                                'Aggregated over %1$s of the %2$s objects'
                                . ' this value sits in, most recent'
                                . ' first.'
                            ),
                            '<strong>' . h(number_format(
                                $siblings['objects']
                            )) . '</strong>',
                            '<strong>' . h(number_format(
                                $siblings['in_objects']
                            )) . '</strong>'
                        ) ?>
                    </span>
                </div>
            <?php endif; ?>

            <?php
            /*
             * The section's own narrowing bar, inside its own
             * `[data-vp-list]`. Phase 18 left this out and said what it
             * would cost: the facet lookups had to be scoped the way
             * paging already was, which `ownNodes` in `value-intelligence.js`
             * now does for every control a list reads.
             *
             * It is a separate bar and not a seventh dropdown on the one
             * above because the two fold different row sets — that one
             * from the events the scan read, this one from the objects
             * the value sits in — and a single bar would print counts
             * that are exact for neither.
             */
            ?>
            <?php $sibHasFacets = false; ?>
            <?php foreach ($sibFacetGroups as $group) {
                if (!empty($sibFacets[$group['key']])) {
                    $sibHasFacets = true;
                }
            } ?>
            <?php if ($sibHasFacets): ?>
                <div class="px-3 pb-2 d-flex flex-wrap gap-2
                            align-items-center">
                    <span class="vp-subhead mb-0 me-1"><?=
                        __('Narrow by') ?></span>

                    <?php foreach ($sibFacetGroups as $group): ?>
                        <?php if (empty($sibFacets[$group['key']])) {
                            continue;
                        } ?>
                        <div class="dropdown">
                            <button type="button"
                                    class="btn btn-sm btn-outline-secondary
                                           dropdown-toggle vp-rel-facet"
                                    data-bs-toggle="dropdown"
                                    data-bs-auto-close="outside"
                                    aria-expanded="false">
                                <?= h($group['title']) ?>
                                <span class="badge text-bg-secondary ms-1">
                                    <?= h(count($sibFacets[$group['key']])) ?>
                                </span>
                            </button>
                            <div class="dropdown-menu vp-rel-facetmenu p-2">
                                <?php
                                /*
                                 * `local`, because this list has no
                                 * narrowing endpoint behind it. The bar
                                 * above can hand an unanswerable tick
                                 * back to the server; here the hundred
                                 * carried rows are the whole of what a
                                 * tick can ever reach, so an entry none
                                 * of them carries is greyed instead of
                                 * offered.
                                 */
                                ?>
                                <?= $this->element(
                                    'Values/View/value_facet_group',
                                    array(
                                        'key' => $group['key'],
                                        'title' => $group['title'],
                                        'icon' => $group['icon'],
                                        'values' => $sibFacets[$group['key']],
                                        'local' => true,
                                    )
                                ) ?>
                            </div>
                        </div>
                    <?php endforeach; ?>

                    <span class="small text-muted ms-2 vp-min-w-0">
                        <?= sprintf(
                            __('Counts are folded from all %1$s siblings,'
                                . ' not from the page.'),
                            '<span class="font-monospace">'
                                . h(number_format($siblings['total']))
                                . '</span>'
                        ) ?>
                        <i class="fas fa-circle-info vp-cap-more"
                           title="<?= h(sprintf(
                               __('A count larger than the table can show'
                                   . ' names a value outside the %s'
                                   . ' carried. An entry none of them'
                                   . ' reaches is greyed — narrowing on'
                                   . ' it could only empty the table.'),
                               number_format(count($siblings['rows']))
                           )) ?>"></i>
                    </span>

                    <span class="small text-muted ms-auto"
                          data-vp-facet-summary>
                        <span class="vp-facet-summary-none">
                            <?= __('No filter applied') ?>
                        </span>
                        <span class="vp-facet-summary-some">
                            <span data-vp-facet-count-active>0</span>
                            <span data-vp-plural="filters"
                                  data-vp-one="<?= h(__('filter')) ?>"
                                  data-vp-many="<?= h(__('filters')) ?>"><?=
                                h(__('filters')) ?></span>
                            &middot;
                            <span data-vp-facet-rows><?=
                                h(count($siblings['rows'])) ?></span>
                            <span data-vp-plural="rows"
                                  data-vp-one="<?= h(__('row')) ?>"
                                  data-vp-many="<?= h(__('rows')) ?>"><?=
                                h(__('rows')) ?></span>
                        </span>
                    </span>

                    <button type="button" class="btn btn-sm btn-link"
                            data-vp-facet-clear disabled>
                        <?= __('Reset') ?>
                    </button>
                </div>
            <?php endif; ?>

            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <?php
                    /*
                     * Every column sorts, clicking the heading:
                     * ascending, descending, then back to the order the
                     * model sent. Three states and not two because that
                     * order — linking fields first, then the objects a
                     * sibling is in, most first — is itself an answer,
                     * and no column would bring it back. Least of all
                     * Relation: the kind is a property of the field,
                     * not of its name, and two relations spelled alike
                     * across two templates can be flagged differently.
                     */
                    $sibCols = array(
                        array('key' => 'object', 'label' => __('Object')),
                        array('key' => 'relation',
                            'label' => __('Relation')),
                        array('key' => 'value',
                            'label' => __('Sibling value')),
                        array('key' => 'type', 'label' => __('Type')),
                        array('key' => 'objects', 'label' => __('Objects'),
                            'class' => 'vp-rel-num'),
                        array('key' => 'specific',
                            'label' => __('Specific to this value'),
                            'only' => $sibSpreadRead),
                        /*
                         * A right-aligned number immediately left of a
                         * left-aligned name reads as one field, so the
                         * count keeps its own gutter.
                         */
                        array('key' => 'events', 'label' => __('Events'),
                            'class' => 'text-end pe-4'),
                        array('key' => 'org',
                            'label' => __('Reported by')),
                    );
                    $sibCols = array_values(array_filter(
                        $sibCols,
                        function ($col) {
                            return !array_key_exists('only', $col)
                                || $col['only'];
                        }
                    ));
                    ?>
                    <thead>
                        <tr>
                            <?php foreach ($sibCols as $col): ?>
                                <th class="<?= h($col['class'] ?? '') ?>">
                                    <button type="button" class="vp-th-sort"
                                            data-vp-sort-col="<?=
                                                h($col['key']) ?>">
                                        <span class="sortable-header"><?=
                                            h($col['label'])
                                        ?><i class="sort-icon"></i></span>
                                    </button>
                                </th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($siblings['rows']
                            as $sibIndex => $sibling): ?>
                            <tr class="vp-rel-stripe vp-rel-k-co"
                                data-vp-facet="<?=
                                    h(implode(' ', $sibling['tokens'])) ?>"<?=
                                $sortAttrs(array(
                                    'vp-sort-object' => mb_strtolower(
                                        $sibling['object']
                                    ),
                                    'vp-sort-relation' => mb_strtolower(
                                        $sibling['relation']
                                    ),
                                    'vp-sort-value' => mb_strtolower(
                                        $sibling['value']
                                    ),
                                    'vp-sort-type' => mb_strtolower(
                                        $sibling['type']
                                    ),
                                    'vp-sort-objects' => $sortNum(
                                        $sibling['objects']
                                    ),
                                    'vp-sort-specific' => $specificSort(
                                        $sibling['objects'],
                                        $sibling['spread'] ?? null,
                                        true
                                    ),
                                    'vp-sort-events' => $sortNum(
                                        $sibling['events']
                                    ),
                                    'vp-sort-org' => $sortOrgs(
                                        $sibling['orgs'],
                                        $sibling['org_total']
                                    ),
                                ), $sibIndex) ?>>
                                <td class="text-nowrap">
                                    <span class="misp-icon misp-icon-object
                                                 misp-simple me-1"></span>
                                    <span class="font-monospace small">
                                        <?= h($sibling['object']) ?>
                                    </span>
                                    <?php
                                    /*
                                     * To the event's objects tab, as the
                                     * other panels link an object: this
                                     * theme's event view takes no
                                     * `focus:`, so the title names it.
                                     */
                                    $sibIds = $sibling['object_ids'] ?? array();
                                    ?>
                                    <?php foreach ($sibIds as $sibObject): ?>
                                        <a href="<?= h($baseurl)
                                            ?>/events/view/<?=
                                            h($sibObject['event'])
                                            ?>#tab-objects"
                                           class="font-monospace small ms-1"
                                           title="<?= h(sprintf(
                                               __('Object #%1$s in event #%2$s'),
                                               $sibObject['id'],
                                               $sibObject['event']
                                           )) ?>">#<?=
                                            h($sibObject['id']) ?></a>
                                    <?php endforeach; ?>
                                    <?php $sibIdsMore = (int)$sibling['objects']
                                        - count($sibIds); ?>
                                    <?php if ($sibIds && $sibIdsMore > 0): ?>
                                        <span class="text-muted small">
                                            <?= h(sprintf(
                                                __('+%d more'),
                                                $sibIdsMore
                                            )) ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <?php $sibDesc = $sibling['kind']
                                    === ValueFieldKind::DESCRIPTIVE; ?>
                                <td>
                                    <span class="vp-relation<?=
                                        $sibDesc
                                            ? ' vp-relation-desc'
                                            : '' ?>"<?= $sibDesc
                                        ? ' title="' . h(__('Descriptive'
                                            . ' — the engine does not'
                                            . ' correlate on this field,'
                                            . ' so it names the capture'
                                            . ' rather than a pivot'))
                                            . '"'
                                        : '' ?>>
                                        <?= h($sibling['relation']) ?>
                                    </span>
                                </td>
                                <td class="font-monospace">
                                    <span class="vp-rel-cell<?=
                                        empty($sibling['warninglists'])
                                            ? ''
                                            : ' vp-rel-listed'
                                    ?><?= $hoverClass ?>"<?=
                                        $hoverCard($sibling['value'])
                                    ?>><?=
                                        h($sibling['value']) ?></span><?=
                                        $listedMark(
                                            $sibling['warninglists']
                                                ?? array()
                                        ) ?>

                                </td>
                                <td><?= $typeBadge($sibling['type']) ?></td>
                                <?php
                                /*
                                 * How many objects this one row stands
                                 * for, on the same bar the roll-ups
                                 * use. The bar carries its own reading,
                                 * so the collapse is still there to be
                                 * read exactly.
                                 */
                                ?>
                                <td><?= $weightBar(
                                    $sibling['objects'],
                                    $maxSibObjects,
                                    $sibling['objects'] > 1
                                        ? $sibFloor
                                        : ''
                                ) ?></td>
                                <?php if ($sibSpreadRead): ?>
                                    <td class="small text-nowrap">
                                        <?= h($specificRead(
                                            $sibling['objects'],
                                            $sibling['spread'] ?? null,
                                            'object',
                                            !empty($sibling['spread_least'])
                                        )) ?>
                                    </td>
                                <?php endif; ?>
                                <td class="text-end pe-4 text-nowrap">
                                    <?php
                                    /*
                                     * The event, wherever the fold left
                                     * one to name — a row standing for
                                     * five objects that all sit in the
                                     * same event knows which event that
                                     * is. Where it stands for several
                                     * events it can only give the
                                     * count, because aggregating to a
                                     * triple loses the ids.
                                     */
                                    ?>
                                    <?php if ($sibling['event'] !== null): ?>
                                        <a href="<?= $baseurl
                                            ?>/events/view/<?=
                                            h($sibling['event']) ?>"
                                           class="font-monospace small">
                                            #<?= h($sibling['event']) ?>
                                        </a>
                                    <?php else: ?>
                                        <span class="font-monospace small">
                                            <?= $sibFloor ?><?=
                                                h(number_format(
                                                    $sibling['events']
                                                )) ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td class="text-nowrap">
                                    <?= h(implode(', ', array_slice(
                                        $sibling['orgs'],
                                        0,
                                        2
                                    ))) ?>
                                    <?php
                                    $sibMore = $sibling['org_total']
                                        - min(2, count($sibling['orgs']));
                                    ?>
                                    <?php if ($sibMore > 0): ?>
                                        <span class="text-muted small">
                                            <?= h(sprintf(
                                                __('+%d more'),
                                                $sibMore
                                            )) ?>
                                        </span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="p-3 d-none" data-vp-list-empty>
                <div class="vp-empty vp-empty-inline">
                    <i class="fas fa-filter"></i>
                    <span>
                        <?= __('No sibling matches the filter you set.') ?>
                    </span>
                </div>
            </div>

            <div class="px-3 py-2 border-top">
                <?= $this->element('Values/View/value_pager', array(
                    'size' => $siblings['page_size'],
                    'shown' => count($siblings['rows']),
                    'total' => $siblings['total'],
                    'noun' => array(
                        'one' => __('sibling'),
                        'many' => __('siblings'),
                    ),
                )) ?>
            </div>

            <?php
            /*
             * §14.6, applied here by phase 24. This carried a
             * `.vp-acl-note` counting the sibling attributes held at a
             * distribution the reader is outside of. A count of what is
             * hidden is a membership oracle over any value the reader
             * cares to type, and the bare fact that something *was*
             * hidden is the same disclosure at one bit — so the band is
             * gone and the aggregate above simply describes what the
             * reader can see. The cap notice stays: a cap is not a
             * permission.
             */
            ?>

        </div>

        </div>

    <?php endif; ?>

<?php
/*
 * `vp-narrow-url` is what makes narrowing honest on a value whose
 * neighbourhood is larger than the table. The rows here are the top
 * `row_cap` by shared events, so a filter the browser applies can only
 * reach the ones that survived that cut — and `abuse.ch`, 9,791 values
 * ranking below it, emptied a table it had just been counted in.
 *
 * The browser still filters whatever it provably can: a facet whose
 * whole count is present in these rows is answerable here, and so is
 * everything when nothing was cut. `vp-narrow-cut` says which case
 * this is.
 *
 * **It is measured against the neighbourhood, not against the filter
 * that produced this page.** The question the script asks it is *could
 * some other narrowing want a row this markup does not have*, and the
 * answer to that never depends on which rows the current one kept.
 * Read from `matched` it did: narrowing `8.8.8.8` to the 37 values on a
 * warninglist made `matched` equal the rows carried, cleared the flag,
 * and told the script the page was complete — so the next tick,
 * *No hit*, was answered from 37 rows none of which is one, and a table
 * with 10,003 matches behind it reported that nothing matched. Any two
 * ticks could do it where the first landed inside `row_cap`; the
 * warninglist pair only made it certain, being complements.
 */
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-co"
     style="--vp-panel-color: var(--vp-rel-co);"
     data-vp-list
     data-vp-narrow-url="<?= h($baseurl) ?>/values/viewRelationCooccurrence/<?=
         h($valueB64) ?>"
     data-vp-narrow-cut="<?= $co['distinct_values'] > count($valueRows)
         ? '1' : '' ?>"
     data-vp-narrow-active="<?= empty($active) ? '' : '1' ?>"
     data-vp-group-active="value"
     <?php
     /*
      * What the contents strip prints for this section. A suppressed
      * value has no count to give — the neighbourhood was never read,
      * which is not the same as being empty — so the card says so in
      * words rather than printing a zero the strip would have invented.
      */
     ?>
     data-vp-rel-summary="cooccurrence"
     data-vp-rel-count="<?= $co['suppressed']
         ? "\u{2014}"
         : h(number_format($co['distinct_values'])) ?>"
     <?php if ($co['suppressed']): ?>
         data-vp-rel-note="<?= h(__('not read')) ?>"
     <?php endif; ?>>

    <?php
    /*
     * Named for the half of the tab it is, now that the object join has
     * a panel of its own. The two controls that used to sit on the right
     * of this header are down beside the narrowing they belong with.
     */
    ?>
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('In the same events'),
        'panelIcon' => 'fas fa-link',
        'panelColor' => 'var(--vp-rel-co)',
        'panelSub' => $headerSub,
    )) ?>

    <?php if ($co['suppressed']): ?>

        <?php
        /*
         * Not an empty state — the opposite claim, and one a reader who
         * saw an empty table would get exactly backwards. There is a
         * neighbourhood; it is in events so large that reading one
         * would say nothing about this value in particular.
         */
        ?>
        <div class="vp-suppressed">
            <i class="fas fa-circle-exclamation"></i>
            <div>
                <span class="vp-suppressed-badge">
                    <?= __('Too large to read') ?>
                </span>
                <div class="mt-2">
                    <?= sprintf(
                        __(
                            '%1$s holds more than %2$s attributes. In'
                            . ' an event that size every value'
                            . ' co-occurs with every other, so a'
                            . ' neighbour list drawn from one would'
                            . ' describe the event rather than this'
                            . ' value — and this panel does not draw'
                            . ' one.'
                        ),
                        '<strong>' . h(__n(
                            'The one event this value appears in',
                            'Every one of the %d events this value'
                                . ' appears in',
                            $scan['events_seen'],
                            $scan['events_seen']
                        )) . '</strong>',
                        '<strong>' . h(number_format(
                            $scan['size_cap']
                        )) . '</strong>'
                    ) ?>
                </div>
                <div class="mt-2">
                    <?= h(__(
                        'Nothing is hidden and nothing is missing.'
                        . ' The object siblings below sit in those'
                        . ' same events and are listed in full — an'
                        . ' object does not get larger because the'
                        . ' event around it did.'
                    )) ?>
                </div>
            </div>
        </div>

    <?php elseif (!$hasRows): ?>

        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-link"></i>
                <span>
                    <?= __('No correlation the engine has stored for'
                        . ' this value.') ?>
                </span>
            </div>
        </div>

    <?php endif; ?>


    <?php if ($hasRows): ?>

        <?php
        /*
         * The ranked table's heading, hoisted out of its roll-up pane so
         * that everything governing this table — the two cap notices,
         * the filter row and the counted bar — sits between this line
         * and the rows, and nothing governing it sits above the sibling
         * section. All four used to open the panel, which put them
         * above a table they say nothing about; a reader could only
         * learn which of the three narrowing controls reached which of
         * the two tables by trying them.
         *
         * Outside `[data-vp-list-rows]`, and that is load-bearing: the
         * row host is hidden when a filter empties the table, and a
         * control inside it would take the reader's only way back out
         * with it.
         */
        ?>
        <div data-vp-group-only="value">
            <div class="px-3 pt-3 mt-2 border-top">
                <div class="vp-subhead d-flex align-items-center gap-2">
                    <i class="fas fa-link"></i>
                    <?= __('Values that appear in the same events') ?>
                    <span class="badge text-bg-secondary">
                        <?= h(number_format($co['distinct_values'])) ?>
                    </span>
                </div>
            </div>
        </div>

        <?php if (!$co['suppressed']): ?>

        <?php
        /*
         * Counts distinct *values* and promises the facet counts below
         * are exact, so it goes away with the roll-up those two belong
         * to. It always showed, which was survivable while it sat at
         * the top of the panel and only wrong once it moved down to
         * where the event table can be the thing underneath it.
         *
         * The scan line below is not gated: what the scan read is the
         * same however the rows are rolled up.
         */
        ?>
        <?php
        /*
         * **The caption names the rank it is describing.** It said
         * `ranked by shared events` unconditionally until a third rank
         * existed, which was true while both of the others agreed about
         * what reaches the cut. `Most specific` does not: it is the
         * first rank whose key is not a column the reader can add up,
         * so the sentence that explains the cut has to say which key
         * made it.
         */
        $rankPhrase = __('ranked by shared events');
        if ($co['rank'] === 'recent') {
            $rankPhrase = __('ranked by when they last appeared together');
        } elseif ($co['rank'] === 'specific') {
            $rankPhrase = __(
                'ranked by how specific each is to this value'
            );
        }
        /*
         * And where the numerator came from, because the rank divides
         * by every event a neighbour is in while counting only the
         * events this scan could afford to read. A neighbour in all 34
         * of a value's events reads `31 of its 34` where three were
         * skipped — understating it, never the reverse. Only the
         * specific rank needs the clause; the other two never divide.
         */
        $rankScope = '';
        if ($co['rank'] === 'specific') {
            $rankScope = ' ' . sprintf(
                __n(
                    'Specificity is counted over the one event read.',
                    'Specificity is counted over the %d events read.',
                    $scan['events_read'],
                    $scan['events_read']
                )
            );
        }
        ?>
        <div class="vp-rel-cap" data-vp-group-only="value">
            <i class="fas fa-filter"
               title="<?= h($co['distinct_values'] > count($valueRows)
                   ? sprintf(
                       __('Facet counts below stay exact at %s: they are'
                           . ' folded from every row read, not tallied'
                           . ' from the page.'),
                       number_format($co['distinct_values'])
                   )
                   : __('Nothing here is ranked away — the cut below is'
                       . ' on which events were read, not on which'
                       . ' values survived.')) ?>"></i>
            <span>
                <?= sprintf(
                    __('%1$s, %2$s.'),
                    '<strong>' . h(
                        $co['distinct_values'] > count($valueRows)
                            ? sprintf(
                                __('%1$s of %2$s distinct values are'
                                    . ' carried'),
                                number_format(count($valueRows)),
                                number_format($co['distinct_values'])
                            )
                            : sprintf(
                                __('All %d distinct values are listed'),
                                $co['distinct_values']
                            )
                    ) . '</strong>',
                    h($rankPhrase)
                ) ?><?= h($rankScope) ?>
            </span>
        </div><?= $warninglistCap ?>


        <?php
        /*
         * The cut this section is made of, in words. Every count
         * above is exact over the events named here and over no
         * others, and a reader who is not told which events were
         * read has no way to judge a neighbour list at all.
         *
         * §14.6 keeps cap notices: a cap is not a permission. None
         * of these numbers says anything about rows the reader may
         * not see — an oversized event is oversized for everybody.
         */
        ?>
        <?php
        /*
         * The budget is named only where it did something. It bounds
         * the scan on every instance, but on a value whose events
         * all fitted inside it, it describes a cut that did not
         * happen — and this sentence's whole job is to say what was
         * read. `events_unread` counts the events it turned away, so
         * it is the one field that knows.
         *
         * The scope reads `all 3 events` and not `3 of this value's
         * 3 events`, which is a fraction a reader has to divide
         * before learning it means everything.
         */
        /*
         * The read's age, because the rows under this panel are
         * held for `RELATION_SCAN_TTL` and a cache that does not
         * say how old it is is the reason a long one is a trap. The
         * phrase is relative because that is what a reader can act
         * on; the exact stamp is in the `title`, and it is what
         * stays true if the tab is left open — the fragment is
         * server-rendered, so the words freeze where they were.
         */
        // the phrase itself lives in Values/View/value_read_age
        $readAt = isset($scan['read_at']) ? (int)$scan['read_at'] : 0;
        $budgetBit = !empty($scan['events_unread']);
        $scanScope = $scan['events_read'] === $scan['events_seen']
            ? __n(
                'the one event this value is in',
                'all %d events this value is in',
                $scan['events_seen'],
                $scan['events_seen']
            )
            : sprintf(
                __('%1$d of this value\'s %2$d events'),
                $scan['events_read'],
                $scan['events_seen']
            );
        ?>
        <div class="vp-rel-cap">
            <i class="fas fa-circle-info"></i>
            <span>
                <?= sprintf(
                    $budgetBit
                        ? __(
                            'Read from %1$s, newest first, within a'
                            . ' budget of %2$s attribute rows —'
                            . ' %3$s read.'
                        )
                        : __(
                            'Read from %1$s, newest first — %3$s'
                            . ' read.'
                        ),
                    '<strong>' . h($scanScope) . '</strong>',
                    h(number_format($scan['budget'])),
                    h(__n(
                        '%s row',
                        '%s rows',
                        $scan['rows_read'],
                        number_format($scan['rows_read'])
                    ))
                ) ?>
                <?php if (!empty($scan['events_oversized'])): ?>
                    <?= h(sprintf(
                        __n(
                            '%1$d event was left out for holding'
                                . ' more than %2$s attributes.',
                            '%1$d events were left out for holding'
                                . ' more than %2$s attributes each.',
                            $scan['events_oversized'],
                            $scan['events_oversized'],
                            number_format($scan['size_cap'])
                        )
                    )) ?>
                <?php endif; ?>
                <?php if (!empty($scan['events_unread'])): ?>
                    <?= h(sprintf(
                        __n(
                            '%d further event fell outside the'
                                . ' budget.',
                            '%d further events fell outside the'
                                . ' budget.',
                            $scan['events_unread'],
                            $scan['events_unread']
                        )
                    )) ?>
                <?php endif; ?>
                <?= $this->element('Values/View/value_read_age',
                    array('readAt' => $readAt)) ?>
                <button type="button"
                        class="btn btn-sm btn-link p-0 align-baseline
                               vp-rel-again"
                        data-vp-narrow-fresh>
                    <i class="fas fa-rotate me-1"></i><?=
                        __('Scan again') ?>
                </button>
            </span>
        </div>

        <?php
        /*
         * The roll-up and the ranking, down here with the narrowing they
         * belong beside rather than up in the panel header. They govern
         * this table and nothing else, and the header is where a reader
         * looks for what the panel *is*, not for what to do to it.
         *
         * Outside the block below, and that is the point of it being its
         * own row: `Group by` is what puts that block away, so a reader
         * who had grouped by event would have no control left to get
         * back with. Both apply to all three roll-ups — every row
         * carries the `data-vp-num` the ranking reads.
         */
        ?>
        <?php if ($headerExtra !== null): ?>
            <div class="px-3 pt-3 d-flex flex-wrap gap-3
                        align-items-center">
                <?= $headerExtra ?>
            </div>
        <?php endif; ?>

        <?php
        /*
         * The narrowing block belongs to the value roll-up and says so
         * when it is not showing. A facet on `type` is a property of a
         * correlated value; an event row is not a value, and narrowing
         * it by the type of one would be a filter that means nothing.
         */
        ?>
        <div data-vp-group-only="value">

            <div class="p-3 border-bottom d-flex flex-wrap gap-2
                        align-items-center">
                <div class="input-group input-group-sm" style="width: 15rem">
                    <span class="input-group-text">
                        <i class="fas fa-magnifying-glass"></i>
                    </span>
                    <input type="text" class="form-control"
                           data-vp-filter-text
                           value="<?= h(isset($active['text'])
                               ? $active['text'] : '') ?>"
                           aria-label="<?= __('Search the listed values') ?>"
                           placeholder="<?= h(__('Search value')) ?>">
                </div>

                <?php
                $selects = array(
                    array('key' => 'type', 'any' => __('Any type'),
                        'rows' => $facets['type']),
                    array('key' => 'organisation',
                        'any' => __('Any organisation'),
                        'rows' => $facets['organisation']),
                    array('key' => 'event', 'any' => __('Any event'),
                        'rows' => $facets['event']),
                );
                ?>
                <select class="form-select form-select-sm w-auto"
                        data-vp-filter-key="category"
                        aria-label="<?= __('Category') ?>">
                    <option value=""><?= __('Any category') ?></option>
                    <?php foreach ($co['categories'] as $category): ?>
                        <option value="<?= h($slug($category)) ?>"<?=
                            isset($activeSelects['category'])
                                && $activeSelects['category']
                                    === $slug($category)
                                ? ' selected' : '' ?>>
                            <?= h($category) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <?php foreach ($selects as $select): ?>
                    <select class="form-select form-select-sm w-auto"
                            data-vp-filter-key="<?= h($select['key']) ?>"
                            aria-label="<?= h($select['any']) ?>">
                        <option value=""><?= h($select['any']) ?></option>
                        <?php foreach ($select['rows'] as $facet): ?>
                            <option value="<?= h($facet['value']) ?>"<?=
                                isset($activeSelects[$select['key']])
                                    && $activeSelects[$select['key']]
                                        === (string)$facet['value']
                                    ? ' selected' : '' ?><?=
                                isset($facet['listed'])
                                    && $facet['listed'] === $facet['count']
                                    ? ' data-vp-complete="1"' : '' ?>>
                                <?= h($facet['label']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                <?php endforeach; ?>

                <div class="input-group input-group-sm" style="width: 12rem">
                    <span class="input-group-text">
                        <?= __('Shared events') ?> &ge;
                    </span>
                    <input type="number" class="form-control" min="1"
                           value="<?= h(isset($active['min_shared'])
                               ? (int)$active['min_shared'] : 1) ?>"
                           data-vp-filter-min="shared"
                           aria-label="<?= __('Minimum shared events') ?>">
                </div>

                <div class="form-check form-switch mb-0 ms-1">
                    <input class="form-check-input" type="checkbox"
                           role="switch" id="vp-rel-siblings-only"
                           data-vp-facet-key="sibling" value="yes"<?=
                        in_array('yes', $activeFacet('sibling'), true)
                            ? ' checked' : '' ?>>
                    <label class="form-check-label small text-muted"
                           for="vp-rel-siblings-only">
                        <?= __('Object siblings only') ?>
                    </label>
                </div>

                <?php
                /*
                 * "No filter applied" and "3 filters" are one line in
                 * two states rather than two lines, so the reader's eye
                 * does not have to move when the first control is set.
                 * It counts every narrowing control — a select and a
                 * threshold narrow the table exactly as a ticked facet
                 * does, and a count that ignored them would let the
                 * panel claim nothing was applied while three were.
                 */
                ?>
                <span class="small text-muted ms-auto"
                      data-vp-facet-summary>
                    <span class="vp-facet-summary-none">
                        <?= __('No filter applied') ?>
                    </span>
                    <span class="vp-facet-summary-some">
                        <span data-vp-facet-count-active>0</span>
                        <span data-vp-plural="filters"
                              data-vp-one="<?= h(__('filter')) ?>"
                              data-vp-many="<?= h(__('filters')) ?>"><?=
                            h(__('filters')) ?></span>
                        &middot;
                        <span data-vp-facet-rows><?=
                            h(count($valueRows)) ?></span>
                        <span data-vp-plural="rows"
                              data-vp-one="<?= h(__('row')) ?>"
                              data-vp-many="<?= h(__('rows')) ?>"><?=
                            h(__('rows')) ?></span>
                    </span>
                </span>

                <button type="button" class="btn btn-sm btn-link"
                        data-vp-facet-clear disabled>
                    <?= __('Reset') ?>
                </button>
            </div>

            <div class="p-3 border-bottom d-flex flex-wrap gap-2
                        align-items-center">
                <span class="vp-subhead mb-0 me-1"><?= __('Narrow by') ?></span>

                <?php foreach ($facetGroups as $group): ?>
                    <?php if (empty($facets[$group['key']])) {
                        continue;
                    } ?>
                    <div class="dropdown">
                        <button type="button"
                                class="btn btn-sm btn-outline-secondary
                                       dropdown-toggle vp-rel-facet"
                                data-bs-toggle="dropdown"
                                data-bs-auto-close="outside"
                                aria-expanded="false">
                            <?= h($group['title']) ?>
                            <span class="badge text-bg-secondary ms-1">
                                <?= h(count($facets[$group['key']])) ?>
                            </span>
                        </button>
                        <div class="dropdown-menu vp-rel-facetmenu p-2">
                            <?= $this->element(
                                'Values/View/value_facet_group',
                                array(
                                    'key' => $group['key'],
                                    'title' => $group['title'],
                                    'icon' => $group['icon'],
                                    'values' => $facets[$group['key']],
                                    'active' => $activeFacet(
                                        $group['key']
                                    ),
                                )
                            ) ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <span class="small text-muted ms-2 vp-min-w-0">
                    <?= sprintf(
                        __('Facet counts are folded from %s, not from'
                            . ' the page.'),
                        '<span class="font-monospace">'
                            . h(sprintf(
                                __('all %s rows read'),
                                number_format($scan['rows_read'])
                            )) . '</span>'
                    ) ?>
                        <i class="fas fa-circle-info vp-cap-more"
                           title="<?= h(sprintf(
                               __('Narrowing on a count larger than the'
                                   . ' %s carried below fetches its rows'
                                   . ' rather than emptying the table.'),
                               number_format(count($valueRows))
                           )) ?>"></i>
                </span>
            </div>

        </div>

        <div class="vp-rel-cap d-none" data-vp-group-not="value">
            <i class="fas fa-circle-info"></i>
            <span>
                <?= __('Narrowing applies to the value roll-up,'
                    . ' not to these event rows.') ?>
            </span>
        </div>


        <?php endif; ?>

        <div data-vp-list-rows>

            <div data-vp-group-pane="value">
                <div class="table-responsive">
                    <table class="table table-sm table-hover vp-table
                                  align-middle mb-0">
                        <thead>
                            <tr>
                                <?php
                                /*
                                 * Tags is the one column with no
                                 * heading to click. A row carries a set
                                 * of them and a set has no place in an
                                 * order — sorting by the first chip
                                 * would look like sorting by tag and be
                                 * sorting by whichever one MISP happened
                                 * to return first. The Tag facet above
                                 * is how a reader gets at them.
                                 */
                                $valCols = array(
                                    array('key' => 'value',
                                        'label' => __('Value')),
                                    array('key' => 'type',
                                        'label' => __('Type')),
                                    array('key' => 'shared',
                                        'label' => __('Shared events'),
                                        'class' => 'vp-rel-num'),
                                    /*
                                     * Beside the count it qualifies,
                                     * not further along: `8 shared` and
                                     * `in 8 of its 204 events` are one
                                     * reading, and a column between
                                     * them makes the reader carry the
                                     * first across the second.
                                     */
                                    array('key' => 'specific',
                                        'label' => __(
                                            'Specific to this value'
                                        ),
                                        'only' => $spreadRead),
                                    array('key' => 'orgs',
                                        'label' => __('Organisations')),
                                    array('key' => 'last',
                                        'label' => __('Last together')),
                                    array('key' => 'distribution',
                                        'label' => __('Distribution')),
                                );
                                ?>
                                <?php
                                $valCols = array_values(array_filter(
                                    $valCols,
                                    function ($col) {
                                        return !array_key_exists(
                                            'only',
                                            $col
                                        ) || $col['only'];
                                    }
                                ));
                                ?>
                                <?php foreach ($valCols as $col): ?>
                                    <th class="<?= h($col['class'] ?? '') ?>">
                                        <button type="button"
                                                class="vp-th-sort"
                                                data-vp-sort-col="<?=
                                                    h($col['key']) ?>">
                                            <span class="sortable-header"><?=
                                                h($col['label'])
                                            ?><i class="sort-icon"></i></span>
                                        </button>
                                    </th>
                                <?php endforeach; ?>
                                <th><?= __('Tags') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($valueRows
                                as $valIndex => $row): ?>
                                <tr class="vp-rel-stripe vp-rel-k-co"
                                    data-vp-group="value"
                                    data-vp-facet="<?= h(implode(
                                        ' ',
                                        $row['tokens']
                                    )) ?>"
                                    data-vp-num="<?= h($numbers(
                                        $row['shared_events'],
                                        $row['last_together']
                                    )) ?>"
                                    data-vp-text="<?= h(strtolower(
                                        $row['value']
                                    )) ?>"<?= $sortAttrs(array(
                                        'vp-sort-value' => mb_strtolower(
                                            $row['value']
                                        ),
                                        'vp-sort-type' => mb_strtolower(
                                            $row['type']
                                        ),
                                        'vp-sort-shared' => $sortNum(
                                            $row['shared_events']
                                        ),
                                        'vp-sort-specific' =>
                                            $specificSort(
                                                $row['shared_events'],
                                                $row['spread'] ?? null
                                            ),
                                        'vp-sort-orgs' => $sortOrgs(
                                            $row['orgs'],
                                            count($row['orgs'])
                                        ),
                                        // Digits of the printed date, so
                                        // the order is the one the cell
                                        // shows.
                                        'vp-sort-last' => preg_replace(
                                            '/\D/',
                                            '',
                                            (string)$row['last_together']
                                        ),
                                        'vp-sort-distribution' => $sortNum(
                                            $row['distribution']
                                        ),
                                    ), $valIndex) ?>>
                                    <td class="font-monospace">
                                        <span class="vp-rel-cell<?=
                                            empty($row['warninglists'])
                                                ? ''
                                                : ' vp-rel-listed'
                                        ?><?= $hoverClass ?>"<?=
                                            $hoverCard($row['value'])
                                        ?>><?=
                                            h($row['value']) ?></span><?=
                                            $listedMark(
                                                $row['warninglists']
                                                    ?? array()
                                            ) ?>

                                    </td>
                                    <td><?= $typeBadge($row['type']) ?></td>
                                    <td><?= $weightBar(
                                        $row['shared_events'],
                                        $maxShared
                                    ) ?></td>
                                    <?php if ($spreadRead): ?>
                                        <td class="small text-nowrap">
                                            <?= h($specificRead(
                                                $row['shared_events'],
                                                $row['spread'] ?? null,
                                                'event',
                                                !empty($row['spread_least'])
                                            )) ?>
                                        </td>
                                    <?php endif; ?>
                                    <td class="small">
                                        <?= h(implode(', ', $row['orgs'])) ?>
                                    </td>
                                    <td class="font-monospace text-nowrap
                                               small">
                                        <?= h($row['last_together']) ?>
                                    </td>
                                    <td><?= $distributionBadge($row) ?></td>
                                    <td><?= $tagChips($row['tags']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div data-vp-group-pane="event" class="d-none">
                <div class="px-3 pt-3 mt-2 border-top">
                    <div class="vp-subhead d-flex align-items-center gap-2">
                        <span class="misp-icon misp-icon-event
                                     misp-simple"></span>
                        <?= __('Events this value shares with something'
                            . ' else') ?>
                        <span class="badge text-bg-secondary">
                            <?= h(number_format(
                                $co['rollups']['event']['total']
                            )) ?>
                        </span>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-hover vp-table
                                  align-middle mb-0">
                        <thead>
                            <tr>
                                <th><?= __('Event') ?></th>
                                <th><?= __('Date') ?></th>
                                <th><?= __('Reported by') ?></th>
                                <th class="vp-rel-num">
                                    <?= __('Shared values') ?>
                                </th>
                                <th><?= __('Distribution') ?></th>
                                <th><?= __('Tags') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($eventRows as $row): ?>
                                <tr class="vp-rel-stripe vp-rel-k-co"
                                    data-vp-group="event"
                                    data-vp-num="<?= h($numbers(
                                        $row['shared_values'],
                                        $row['event']['date']
                                    )) ?>">
                                    <td class="vp-min-w-0">
                                        <a href="<?= $baseurl
                                            ?>/events/view/<?=
                                            h($row['event']['id']) ?>"
                                           class="font-monospace small">
                                            #<?= h($row['event']['id']) ?>
                                        </a>
                                        <div class="small text-muted
                                                    vp-rel-cell">
                                            <?= h($row['event']['info']) ?>
                                        </div>
                                    </td>
                                    <td class="font-monospace text-nowrap
                                               small">
                                        <?= h($row['event']['date']) ?>
                                    </td>
                                    <td class="text-nowrap">
                                        <?= h($row['org']) ?>
                                    </td>
                                    <td><?= $weightBar(
                                        $row['shared_values'],
                                        $maxEventShared
                                    ) ?></td>
                                    <td><?= $distributionBadge($row) ?></td>
                                    <td><?= $tagChips($row['tags']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div data-vp-group-pane="object" class="d-none">
                <div class="px-3 pt-3 mt-2 border-top">
                    <div class="vp-subhead d-flex align-items-center gap-2">
                        <span class="misp-icon misp-icon-object
                                     misp-simple"></span>
                        <?= __('Objects the correlated attributes sit in') ?>
                        <span class="badge text-bg-secondary">
                            <?= h(number_format(
                                $co['rollups']['object']['total']
                            )) ?>
                        </span>
                    </div>
                    <div class="small text-muted mb-2">
                        <?= __('Shorter than the other two roll-ups because'
                            . ' most correlated attributes are not in an'
                            . ' object at all.') ?>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-hover vp-table
                                  align-middle mb-0">
                        <thead>
                            <tr>
                                <th><?= __('Object') ?></th>
                                <th><?= __('Event') ?></th>
                                <th><?= __('Reported by') ?></th>
                                <th class="vp-rel-num">
                                    <?= __('Related values') ?>
                                </th>
                                <th><?= __('Relations') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($objectRows as $row): ?>
                                <tr class="vp-rel-stripe vp-rel-k-co"
                                    data-vp-group="object"
                                    data-vp-num="shared:<?=
                                        h((int)$row['values']) ?> recent:0">
                                    <td class="text-nowrap">
                                        <span class="misp-icon
                                                     misp-icon-object
                                                     misp-simple me-1"></span>
                                        <span class="font-monospace small">
                                            <?= h($row['object']['name']) ?>
                                        </span>
                                        <span class="text-muted small">
                                            #<?= h($row['object']['id']) ?>
                                        </span>
                                    </td>
                                    <td class="text-nowrap">
                                        <a href="<?= $baseurl
                                            ?>/events/view/<?=
                                            h($row['event']) ?>"
                                           class="font-monospace small">
                                            #<?= h($row['event']) ?>
                                        </a>
                                    </td>
                                    <td class="text-nowrap">
                                        <?= h($row['org']) ?>
                                    </td>
                                    <td><?= $weightBar(
                                        $row['values'],
                                        $maxObjectValues
                                    ) ?></td>
                                    <td>
                                        <?php foreach (
                                            $row['relations'] as $relation
                                        ): ?>
                                            <span class="vp-relation me-1">
                                                <?= h($relation) ?>
                                            </span>
                                        <?php endforeach; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        </div>

        <?php
        /*
         * Only a filter can produce this. The value with no correlation
         * at all has its own empty state above, and "no row matches
         * your filter" over it would be a different and false claim.
         */
        ?>
        <div class="p-3 d-none" data-vp-list-empty>
            <div class="vp-empty vp-empty-inline">
                <i class="fas fa-filter"></i>
                <span>
                    <?= __('No correlation matches the filter you set.') ?>
                </span>
            </div>
        </div>

        <div class="px-3 py-2 border-top">
            <?php
            /*
             * The one pager on this page whose total is not the
             * section's own count. `matched` is what the *filter* left
             * before the cut, so with a narrowing active the line has
             * to say `(10,003 match)` — *"in total"* over the same
             * number claims the value has 10,003 neighbours when it
             * has 10,040, and the two disagree by exactly the rows the
             * filter dropped. Unfiltered the two are the same number,
             * and *"in total"* is then the true sentence.
             *
             * Either way it counts *values*, while the range beside it
             * counts the roll-up on screen — so it is named to the
             * value roll-up and goes away with it. On the event pane it
             * was reading `1–8 of 18 rows (10,040 in total)`, which is
             * two units on one line; each pane's heading carries its
             * own total, so nothing is lost by its absence.
             */
            ?>
            <?= $this->element('Values/View/value_pager', array(
                'size' => $co['page_size'],
                'shown' => count($valueRows),
                'total' => $co['matched'],
                'totalNote' => empty($active)
                    ? null
                    : sprintf(__('(%d match)'), $co['matched']),
                'totalGroup' => 'value',
                'noun' => array(
                    'one' => __('row'),
                    'many' => __('rows'),
                ),
            )) ?>
        </div>

    <?php endif; ?>

    <?php
    /*
     * §14.6, applied here by phase 24. This carried a `.vp-acl-note`
     * reading *"4 further correlations point into events you cannot
     * see. They are counted in the 31 and are not listed."* — a count
     * of the invisible, stated on a page whose URL takes any value the
     * reader types. Removed, along with the *"N of the M stored rows
     * are visible to you"* sentence above, which named the same number
     * by subtraction.
     */
    ?>


    <?php
    /*
     * ------------------------------------------------------------------
     * §10.2 — the labels on those events
     * ------------------------------------------------------------------
     * A third section in this element, beside the object siblings and
     * the co-occurrence table, and a section rather than more rows in
     * the table above it.
     *
     * §10.2 asked for one table over both — *"the same facets, ranks and
     * pager over all of it"* — and building it is what established that
     * only the pager is shareable, and that sharing it was the worst
     * part: merged, the first galaxy cluster on `Malicious` was on page
     * fourteen.
     *
     *   the **rank** counts different scopes. A value neighbour is
     *   counted over the events the attribute budget could read; a label
     *   over every event the value is in, because an event's tags cost
     *   one indexed read whatever its size. On `443` that is 38 against
     *   196, and one order over both put a hundred tags and no values on
     *   the page.
     *
     *   the **facets** do not apply. Five of the eight above describe a
     *   correlated attribute: a cluster has no MISP type, sits in no
     *   object and carries no warninglist verdict. Ticking one emptied
     *   the table of every cluster it had just counted — which is the
     *   control the note under the roll-up switch already calls *"a
     *   control that means nothing"*.
     *
     *   the **columns** do not apply. `Specific to this value` divides
     *   by a spread a label has none of.
     *
     * So this gets what the siblings above get: its own rows, its own
     * bar, its own pager, its own empty state. What it shares with the
     * table above is the fold and the scan behind it, which is where
     * sharing was actually worth having.
     *
     * **The bar is local**, like the sibling bar and unlike the value
     * table's: there is no narrowing endpoint behind these rows, so a
     * tick reaches the rows carried and `value_facet_group` greys an
     * entry none of them holds rather than offering a cut that could
     * only empty the table.
     * ------------------------------------------------------------------
     */
    ?>
    <?php if (!empty($labelRows)): ?>

        <div class="card shadow-sm mb-3 vp-panel vp-rel-k-co"
             style="--vp-panel-color: var(--vp-rel-co);"
             data-vp-rel-summary="labels"
             data-vp-rel-count="<?= h(number_format($labels['total'])) ?>"
             <?php if ($labelCapped): ?>
                 data-vp-rel-note="<?= h(sprintf(
                     __('%s listed'),
                     number_format(count($labelRows))
                 )) ?>"
             <?php endif; ?>>

        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('Labels in this neighbourhood'),
            'panelIcon' => 'misp-icon misp-icon-galaxy misp-simple',
            'panelColor' => 'var(--vp-rel-co)',
            'panelSub' => $labelHeaderSub,
        )) ?>

        <div data-vp-list>

            <?php
            /*
             * The wider scope belongs on the glyph, not in the line:
             * it matters only to a reader comparing this panel with the
             * one above, and that panel already states its own cut. The
             * section is named rather than called *the table above*,
             * which on a tab of seven tables names nothing.
             */
            $labelTip = __('A label sits on this value, on a neighbour'
                . ' or on the event itself — Attached to says which.');
            if ($labelScopeDiffers) {
                $labelSkipped = $labelScope - (int)$scan['events_read'];
                $labelTip .= ' ' . sprintf(
                    __n(
                        'All %1$d events are read here, including the'
                            . ' one In the same events could not afford'
                            . ' to open.',
                        'All %1$d events are read here, including the'
                            . ' %2$d In the same events could not afford'
                            . ' to open.',
                        $labelSkipped
                    ),
                    $labelScope,
                    $labelSkipped
                );
            }
            ?>
            <div class="vp-rel-cap">
                <i class="fas fa-circle-info"
                   title="<?= h($labelTip) ?>"></i>
                <span>
                    <?= sprintf(
                        __('Galaxy clusters and taxonomy tags across'
                            . ' %s.'),
                        '<strong>' . h(sprintf(
                            __n(
                                'the one event this value is in',
                                'all %d events this value is in',
                                $labelScope,
                                $labelScope
                            )
                        )) . '</strong>'
                    ) ?>
                </span>
            </div>

            <?php if ($labelCapped): ?>
                <div class="vp-rel-cap">
                    <i class="fas fa-filter"
                       title="<?= h(__(
                           'The bar below narrows the rows this table'
                           . ' holds, not the fold behind them.'
                       )) ?>"></i>
                    <span>
                        <?= sprintf(
                            __('%s, ranked by shared events.'),
                            '<strong>' . h(sprintf(
                                __('%1$s of %2$s are listed'),
                                number_format(count($labelRows)),
                                number_format($labels['total'])
                            )) . '</strong>'
                        ) ?>
                    </span>
                </div>
            <?php endif; ?>

            <div class="p-3 border-bottom d-flex flex-wrap gap-2
                        align-items-center">
                <span class="vp-subhead mb-0 me-1"><?= __('Narrow by') ?></span>

                <?php foreach ($labelFacetGroups as $group): ?>
                    <?php if (empty($labelFacets[$group['key']])) {
                        continue;
                    } ?>
                    <div class="dropdown">
                        <button type="button"
                                class="btn btn-sm btn-outline-secondary
                                       dropdown-toggle vp-rel-facet"
                                data-bs-toggle="dropdown"
                                data-bs-auto-close="outside"
                                aria-expanded="false">
                            <?= h($group['title']) ?>
                            <span class="badge text-bg-secondary ms-1">
                                <?= h(count($labelFacets[$group['key']])) ?>
                            </span>
                        </button>
                        <div class="dropdown-menu vp-rel-facetmenu p-2">
                            <?= $this->element(
                                'Values/View/value_facet_group',
                                array(
                                    'key' => $group['key'],
                                    'title' => $group['title'],
                                    'icon' => $group['icon'],
                                    'values' => $labelFacets[$group['key']],
                                    'local' => true,
                                )
                            ) ?>
                        </div>
                    </div>
                <?php endforeach; ?>

                <span class="small text-muted ms-auto"
                      data-vp-facet-summary>
                    <span class="vp-facet-summary-none">
                        <?= __('No filter applied') ?>
                    </span>
                    <span class="vp-facet-summary-some">
                        <span data-vp-facet-count-active>0</span>
                        <span data-vp-plural="filters"
                              data-vp-one="<?= h(__('filter')) ?>"
                              data-vp-many="<?= h(__('filters')) ?>"><?=
                            h(__('filters')) ?></span>
                        &middot;
                        <span data-vp-facet-rows><?=
                            h(count($labelRows)) ?></span>
                        <span data-vp-plural="rows"
                              data-vp-one="<?= h(__('row')) ?>"
                              data-vp-many="<?= h(__('rows')) ?>"><?=
                            h(__('rows')) ?></span>
                    </span>
                </span>

                <button type="button" class="btn btn-sm btn-link"
                        data-vp-facet-clear disabled>
                    <?= __('Reset') ?>
                </button>
            </div>

            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <thead>
                        <tr>
                            <?php
                            /*
                             * `Attached to` is a column and not only a
                             * mark on the name, because it is the one
                             * dimension here a reader sorts by: *show
                             * me what was said about this value* is a
                             * different question from *what was said
                             * about the reports it turned up in*.
                             */
                            $labelCols = array(
                                array('key' => 'label',
                                    'label' => __('Label')),
                                array('key' => 'family',
                                    'label' => __('Family')),
                                array('key' => 'attach',
                                    'label' => __('Attached to')),
                                array('key' => 'shared',
                                    'label' => __('Shared events'),
                                    'class' => 'vp-rel-num'),
                                array('key' => 'orgs',
                                    'label' => __('Organisations')),
                                array('key' => 'last',
                                    'label' => __('Last together')),
                                array('key' => 'distribution',
                                    'label' => __('Distribution')),
                            );
                            ?>
                            <?php foreach ($labelCols as $col): ?>
                                <th class="<?= h($col['class'] ?? '') ?>">
                                    <button type="button"
                                            class="vp-th-sort"
                                            data-vp-sort-col="<?=
                                                h($col['key']) ?>">
                                        <span class="sortable-header"><?=
                                            h($col['label'])
                                        ?><i class="sort-icon"></i></span>
                                    </button>
                                </th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($labelRows
                            as $labIndex => $row): ?>
                            <tr class="vp-rel-stripe vp-rel-k-co"
                                data-vp-facet="<?= h(implode(
                                    ' ',
                                    $row['tokens']
                                )) ?>"
                                data-vp-num="<?= h($numbers(
                                    $row['shared_events'],
                                    $row['last_together']
                                )) ?>"<?php /*
                                 * Both names, so the text filter finds
                                 * a cluster by what the row prints and
                                 * by the tag string a reader pasted out
                                 * of an event.
                                 */ ?>
                                data-vp-text="<?= h(mb_strtolower(
                                    $row['label'] === $row['value']
                                        ? $row['value']
                                        : $row['label'] . ' '
                                            . $row['value']
                                )) ?>"<?= $sortAttrs(array(
                                    'vp-sort-label' => mb_strtolower(
                                        $row['label']
                                    ),
                                    'vp-sort-family' => mb_strtolower(
                                        $row['family']
                                    ),
                                    /*
                                     * Tightest first when the column is
                                     * sorted ascending, which is the
                                     * order the word is a scale in —
                                     * the digit is what makes a string
                                     * compare agree with it.
                                     */
                                    'vp-sort-attach' => $attachSort($row),
                                    'vp-sort-shared' => $sortNum(
                                        $row['shared_events']
                                    ),
                                    'vp-sort-orgs' => $sortOrgs(
                                        $row['orgs'],
                                        count($row['orgs'])
                                    ),
                                    'vp-sort-last' => preg_replace(
                                        '/\D/',
                                        '',
                                        (string)$row['last_together']
                                    ),
                                    /*
                                     * The empty token on a row with no
                                     * audience to state, which the
                                     * comparator sorts last whichever
                                     * way the heading points — `0`
                                     * would claim the row was org-only.
                                     */
                                    'vp-sort-distribution' =>
                                        $row['distribution'] === null
                                            ? ''
                                            : $sortNum(
                                                $row['distribution']
                                            ),
                                ), $labIndex) ?>>
                                <td><?= $labelCell($row) ?></td>
                                <td><?= $labelFamilyCell($row) ?></td>
                                <td><?= $attachCell($row) ?></td>
                                <td><?= $weightBar(
                                    $row['shared_events'],
                                    $maxLabelShared
                                ) ?></td>
                                <td class="small">
                                    <?= h(implode(', ', $row['orgs'])) ?>
                                </td>
                                <td class="font-monospace text-nowrap
                                           small">
                                    <?= h($row['last_together']) ?>
                                </td>
                                <td><?= $distributionBadge($row) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="p-3 d-none" data-vp-list-empty>
                <div class="vp-empty vp-empty-inline">
                    <i class="fas fa-filter"></i>
                    <span>
                        <?= __('No label matches the filter you set.') ?>
                    </span>
                </div>
            </div>

            <div class="px-3 py-2 border-top">
                <?= $this->element('Values/View/value_pager', array(
                    'size' => $labels['page_size'],
                    'shown' => count($labelRows),
                    'total' => $labels['total'],
                    'noun' => array(
                        'one' => __('label'),
                        'many' => __('labels'),
                    ),
                )) ?>
            </div>

        </div>

        </div>

    <?php endif; ?>


</div>
