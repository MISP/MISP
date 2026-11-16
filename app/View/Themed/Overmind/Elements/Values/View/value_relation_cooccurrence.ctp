<?php
App::uses('ValueFieldKind', 'Tools/ValueIntelligence');
App::uses('ValueRelationTool', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('TagChipTool', 'Tools');
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
 * The specificity column's sort token, the rank's key exactly: shared
 * count, then the ratio, both zero-padded for the lexicographic compare.
 * An unread spread gives the empty token, which sorts last.
 *
 * @param int $shared Events shared with this value
 * @param int|null $spread The neighbour's own event count
 * @return string
 */
$specificSort = function ($shared, $spread) use ($sortNum) {
    if ($spread === null || (int)$spread < 1) {
        return '';
    }
    $shared = (int)$shared;
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
        ? ' data-vp-hc-value="' . h(ValueUrlTool::address($value)) . '"'
        : '';
};
$hoverClass = $hoverCardOn ? ' vp-hc-trigger' : '';

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
            'inline' => true,
        )
    );
}
unset($facet);

$valueRows = $co['rollups']['value']['rows'];
$eventRows = $co['rollups']['event']['rows'];
$objectRows = $co['rollups']['object']['rows'];
$hasRows = !empty($valueRows);


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
$labelByKind = $labels['by_kind'];

/*
 * Labels are read over every event the value is in, the value neighbours
 * over the events the attribute budget afforded; the header names the
 * wider scope.
 */
$labelScope = (int)$scan['events_seen'];

/*
 * Three tiers by how close a label sits to this value, then one line per
 * family (a galaxy, a taxonomy namespace, the free-text tags) in the
 * order the labels came: the profile's priorities, then shared events.
 */
$labelTiers = array(
    'value' => array(
        'title' => __('On this value'),
        'hint' => __('tagged on its own attributes'),
        'families' => array(),
        'count' => 0,
    ),
    'neighbour' => array(
        'title' => __('On values beside it'),
        'hint' => __('tagged on other attributes of the same events'),
        'families' => array(),
        'count' => 0,
    ),
    'event' => array(
        'title' => __('On the events'),
        'hint' => __('tagged on the events it sits in'),
        'families' => array(),
        'count' => 0,
    ),
);
foreach ($labelRows as $row) {
    $tier = isset($labelTiers[$row['attachment']])
        ? $row['attachment']
        : 'event';
    $family = $row['kind'] . '|' . $row['family'];
    if (!isset($labelTiers[$tier]['families'][$family])) {
        $labelTiers[$tier]['families'][$family] = array(
            'name' => $row['family'] === ''
                ? __('Free-text tags')
                : $row['family'],
            'rows' => array(),
        );
    }
    $labelTiers[$tier]['families'][$family]['rows'][] = $row;
    $labelTiers[$tier]['count']++;
}
$labelFold = 6;

/**
 * One label as MISP's own chip, the family's name left out where the
 * line already prints it, and how many of the value's events carry it,
 * on a bar against all of them.
 *
 * @param array $row
 * @return string
 */
$labelChip = function (array $row) use ($view, $labelScope) {
    $events = array_values($row['events']);
    $note = sprintf(
        __n('In event %s', 'In events %s', count($events)),
        '#' . implode(', #', $events)
    ) . "\n" . implode(', ', $row['orgs'])
        . ($row['last_together'] === ''
            ? ''
            : ' · ' . sprintf(__('last together %s'), $row['last_together']));
    $noteFn = function () use ($note) {
        return $note;
    };
    if ($row['kind'] === ValueRelationTool::KIND_CLUSTER) {
        $cluster = isset($row['cluster']['GalaxyCluster'])
            ? $row['cluster']['GalaxyCluster']
            : array();
        $chip = $view->TagChip->cluster(array(
            'id' => $cluster['id'] ?? null,
            'value' => $row['label'],
            'galaxy' => $row['family'],
        ), array('display' => 'leaf', 'note' => $noteFn));
    } elseif (empty($row['tag'])) {
        $chip = '<span class="vp-rel-cell">' . h($row['label']) . '</span>';
    } else {
        // A namespace's value alone; a predicate stays, the line does not
        // print it.
        $parsed = TagChipTool::parse((string)$row['tag']['name']);
        $chip = $view->TagChip->chip(array(
            'Tag' => $row['tag'],
            'local' => !empty($row['tag']['local']),
        ), array(
            'display' => $parsed['namespace'] !== null && empty($parsed['above'])
                ? 'leaf'
                : 'full',
            'inline' => true,
            'note' => $noteFn,
        ));
    }
    if ($labelScope < 2) {
        return $chip;
    }
    $count = (int)$row['shared_events'];
    return $chip . '<span class="vp-lab-cov" title="' . h(sprintf(
            __('In %1$s of its %2$s events'),
            number_format($count),
            number_format($labelScope)
        )) . '"><span class="vp-lab-cov-bar"><i style="width: '
        . min(100, round(100 * $count / $labelScope, 1)) . '%;"></i></span>'
        . '<span><strong>' . h(number_format($count)) . '</strong>/'
        . h(number_format($labelScope)) . '</span></span>';
};
// Neighbours on a warninglist, counted over the whole fold.
$listsHit = isset($co['warninglists_listed'])
    ? (int)$co['warninglists_listed']
    : 0;
/*
 * The three groupings as tabs, each with its own count, and the rank as
 * a switch beside the search. **Most specific** is offered only where the
 * spread was read: a rank by a number nobody fetched would look like a
 * bug.
 */
$groupTabs = array(
    'value' => array(__('Values'), (int)$co['distinct_values']),
    'event' => array(__('Events'), (int)$co['rollups']['event']['total']),
    'object' => array(__('Objects'), (int)$co['rollups']['object']['total']),
);
$rankPills = array(
    'shared' => __('Most shared'),
    'recent' => __('Most recent'),
);
if ($spreadRead) {
    $rankPills['specific'] = __('Most specific');
}
$rankPhrase = __('ranked by shared events');
if ($co['rank'] === 'recent') {
    $rankPhrase = __('ranked by when they last appeared together');
} elseif ($co['rank'] === 'specific') {
    $rankPhrase = __('ranked by how specific each is to this value');
}

$eventPeeks = isset($co['event_peeks']) ? $co['event_peeks'] : array();

/**
 * An event as the indexes name it: its id, and its preview.
 *
 * @param int $eventId
 * @return string
 */
$eventRef = function ($eventId) use ($view, $eventPeeks) {
    $event = isset($eventPeeks[(int)$eventId])
        ? $eventPeeks[(int)$eventId]
        : array('id' => (int)$eventId);
    return $view->element('Attributes/event_ref', array('event' => $event));
};

/**
 * Who reported a value: one organisation by tile and name, several by
 * their tiles, three at most and the rest counted.
 *
 * @param array $list [['id' =>, 'name' =>], …]
 * @return string
 */
$orgCell = function (array $list) use ($view) {
    if (count($list) === 1) {
        return $view->element('Values/View/value_org_link',
            array('org' => $list[0], 'small' => true));
    }
    $out = '<span class="vp-co-orgs">';
    foreach (array_slice($list, 0, 3) as $org) {
        $out .= $view->element('Values/View/value_org_link',
            array('org' => $org, 'bare' => true));
    }
    $rest = array_slice($list, 3);
    if (!empty($rest)) {
        $out .= '<span class="vp-co-more" title="' . h(implode(', ',
            array_column($rest, 'name'))) . '">+' . count($rest) . '</span>';
    }
    return $out . '</span>';
};

/**
 * How specific a value is to this one: a meter and its sentence.
 *
 * @param array $row
 * @return string
 */
$withCell = function (array $row) use ($specificRead) {
    $spread = $row['spread'] ?? null;
    $read = $specificRead($row['shared_events'], $spread, 'event',
        !empty($row['spread_least']));
    if ($read === '') {
        return '';
    }
    $share = $spread > 0
        ? min(100, max(3, round(100 * $row['shared_events'] / $spread)))
        : 0;
    return '<span class="vp-sib-with"><span class="vp-sib-meter"><i style="'
        . 'width: ' . h($share) . '%;"></i></span><span>' . h($read)
        . '</span></span>';
};

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
        <?= h(sprintf(
            __('%1$s in %2$s'),
            __n('%s other value', '%s other values',
                (int)$co['distinct_values'],
                number_format($co['distinct_values'])),
            __n('%s event', '%s events', (int)$co['events'],
                number_format($co['events']))
        )) ?>
    <?php else: ?>
        <?= h(__('No other value')) ?>
    <?php endif; ?>
    &nbsp;·&nbsp;<span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
        h(__('Machine-derived')) ?></span>
<?php
$headerSub = ob_get_clean();
?>
    <?= $this->element('Values/View/value_relation_siblings', array(
        'siblings' => $siblings,
        'specificRead' => $specificRead,
    )) ?>

<?php
/*
 * The "In the same events" card. Three tabs over one list — the values
 * these events share with this one, the events, the objects in them —
 * each drawn as its index draws it.
 *
 * `vp-narrow-url`: the value rows are the top `row_cap` of the fold, so
 * a narrowing the browser cannot prove complete goes back to the fold
 * rather than emptying a table that only lost its cut. `vp-narrow-cut`
 * is measured against the neighbourhood, never against the narrowing
 * that produced this page.
 */
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
$objectHead = '<thead><tr><th>' . h(__('Value')) . '</th><th>'
    . h(__('Category')) . '</th><th>' . h(__('Type')) . '</th>'
    . '<th class="text-center">' . h(__('IDS')) . '</th></tr></thead>';
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
     data-vp-rel-summary="cooccurrence"
     data-vp-rel-count="<?= $co['suppressed']
         ? "\u{2014}"
         : h(number_format($co['distinct_values'])) ?>"
     <?= $co['suppressed']
         ? 'data-vp-rel-note="' . h(__('not read')) . '"'
         : '' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('In the same events'),
        'panelIcon' => 'fas fa-link',
        'panelColor' => 'var(--vp-rel-co)',
        'panelSub' => $headerSub,
    )) ?>

    <?php if ($co['suppressed']): ?>
        <?php // Not an empty state: there is a neighbourhood, in events too large to say anything about this value. ?>
        <div class="vp-suppressed">
            <i class="fas fa-circle-exclamation"></i>
            <div>
                <span class="vp-suppressed-badge"><?= __('Too large to read') ?></span>
                <div class="mt-2">
                    <?= sprintf(
                        __('%1$s holds more than %2$s attributes. In an event that size every value co-occurs with'
                            . ' every other, so a neighbour list drawn from one would describe the event rather than'
                            . ' this value — and this panel does not draw one.'),
                        '<strong>' . h(__n(
                            'The one event this value appears in',
                            'Every one of the %d events this value appears in',
                            $scan['events_seen'],
                            $scan['events_seen']
                        )) . '</strong>',
                        '<strong>' . h(number_format($scan['size_cap'])) . '</strong>'
                    ) ?>
                </div>
                <div class="mt-2">
                    <?= h(__('Nothing is hidden and nothing is missing. The objects in the card above sit in those'
                        . ' same events and are listed in full — an object does not get larger because the event'
                        . ' around it did.')) ?>
                </div>
            </div>
        </div>
    <?php elseif (!$hasRows): ?>
        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-link"></i>
                <span><?= __('Nothing else in the events this value is in.') ?></span>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($hasRows): ?>

        <ul class="nav ov-view-tabs is-inline vp-co-tabs" role="tablist"
            data-vp-group data-vp-value="value" aria-label="<?= h(__('Group by')) ?>"
            style="--ov-view-tab-accent: var(--vp-rel-co); --ov-view-tab-accent-bg: color-mix(in srgb, var(--vp-rel-co) 14%, transparent);">
            <?php foreach ($groupTabs as $key => $tab): ?>
                <?php if ($key !== 'value' && $tab[1] === 0) {
                    continue;
                } ?>
                <li class="nav-item" role="presentation">
                    <button type="button" role="tab" class="nav-view nav-link<?= $key === 'value' ? ' active' : '' ?>"
                            data-vp-pill="<?= h($key) ?>" aria-pressed="<?= $key === 'value' ? 'true' : 'false' ?>">
                        <?= h($tab[0]) ?>
                        <span class="ov-tab-count"><?= h(number_format($tab[1])) ?></span>
                    </button>
                </li>
            <?php endforeach; ?>
        </ul>

        <?php // Outside the row host: a filter that empties the table must not take its controls with it. ?>
        <div class="vp-co-bar" data-vp-group-only="value">
            <div class="input-group input-group-sm vp-card-search">
                <span class="input-group-text"><i class="fas fa-magnifying-glass" aria-hidden="true"></i></span>
                <input type="search" class="form-control" data-vp-filter-text autocomplete="off"
                       value="<?= h(isset($active['text']) ? $active['text'] : '') ?>"
                       aria-label="<?= h(__('Search the values')) ?>"
                       placeholder="<?= h(sprintf(__('Search the %s values…'), number_format($co['distinct_values']))) ?>">
            </div>

            <div class="btn-group btn-group-sm vp-co-rank" role="group" aria-label="<?= h(__('Rank by')) ?>"
                 data-vp-sort data-vp-value="<?= h($co['rank']) ?>">
                <?php foreach ($rankPills as $key => $label): ?>
                    <button type="button" class="btn btn-outline-secondary<?= $key === $co['rank'] ? ' active' : '' ?>"
                            data-vp-pill="<?= h($key) ?>" aria-pressed="<?= $key === $co['rank'] ? 'true' : 'false' ?>">
                        <?= h($label) ?>
                    </button>
                <?php endforeach; ?>
            </div>

            <div class="dropdown">
                <button type="button" class="btn btn-sm btn-outline-secondary vp-co-filters-btn"
                        data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false"
                        data-vp-facet-summary>
                    <i class="fas fa-filter" aria-hidden="true"></i>
                    <?= __('Filters') ?>
                    <span class="vp-facet-summary-some vp-co-filters-n" data-vp-facet-count-active>0</span>
                </button>
                <div class="dropdown-menu vp-co-filters">
                    <div class="vp-co-filters-grid">
                        <?php foreach ($facetGroups as $group): ?>
                            <?php if (empty($facets[$group['key']])) {
                                continue;
                            } ?>
                            <div class="vp-co-filters-group">
                                <?= $this->element('Values/View/value_facet_group', array(
                                    'key' => $group['key'],
                                    'title' => $group['title'],
                                    'icon' => $group['icon'],
                                    'values' => $facets[$group['key']],
                                    'active' => $activeFacet($group['key']),
                                    'limit' => 6,
                                )) ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <div class="vp-co-filters-foot">
                        <select class="form-select form-select-sm w-auto" data-vp-filter-key="category"
                                aria-label="<?= __('Category') ?>">
                            <option value=""><?= __('Any category') ?></option>
                            <?php foreach ($co['categories'] as $category): ?>
                                <option value="<?= h($slug($category)) ?>"<?=
                                    isset($activeSelects['category']) && $activeSelects['category'] === $slug($category)
                                        ? ' selected' : '' ?>><?= h($category) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="input-group input-group-sm vp-co-min">
                            <span class="input-group-text"><?= __('Shared events') ?> &ge;</span>
                            <input type="number" class="form-control" min="1"
                                   value="<?= h(isset($active['min_shared']) ? (int)$active['min_shared'] : 1) ?>"
                                   data-vp-filter-min="shared" aria-label="<?= __('Minimum shared events') ?>">
                        </div>
                        <div class="form-check form-switch mb-0">
                            <input class="form-check-input" type="checkbox" role="switch" id="vp-rel-siblings-only"
                                   data-vp-facet-key="sibling" value="yes"<?=
                                in_array('yes', $activeFacet('sibling'), true) ? ' checked' : '' ?>>
                            <label class="form-check-label small" for="vp-rel-siblings-only"
                                   title="<?= h(__('Values recorded in an object of a template this value also sits in')) ?>">
                                <?= __('Same object template only') ?>
                            </label>
                        </div>
                        <button type="button" class="btn btn-sm btn-link ms-auto" data-vp-facet-clear disabled>
                            <?= __('Reset') ?>
                        </button>
                    </div>
                    <div class="vp-co-filters-note">
                        <?= h(sprintf(
                            __('Counts are folded from all %s rows read, not from the page.'),
                            number_format($scan['rows_read'])
                        )) ?>
                    </div>
                </div>
            </div>

            <span class="vp-co-count">
                <strong data-vp-list-shown><?= h(number_format(count($valueRows))) ?></strong>
                <?= h(sprintf(__('of %s values'), number_format($co['distinct_values']))) ?>
                · <?= h($rankPhrase) ?>
                <?php if ($listsHit > 0): ?>
                    · <span title="<?= h(sprintf(
                        __('Checked against %d enabled lists. The Warninglist filter keeps or drops them; the ranking'
                            . ' does not account for them.'),
                        (int)($co['warninglists_checked'] ?? 0)
                    )) ?>"><?= h(sprintf(__('%s on a warninglist, dimmed'), number_format($listsHit))) ?></span>
                <?php endif; ?>
            </span>
        </div>

        <div data-vp-list-rows>

            <div data-vp-group-pane="value">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0 ix-table vp-co-table">
                        <thead>
                            <tr>
                                <?php
                                $valCols = array(
                                    array('key' => 'value', 'label' => __('Value')),
                                    array('key' => 'shared', 'label' => __('Together in')),
                                    array('key' => 'specific', 'label' => __('With this value'), 'only' => $spreadRead),
                                    array('key' => 'orgs', 'label' => __('Reported by')),
                                    array('key' => 'last', 'label' => __('Last together')),
                                );
                                ?>
                                <?php foreach ($valCols as $col): ?>
                                    <?php if (array_key_exists('only', $col) && !$col['only']) {
                                        continue;
                                    } ?>
                                    <th>
                                        <button type="button" class="vp-th-sort" data-vp-sort-col="<?= h($col['key']) ?>">
                                            <span class="sortable-header"><?= h($col['label']) ?><i class="sort-icon"></i></span>
                                        </button>
                                    </th>
                                <?php endforeach; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($valueRows as $valIndex => $row): ?>
                                <?php
                                $rowEvents = array_values($row['events']);
                                $moreEvents = array_slice($rowEvents, 3);
                                ?>
                                <tr data-vp-list-row data-vp-group="value"
                                    class="<?= $row['shared_events'] > 1 ? 'vp-co-recur' : '' ?>"
                                    data-vp-facet="<?= h(implode(' ', $row['tokens'])) ?>"
                                    data-vp-num="<?= h($numbers($row['shared_events'], $row['last_together'])) ?>"
                                    data-vp-text="<?= h(mb_strtolower($row['value'])) ?>"<?= $sortAttrs(array(
                                        'vp-sort-value' => mb_strtolower($row['value']),
                                        'vp-sort-shared' => $sortNum($row['shared_events']),
                                        'vp-sort-specific' => $specificSort($row['shared_events'], $row['spread'] ?? null),
                                        'vp-sort-orgs' => $sortOrgs($row['orgs'], count($row['orgs'])),
                                        'vp-sort-last' => preg_replace('/\D/', '', (string)$row['last_together']),
                                    ), $valIndex) ?>>
                                    <td class="vp-co-valcell">
                                        <div class="vp-co-val">
                                            <span class="vp-rel-cell font-monospace<?= empty($row['warninglists']) ? '' : ' vp-rel-listed'
                                                ?><?= $hoverClass ?>"<?= $hoverCard($row['value']) ?> title="<?= h($row['value']) ?>"><?= h($row['value']) ?></span><?=
                                                $listedMark($row['warninglists'] ?? array()) ?>
                                            <?= $this->element('genericElementsBS5/Badges/type', array('type' => $row['type'])) ?>
                                            <?php if (!empty($row['ids'])): ?>
                                                <?= $this->element('genericElementsBS5/IndexTable/Fields/ids', array(
                                                    'row' => array('to_ids' => true),
                                                    'field' => array('data_path' => 'to_ids', 'readonly' => true),
                                                )) ?>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="vp-co-events">
                                            <?php foreach (array_slice($rowEvents, 0, 3) as $eventId): ?>
                                                <?= $eventRef($eventId) ?>
                                            <?php endforeach; ?>
                                            <?php if (!empty($moreEvents)): ?>
                                                <span class="vp-co-more" title="<?= h('#' . implode(', #', $moreEvents)) ?>">+<?= count($moreEvents) ?></span>
                                            <?php endif; ?>
                                        </span>
                                    </td>
                                    <?php if ($spreadRead): ?>
                                        <td class="text-nowrap"><?= $withCell($row) ?></td>
                                    <?php endif; ?>
                                    <td><?= $orgCell($row['org_list'] ?? array()) ?></td>
                                    <td class="vp-co-date"><?= h($row['last_together']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div data-vp-group-pane="event" class="d-none">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0 ix-table vp-co-table">
                        <thead>
                            <tr>
                                <th><?= __('Event') ?></th>
                                <th><?= __('Creator org') ?></th>
                                <th><?= __('Date') ?></th>
                                <th class="text-end"><?= __('Other values') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($eventRows as $row): ?>
                                <?php $event = $eventPeeks[(int)$row['event']['id']] ?? $row['event']; ?>
                                <tr data-vp-list-row data-vp-group="event"
                                    data-vp-num="<?= h($numbers($row['shared_values'], $row['event']['date'])) ?>">
                                    <td class="vp-co-eventcell">
                                        <div class="vp-co-event">
                                            <?= $this->element('Attributes/event_ref', array('event' => $event)) ?>
                                            <?= $this->element('genericElementsBS5/Badges/distribution', array(
                                                'distribution' => (int)$row['distribution'],
                                                'full' => false,
                                            )) ?>
                                            <a class="vp-co-event-info" href="<?= h($baseurl . '/events/view/' . (int)$row['event']['id']) ?>"
                                               title="<?= h($row['event']['info']) ?>"><?= h($row['event']['info']) ?></a>
                                        </div>
                                    </td>
                                    <td>
                                        <?= $this->element('Values/View/value_org_link', array(
                                            'org' => array('id' => $row['org_id'] ?? 0, 'name' => $row['org']),
                                            'small' => true,
                                        )) ?>
                                    </td>
                                    <td class="vp-co-date"><?= h($row['event']['date']) ?></td>
                                    <td class="text-end vp-co-n"><?= h(number_format($row['shared_values'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <div data-vp-group-pane="object" class="d-none">
                <div class="table-responsive">
                    <table class="table align-middle mb-0 ix-table oi-table vp-co-table">
                        <thead>
                            <tr>
                                <th><?= __('Object') ?></th>
                                <th><?= __('Event') ?></th>
                                <th><?= __('Creator org') ?></th>
                            </tr>
                        </thead>
                        <?php foreach ($objectRows as $row): ?>
                            <?php
                            $object = $row['object'];
                            $attributes = $row['attributes'] ?? array();
                            $first = empty($attributes) ? null : $attributes[0];
                            ?>
                            <tbody data-vp-list-row data-vp-group="object" data-vp-obj
                                   data-vp-num="shared:<?= (int)$row['values'] ?> recent:0">
                                <tr>
                                    <td class="oi-col-object">
                                        <div class="oi-object">
                                            <button type="button" class="oi-expand" data-vp-obj-disc aria-expanded="false"
                                                    title="<?= h(__('Show its attributes')) ?>">
                                                <i class="fas fa-chevron-right" aria-hidden="true"></i>
                                            </button>
                                            <?= $this->element('Objects/object_header', array(
                                                'object' => $object,
                                                'ctx' => array(
                                                    'count' => count($attributes),
                                                    'deleted' => false,
                                                    'firstValue' => $first === null ? '' : (string)$first['value'],
                                                    'firstRelation' => $first === null ? '' : (string)$first['relation'],
                                                ),
                                            )) ?>
                                        </div>
                                        <?= $this->element('genericElementsBS5/Badges/comment', array(
                                            'comment' => $object['comment'] ?? '',
                                            'class' => 'oi-comment',
                                        )) ?>
                                    </td>
                                    <td class="oi-col-event"><?= $eventRef($row['event']) ?></td>
                                    <td class="oi-col-org">
                                        <?= $this->element('Values/View/value_org_link', array(
                                            'org' => array('id' => $row['org_id'] ?? 0, 'name' => $row['org']),
                                            'small' => true,
                                        )) ?>
                                    </td>
                                </tr>
                                <tr class="oi-detail d-none" data-vp-obj-fold>
                                    <td colspan="3">
                                        <div class="oi-card">
                                            <table class="table table-hover align-middle mb-0 ix-table">
                                                <?= $objectHead ?>
                                                <tbody>
                                                    <?php foreach ($attributes as $attribute): ?>
                                                        <tr>
                                                            <td class="text-break">
                                                                <?= $this->element('genericElementsBS5/IndexTable/Fields/attribute_value', array(
                                                                    'row' => array('Attribute' => $attribute + array(
                                                                        'object_relation' => $attribute['relation'],
                                                                    )),
                                                                    'field' => array('data_path' => 'Attribute'),
                                                                )) ?>
                                                            </td>
                                                            <td>
                                                                <div class="d-flex align-items-center gap-1">
                                                                    <?= $this->element('genericElementsBS5/Badges/category', array(
                                                                        'category' => $attribute['category'],
                                                                        'full' => $attribute['relation'] !== '',
                                                                    )) ?>
                                                                    <?= $this->element('genericElementsBS5/Badges/object_relation', array(
                                                                        'relation' => $attribute['relation'],
                                                                    )) ?>
                                                                </div>
                                                            </td>
                                                            <td><?= $this->element('genericElementsBS5/Badges/type', array('type' => $attribute['type'])) ?></td>
                                                            <td class="text-center">
                                                                <?= $this->element('genericElementsBS5/IndexTable/Fields/ids', array(
                                                                    'row' => $attribute,
                                                                    'field' => array('data_path' => 'to_ids', 'readonly' => true),
                                                                )) ?>
                                                            </td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        <?php endforeach; ?>
                    </table>
                </div>
            </div>

        </div>

        <div class="p-3 d-none" data-vp-list-empty>
            <div class="vp-empty vp-empty-inline">
                <i class="fas fa-filter"></i>
                <span><?= __('No value matches the filter you set.') ?></span>
            </div>
        </div>

        <div class="vp-co-foot">
            <?php // `matched` is what the filter left before the cut, so a narrowed page says "match", not "in total". ?>
            <?= $this->element('Values/View/value_pager', array(
                'size' => $co['page_size'],
                'shown' => count($valueRows),
                'total' => $co['matched'],
                'totalNote' => empty($active) ? null : sprintf(__('(%d match)'), $co['matched']),
                'totalGroup' => 'value',
                'noun' => array('one' => __('row'), 'many' => __('rows')),
            )) ?>
            <div class="vp-co-scan">
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <span>
                    <?= h(sprintf(
                        __('Read from %1$s, newest first · %2$s'),
                        $scanScope,
                        __n('%s row', '%s rows', $scan['rows_read'], number_format($scan['rows_read']))
                    )) ?>
                    <?php if (!empty($scan['events_unread'])): ?>
                        · <?= h(sprintf(
                            __n('%1$d more event past the budget of %2$s rows', '%1$d more events past the budget of %2$s rows',
                                $scan['events_unread']),
                            $scan['events_unread'],
                            number_format($scan['budget'])
                        )) ?>
                    <?php endif; ?>
                    <?php if (!empty($scan['events_oversized'])): ?>
                        · <?= h(sprintf(
                            __n('%1$d event left out for holding more than %2$s attributes',
                                '%1$d events left out for holding more than %2$s attributes each',
                                $scan['events_oversized']),
                            $scan['events_oversized'],
                            number_format($scan['size_cap'])
                        )) ?>
                    <?php endif; ?>
                    · <?= $this->element('Values/View/value_read_age', array(
                        'readAt' => isset($scan['read_at']) ? (int)$scan['read_at'] : 0,
                    )) ?>
                </span>
                <button type="button" class="btn btn-sm btn-link p-0 align-baseline vp-rel-again" data-vp-narrow-fresh>
                    <i class="fas fa-rotate me-1"></i><?= __('Scan again') ?>
                </button>
            </div>
        </div>

    <?php endif; ?>
</div>

<?php
/*
 * The labels on this value, on the values beside it and on its events:
 * galaxy clusters and taxonomy tags, read over every event the value is
 * in. Its own card and its own filtering (value-intelligence.js
 * `refreshLabels`): the facets of the values above do not apply to a
 * label.
 */
?>
<?php if (!empty($labelRows)): ?>
    <?php
    $labelTally = array();
    if (!empty($labelByKind['cluster'])) {
        $labelTally[] = __n('%s cluster', '%s clusters', $labelByKind['cluster'],
            number_format($labelByKind['cluster']));
    }
    if (!empty($labelByKind['tag'])) {
        $labelTally[] = __n('%s tag', '%s tags', $labelByKind['tag'],
            number_format($labelByKind['tag']));
    }
    $labelSub = '<span class="vp-rel-tag me-1"><i class="misp-icon misp-icon-galaxy misp-simple"></i>'
        . h(__('Labels')) . '</span>'
        . h(sprintf(
            __('%1$s across %2$s'),
            implode(' · ', $labelTally),
            __n('its only event', 'its %s events', $labelScope, number_format($labelScope))
        ));
    if ($labelTiers['value']['count'] > 0) {
        $labelSub .= ' · <strong class="vp-lab-own">' . h(sprintf(
            __('%s on this value'),
            number_format($labelTiers['value']['count'])
        )) . '</strong>';
    }
    if ($labelCapped) {
        $labelSub .= ' · ' . h(sprintf(
            __('the first %1$s of %2$s'),
            number_format(count($labelRows)),
            number_format($labels['total'])
        ));
    }
    $labelSub .= ' · <span class="vp-rel-prov"><i class="fas fa-tag"></i>' . h(__('Tagged')) . '</span>';

    $labelTools = '<div class="vp-lab-tools">'
        . '<div class="input-group input-group-sm vp-card-search">'
        . '<span class="input-group-text"><i class="fas fa-magnifying-glass" aria-hidden="true"></i></span>'
        . '<input type="search" class="form-control" data-vp-lab-filter autocomplete="off"'
        . ' placeholder="' . h(__('Find a label…')) . '" aria-label="' . h(__('Find a label')) . '"></div>';
    if (!empty($labelByKind['cluster']) && !empty($labelByKind['tag'])) {
        $labelTools .= '<div class="vp-seg" role="group" aria-label="' . h(__('Kind')) . '">';
        foreach (array('all' => __('All'), 'cluster' => __('Clusters'), 'tag' => __('Tags')) as $key => $text) {
            $labelTools .= '<button type="button" class="vp-seg-btn' . ($key === 'all' ? ' active' : '') . '"'
                . ' data-vp-lab-kind-btn="' . h($key) . '" aria-pressed="' . ($key === 'all' ? 'true' : 'false') . '">'
                . h($text) . '</button>';
        }
        $labelTools .= '</div>';
    }
    $labelTools .= '</div>';
    ?>
    <div class="card shadow-sm mb-3 vp-panel vp-rel-k-co"
         style="--vp-panel-color: var(--vp-rel-co);"
         data-vp-lab-card
         data-vp-rel-summary="labels"
         data-vp-rel-count="<?= h(number_format($labels['total'])) ?>"
         <?= $labelCapped
             ? 'data-vp-rel-note="' . h(sprintf(__('%s listed'), number_format(count($labelRows)))) . '"'
             : '' ?>>

        <?= $this->element('Values/View/value_panel_header', array(
            'panelTitle' => __('Labels in this neighbourhood'),
            'panelIcon' => 'misp-icon misp-icon-galaxy misp-simple',
            'panelColor' => 'var(--vp-rel-co)',
            'panelSub' => $labelSub,
            'panelExtra' => $labelTools,
        )) ?>

        <?php foreach ($labelTiers as $tierKey => $tier): ?>
            <?php if (empty($tier['families'])) {
                continue;
            } ?>
            <section class="vp-lab-tier is-<?= h($tierKey) ?>" data-vp-lab-tier>
                <div class="vp-lab-tier-h">
                    <strong><?= h($tier['title']) ?></strong>
                    <span><?= h(number_format($tier['count'])) ?> · <?= h($tier['hint']) ?></span>
                </div>
                <?php foreach ($tier['families'] as $family): ?>
                    <?php $folded = count($family['rows']) - $labelFold; ?>
                    <div class="vp-lab-fam" data-vp-lab-fam>
                        <div class="vp-lab-fam-name" title="<?= h($family['name']) ?>">
                            <?= h($family['name']) ?>
                            <span><?= h(count($family['rows'])) ?></span>
                        </div>
                        <div class="vp-lab-chips">
                            <?php foreach ($family['rows'] as $at => $row): ?>
                                <span class="vp-lab<?= $at >= $labelFold ? ' is-folded d-none' : '' ?>" data-vp-lab
                                      data-vp-lab-kind="<?= h($row['kind']) ?>"
                                      data-vp-lab-text="<?= h(mb_strtolower($family['name'] . ' ' . $row['label']
                                          . ($row['label'] === $row['value'] ? '' : ' ' . $row['value']))) ?>"><?=
                                    $labelChip($row) ?></span>
                            <?php endforeach; ?>
                            <?php if ($folded > 0): ?>
                                <button type="button" class="vp-lab-more" data-vp-lab-more
                                        data-vp-lab-more-label="<?= h(__('+%d more')) ?>"><?= h(sprintf(__('+%d more'), $folded)) ?></button>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </section>
        <?php endforeach; ?>

        <div class="p-3 d-none" data-vp-lab-empty>
            <div class="vp-empty vp-empty-inline">
                <i class="fas fa-filter" aria-hidden="true"></i>
                <span><?= __('No label matches.') ?></span>
            </div>
        </div>
    </div>
<?php endif; ?>
