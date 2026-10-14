<?php
/**
 * Value Intelligence — the page whose subject is one value rather than one
 * event. The frame renders here; every panel is lazily loaded.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

/*
 * Chart.js is loaded once here rather than per fragment: several panels
 * draw curves, and a lazily-injected fragment cannot be trusted to be
 * the first one to need it. The panels poll for the global instead of
 * assuming it has arrived.
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array(
        'value-palette', 'value-widgets', 'misp-brush', 'misp-matrix',
        'org-tile', 'tile-drawer', 'value-intelligence',
    ),
    'js' => array(
        'Chart.min', 'misp-brush', 'misp-matrix', 'tile-drawer',
        'value-intelligence',
    ),
));

$profile = $valueIntelligence;

/*
 * ------------------------------------------------------------------
 * Banner
 * ------------------------------------------------------------------
 * The value itself, monospace and selectable, followed by one chip per
 * MISP type it appears as. Values are stored refanged, so there is no
 * defanged form to toggle to.
 */
$titleHtml = '<span class="vp-value font-monospace user-select-all">'
    . h($profile['value']) . '</span>';

/*
 * A button, not a label: pressing one narrows the occurrence table to
 * that type, and pressing it again lets it go. The slug is what the
 * table's rows carry, since a MISP type can hold characters a class
 * name cannot — `domain|ip`.
 */
foreach ($profile['types'] as $type) {
    $slug = preg_replace('/[^a-z0-9]+/', '-', strtolower($type['type']));
    $titleHtml .= '<button type="button" class="vp-type-chip"'
        . ' data-vp-type="' . h($type['type']) . '"'
        . ' data-vp-type-slug="' . h($slug) . '"'
        . ' aria-pressed="false" title="'
        . h(sprintf(
            __('%s — show only these rows in the occurrence table'),
            __n(
                '%1$s occurrence of type %2$s',
                '%1$s occurrences of type %2$s',
                $type['count'],
                $type['count'],
                $type['type']
            )
        )) . '">'
        . '<span class="vp-type-chip-name">' . h($type['type']) . '</span>'
        . '<span class="vp-type-chip-count">' . h($type['count'])
        . '</span></button>';
}

foreach ($profile['warninglists'] as $warninglist) {
    $titleHtml .= '<span class="vp-warninglist-chip" title="'
        . h($warninglist['name']) . '">'
        . '<i class="fas fa-exclamation-triangle"></i>'
        . h(__('Warninglist hit')) . '</span>';
}

$description = null;
if (!empty($profile['value2_note'])) {
    $description = h($profile['value2_note']);
}

/*
 * ------------------------------------------------------------------
 * Header actions
 * ------------------------------------------------------------------
 * Everything on this page that would write is rendered visibly disabled
 * rather than silently dead. Grouping is switched off so each control
 * keeps its own button: folding the writes behind a caret would hide
 * what the page deliberately shows as unavailable.
 */
$noWrites = __(
    'Disabled in this pass — the Value Intelligence page does not write to'
    . ' the database yet.'
);

$headerActions = array(
    array(
        'type' => 'navigate',
        'label' => __('Add sighting'),
        'icon' => 'eye',
        'class' => 'btn btn-primary disabled',
        'title' => $noWrites,
    ),
    /*
     * *Enrich* was here, and it was the last of these four that could
     * still be called an honest placeholder. The other three name
     * writes this page does not make; that one named a capability the
     * page now has in two places — the Enrichment tab runs any module
     * a reader may ask for, and the Overview panel draws what they
     * said. A disabled control for something the page does is not a
     * promise, it is a wrong answer.
     */
    $this->Acl->canAccess('collectionElements', 'addElementToCollection')
        ? array(
            'type' => 'modal',
            'label' => __('Add to collection'),
            'icon' => 'folder-plus',
            'class' => 'btn btn-outline-dark',
            'url' => $baseurl . '/collectionElements/addElementToCollection/Value/' . $valueB64,
            'size' => 'xl',
        )
        : array(
            'type' => 'navigate',
            'label' => __('Add to collection'),
            'icon' => 'folder-plus',
            'class' => 'btn btn-outline-dark disabled',
            'title' => __('Your role does not allow adding to collections.'),
        ),
    $this->Acl->canAccess('analystGraphs', 'addNodes')
        ? array(
            'type' => 'navigate',
            'label' => __('Add to graph'),
            'icon' => 'circle-nodes',
            'class' => 'btn btn-outline-dark',
            'attributes' => array('data-intel-graph-add' => json_encode(array(array(
                'type' => 'Value', 'value' => $profile['value'], 'label' => $profile['value'],
            )))),
        )
        : null,
);
$headerActions = array_values(array_filter($headerActions));

$this->set('headerTitleHtml', $titleHtml);
$this->set('headerBreadcrumb', array(
    array('label' => __('Values'),
        'url' => array('controller' => 'values', 'action' => 'index')),
    __('Value Intelligence'),
));
$this->set('headerDescription', $description);
$this->set('headerActions', $headerActions);
$this->set('headerActionGroups', array('navigate' => array('mode' => 'none')));

echo $this->element('Values/View/value_fact_strip', array(
    'facts' => $profile['facts'],
));

/*
 * ------------------------------------------------------------------
 * The pivot rail was here, and phase 29 withdrew it
 * ------------------------------------------------------------------
 * Five chips — containing CIDR, ASN, geolocation, ports seen, passive
 * DNS — none of which MISP stores for a value. Every one is an
 * enrichment answer, and the Analyst Profile's D15 settled that nothing
 * on this page runs a module without a press, so the rail could only
 * ever have been filled by running five modules on every page load.
 * An inert control is an unfinished promise to an analyst, so it is
 * gone rather than disabled. A rail founded on pivots the database can
 * actually resolve would be a different feature.
 */

/*
 * ------------------------------------------------------------------
 * Tabs
 * ------------------------------------------------------------------
 * Every tab is assembled from lazily-loaded panels, one endpoint each,
 * so a slow panel never holds up the rest of the page and each one's
 * implementation stays a local change.
 */
$counts = $profile['counts'];

/*
 * ------------------------------------------------------------------
 * What each endpoint's panels look like before they arrive
 * ------------------------------------------------------------------
 * Every panel below is fetched after the page paints, and the layout
 * used to hold nothing for it but a centred spinner — so a tab opened
 * as a column of 60px spinners and grew to its real height one fetch at
 * a time. A reader could not tell which section was which, could not
 * reach the one they came for, and watched the page move under the
 * cursor until the slowest endpoint answered.
 *
 * This table is the shape of the answer, stated before it comes:
 * `value_panel_loading` draws the real card chrome from it, so the
 * structure and the section names are there from the first paint.
 *
 * **It repeats each panel's title, and that is the cost of the move.**
 * The titles live in the panel templates, which is where they have to
 * live — a panel composes its own subtitle out of its own numbers — so
 * a name changed there and not here shows the old one for as long as
 * the fetch takes. The alternative is a spinner that says nothing at
 * all, and a wrong name for 400ms is cheaper than no name at all.
 *
 * `lines` is how many body bars to shimmer, and it is a guess at the
 * panel's height rather than a claim about its contents. Guessed low on
 * purpose: the panel that lands is then taller than its skeleton, so
 * the page grows rather than shrinking, which is the direction that
 * does not pull a section out from under a reader who has scrolled to
 * it.
 */
$icoAttr = 'misp-icon misp-icon-attribute misp-simple';
$icoNote = 'misp-icon misp-icon-analyst-note misp-simple';
$icoSight = 'misp-icon misp-icon-sighting misp-simple';
$icoTag = 'misp-icon misp-icon-tag misp-simple';
$icoObj = 'misp-icon misp-icon-object misp-simple';
$icoGalaxy = 'misp-icon misp-icon-galaxy misp-simple';
$icoOrg = 'misp-icon misp-icon-organisation misp-simple';

/**
 * One card of chrome.
 *
 * @param string|null $title Null only on an `aside`, whose title this
 *                           page cannot know — see the element
 * @param string|null $icon
 * @param string $color
 * @param int $lines
 * @param array $extra `shape` and `col`, for the two endpoints that
 *                     own their own split and the rail's lighter card
 * @return array
 */
$await = function ($title, $icon, $color, $lines = 3,
    array $extra = array()
) {
    return $extra + array(
        'title' => $title,
        'icon' => $icon,
        'color' => $color,
        'lines' => $lines,
    );
};

$aside = array('shape' => 'aside');

$panelChrome = array(
    'viewOccurrences' => array(
        $await(__('Occurrences'), $icoAttr, 'var(--attribute)', 4),
    ),
    'viewReporting' => array(
        $await(__('Reporting'), $icoOrg, 'var(--object)', 4),
    ),
    'viewContext' => array(
        $await(__('Tags and galaxies'), $icoTag, 'var(--tag)', 4),
    ),
    'viewAnalystPreview' => array(
        $await(__('Analyst data'), $icoNote, 'var(--analystData)'),
    ),
    'viewVerdictCard' => array(
        $await(__('Assessment'), 'fas fa-gavel', 'var(--primary)', 4),
    ),
    'viewSightings' => array(
        $await(__('Sightings'), $icoSight, 'var(--sighting)'),
    ),
    'viewLifecycle' => array(
        $await(__('Lifecycle'), 'fas fa-hourglass-half',
            'var(--correlation)'),
    ),
    // No skeleton: most values carry no matrix technique, and the card
    // only appears when one does.
    'viewMatrix' => array(),
    'viewExternal' => array(
        $await(__('External presence'), 'fas fa-cloud-arrow-down',
            'var(--enrichment)'),
    ),
    'viewVerdict' => array(
        $await(__('Assessment'), 'fas fa-gavel', 'var(--primary)', 10),
    ),
    /*
     * The rail is four cards or five and each one's title with it, so
     * the skeleton holds three unnamed ones: the shape is honest, the
     * names would be guesses.
     */
    'viewVerdictAside' => array(
        $await(null, null, 'var(--primary)', 4, $aside),
        $await(null, null, 'var(--primary)', 4, $aside),
        $await(null, null, 'var(--primary)', 3, $aside),
    ),
    'viewOccurrenceTable' => array(
        $await(__('Filters'), 'fas fa-filter', 'var(--attribute)', 5,
            array('col' => 3)),
        $await(__('Occurrences'), $icoAttr, 'var(--attribute)', 8,
            array('col' => 9)),
    ),
    'viewSightingChart' => array(
        $await(__('Sightings over time'), $icoSight, 'var(--sighting)',
            6),
    ),
    'viewSightingList' => array(
        $await(__('Individual sightings'), $icoSight, 'var(--sighting)',
            6),
    ),
    'viewRelevance' => array(
        $await(__('Lifetime'), 'fas fa-hourglass-half',
            'var(--correlation)', 3, $aside),
    ),
    'viewSightingReporters' => array(
        $await(__('Reporters'), $icoOrg, 'var(--sighting)', 3, $aside),
    ),
    'viewSightingAdd' => array(
        $await(__('Report a sighting'), $icoSight, 'var(--sighting)', 3,
            $aside),
    ),
    /*
     * Three panels out of one endpoint, in the order it draws them.
     * Two of the three are conditional on the value having such rows —
     * but the contents strip above already lists all three whatever the
     * value turns out to hold, so a skeleton that listed fewer would
     * disagree with the page's own table of contents.
     */
    'viewRelationCooccurrence' => array(
        $await(__('In the same object'), $icoObj, 'var(--vp-rel-co)', 6),
        $await(__('In the same events'), 'fas fa-link',
            'var(--vp-rel-co)', 8),
        $await(__('Labels in this neighbourhood'), $icoGalaxy,
            'var(--vp-rel-co)', 5),
    ),
    'viewRelationDated' => array(
        $await(__('Dated relations'), 'fas fa-clock-rotate-left',
            'var(--vp-rel-object)', 6),
    ),
    'viewRelationNearMatch' => array(
        $await(__('Near-matches'), 'fas fa-code-compare',
            'var(--vp-rel-near)', 5),
    ),
    'viewRelationExternal' => array(
        $await(__('Outside this instance'), 'fas fa-cloud-arrow-down',
            'var(--vp-rel-external)', 4),
    ),
    'viewRelationReferences' => array(
        $await(__('Object relationships'), 'fas fa-diagram-project',
            'var(--vp-rel-reference)', 5),
    ),
    'viewRelationAsserted' => array(
        $await(__('Asserted by analysts'), $icoNote,
            'var(--vp-rel-human)', 4),
    ),
    'viewRelationGraph' => array(
        $await(__('Neighbourhood'), 'fas fa-circle-nodes',
            'var(--bs-secondary-color)', 5),
    ),
    'viewRelationThreats' => array(
        $await(__('Named threats in this neighbourhood'), $icoGalaxy,
            'var(--bs-secondary-color)', 4),
    ),
    'viewRelationSettings' => array(
        $await(__('What is counted'), 'fas fa-sliders',
            'var(--bs-secondary-color)', 4),
    ),
    'viewEnrichment' => array(
        $await(__('Enrichment'), 'fas fa-wand-magic-sparkles',
            'var(--vp-e-accent)', 8),
    ),
    /*
     * Two lines, because the panel is one row per module and four
     * modules is the wide case. Guessed low like the rest: the card
     * that lands is then taller than its skeleton, so the page grows
     * rather than pulling the Occurrences card up out from under a
     * reader.
     */
    'viewEnrichmentPanel' => array(
        $await(__('Enrichment'), 'fas fa-wand-magic-sparkles',
            'var(--vp-e-accent)', 2),
    ),
    'viewAnalystStanding' => array(
        $await(__('Where the organisations stand'),
            'fas fa-arrows-left-right-to-line', 'var(--analystData)', 6),
    ),
    'viewAnalystThread' => array(
        $await(__('Notes, opinions and proposals'), $icoNote,
            'var(--analystData)', 6),
    ),
    /*
     * Added with the panel in phase 26. Without an entry here the card
     * arrives with no skeleton at all, which on a tab where both its
     * siblings show one reads as a panel that failed rather than one
     * still loading.
     */
    'viewAnalystReports' => array(
        $await(__('Event reports'), 'fas fa-file-lines',
            'var(--analystData)', 4),
    ),
    'viewAnalystComments' => array(
        $await(__('Attribute comments'), 'fas fa-comment-dots',
            'var(--analystData)', 4),
    ),
    'viewTimeline' => array(
        $await(__('Timeline'), 'fas fa-clock', 'var(--bs-info)', 8),
    ),
    'viewHistory' => array(
        $await(__('Filters'), 'fas fa-filter',
            'var(--bs-secondary-color)', 5, array('col' => 3)),
        $await(__('History'), 'fas fa-history',
            'var(--bs-secondary-color)', 8, array('col' => 9)),
    ),
);

/**
 * The optional anchor is the panel's *container*, not its card: it is
 * put on the empty div that holds the spinner, so a link can reach the
 * section before the fetch that fills it has come back. Only the
 * Relationships tab asks for one, because only it has a contents strip
 * pointing at its own sections.
 *
 * @param string $action
 * @param string $anchor
 * @return array A view_layout card pointing at one panel endpoint
 */
$panel = function ($action, $anchor = null) use ($baseurl, $valueB64,
    $panelChrome
) {
    $card = array(
        'ajax' => $baseurl . '/values/' . $action . '/' . h($valueB64),
    );
    if ($anchor !== null) {
        $card['id'] = $anchor;
    }
    if (isset($panelChrome[$action])) {
        $card['placeholder'] = array(
            'element' => 'Values/View/value_panel_loading',
            'params' => array('panels' => $panelChrome[$action]),
        );
    }
    return $card;
};

/*
 * The Assessment tab's state pill. A lean is a state, not a count, so
 * it gets a badge rather than the parenthesised number the other tabs
 * use. The colour names the lean; the label carries the signal strength when
 * there is one to carry.
 */
$verdict = $profile['verdict'];
$verdictBadge = array(
    'label' => $verdict['signal_strength'] === null
        ? ValueLean::label($verdict['lean'])
        : ValueLean::label($verdict['lean']) . ' '
            . $verdict['signal_strength'],
    'color' => ValueLean::colour($verdict['lean']),
    'dot' => true,
);

/*
 * A `none` lean has nothing for the Assessment rail — no signal strength to
 * compose, no shelf life to run down, no warninglist hit to explain —
 * so that tab keeps the full width rather than reserving a column for
 * cards that would each render their own nothing. `value_verdict_aside`
 * holds the matching decision about which cards apply.
 */
$hasVerdictAside = $verdict['lean'] !== 'none';

/*
 * The Relationships pill: one notion, named, and only when it is there.
 *
 * A pill rather than the parenthesised count because `(15)` on this tab
 * would read as fifteen *relationships*, which nothing here counts.
 * The label carries
 * the unit, so the number says what it counts, and it counts the notion
 * the tab is founded on rather than a total across seven of them.
 *
 * Null at zero: a value in no object can still hold a claim, a
 * near-match or a remote hit, so *0 objects* would answer *is this
 * worth opening* wrongly. No pill means what it means on Sightings and
 * Timeline — no number can be told truly — and never *nothing here*.
 * `ValueIntelligence::forTabCounts` has the cost and the rest of the case.
 */
$relationshipObjects = (int)($counts['relationship_objects'] ?? 0);
$relationshipBadge = $relationshipObjects === 0 ? null : array(
    'label' => sprintf(
        __n('%s object', '%s objects', $relationshipObjects),
        number_format($relationshipObjects)
    ),
    'color' => 'var(--vp-rel-object)',
);

/*
 * The Occurrences pill: the number, and only the number.
 *
 * A pill rather than the parenthesised `(17)` the generic layout draws
 * from `count`, so that every number on this bar is the same object in
 * the same place. That branch stays where it is — `Servers/
 * server_settings` renders its per-tab error counts through it.
 *
 * No unit, which is where this parts from the Relationships pill above.
 * That one has to say *15 objects* because `(15)` on that tab would
 * read as fifteen relationships. Here the tab title is already the noun
 * the panel uses — `value_occurrence_table` reads *Showing 50 of 1,231
 * occurrences* — so a unit on the pill would only say it twice.
 *
 * Null at zero, which is what `!empty($tab['count'])` already did: it
 * never drew `(0)`, and this change is a rendering and not a new claim.
 */
$occurrences = (int)($counts['occurrences'] ?? 0);
$occurrenceBadge = $occurrences === 0 ? null : array(
    'label' => number_format($occurrences),
    'color' => 'var(--vp-occ-attribute)',
);

/*
 * And the sightings pill, on the same two rules. No unit, because the
 * tab is already called Sightings; null at zero, because *0* on a tab
 * answers *is this worth opening* in the one direction that costs the
 * reader nothing to get wrong by staying silent.
 *
 * It is the viewer's own number — `Value::sightingCountsFor` applies
 * `Sightings_policy` in SQL — and it is the number the fact strip
 * prints, from the same call rather than from a second one.
 */
$sightings = (int)($counts['sightings'] ?? 0);
$sightingBadge = $sightings === 0 ? null : array(
    'label' => number_format($sightings),
    'color' => 'var(--sighting)',
);

/*
 * The Enrichment pill, and it names its unit for the Relationships
 * reason: `(3)` on a tab whose rail lists twelve modules reads as
 * three *modules*, and the number is three **answers** — what this
 * organisation already holds about this value, which is what decides
 * whether the tab is worth opening.
 *
 * Not the count phase 28 dropped. That one was the eligible-module
 * total and it was dropped because it cannot be told without asking
 * the modules service on every page load; this is one index-only
 * count in MISP's own store (`ValueEnrichmentRun::heldCountFor`).
 *
 * Null at zero, so an instance that has never enriched anything has
 * the tab bar it had before the store existed.
 */
$enrichmentHeld = (int)($counts['enrichment'] ?? 0);
$enrichmentBadge = $enrichmentHeld === 0 ? null : array(
    'label' => sprintf(
        __n('%s answer', '%s answers', $enrichmentHeld),
        number_format($enrichmentHeld)
    ),
    'color' => 'var(--enrichment)',
);

/*
 * The Overview's left column, assembled rather than declared, because
 * its first entry is conditional.
 *
 * `enrichment_panel` is the frame's answer to *is there anything to
 * draw* — one indexed read of the run store and one look at the
 * profile, both of which the page was paying for already. It is looser
 * than the panel's own test and never stricter: the frame does not
 * know whether a declared module is enabled on this instance, because
 * finding out is a call to the modules service and the page will not
 * make one to decide whether to draw a card. A yes the panel then
 * contradicts costs an empty container; a no would hide an answer.
 */
$overviewLeft = array();
if (!empty($profile['enrichment_panel'])) {
    $overviewLeft[] = $panel('viewEnrichmentPanel');
}
$overviewLeft[] = $panel('viewOccurrences');
$overviewLeft[] = $panel('viewReporting');
$overviewLeft[] = $panel('viewContext');
$overviewLeft[] = $panel('viewAnalystPreview');

$tabRegistry = array(
    array(
        'id' => 'general',
        'title' => __('Overview'),
        'icon' => 'fas fa-info-circle',
        /*
         * **Reporting sits under the occurrence preview**, which is
         * where the questions it answers were being asked. Phase 31 cut
         * that preview from twenty-five rows to eight — 792px of a
         * 1531px column, clipped at 70vh and scrolling inside its own
         * card — and a reader's next move after skimming it was to
         * count organisations down the *Reported by* column and guess
         * at the dates. Both are one grouped aggregate, so both are
         * stated: the split is the Assessment tab's *Who says what*
         * and the strip is the Timeline tab's *Activity on this value*,
         * each read through that tab's own method.
         *
         * **Enrichment leads the column, and only where there is an
         * answer to lead with.** The Overview refused anything from
         * that tab for three phases, on the grounds that everything
         * there was a network request and this tab renders eight
         * panels whether or not a module is up. A store of what
         * modules last said is not a network request, so the objection
         * no longer holds — but the emptier version of it would: a
         * card that says *nothing has been asked* on every value of
         * every instance that never enriched anything is the
         * permanently empty first row those two phases exist to
         * refuse. So the frame decides whether the container is
         * emitted at all, and an instance with nothing to show has the
         * tab it had before.
         *
         * A full-width row is the *cheapest* placement for this, not
         * the dearest: four modules of chips across a 9-wide column
         * take one line each, where the same content stacked in the
         * 3-wide rail runs past 300px.
         */
        'left' => $overviewLeft,
        'right' => array(
            $panel('viewVerdictCard'),
            $panel('viewLifecycle'),
            $panel('viewMatrix'),
            $panel('viewSightings'),
            $panel('viewExternal'),
        ),
    ),
    array(
        'id' => 'assessment',
        'title' => __('Assessment'),
        'icon' => 'fas fa-gavel',
        'badge' => $verdictBadge,
        /*
         * The same 9/3 split as the Overview tab: the evidence — the
         * ledger grid, the occurrence tables, the two opposed cases —
         * needs the width, while the summaries and reference facts read
         * better beside it than under it.
         */
        'left' => array(
            $panel('viewVerdict'),
        ),
        'right' => $hasVerdictAside
            ? array($panel('viewVerdictAside'))
            : null,
    ),
    array(
        'id' => 'occurrences',
        'title' => __('Occurrences'),
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        /*
         * The viewer's own count, off the same aggregate the tab's
         * header uses, so the badge and the panel cannot disagree —
         * `ValueIntelligence::forTabCounts`.
         */
        'badge' => $occurrenceBadge,
        /*
         * One full-width slot, and the panel lays out its own internal
         * row: the rail on the left at col-lg-3, the table at col-lg-9,
         * the reverse of this page's usual split. Both come out of one
         * fetch, which is why they are one panel — a facet count and
         * the rows it counts must not be able to disagree.
         */
        'left' => array(
            $panel('viewOccurrenceTable'),
        ),
        'right' => null,
    ),
    array(
        'id' => 'sightings',
        'title' => __('Sightings'),
        'icon' => 'misp-icon misp-icon-sighting misp-simple',
        /*
         * **A real count since phase 29**, and it is the viewer's.
         * There was none here for two reasons, one of which has gone:
         * a sighting count is the *viewer's* — `Sightings_policy` hides
         * whole reports — and getting it used to cost the panel's own
         * thirteen queries on every page load. `Value::sightingCountsFor`
         * is one indexed aggregate with the policy expressed as SQL, so
         * the price is a single count on the frame's own read, off the
         * same rule `listSightings` applies.
         *
         * `ValueIntelligence::forTabCounts` holds the rest of the reasoning.
         *
         * The page's usual 9/3 split. The overlay is the tab, and it
         * needs the width: bars stacked by organisation under the shelf
         * life on its own axis is not a chart that survives being put in
         * a card beside something else.
         */
        'badge' => $sightingBadge,
        'left' => array(
            $panel('viewSightingChart'),
            $panel('viewSightingList'),
        ),
        'right' => array(
            $panel('viewRelevance'),
            $panel('viewSightingReporters'),
            $panel('viewSightingAdd'),
        ),
    ),
    array(
        'id' => 'relationships',
        'title' => __('Relationships'),
        'icon' => 'fas fa-link',
        /*
         * A pill naming objects, not the parenthesised count. There is
         * no correlation total to show: co-occurrence here is an event
         * join, not correlation output. That join's own total is
         * refused — it means running the panel's whole scan, up to
         * 20,000 attribute rows and a second on the heaviest value, on
         * every page load for a tab most readers never open.
         *
         * What the pill carries instead is the notion §26 re-founded
         * the tab on, off one indexed aggregate, and it is the same
         * number the sibling panel and the graph's object layer print.
         * `$relationshipBadge` above and `ValueIntelligence::forTabCounts`
         * hold the case, the cost and why zero shows nothing.
         */
        'badge' => $relationshipBadge,
        /*
         * Six panels rather than one, top to bottom in the order the
         * six notions should be read: what shares an event and an
         * object, when an object says that join held, what is merely
         * close, what somebody outside this instance holds it
         * alongside, and then the two a person wrote — MISP's own typed
         * reference and an analyst's claim. Machine-derived before
         * human, which is what the separation rule encodes.
         *
         * **Dated relations sits second**, directly under the section
         * whose rows it dates: it is the object join again, with the
         * one thing that join records and the table above has no column
         * for. Splitting it out rather than adding two columns is
         * `03-relationships.md` §23.5 — most object joins carry no date
         * at all, and two empty columns on every row would be a worse
         * answer than a panel that says so once.
         *
         * They are separate endpoints because they cost wildly
         * different amounts — the first reads up to 20,000 rows and the
         * references a handful — and one slow scan must not hold up the
         * two sections a person wrote by hand.
         */
        'left' => array(
            /*
             * A contents strip over the six endpoints, and the only
             * thing on this tab that renders before them: seven cards
             * — the co-occurrence endpoint draws two sections — each
             * holding one section's headline number and jumping to it.
             * It is markup only. The numbers arrive from the panels
             * themselves as they land, because computing any of them
             * here would mean running the scan the tab is lazily
             * loaded to avoid.
             */
            array('element' => 'Values/View/value_relation_summary'),
            $panel('viewRelationCooccurrence', 'vp-rel-sec-cooccurrence'),
            $panel('viewRelationDated', 'vp-rel-sec-dated'),
            $panel('viewRelationNearMatch', 'vp-rel-sec-near'),
            $panel('viewRelationExternal', 'vp-rel-sec-external'),
            $panel('viewRelationReferences', 'vp-rel-sec-references'),
            $panel('viewRelationAsserted', 'vp-rel-sec-asserted'),
        ),
        /*
         * Shape, then names, then bookkeeping. The graph says how many
         * blobs the neighbourhood has and how big they are; the card
         * under it says who is in them; the settings card is the
         * bookkeeping and stays last.
         *
         * The named-threat card is the only thing on this tab that
         * answers *what does this mean* rather than *what is related*,
         * and it is in the rail because that is where the headroom is
         * — the tab measured ~5,700px against a rail of ~1,700px on
         * `8.8.8.8`. Not an eighth card on the contents strip: each of
         * those carries one section's headline number and jumps to it,
         * and this has no left-column section to jump to.
         */
        'right' => array(
            $panel('viewRelationGraph'),
            $panel('viewRelationThreats'),
            $panel('viewRelationSettings'),
        ),
    ),
    array(
        'id' => 'enrichment',
        'title' => __('Enrichment'),
        'icon' => 'fas fa-wand-magic-sparkles',
        /*
         * **A count of answers held, not of modules eligible.** Phase
         * 28 dropped this tab's number and its reason stands: the
         * eligible-module count would make every page load, on every
         * tab, depend on an external HTTP service — and pay that
         * service's 1 s timeout whenever it is down — for a number on
         * a tab most readers never open. That number is still not
         * MISP's to state.
         *
         * What the run store made countable is a different one and it
         * is entirely MISP's: how many answers this organisation
         * already holds about this value. One index-only count over
         * the unique key's two leading columns, and the pill says
         * *answers* so it cannot be read as the module total.
         */
        'badge' => $enrichmentBadge,
        /*
         * One full-width slot, and the panel owns its own split: the
         * module rail at ~40% and one module's results beside it. Not
         * this page's 9/3, because the rail scrolls independently of
         * the pane once there are more modules than fit — thirty is
         * as ordinary a number here as three.
         */
        'left' => array(
            $panel('viewEnrichment'),
        ),
        'right' => null,
    ),
    array(
        /*
         * **The id stays `analyst` while the label does not.** `#tab-analyst`
         * is an address — the Overview card's *Open thread* button
         * points at it, and so does anything anyone has bookmarked —
         * and an id is not a name. Renaming it would break those to
         * rename nothing the reader can see.
         */
        'id' => 'analyst',
        /*
         * **Renamed from *Analyst data* by phase 26**, because the tab
         * stopped being about analyst data and the name stopped being
         * true. *Analyst data* is a MISP feature — the three
         * `AnalystData` subclasses — and this tab now also carries
         * proposals, which are `shadow_attributes` and predate that
         * feature, and event reports, which are neither. Its subject is
         * everything anybody has said about this value, which is the
         * one thing separating it from every other tab on the page:
         * the rest are machine-derived.
         *
         * *Collaboration* is the only single word that covers a note,
         * an opinion, a proposal and a report without stretching any of
         * them — a proposal is literally somebody else's edit offered
         * to your event. `26-analyst.md` §11.4.
         */
        'title' => __('Collaboration'),
        'icon' => 'misp-icon misp-icon-analyst-note misp-simple',
        /*
         * No count, for both of the reasons the Timeline and History
         * tabs carry. It is the
         * *viewer's* count — `AnalystData::buildConditions` scopes
         * every note and opinion, and a CIRCL reader sees four items
         * on `8.8.8.8` where a site admin sees six — so two users
         * would read two numbers off one value's tab bar. And a badge
         * that agreed with the panel would have to do the panel's
         * work: the union is five anchor kinds over two tables and
         * costs 5 to 26 queries, which is not a page-load price for a
         * number on a tab nobody may open.
         */
        /*
         * One full-width slot, and the standing panel lays out its own
         * internal row: the histogram at col-lg-4 beside the
         * per-organisation table at col-lg-8. Not this page's 9/3,
         * because the position strip spans the whole panel above both
         * of them — it is the tab's opening claim and a rail would cut
         * a hundred-point scale down to a quarter of the page.
         */
        'left' => array(
            $panel('viewAnalystStanding'),
            $panel('viewAnalystThread'),
            /*
             * **The tab's third row is two panels wide on a large
             * screen**, and the pair is the tab's second half: what was
             * written *around* this value, where the two above are the
             * argument *about* it.
             *
             * Side by side because they are the two shortest things on
             * the tab and they are short in opposite directions — a
             * value with eleven comments has no report, and one with
             * eight reports has three comments. Stacked, a reader paid
             * for both; in a row the tab is as tall as the taller of
             * them rather than as tall as the sum, which is a saving on
             * every value and never a cost.
             *
             * **`col-xl-6` rather than the group's `col-lg-6` default,
             * and the breakpoint is measured rather than picked.** A
             * report row is a title, an extract and a meta line, and
             * halving its width wraps all three: the reports panel is
             * 660px at full width and **887px** in a 472px column. So
             * at `lg`'s 992px the row costs 887 against the 834 the two
             * stacked, and the arrangement is worse than what it
             * replaces. The crossover sits near 1,100px — at 1,200 the
             * row is 689 against 834 — so the split starts at `xl`,
             * where it is a saving on every value.
             *
             * Below it they stack exactly as they did. Two panels
             * beside each other is a claim about horizontal room and a
             * narrow window has none.
             */
            array('row' => array(
                /*
                 * Left of the pair. The three panels before it are
                 * anchored to uuids and spend a chip per row saying
                 * which container they are really about; this one is
                 * the `comment` column of the value's own occurrences,
                 * so it is the only thing on the tab written *about the
                 * value* with nothing to qualify. It leads the row for
                 * that reason.
                 */
                $panel('viewAnalystComments') + array('col' => 'col-xl-6'),
                /*
                 * The narrative list, added by phase 26 —
                 * `value-intelligence-coverage.md` §4.5 places event reports
                 * on this tab, and a report is a document rather than a
                 * turn in the thread above it. Its own endpoint,
                 * because it is one `fetchReports` over the value's
                 * events and should not wait on the thread's
                 * five-anchor union.
                 */
                $panel('viewAnalystReports') + array('col' => 'col-xl-6'),
            )),
        ),
        'right' => null,
    ),
    array(
        'id' => 'timeline',
        'title' => __('Timeline'),
        'icon' => 'fas fa-clock',
        /*
         * No count. "67 dated entries" is the *viewer's* count —
         * `Sightings_policy` can hide whole sightings and
         * `Sightings_anonymise` refiles foreign orgs — so two users
         * would read two numbers off one value's tab bar.
         *
         * One full-width slot, and the panel owns its own three cards.
         * Not this page's 9/3 and not three panels: the brush is one
         * control driving two regions that must already exist when it
         * fires, and three `.ajax-card`s resolve independently.
         */
        'left' => array(
            $panel('viewTimeline'),
        ),
        'right' => null,
    ),
    array(
        'id' => 'history',
        'title' => __('History'),
        'icon' => 'fas fa-history',
        /*
         * No count, and for a stronger reason than the Timeline tab's.
         * An audit-entry count is the *viewer's*: a plain analyst, an
         * org admin and a site admin get three different numbers for
         * one value. And on a default instance `MISP.log_new_audit` is
         * off, so it is 0 for a reason that has nothing to do with the
         * value. A number meaning three things and usually zero is
         * worse than no number.
         *
         * One full-width slot, and the panel owns its rail: the facet
         * control binds checkboxes to rows through the nearest
         * `data-vp-list` ancestor, so the two cannot be separate cards.
         */
        'left' => array(
            $panel('viewHistory'),
        ),
        'right' => null,
    ),
);

$tabs = array();
foreach ($tabRegistry as $tab) {
    $tabs[] = array(
        'id' => $tab['id'],
        'title' => $tab['title'],
        'icon' => $tab['icon'],
        'count' => $tab['count'] ?? null,
        'badge' => $tab['badge'] ?? null,
        'right' => $tab['right'] ?? null,
        'left' => $tab['left'],
    );
}

echo $this->OrgGrade->config($orgGrading ?? null);

echo $this->element('genericElementsBS5/Layout/view_layout', array(
    'data' => $profile,
    'tabs' => $tabs,
));
