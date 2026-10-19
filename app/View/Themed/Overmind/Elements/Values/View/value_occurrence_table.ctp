<?php
/**
 * The Occurrences tab: every attribute row carrying this value, with the
 * counted rail that narrows it.
 *
 * The Overview already previews this table. What this one adds is
 * filtering, selection and the three columns the preview drops — so the
 * rail is the first thing on screen, and the panel lays out its own row
 * rather than taking `view_layout`'s split: the counts and the rows they
 * count come out of one fetch and cannot be allowed to disagree.
 *
 * An `index_table` over `$valueIntelligence['occurrences']`, shaped like a
 * `fetchAttributes` result, so the field renderers are the ones every
 * other MISP index uses.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewOccurrenceTable.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$profile = $valueIntelligence;
$rows = $profile['occurrences'];
$stats = $profile['occurrence_stats'];
$facets = $profile['occurrence_facets'];
$feedsShown = !empty($profile['feeds_shown']);
/*
 * The same plan the rail beside this table was folded with, so the
 * two cannot rank one taxonomy two ways.
 */
$labelPlan = $profile['label_plan'];

/*
 * Rows are drawn from one page of the panel's own rows, never fetched
 * again: `00-shared.md` §6.
 *
 * Sixty because that is MISP's own index page size —
 * `AttributesController::$paginate['limit']` and `EventsController`'s
 * both — so a reader arriving from an attribute index finds the same
 * number of rows rather than a sixth of them.
 *
 * The reader can change it. `$sizes` is offered rather than fixed
 * because the right answer depends on the screen and on what they are
 * doing, and because the page control renders one button per page: a
 * larger page is also what keeps that control small enough for the
 * panel header to carry it (`22-occurrences.md` §6).
 */
$pageSize = 60;
/*
 * Every size offered has to leave a panel header that renders. The page
 * control draws one button per page, so 300 rows at 60 is five pages and
 * seven buttons, and at 150 or 300 it is fewer. A 25-row page would be
 * twelve pages and fourteen buttons, which squeezes the subtitle to a
 * 156px column beside the picker — measured, and the reason 25 is not on
 * the list.
 */
$pageSizes = array(60, 150, 300);

$view = $this;

/**
 * Tokens are matched by the rail, so they are derived from the row's own
 * domain values by the same rule the rail counted by.
 *
 * The rule lives in `ValueStatsTool` rather than here because it has two
 * callers: this stamps the token on the row, and the tool counts the
 * facet the token matches, so the two cannot drift apart.
 *
 * @param string $text
 * @return string
 */
$slug = function ($text) {
    return ValueStatsTool::facetToken($text);
};

/**
 * @param array $row
 * @return string Space-separated `key:value` facet tokens
 */
$tokens = function ($row) use ($slug) {
    $attribute = $row['Attribute'];
    $tokens = array(
        'organisation:' . $row['Event']['Orgc']['id'],
        'type:' . $slug($attribute['type']),
        // The object template, or the standalone value the rail counts
        // so that group partitions the rows rather than covering only
        // the occurrences that happen to sit in one.
        'object:' . (empty($row['Object']['name'])
            ? 'standalone'
            : $slug($row['Object']['name'])),
        'category:' . $slug($attribute['category']),
        'ids:' . (!empty($attribute['to_ids']) ? 'set' : 'unset'),
    );
    /*
     * The effective level, matching what the rail counted — never
     * `Attribute.distribution`, which is `Inherited` on almost every
     * real row and would put the whole table in one facet.
     */
    $effective = $row['effective_distribution'];
    if ($effective['level'] !== null) {
        $tokens[] = 'distribution:' . $effective['level'];
        if ($effective['level'] === 4
            && !empty($effective['sharing_group_id'])
        ) {
            $tokens[] = 'sharing_group:'
                . $effective['sharing_group_id'];
        }
    }
    /*
     * **Both scopes under one key.** The Tags column draws the
     * attribute's labels and its event's as one list, and the rail has
     * one Tag group counting them the same way — an event's labelling
     * covers the attributes inside it, so *this occurrence is labelled
     * X* and *this occurrence arrived in a report labelled X* is one
     * question about the row for a reader narrowing a table.
     *
     * Deduplicated, so a row carrying `tlp:white` on both sides stamps
     * the token once. The rail counts that row once too, and a rail
     * disagreeing with the table beside it is the one thing
     * `forOccurrenceTable` being a single fetch exists to prevent.
     */
    $tagTokens = array();
    $rowTags = array();
    foreach ($row['AttributeTag'] as $attributeTag) {
        if (!empty($attributeTag['Tag'])) {
            $rowTags[] = $attributeTag['Tag'];
        }
    }
    foreach ($row['EventTag'] ?? array() as $eventTag) {
        if (!empty($eventTag['Tag'])) {
            $rowTags[] = $eventTag['Tag'];
        }
    }
    foreach ($rowTags as $tag) {
        // Galaxy tags are not drawn in the Tags column either, and a
        // filter on something invisible is not a filter.
        if (!empty($tag['is_galaxy'])) {
            continue;
        }
        $tagTokens[$slug($tag['name'])] = true;
    }
    foreach (array_keys($tagTokens) as $tagToken) {
        $tokens[] = 'tag:' . $tagToken;
    }
    /*
     * **Clusters are their own key, unlike the two tag scopes.** A
     * galaxy tag and a plain tag are two different questions — *what
     * is this labelled* and *what is it attributed to* — where the two
     * scopes of one tag were the same question asked of two rows.
     *
     * Keyed on the cluster's **tag name** and not its drawn name:
     * `attachClusters` has already deduplicated the row's clusters and
     * ruled on them, and two galaxies can hold clusters that read the
     * same. The rail bumps the same token from the same array.
     */
    foreach ($row['Cluster'] ?? array() as $cluster) {
        $tokens[] = 'galaxy:' . $slug($cluster['tag_name']);
    }
    if (!empty($row['proposal_count'])) {
        $tokens[] = 'state:proposal';
    }
    return implode(' ', $tokens);
};

/**
 * One sortable token per column, so ordering compares what the column
 * means rather than what its cell happens to read.
 *
 * Cell text would not do it. Three columns render a glyph and no words
 * at all — IDS, Distribution, State — an event id sorts as `10, 9` when
 * compared as text, and a distribution's audience has an order (`0, 4,
 * 1, 2, 3`) that neither its label nor its level number expresses.
 *
 * Every token is a string built to sort lexicographically, so the script
 * needs one comparison and no per-column knowledge: numbers are
 * zero-padded, dates are `YmdHi` digits, text is lowercased. An empty
 * token means the row has no value for that column, and the script puts
 * those last in both directions — `Not set` belongs at the bottom
 * whichever way the reader is looking.
 *
 * @param array $row
 * @return array `vp-sort-<column>` => token
 */
$sortKeys = function ($row) {
    $attribute = $row['Attribute'];
    $effective = $row['effective_distribution'];
    $pad = function ($number, $width = 12) {
        return str_pad((string)(int)$number, $width, '0', STR_PAD_LEFT);
    };
    $stamp = function ($value) {
        return empty($value) ? '' : date('YmdHi', strtotime($value));
    };
    /*
     * The exception columns first when ascending: a reader sorting by
     * State is looking for the rows that are not ordinary.
     */
    $state = 3;
    if (!empty($row['proposal_count'])) {
        $state = 1;
    } elseif (!empty($attribute['deleted'])) {
        $state = 2;
    }
    /*
     * **What the Tags column draws, counted the way it draws it.** The
     * column has shown both scopes deduplicated by name since
     * 2026-09-14 and this counted `AttributeTag` alone, so sorting by
     * Tags put a row showing nine chips below one showing two — and on
     * `8.8.8.8`, where no occurrence carries a tag of its own, it
     * ordered every row as if the column were empty.
     */
    $tagNames = array();
    foreach ($row['AttributeTag'] as $attributeTag) {
        if (!empty($attributeTag['Tag']['name'])
            && empty($attributeTag['Tag']['is_galaxy'])
        ) {
            $tagNames[$attributeTag['Tag']['name']] = true;
        }
    }
    foreach ($row['EventTag'] ?? array() as $eventTag) {
        if (!empty($eventTag['Tag']['name'])
            && empty($eventTag['Tag']['is_galaxy'])
        ) {
            $tagNames[$eventTag['Tag']['name']] = true;
        }
    }
    $tags = count($tagNames);
    $clusters = count($row['Cluster'] ?? array());
    $context = '';
    if (!empty($row['Object']['name'])) {
        $context = mb_strtolower(
            $row['Object']['name'] . ' ' . $attribute['object_relation']
        );
    }
    return array(
        'vp-sort-state' => (string)$state,
        'vp-sort-event' => $pad($row['Event']['id']),
        'vp-sort-org' => mb_strtolower($row['Event']['Orgc']['name']),
        'vp-sort-type' => mb_strtolower($attribute['type']),
        'vp-sort-category' => mb_strtolower($attribute['category']),
        'vp-sort-ids' => empty($attribute['to_ids']) ? '0' : '1',
        'vp-sort-feeds' => empty($row['Feed'])
            ? ''
            : $pad(count($row['Feed']), 4),
        // By audience, tightest first — the order `ValueStatsTool`
        // resolved the chain by, which is why it hands back a rank.
        'vp-sort-distribution' => $pad($effective['rank'], 2),
        'vp-sort-context' => $context,
        'vp-sort-comment' => mb_strtolower((string)$attribute['comment']),
        'vp-sort-first-seen' => $stamp($attribute['first_seen'] ?? null),
        'vp-sort-last-seen' => $stamp($attribute['last_seen'] ?? null),
        'vp-sort-tags' => $tags === 0 ? '' : $pad($tags, 4),
        'vp-sort-galaxies' => $clusters === 0
            ? ''
            : $pad($clusters, 4),
    );
};

/*
 * What the rail matches on, and what the bulk bar's scope line counts.
 * `row_class_callable` could not carry this: a row matched on type and
 * organisation and tag at once cannot say so as a class string without
 * the reader parsing class names back into fields.
 */
$defaultOrder = 0;
$rowData = function ($row) use ($tokens, $sortKeys, &$defaultOrder) {
    /*
     * The row's position in the order the model sent — most recently
     * modified first. Reordering the table moves the rows themselves, so
     * clearing a column sort has to restore this rather than merely stop
     * comparing; without it the default order is gone after one click,
     * and `Attribute.timestamp` is not one of the twelve columns for the
     * reader to sort back by.
     */
    $data = array_merge(array(
        'vp-facet' => $tokens($row),
        'vp-event' => $row['Event']['id'],
        'vp-org' => $row['Event']['Orgc']['name'],
        'vp-sort-default' => str_pad(
            (string)$defaultOrder++,
            6,
            '0',
            STR_PAD_LEFT
        ),
    ), $sortKeys($row));
    /*
     * The dates the rail's ranges cut on, as the `YmdHi` digits of the
     * printed wall clock rather than epochs — a row's time is rendered
     * server-side, so comparing epochs would hand a reader in another
     * timezone a different set of rows than the times on those rows say
     * the period holds.
     *
     * An unpublished event contributes no `published` key at all, which
     * is what makes a cut on it drop the row rather than treat "never"
     * as some particular date. The rail counts how many that is.
     */
    $times = array();
    if (!empty($row['Attribute']['timestamp'])) {
        $times[] = 'timestamp:'
            . date('YmdHi', (int)$row['Attribute']['timestamp']);
    }
    if (!empty($row['Attribute']['created'])) {
        $times[] = 'created:'
            . date('YmdHi', (int)$row['Attribute']['created']);
    }
    if (!empty($row['Event']['publish_timestamp'])) {
        $times[] = 'published:'
            . date('YmdHi', (int)$row['Event']['publish_timestamp']);
    }
    if (!empty($row['Event']['timestamp'])) {
        $times[] = 'event:'
            . date('YmdHi', (int)$row['Event']['timestamp']);
    }
    /*
     * An interval, so the seen cut is an overlap test. A row with one
     * end is a point at that end, as the rail's bars count it.
     */
    $first = empty($row['Attribute']['first_seen'])
        ? false : strtotime($row['Attribute']['first_seen']);
    $last = empty($row['Attribute']['last_seen'])
        ? false : strtotime($row['Attribute']['last_seen']);
    if ($first !== false || $last !== false) {
        $from = $first === false ? $last : $first;
        $to = $last === false ? $first : $last;
        $times[] = 'seen:' . date('YmdHi', min($from, $to))
            . '-' . date('YmdHi', max($from, $to));
    }
    if (!empty($times)) {
        $data['vp-times'] = implode(' ', $times);
    }
    if (!empty($row['Attribute']['deleted'])) {
        // A reveal, not a facet value: filtering *to* deleted rows and
        // including them alongside the rest are different questions.
        $data['vp-hidden'] = 'deleted';
    }
    return $data;
};

$rowClass = function ($row) {
    return empty($row['Attribute']['deleted']) ? '' : 'vp-occ-deleted';
};

/**
 * The row's exception column, and empty for an ordinary row. It carries
 * the two states that change what a row *means* rather than what it
 * says: a pending shadow attribute proposing a change to it, and a
 * soft-delete that makes it history rather than current state.
 *
 * @param array $row
 * @return string
 */
$feedCell = function ($row) use ($baseurl) {
    if (empty($row['Feed'])) {
        return '<span class="text-muted">&mdash;</span>';
    }
    $names = array_column($row['Feed'], 'name');
    $first = $row['Feed'][0];
    $label = count($names) === 1
        ? h($first['name'])
        : h(sprintf(
            __n('%s feed', '%s feeds', count($names)),
            count($names)
        ));
    return '<a class="badge bg-info-subtle text-info-emphasis'
        . ' border border-info-subtle text-decoration-none"'
        . ' href="' . h($baseurl . '/feeds/previewIndex/' . $first['id'])
        . '" title="' . h(implode(', ', $names)) . '">'
        . '<i class="fas fa-rss me-1"></i>' . $label . '</a>';
};

$stateCell = function ($row) use ($view) {
    $badges = array();
    if (!empty($row['proposals'])) {
        /*
         * `fixed`, so the menu is not clipped by the table's scrolling
         * wrapper.
         */
        $badges[] = '<div class="dropdown d-inline-block">'
            . '<button type="button" class="badge d-inline-flex'
            . ' align-items-center gap-1 bg-warning-subtle'
            . ' text-warning-emphasis border border-warning-subtle"'
            . ' data-bs-toggle="dropdown" data-bs-auto-close="outside"'
            . ' data-bs-popper-config=\'{"strategy":"fixed"}\''
            . ' aria-expanded="false" title="' . h(__n(
                'A pending proposal changes this occurrence',
                '%d pending proposals change this occurrence',
                count($row['proposals'])
            )) . '">'
            . '<i class="fas fa-code-pull-request"></i>'
            . h(count($row['proposals'])) . '</button>'
            . $view->element('Values/View/value_occurrence_proposals', array(
                'proposals' => $row['proposals'],
            ))
            . '</div>';
    } elseif (!empty($row['proposal_count'])) {
        $badges[] = '<span class="badge d-inline-flex align-items-center'
            . ' gap-1 bg-warning-subtle text-warning-emphasis'
            . ' border border-warning-subtle" title="'
            . h(__(
                'A pending shadow attribute proposes a change to this'
                . ' occurrence'
            )) . '">'
            . '<i class="fas fa-code-pull-request"></i>'
            . h($row['proposal_count']) . '</span>';
    }
    if (!empty($row['Attribute']['deleted'])) {
        $badges[] = '<span class="badge d-inline-flex align-items-center'
            . ' gap-1 bg-secondary-subtle text-secondary-emphasis'
            . ' border border-secondary-subtle" title="'
            . h(__('Soft-deleted — history, not current state')) . '">'
            . '<i class="fas fa-trash"></i>' . h(__('Del')) . '</span>';
    }
    if (empty($badges)) {
        return '<span class="text-muted">&mdash;</span>';
    }
    return implode(' ', $badges);
};

/**
 * A one-letter disc before the organisation name, so four organisations
 * are distinguishable down the column without reading them.
 *
 * It stands in for a logo rather than joining one: MISP's organisation
 * renderer already draws a logo where the organisation has uploaded
 * one, and two glyphs before a name is one more than the column needs.
 * The hue is derived from the name rather than taken from the theme's
 * palette — there is no fixed set of organisations to assign variables
 * to, and the same organisation has to land on the same colour on every
 * page that draws it.
 *
 * @param array $row
 * @return string
 */
$organisationCell = function ($row) use ($view) {
    $org = $row['Event']['Orgc'];
    $rendered = $view->element(
        'genericElementsBS5/IndexTable/Fields/organisation',
        array(
            'field' => array('data_path' => 'Event.Orgc'),
            'row' => $row,
            'data_path' => 'Event.Orgc',
            'viewMode' => 'table',
        )
    );
    if (strpos($rendered, '<img') !== false) {
        return $rendered;
    }
    $initial = mb_strtoupper(mb_substr($org['name'], 0, 1));
    return '<div class="d-inline-flex align-items-center gap-2">'
        . '<span class="vp-occ-orgdot" style="--vp-orgdot-hue: '
        . h(crc32($org['name']) % 360) . '" aria-hidden="true">'
        . h($initial) . '</span>'
        . $rendered
        . '</div>';
};

/*
 * ------------------------------------------------------------------
 * Thirteen columns, ten of them shown
 * ------------------------------------------------------------------
 * Stated once, so the Columns menu, the header's ratio and the table
 * itself cannot come to disagree about which columns exist. `shown` is
 * only the default: the menu reveals the rest in place.
 *
 * Category, Comment and First seen are the three folded away. Category
 * mostly follows from the type; Comment is already summarised under the
 * Context column; and of the two seen dates only one can be read at a
 * glance in a column this narrow.
 */
$columns = array(
    array(
        'key' => 'state',
        'label' => __('State'),
        'shown' => true,
        'field' => array(
            'name' => __('State'),
            'element' => 'custom',
            'function' => $stateCell,
            'class' => 'text-nowrap',
        ),
    ),
    array(
        'key' => 'event',
        'label' => __('Event'),
        'shown' => true,
        'field' => array(
            'name' => __('Event'),
            'element' => 'event',
            'data_path' => 'Event.id, Event.info',
            'url' => $baseurl . '/events/view/%id%',
        ),
    ),
    array(
        'key' => 'org',
        'label' => __('Reported by'),
        'shown' => true,
        'field' => array(
            'name' => __('Reported by'),
            'element' => 'custom',
            'function' => $organisationCell,
            // The shared column rule the organisation renderer expects,
            // named here because the cell arrives through `custom`.
            'class' => 'idx-col-organisation',
        ),
    ),
    array(
        'key' => 'type',
        'label' => __('Type'),
        'shown' => true,
        'field' => array(
            'name' => __('Type'),
            'element' => 'type',
            'data_path' => 'Attribute.type',
        ),
    ),
    array(
        'key' => 'category',
        'label' => __('Category'),
        'shown' => false,
        'field' => array(
            'name' => __('Category'),
            'element' => 'category',
            'data_path' => 'Attribute.category',
        ),
    ),
    array(
        'key' => 'ids',
        'label' => __('IDS'),
        'shown' => true,
        'field' => array(
            'name' => __('IDS'),
            'element' => 'ids',
            'data_path' => 'Attribute.to_ids',
            // This page reports the flag; the event that owns it sets it.
            'readonly' => true,
        ),
    ),
    array(
        'key' => 'feeds',
        'label' => __('Feeds'),
        'shown' => $feedsShown,
        'field' => array(
            'name' => __('Feeds'),
            'element' => 'custom',
            'function' => $feedCell,
            'class' => 'text-nowrap',
        ),
    ),
    array(
        'key' => 'distribution',
        'label' => __('Distribution'),
        'shown' => true,
        'field' => array(
            'name' => __('Distribution'),
            /*
             * Not the shared `distribution` renderer over
             * `Attribute.distribution`, which is `Inherited` on almost
             * every row a real instance holds: the level a reader is
             * asking after is the conjunction of the attribute's, its
             * object's and its event's. The element draws the stamp the
             * model resolved, and the Overview card draws the same one.
             */
            'element' => 'value_distribution',
        ),
    ),
    array(
        'key' => 'context',
        'label' => __('Context'),
        'shown' => true,
        'field' => array(
            'name' => __('Context'),
            'element' => 'value_object_context',
            'object_name_path' => 'Object.name',
            'object_id_path' => 'Object.id',
            'relation_path' => 'Attribute.object_relation',
            'comment_path' => 'Attribute.comment',
            'spelled_path' => 'spelled',
        ),
    ),
    array(
        'key' => 'comment',
        'label' => __('Comment'),
        'shown' => false,
        'field' => array(
            'name' => __('Comment'),
            'data_path' => 'Attribute.comment',
            'empty' => '—',
        ),
    ),
    array(
        'key' => 'first-seen',
        'label' => __('First seen'),
        'shown' => false,
        'field' => array(
            'name' => __('First seen'),
            'element' => 'datetime',
            'data_path' => 'Attribute.first_seen',
            'format' => 'Y-m-d H:i',
            // The words, never a dash: "unknown" and "no value" are
            // different claims about an optional column.
            'empty' => __('Not set'),
        ),
    ),
    array(
        'key' => 'last-seen',
        'label' => __('Last seen'),
        'shown' => true,
        'field' => array(
            'name' => __('Last seen'),
            'element' => 'datetime',
            'data_path' => 'Attribute.last_seen',
            'format' => 'Y-m-d H:i',
            'empty' => __('Not set'),
        ),
    ),
    array(
        'key' => 'tags',
        'label' => __('Tags'),
        'shown' => true,
        'field' => array(
            'name' => __('Tags'),
            // Both scopes as one list — see `value_tag_list`, and the
            // Overview preview carries the same column.
            'element' => 'value_tag_list',
            'data_path' => 'AttributeTag',
            'event_data_path' => 'EventTag',
            'plan' => $labelPlan,
        ),
    ),
    /*
     * **Beside Tags and not inside it.** A cluster is not a label:
     * `tlp:amber` is a statement about handling and *APT29* is a
     * statement about who, and the Overview's card has drawn them
     * apart since it existed. One cell holding both would also have to
     * pick one `+N` over two kinds of thing.
     *
     * Last, because it is the widest cell on the row — an ATT&CK
     * technique's name runs to forty characters — and the column the
     * table can afford to let run to the edge is the last one.
     */
    array(
        'key' => 'galaxies',
        'label' => __('Galaxies'),
        'shown' => true,
        'field' => array(
            'name' => __('Galaxies'),
            'element' => 'value_cluster_list',
            'data_path' => 'Cluster',
            'max_visible' => 3,
            'plan' => $labelPlan,
        ),
    ),
);

$fields = array();
$shownColumns = 0;
foreach ($columns as $column) {
    $field = $column['field'];
    $classes = array('vp-occ-col-' . $column['key']);
    if (!$column['shown']) {
        $classes[] = 'd-none';
    } else {
        $shownColumns++;
    }
    if (!empty($field['class'])) {
        $classes[] = $field['class'];
    }
    // The same classes on the heading and on the cells, so hiding a
    // column takes its heading with it.
    $field['class'] = implode(' ', $classes);
    $field['header_class'] = implode(' ', $classes);
    /*
     * Every column is orderable, including the three that render a glyph
     * and no text — `$sortKeys` gives each row a token per column, so
     * what gets compared is the column's meaning rather than its cell.
     * `client_sort` and not `sort`: the latter is Paginator's and would
     * reload the page.
     */
    $field['client_sort'] = $column['key'];
    $fields[] = $field;
}

/*
 * Formatted and pluralised, to match the fact strip and the Overview's
 * card: all three read one aggregate now, and printing the same number
 * three ways is a difference a reader has to stop and rule out.
 *
 * `data-vp-list-shown` is rewritten by the page's own filtering, so it
 * carries the raw count rather than a formatted one — what the script
 * puts back has to be the same shape as what it found.
 */
$subtitle = implode(' &nbsp;·&nbsp; ', array(
    sprintf(
        __('Showing %1$s of %2$s occurrences'),
        '<span data-vp-list-shown>' . h($stats['shown']) . '</span>',
        h(number_format($stats['total']))
    ),
    h(sprintf(
        __n('%s event', '%s events', $stats['events']),
        number_format($stats['events'])
    )),
    h(sprintf(
        __n('%s organisation', '%s organisations', $stats['orgs']),
        number_format($stats['orgs'])
    )),
));

ob_start();
?>
    <div class="dropdown">
        <?php
        /*
         * `auto-close: outside` so ticking a column does not shut the
         * menu the reader is working through.
         */
        ?>
        <button class="btn btn-sm btn-outline-secondary dropdown-toggle"
                type="button" data-bs-toggle="dropdown"
                data-bs-auto-close="outside" aria-expanded="false">
            <i class="fas fa-table-columns me-1"></i>
            <?= sprintf(
                __('Columns (%1$s of %2$s)'),
                '<span data-vp-col-shown>' . h($shownColumns) . '</span>',
                h(count($columns))
            ) ?>
        </button>
        <ul class="dropdown-menu dropdown-menu-end shadow-sm">
            <?php foreach ($columns as $column): ?>
                <li>
                    <label class="dropdown-item d-flex align-items-center
                                  gap-2 mb-0">
                        <input type="checkbox" class="form-check-input mt-0"
                               data-vp-col="vp-occ-col-<?= h($column['key']) ?>"
                               <?= $column['shown'] ? 'checked' : '' ?>>
                        <?= h($column['label']) ?>
                    </label>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>

    <?= $this->element('Values/View/value_pager', array(
        'size' => $pageSize,
        'sizes' => $pageSizes,
        'shown' => count($rows),
        'total' => $stats['total'],
    )) ?>
<?php
$headerExtra = ob_get_clean();
?>
<div class="row"<?= empty($rows) ? '' : ' data-vp-list' ?>>

    <?php if (!empty($facets)): ?>
        <div class="col-lg-3">
            <?= $this->element('Values/View/value_occurrence_facets', array(
                'facets' => $facets,
            )) ?>
        </div>
    <?php endif; ?>

    <div class="<?= empty($facets) ? 'col-12' : 'col-lg-9' ?>">
        <div class="card shadow-sm mb-3 vp-panel"
             style="--vp-panel-color: var(--attribute);">

            <?= $this->element('Values/View/value_panel_header', array(
                'panelTitle' => __('Occurrences'),
                'panelIcon' => 'misp-icon misp-icon-attribute misp-simple',
                'panelColor' => 'var(--attribute)',
                'panelSub' => empty($rows) ? null : $subtitle,
                'panelExtra' => empty($rows) ? null : $headerExtra,
            )) ?>

            <?php if (empty($rows)): ?>
                <?php
                /*
                 * One empty state rather than an empty rail beside an
                 * empty table — and "no event you can see" rather than
                 * "no occurrences", because for a value-centric page the
                 * difference between absent and hidden is the point and
                 * only one of the two is knowable here.
                 */
                ?>
                <div class="vp-empty">
                    <span class="misp-icon misp-icon-attribute misp-simple">
                    </span>
                    <span><?= __(
                        'This value has no occurrences on this instance.'
                    ) ?></span>
                </div>
            <?php else: ?>

                <div class="card-body p-0" data-vp-list-rows>
                    <?= $this->element(
                        'genericElementsBS5/IndexTable/index_table',
                        array(
                            'scaffold_data' => array(
                                'data' => array(
                                    'data' => $rows,
                                    'fields' => $fields,
                                    'primary_id_path' => 'Attribute.id',
                                    'row_class_callable' => $rowClass,
                                    'row_data_callable' => $rowData,
                                ),
                            ),
                        )
                    ) ?>
                </div>

                <?php
                /*
                 * Only a filter can produce this. A value with no
                 * occurrences keeps the empty state above: "no rows
                 * match your filter" over it would be a different and
                 * false claim.
                 */
                ?>
                <div class="vp-empty d-none" data-vp-list-empty>
                    <i class="fas fa-filter"></i>
                    <span><?= __(
                        'No occurrence you can see matches these filters.'
                    ) ?></span>
                </div>

            <?php endif; ?>

            <?php if (!empty($profile['occurrence_cap'])): ?>
                <?php
                /*
                 * A cap, not a permission — which is why this band
                 * survived §14.6 and the ACL note that used to sit here
                 * did not. Every count on this panel is now the
                 * viewer's, so there is no gap between what the
                 * instance holds and what the table shows for the page
                 * to explain; what is left to say is that a value with
                 * tens of thousands of occurrences is not served whole,
                 * and how many of them the rail beside it describes.
                 *
                 * Both numbers, not a ratio. "1,000 of 33,110" is a
                 * fact the reader can act on; "3% shown" is not.
                 */
                ?>
                <div class="vp-acl-note">
                    <i class="fas fa-layer-group"></i>
                    <span><?= h(sprintf(
                        __(
                            'This table and the filters beside it'
                            . ' describe the %1$s most recent of %2$s'
                            . ' occurrences you can see.'
                        ),
                        $profile['occurrence_cap']['shown'],
                        $profile['occurrence_cap']['total']
                    )) ?></span>
                </div>
            <?php endif; ?>

        </div>

        <?php
        /*
         * **Below the table, and outside its card.** A value with no
         * occurrence keeps the table's own empty state — *this value
         * has no occurrences on this instance*, which is true and is
         * the answer to the question the tab asks — and this block then
         * says what does exist. Reversing the order would open the tab
         * on an exception before stating the rule.
         *
         * Outside `[data-vp-list-rows]` by construction, so the script
         * that filters, sorts and pages the table never sees these
         * rows: `value-intelligence.js` resolves a list's rows through that
         * host, and a block that wanted its own sorting would declare
         * its own `data-vp-list`. This one is short and has no rail to
         * disagree with.
         */
        ?>
        <?php if (!empty($profile['standalone_proposals'])): ?>
            <?= $this->element(
                'Values/View/value_standalone_proposals',
                array('proposals' => $profile['standalone_proposals'])
            ) ?>
        <?php endif; ?>

    </div>
</div>
