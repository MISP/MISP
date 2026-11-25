<?php
/**
 * The Occurrences tab, drawn as the event view's Attributes tab: the
 * shared index filter bar, the count line and pager, then the Overview
 * card's table over one page of the value's occurrences.
 *
 * Filtered and paged on the server (ValuesController::viewOccurrenceTable);
 * the bar reloads this fragment in its tab. The pickers offer what the
 * reader's occurrences carry, counted by `Value::occurrenceFacetsFor`
 * beside the other filters; the Period draws its strip across the bar.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 * @var array $filterLabels IndexPicker::resolve() for the chosen tags and clusters
 */
App::uses('DistributionLevel', 'Tools');
App::uses('IndexFilterState', 'Tools');

$profile = $valueIntelligence;
$rows = $profile['occurrences'];
$stats = $profile['occurrence_stats'];
$facets = $profile['occurrence_facets'];
$named = $this->request->params['named'] ?? array();
$tabUrl = $baseurl . '/values/viewOccurrenceTable/' . $valueB64;
$filterLabels = $filterLabels ?? array('tag' => array(), 'galaxy' => array());
$canGraph = $this->Acl->canAccess('collectionElements', 'addItems');

$group = __('Occurrences');
$set = function ($name) use ($named) {
    return isset($named[$name]) && !is_array($named[$name]) && (string)$named[$name] !== ''
        ? (string)$named[$name] : null;
};
/*
 * A column as the list of its values in the Filters panel, each with the
 * rows it keeps beside the other filters and a bar for its share. The
 * value set is listed even when nothing beside the others carries it.
 */
$list = function ($name, $label, array $counts, array $labels, array $html = array(), $icon = null) use ($group, $set) {
    $picked = $set($name);
    if ($picked !== null && !isset($labels[$picked])) {
        $labels[$picked] = $picked;
    }
    return array(
        'type' => 'dropdown',
        'display' => 'list',
        'name' => $name,
        'label' => $label,
        'icon' => $icon,
        'options' => array('' => __('Any')) + $labels,
        'counts' => $counts,
        'html' => $html,
        'fold' => 7,
        'group' => $group,
    );
};
$facet = function ($key) use ($facets) {
    return isset($facets[$key]) ? $facets[$key] : array();
};

$orgs = $orgHtml = array();
foreach ($facet('org') as $orgId => $count) {
    $name = $facets['org_names'][$orgId] ?? ('#' . $orgId);
    $orgs[(string)$orgId] = $name;
    $orgHtml[(string)$orgId] = $this->EventIndex->orgTile(array('id' => $orgId, 'name' => $name), 16)
        . '<span>' . h($name) . '</span>';
}
if ($set('org') !== null && !isset($orgs[$set('org')]) && isset($facets['org_names'][$set('org')])) {
    $orgs[$set('org')] = $facets['org_names'][$set('org')];
}
$types = $typeHtml = array();
foreach ($facet('type') as $type => $count) {
    $types[$type] = $type;
    $typeHtml[$type] = '<span class="ifp-lv-code">' . h($type) . '</span>';
}
$categories = array();
foreach ($facet('category') as $category => $count) {
    $categories[$category] = $category;
}
$objects = $objectCounts = $objectHtml = array();
foreach ($facet('object') as $name => $count) {
    $key = $name === '' ? '0' : $name;
    $objects[$key] = $name === '' ? __('Standalone attribute') : $name;
    $objectCounts[$key] = $count;
    $objectHtml[$key] = $name === ''
        ? '<span class="text-body-secondary fst-italic">' . h(__('Standalone attribute')) . '</span>'
        : '<i class="misp-icon misp-icon-object misp-simple" aria-hidden="true"></i><span>' . h($name) . '</span>';
}
$distributions = array();
foreach ($facet('distribution') as $level => $count) {
    $distributions[(string)$level] = DistributionLevel::get($level)['label'];
}
// The flag is stored 1 / 0 and filtered on as 1 / 2.
$idsCounts = array();
foreach ($facet('ids') as $flag => $count) {
    $idsCounts[(string)$flag === '1' ? '1' : '2'] = $count;
}
$idsHtml = array(
    '1' => '<i class="fas fa-shield-halved text-success" aria-hidden="true"></i><span>' . h(__('Flagged for detection')) . '</span>',
    '2' => '<i class="fas fa-shield text-body-secondary" aria-hidden="true"></i><span>' . h(__('Not flagged')) . '</span>',
);
$idsLabels = array();
foreach (array('1' => __('Yes'), '2' => __('No')) as $flag => $text) {
    if (isset($idsCounts[$flag])) {
        $idsLabels[$flag] = $text;
    }
}

// The tags and clusters most rows carry, under their picker; the row is the
// link, so the chip is not one.
$view = $this;
$unlinked = array('searchUrl' => '', 'href' => function () {
    return null;
});
$topOf = function ($key) use ($facets, $view, $unlinked) {
    $labels = $facets['labels'][$key] ?? array('rows' => array(), 'total' => 0);
    $top = array();
    foreach ($labels['rows'] as $tag) {
        if ($key === 'galaxy' && !empty($tag['cluster'])) {
            $label = $tag['cluster']['value'];
            $html = $view->TagChip->cluster(array(
                'id' => $tag['cluster']['id'],
                'value' => $tag['cluster']['value'],
                'galaxy' => $tag['cluster']['galaxy'],
            ), array('display' => 'leaf') + $unlinked)
                . '<span class="text-body-secondary small">' . h($tag['cluster']['galaxy']) . '</span>';
        } else {
            $label = $tag['name'];
            $html = $view->TagChip->chip(array('Tag' => $tag), array('inline' => true) + $unlinked);
        }
        $top[] = array('value' => $tag['name'], 'label' => $label, 'html' => $html, 'count' => $tag['count']);
    }
    return array($top, $labels['total'] ?? null);
};
list($topTags, $topTagsTotal) = $topOf('tags');
list($topClusters, $topClustersTotal) = $topOf('galaxy');

$children = array(
    array(
        'type' => 'search',
        'mode' => 'legacy',
        'name' => 'q',
        'button' => __('Search'),
        'chip_label' => __('Search'),
        'placeholder' => __('Filter by event, comment or UUID'),
    ),
    array(
        'key' => 'event',
        'label' => __('Event'),
        'shown' => true,
        'field' => array(
            'name' => __('Event'),
            // Its id and icon, a peek on hover; the class reaches the heading too.
            'element' => 'event_peek',
            'data_path' => 'Event.id, Event.info',
            'class' => 'idx-col-event_peek',
        ),
    ),
);
$children[] = array(
    'type' => 'picker',
    'name' => 'galaxy',
    'label' => __('Galaxy'),
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
    'source' => $baseurl . '/galaxy_clusters/pickerSearch',
    'separator' => '||',
    'resolved' => $filterLabels['galaxy'],
    'hint' => __('Clusters on the occurrence or its event.'),
    'group' => $group,
    'top' => $topClusters,
    'top_total' => $topClustersTotal,
    'browser' => array(
        'kind' => 'galaxy',
        'scopes' => $baseurl . '/galaxies/pickerScopes',
    ),
);

// The period, on the dates the old facet rail offered.
$timePresets = array(
    array('value' => '7d', 'label' => __('7d'), 'title' => __('last 7 days')),
    array('value' => '30d', 'label' => __('30d'), 'title' => __('last 30 days')),
    array('value' => '90d', 'label' => __('90d'), 'title' => __('last 90 days')),
    array('value' => '365d', 'label' => __('1y'), 'title' => __('last year')),
);
$children[] = array(
    'type' => 'time',
    'name' => 'time',
    'label' => __('Period'),
    'icon' => 'far fa-clock',
    'fields' => array(
        array('name' => 'changed', 'label' => __('Changed')),
        array('name' => 'created', 'label' => __('Created')),
        array('name' => 'seen', 'label' => __('Last seen')),
        array('name' => 'published', 'label' => __('Event published')),
    ),
    'presets' => $timePresets,
    'group' => $group,
    // The strip across the bar: each date's rows by day, week or month.
    'histograms' => $facet('times'),
    'strip_label' => __('When'),
    'note' => __('The strip in the bar keeps a period; here, presets, exact dates, and several dates at once.'),
);
$timeTitles = array_column($timePresets, 'title', 'value');
$timeLabel = function ($value) use ($timeTitles) {
    if (isset($timeTitles[$value])) {
        return $timeTitles[$value];
    }
    $range = explode('|', str_replace('||', '|', (string)$value), 2);
    if (count($range) === 2) {
        $from = $range[0] === '' || $range[0] === '0' ? '…' : substr($range[0], 0, 10);
        $to = $range[1] === '' ? '…' : substr($range[1], 0, 10);
        return $from . ' – ' . $to;
    }
    return sprintf(__('since %s'), $value);
};

// The toggles keep every other filter of the tab, as on the event's Attributes tab.
$tabState = new IndexFilterState($tabUrl, $named);
$currentDeleted = (int)($named['deleted'] ?? 0);
$currentProposal = (int)($named['proposal'] ?? 0);
$children[] = array(
    'type' => 'button',
    'url' => $tabState->url(array('proposal' => $currentProposal ? null : 1)),
    'class' => 'btn ' . ($currentProposal ? 'btn-warning' : 'btn-outline-warning'),
    'icon' => 'fas fa-comment-dots',
    'label' => __('Proposals'),
    'count' => (int)$stats['proposals'],
    'pressed' => (bool)$currentProposal,
);
$children[] = array(
    'type' => 'button',
    'url' => $tabState->url(array('deleted' => $currentDeleted ? null : 2)),
    'class' => 'btn ' . ($currentDeleted ? 'btn-danger' : 'btn-outline-danger'),
    'icon' => 'fas fa-trash',
    'label' => __('Deleted'),
    'count' => (int)$stats['deleted'],
    'pressed' => (bool)$currentDeleted,
);

$filterBar = array(
    'pull' => 'right',
    'children' => $children,
    'base_url' => $tabUrl,
    'view_switch' => false,
    'chips' => array(
        'labels' => array(
            'deleted' => __('Deleted'),
            'proposal' => __('Proposals'),
            'changed' => __('Changed'),
            'created' => __('Created'),
            'seen' => __('Last seen'),
            'published' => __('Event published'),
        ),
        'values' => array(
            'deleted' => array('1' => __('included'), '2' => __('only')),
            'proposal' => array('1' => __('only')),
            'changed' => $timeLabel,
            'created' => $timeLabel,
            'seen' => $timeLabel,
            'published' => $timeLabel,
        ),
    ),
    'mass_sighting' => true,
    'mass_graph' => $canGraph,
);

echo $this->element('genericElementsBS5/IndexTable/scaffold', array(
    'scaffold_data' => array(
        'data' => array(
            'data' => $rows,
            'table_class' => 'ai-table vp-occ-table',
            // No table/card switch here, so no card view to render.
            'card_view' => false,
            'primary_id_path' => 'Attribute.id',
            'row_class_callable' => function ($row) {
                return empty($row['Attribute']['deleted']) ? '' : 'attr-deleted';
            },
            'filter_bar' => $filterBar,
            'fields' => $this->ValueOccurrence->fields(array(
                'plan' => $profile['label_plan'],
                'select' => true,
                'sortable' => true,
                'feeds' => !empty($profile['feeds_shown']),
                'seen' => true,
            )),
        ),
    ),
    'item_url' => '/values',
));

if (!empty($profile['standalone_proposals'])) {
    echo $this->element('Values/View/value_standalone_proposals', array(
        'proposals' => $profile['standalone_proposals'],
    ));
}
