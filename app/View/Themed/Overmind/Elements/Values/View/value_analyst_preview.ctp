<?php
/**
 * The Overview's preview of the Collaboration tab, drawn as the event
 * overview's Assessment card: the counts and a link to the tab in the
 * header, then the newest notes and opinions through the shared
 * AnalystData/thread, replies folded under them. Read-only: analyst data
 * is written from the tab.
 *
 * Off `ValueIntelligence::forAnalystPreview`, the union the tab reads, so
 * the counts here and on the tab agree.
 *
 * Lazily loaded from ValuesController::viewAnalystPreview.
 *
 * @var array $valueIntelligence
 */
$analyst = $valueIntelligence['analyst'];
$counts = $analyst['counts'];
$items = $analyst['preview'];
$standing = isset($analyst['standing']) ? $analyst['standing'] : null;
$notes = (int)$counts['notes'];
$opinions = (int)$counts['opinions'];
$proposals = (int)$counts['proposals'];
$reports = (int)$counts['reports'];
$written = $notes + $opinions;
$shown = count($items);

// Analyst data on the value itself is keyed by the SHA-256 of its text.
$hex = hash('sha256', (string)$valueIntelligence['value']);

/**
 * One item of the value's union, in the shape AnalystData/thread reads.
 *
 * @param array $item
 * @return array
 */
$threadRow = function (array $item) use (&$threadRow) {
    $row = array(
        'id' => isset($item['id']) ? $item['id'] : null,
        'uuid' => isset($item['uuid']) ? $item['uuid'] : null,
        'created' => isset($item['created']) ? $item['created'] : $item['date'],
        'distribution' => $item['distribution'],
        'authors' => $item['author'],
        'Orgc' => array('name' => $item['org']),
        '_canEdit' => !empty($item['can_edit']),
        '_max_depth_reached' => !empty($item['max_depth_reached']),
        'Note' => array(),
        'Opinion' => array(),
    );
    if ($item['kind'] === 'opinion') {
        $row['opinion'] = (int)$item['score'];
        $row['comment'] = $item['body'];
    } else {
        $row['note'] = $item['body'];
    }
    $children = isset($item['children']) ? $item['children'] : array();
    foreach ($children as $child) {
        $row[$child['kind'] === 'opinion' ? 'Opinion' : 'Note'][] = $threadRow($child);
    }
    return $row;
};
$thread = array(
    'Note' => array(),
    'Opinion' => array(),
    'Relationship' => array(),
    'RelationshipInbound' => array(),
);
foreach ($items as $item) {
    $thread[$item['kind'] === 'opinion' ? 'Opinion' : 'Note'][] = $threadRow($item);
}

$facts = array();
if ($notes > 0) {
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-note misp-simple"></i>'
        . h(sprintf(__n('%s note', '%s notes', $notes), number_format($notes)))
        . '</span>';
}
if ($opinions > 0) {
    $aggregate = isset($standing['aggregate']) ? $standing['aggregate'] : null;
    $mean = !empty($aggregate['n']) ? $aggregate['mean'] : null;
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-analyst-opinion misp-simple"></i>'
        . h(sprintf(__n('%s opinion', '%s opinions', $opinions), number_format($opinions)))
        . ($mean === null ? '' : ' <span class="eo-muted" title="'
            . h(__('Mean of the opinions that rate the value')) . '">'
            . h(sprintf(__('avg. %s/100'), (int)round($mean))) . '</span>')
        . '</span>';
}
if ($proposals > 0) {
    $facts[] = '<span class="eo-fact"><i class="fas fa-code-pull-request"></i>'
        . h(sprintf(__n('%s proposal', '%s proposals', $proposals), number_format($proposals)))
        . '</span>';
}
if ($reports > 0) {
    // A report attaches to an event, never to the value: the phrase says so.
    $facts[] = '<span class="eo-fact"><i class="misp-icon misp-icon-report misp-simple"></i>'
        . h(sprintf(
            __n('%s report on its events', '%s reports on its events', $reports),
            number_format($reports)
        ))
        . '</span>';
}
// Nothing on the tab means nothing to open.
if ($written > 0 || $proposals > 0 || $reports > 0) {
    $facts[] = '<a class="eo-fact vp-head-link" href="#tab-analyst">'
        . h($shown > 0 && $shown < $written
            ? sprintf(__('Latest %s · open the thread'), $shown)
            : __('Open the thread'))
        . ' <i class="fas fa-arrow-right" aria-hidden="true"></i></a>';
}
$subtitle = empty($facts)
    ? null
    : '<span class="eo-assessment-facts">' . implode('', $facts) . '</span>';

$headerExtra = '';
if ($shown > 0) {
    $headerExtra .= '<div class="input-group input-group-sm eo-filter">'
        . '<span class="input-group-text border-end-0">'
        . '<i class="fas fa-search text-muted small"></i></span>'
        . '<input type="search" class="form-control border-start-0 ps-0"'
        . ' data-vp-analyst-filter autocomplete="off"'
        . ' placeholder="' . h(__('Filter notes, opinions…')) . '"'
        . ' aria-label="' . h(__('Filter analyst data')) . '">'
        . '</div>';
}

// Nobody wrote here, but the tab may still hold proposals or reports.
$elsewhere = array_filter(array(
    $proposals > 0 ? __('proposals on it') : null,
    $reports > 0 ? __('event reports on its events') : null,
));
$emptyText = empty($elsewhere)
    ? __('No analyst has written about this value.')
    : sprintf(
        __('Nobody has written a note or an opinion about this value, but there are %s.'),
        implode(__(' and '), $elsewhere)
    );
?>
<div class="card shadow-sm mb-3 vp-panel eo-assessment vp-analyst-card"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-preview>
    <?= $this->element('Values/View/value_analyst_tab_badge', array(
        'counts' => $counts,
    )) ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Analyst data'),
        'panelIcon' => 'misp-icon misp-icon-analyst-note misp-simple',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra === '' ? null : $headerExtra,
    )) ?>

    <?php if ($shown > 0): ?>
        <div class="eo-assessment-thread" data-collapse-tall="350" data-collapse-peek="[data-collapse-peek-label]">
            <?= $this->element('AnalystData/thread', array(
                'analystData' => $thread,
                'objectType' => 'AttributeValue',
                'objectUuid' => $hex,
                'peek' => true,
                'showEmpty' => false,
                // Written from the Collaboration tab, not from here.
                'reply' => false,
            )) ?>
        </div>
        <div class="eo-empty d-none" data-vp-analyst-none><?= __('No analyst data matches.') ?></div>
    <?php else: ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-analyst-note misp-simple"></span>
            <span><?= h($emptyText) ?></span>
        </div>
    <?php endif; ?>
</div>
