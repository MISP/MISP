<?php
App::uses('AnalystData', 'Model');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/**
 * What a note, an opinion or a relationship points at, drawn by its kind: an
 * event as its id and icon with its peek (Events/peek_link) and its title; an
 * attribute, an object or a report as itself, over the event it belongs to; a
 * cluster as its chip; the rest by name behind the kind's icon. A target the
 * user cannot open keeps its kind and address, without a link.
 *
 * Parameters:
 *   type     string      the target's type (object_type, related_object_type)
 *   address  string      its uuid, or the SHA-256 of a value's text
 *   target   array|null  its entry in AnalystData::describeTargets(); null
 *                        when it is not on this instance or not visible
 */
$type = (string)($type ?? '');
$address = (string)($address ?? '');
$target = $target ?? null;
$record = $target['record'] ?? [];

$kinds = [
    'Event' => ['misp-icon misp-icon-event misp-simple', 'event', __('Event')],
    'Attribute' => ['misp-icon misp-icon-attribute misp-simple', 'attribute', __('Attribute')],
    'Object' => ['misp-icon misp-icon-object misp-simple', 'object', __('Object')],
    'EventReport' => ['misp-icon misp-icon-report misp-simple', 'report', __('Event report')],
    'GalaxyCluster' => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy', __('Galaxy cluster')],
    'Galaxy' => ['misp-icon misp-icon-galaxy misp-simple', 'galaxy', __('Galaxy')],
    'Note' => ['misp-icon misp-icon-analyst-note misp-simple', 'analystData', __('Note')],
    'Opinion' => ['misp-icon misp-icon-analyst-opinion misp-simple', 'analystData', __('Opinion')],
    'Relationship' => ['fas fa-diagram-project', 'analystData', __('Relationship')],
    'Organisation' => ['misp-icon misp-icon-organisation misp-simple', 'primary', __('Organisation')],
    'SharingGroup' => ['misp-icon misp-icon-sharing-group misp-simple', 'primary', __('Sharing group')],
    'Collection' => ['fas fa-layer-group', 'primary', __('Collection')],
    'Graph' => ['misp-icon misp-icon-analyst-graph misp-simple', 'analystGraph', __('Saved graph')],
    'AttributeValue' => ['misp-icon misp-icon-value-intelligence misp-simple', 'valueIntelligence', __('Value')],
];
list($icon, $colour, $kindLabel) = $kinds[$type] ?? ['fas fa-link', 'secondary', $type !== '' ? $type : __('Object')];

$tile = function ($missing = false) use ($icon, $kindLabel) {
    return sprintf(
        '<span class="adt-kind%s" title="%s"><i class="%s" aria-hidden="true"></i></span>',
        $missing ? ' is-missing' : '',
        h($kindLabel),
        h($icon)
    );
};
// The event an attribute, object or report sits in: its peek, then its title.
$inEvent = function () use ($target) {
    if (empty($target['event']['id'])) {
        return '';
    }
    return '<span class="adt-in"><span class="adt-in-word">' . h(__('in')) . '</span>'
        . $this->element('Events/peek_link', ['id' => $target['event']['id'], 'info' => $target['event']['info']])
        . '<span class="adt-in-info" title="' . h($target['event']['info']) . '">' . h($target['event']['info']) . '</span>'
        . '</span>';
};
$piece = function ($text, $class = '') {
    return $text === '' || $text === null ? '' : '<span class="adt-piece ' . $class . '">' . h($text) . '</span>';
};

if ($address === '') {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
if (empty($this->viewVars['_analystTargetAssets'])) {
    $this->viewVars['_analystTargetAssets'] = true;
    echo $this->element('genericElements/assetLoader', ['css' => ['analyst-target']]);
}

if ($target === null) {
    $isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
    $why = $isValue
        ? __('This value could not be resolved, so it is shown by the SHA-256 of its text.')
        : __('This %s is not on this instance, or is not visible to you.', strtolower($kindLabel));
    ?>
    <div class="adt is-missing" style="--adt-c: var(--bs-secondary-color)" title="<?= h($why) ?>">
        <?= $tile(true) ?>
        <div class="adt-body">
            <div class="adt-main">
                <span class="adt-missing-kind"><?= h($kindLabel) ?></span>
                <span class="adt-missing-note"><?= h($isValue ? __('unresolved') : __('not available here')) ?></span>
            </div>
            <div class="adt-sub"><span class="adt-address"><?= h($address) ?></span></div>
        </div>
    </div>
    <?php
    return;
}

$main = $sub = '';
$lead = $tile();
switch ($type) {
    case 'Event':
        $lead = $this->element('Events/peek_link', ['id' => $record['id'], 'info' => $record['info']]);
        $main = sprintf(
            '<a class="adt-label" href="%s" title="%s">%s</a>',
            h($baseurl . '/events/view/' . $record['id']),
            h($record['info']),
            h($record['info'])
        );
        $count = (int)($record['attribute_count'] ?? 0);
        $sub = $piece($record['date'] ?? '', 'adt-date')
            . $piece(__n('%s attribute', '%s attributes', $count, $count));
        break;

    case 'Attribute':
        $main = $this->element('genericElementsBS5/Badges/type', ['type' => $record['type']])
            . sprintf(
                '<a class="adt-label adt-mono" href="%s" title="%s">%s</a>',
                h($baseurl . '/attributes/view/' . $record['id']),
                h($record['value']),
                h($record['value'])
            );
        $sub = $piece($record['category'] ?? '') . $inEvent();
        break;

    case 'Object':
        $headline = $target['headline'] ?? null;
        $count = (int)($target['count'] ?? 0);
        $main = '<a class="adt-label ov-obj-name" href="' . h($baseurl . '/objects/view/' . $record['id']) . '">'
            . $this->element('Objects/meta_category', ['meta' => $record['meta-category'] ?? ''])
            . '<span class="text-truncate">' . h($record['name']) . '</span></a>'
            . '<span class="ov-obj-count" title="' . h(__n('%s attribute', '%s attributes', $count, $count)) . '">'
            . '<span class="misp-icon misp-icon-attribute misp-simple"></span>' . $count . '</span>';
        if ($headline !== null) {
            $sub = '<span class="ov-obj-first" title="' . h($headline['relation'] . ': ' . $headline['value']) . '">'
                . '<span class="ov-obj-first-rel">' . h($headline['relation']) . '</span>'
                . '<span class="ov-obj-first-val">' . h($headline['value']) . '</span></span>';
        }
        $sub .= $inEvent();
        break;

    case 'EventReport':
        $main = sprintf(
            '<a class="adt-label" href="%s" title="%s">%s</a>',
            h($baseurl . '/eventReports/view/' . $record['id']),
            h($record['name']),
            h($record['name'])
        );
        $sub = $inEvent();
        break;

    case 'GalaxyCluster':
        $main = $this->element('genericElementsBS5/Badges/galaxy_cluster', [
            'cluster' => $record,
            'link' => true,
            'showGalaxy' => false,
        ]);
        $sub = $piece($record['Galaxy']['name'] ?? '')
            . $piece(mb_strimwidth(trim((string)($record['description'] ?? '')), 0, 160, '…'), 'adt-text');
        break;

    case 'AttributeValue':
        $main = sprintf(
            '<a class="adt-label adt-mono" href="%s" title="%s">%s</a>',
            h($baseurl . '/values/view/' . ValueUrlTool::address($target['value'])),
            h($target['value']),
            h($target['label'])
        );
        $sub = $piece($kindLabel);
        break;

    case 'Note':
        $main = sprintf(
            '<a class="adt-label adt-clamp" href="%s" title="%s">%s</a>',
            h($baseurl . '/analystData/view/Note/' . $address),
            h($record['note']),
            h($target['label'])
        );
        $sub = $piece($kindLabel) . $piece($record['language'] ?? '') . $piece($record['authors'] ?? '');
        break;

    case 'Opinion':
        $main = $this->element('AnalystData/stance', ['score' => $record['opinion'] ?? 50]);
        if (($record['comment'] ?? '') !== '') {
            $main .= sprintf(
                '<a class="adt-label" href="%s" title="%s">%s</a>',
                h($baseurl . '/analystData/view/Opinion/' . $address),
                h($record['comment']),
                h($target['label'])
            );
        }
        $sub = $piece($kindLabel);
        break;

    case 'Relationship':
        $main = sprintf(
            '<a class="adt-label adt-mono" href="%s">%s</a>',
            h($baseurl . '/analystData/view/Relationship/' . $address),
            h($record['relationship_type'] ?? '')
        );
        $sub = $piece($kindLabel)
            . $piece(!empty($record['related_object_type']) ? __('to %s', $record['related_object_type']) : '');
        break;

    case 'Organisation':
        $lead = '<span class="adt-logo">' . $this->OrgImg->getOrgLogoV2($record, 22) . '</span>';
        $main = sprintf(
            '<a class="adt-label" href="%s">%s</a>',
            h($baseurl . '/organisations/view/' . $record['id']),
            h($record['name'])
        );
        $sub = $piece($kindLabel) . $piece($record['type'] ?? '');
        break;

    default:
        $paths = [
            'SharingGroup' => '/sharing_groups/view/' . ($record['id'] ?? ''),
            'Galaxy' => '/galaxies/view/' . ($record['id'] ?? ''),
            'Collection' => '/collections/view/' . $address,
            'Graph' => '/analyst_graphs/view/' . $address,
        ];
        $main = sprintf(
            '<a class="adt-label" href="%s">%s</a>',
            h($baseurl . ($paths[$type] ?? '/' . Inflector::tableize($type) . '/view/' . $address)),
            h($target['label'] !== '' ? $target['label'] : $kindLabel)
        );
        $sub = $piece($kindLabel) . $piece($record['type'] ?? '');
}
?>
<div class="adt" data-kind="<?= h($type) ?>" style="--adt-c: var(--bs-<?= h($colour) ?>)">
    <?= $lead ?>
    <div class="adt-body">
        <div class="adt-main"><?= $main ?></div>
        <?php if ($sub !== ''): ?>
            <div class="adt-sub"><?= $sub ?></div>
        <?php endif; ?>
    </div>
</div>
