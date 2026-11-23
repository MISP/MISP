<?php
/**
 * The Relationships tab's Object relationships: MISP's object references
 * that reach this value, at one of its attributes or through an object it
 * sits in, folded by the record at their other end. Each record is drawn as
 * the objects index draws it (an object opens on its attributes; an
 * attribute is its value and type), with every relationship linking it to
 * this value as a chip: its direction, how often it repeats over the
 * occurrences, and which object of this value it starts from.
 *
 * A reference relating the value to itself is not listed. The relationship
 * type is printed verbatim: it is whatever the event's author typed.
 *
 * Lazily loaded from ValuesController::viewRelationReferences.
 *
 * @var array $valueIntelligence
 */
$references = $valueIntelligence['relationships']['references'];
$records = $references['records'] ?? array();
$events = $references['event_peeks'] ?? array();
$pageSize = max(1, (int)($references['page_size'] ?? 8));

$byKind = array('object' => 0, 'attribute' => 0);
foreach ($records as $record) {
    $byKind[$record['kind']]++;
}

$arrows = array(
    'out' => array('fas fa-arrow-right-long', __('This value\'s object names it')),
    'in' => array('fas fa-arrow-left-long', __('It names this value')),
    'both' => array('fas fa-arrows-left-right', __('Both ways')),
);

/**
 * One relationship as a chip: its direction, its type verbatim, ×N where
 * it repeats over this value's occurrences.
 *
 * @param array $link
 * @return string
 */
$linkChip = function (array $link) use ($arrows) {
    list($icon, $sense) = $arrows[$link['direction']];
    $title = $sense . (empty($link['comments']) ? '' : "\n" . implode("\n", $link['comments']));
    return '<span class="vp-ref-link' . ($link['named'] ? '' : ' is-unnamed') . '" title="' . h($title) . '">'
        . '<i class="' . h($icon) . '" aria-hidden="true"></i>'
        . '<span>' . h($link['relationship']) . '</span>'
        . ($link['times'] > 1 ? '<span class="vp-ref-link-n">&times;' . (int)$link['times'] . '</span>' : '')
        . '</span>';
};

/**
 * Which records of this value the links start from.
 *
 * @param array $links
 * @return string
 */
$viaLine = function (array $links) {
    $nears = array();
    foreach ($links as $link) {
        $nears[$link['near'] === null ? '' : $link['near']] = true;
    }
    $words = array();
    foreach (array_keys($nears) as $near) {
        $words[] = $near === ''
            ? __('its occurrences')
            : sprintf(__('its %s object'), $near);
    }
    return '<div class="vp-ref-via">' . h(sprintf(__('via %s'), implode(', ', $words))) . '</div>';
};

$attrHead = '<thead><tr><th>' . h(__('Value')) . '</th><th>' . h(__('Category')) . '</th><th>'
    . h(__('Type')) . '</th><th class="text-center">' . h(__('IDS')) . '</th></tr></thead>';

$sub = '<span class="vp-rel-tag me-1"><i class="fas fa-diagram-project"></i>' . h(__('References')) . '</span>';
if (!empty($records)) {
    $sub .= h(sprintf(
        __('%1$s · %2$s'),
        __n('%s record linked', '%s records linked', count($records), number_format(count($records))),
        __n('%s reference', '%s references', $references['total'], number_format($references['total']))
    )) . ' · ';
}
$sub .= '<span class="vp-rel-prov vp-rel-prov-human"><i class="fas fa-user-pen"></i>'
    . h(__('Written by the event\'s authors')) . '</span>';

$switch = null;
if ($byKind['object'] > 0 && $byKind['attribute'] > 0) {
    $switch = '<div class="vp-seg" role="group" aria-label="' . h(__('Kind')) . '"'
        . ' data-vp-filter-seg data-vp-filter-key="refkind" data-vp-value="">';
    foreach (array(
        '' => sprintf(__('All %s'), count($records)),
        'object' => sprintf(__('Objects %s'), $byKind['object']),
        'attribute' => sprintf(__('Attributes %s'), $byKind['attribute']),
    ) as $key => $label) {
        $switch .= '<button type="button" class="vp-seg-btn' . ($key === '' ? ' active' : '') . '"'
            . ' data-vp-pill="' . h($key) . '" aria-pressed="' . ($key === '' ? 'true' : 'false') . '">'
            . h($label) . '</button>';
    }
    $switch .= '</div>';
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-reference"
     style="--vp-panel-color: var(--vp-rel-reference);"
     id="vp-relation-references"
     data-vp-list
     data-vp-rel-summary="references"
     data-vp-rel-count="<?= h(number_format($references['total'])) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Object relationships'),
        'panelIcon' => 'fas fa-diagram-project',
        'panelColor' => 'var(--vp-rel-reference)',
        'panelSub' => $sub,
        'panelExtra' => $switch,
    )) ?>

    <?php if (empty($records)): ?>
        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-diagram-project" aria-hidden="true"></i>
                <span>
                    <?php if ($references['read_objects'] === 0 && $references['occurrences'] === 0): ?>
                        <?= __('No occurrence of this value that you can see, so there is nothing for a reference to point at.') ?>
                    <?php elseif ($references['with_references'] > 0): ?>
                        <?= h(__n(
                            'One of this value\'s objects carries a reference, and it points back at this value.',
                            '%s of this value\'s objects carry references, and they all point back at this value.',
                            $references['with_references'],
                            number_format($references['with_references'])
                        )) ?>
                    <?php else: ?>
                        <?= __('Nothing references this value, and nothing it sits in references anything.') ?>
                    <?php endif; ?>
                </span>
            </div>
        </div>
    <?php else: ?>
        <div class="table-responsive" data-vp-list-rows>
            <table class="table align-middle mb-0 ix-table oi-table vp-ref-table">
                <thead>
                    <tr>
                        <th><?= __('The other end') ?></th>
                        <th><?= __('Relationship') ?></th>
                        <th><?= __('Event') ?></th>
                        <th><?= __('Creator org') ?></th>
                    </tr>
                </thead>
                <?php foreach ($records as $index => $record): ?>
                    <?php
                    $event = $events[$record['event']] ?? array('id' => $record['event']);
                    $org = $event['Orgc'] ?? null;
                    $isObject = $record['kind'] === 'object';
                    $attributes = $record['attributes'] ?? array();
                    // The header names the first value MISP links on, in the template's order.
                    $linking = array();
                    foreach ($record['values'] as $face) {
                        $linking[$face['relation'] . "\0" . $face['value']] = true;
                    }
                    $first = null;
                    foreach ($isObject ? $attributes : array() as $attribute) {
                        if (isset($linking[$attribute['relation'] . "\0" . $attribute['value']])) {
                            $first = $attribute;
                            break;
                        }
                    }
                    if ($first === null) {
                        $first = $isObject && !empty($attributes)
                            ? $attributes[0]
                            : ($record['values'][0] ?? null);
                    }
                    $text = array($record['name'], '#' . $record['event'], $event['info'] ?? '');
                    foreach ($record['links'] as $link) {
                        $text[] = $link['relationship'];
                    }
                    foreach ($isObject ? $attributes : $record['values'] as $attribute) {
                        $text[] = $attribute['value'];
                    }
                    ?>
                    <tbody data-vp-list-row<?= $isObject ? ' data-vp-obj' : '' ?>
                           data-vp-facet="refkind:<?= h($record['kind']) ?>"
                           data-vp-text="<?= h(mb_strtolower(implode(' ', $text))) ?>"
                           <?= $index >= $pageSize ? 'class="d-none"' : '' ?>>
                        <tr>
                            <td class="oi-col-object">
                                <div class="oi-object">
                                    <?php if ($isObject): ?>
                                        <button type="button" class="oi-expand" data-vp-obj-disc aria-expanded="false"
                                                title="<?= h(__('Show its attributes')) ?>">
                                            <i class="fas fa-chevron-right" aria-hidden="true"></i>
                                        </button>
                                        <?= $this->element('Objects/object_header', array(
                                            'object' => array(
                                                'name' => $record['name'],
                                                'meta-category' => $record['meta-category'] ?? '',
                                                'template_version' => $record['template_version'] ?? null,
                                                'distribution' => $record['distribution'] ?? 0,
                                                'timestamp' => $record['timestamp'] ?? 0,
                                            ),
                                            'ctx' => array(
                                                'count' => count($attributes),
                                                'deleted' => false,
                                                'firstValue' => $first === null ? '' : (string)$first['value'],
                                                'firstRelation' => $first === null ? '' : (string)$first['relation'],
                                            ),
                                        )) ?>
                                    <?php else: ?>
                                        <span class="oi-expand vp-ref-noexpand" aria-hidden="true"></span>
                                        <span class="vp-ref-attr">
                                            <span class="vp-ref-attr-value font-monospace"><?= h($first['value'] ?? '') ?></span>
                                            <?= $this->element('genericElementsBS5/Badges/type', array('type' => $first['type'] ?? '')) ?>
                                            <?php if (!empty($record['name'])): ?>
                                                <span class="vp-ref-attr-in"><?= h(sprintf(__('in a %s object'), $record['name'])) ?></span>
                                            <?php endif; ?>
                                        </span>
                                    <?php endif; ?>
                                </div>
                                <?php if ($isObject): ?>
                                    <?= $this->element('genericElementsBS5/Badges/comment', array(
                                        'comment' => $record['comment'] ?? '',
                                        'class' => 'oi-comment',
                                    )) ?>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="vp-ref-links">
                                    <?php foreach ($record['links'] as $link): ?>
                                        <?= $linkChip($link) ?>
                                    <?php endforeach; ?>
                                </div>
                                <?= $viaLine($record['links']) ?>
                            </td>
                            <td class="oi-col-event"><?= $this->element('Attributes/event_ref', array('event' => $event)) ?></td>
                            <td class="oi-col-org">
                                <?php if (!empty($org['name'])): ?>
                                    <?= $this->element('Values/View/value_org_link', array('org' => $org, 'small' => true)) ?>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php if ($isObject): ?>
                            <tr class="oi-detail d-none" data-vp-obj-fold>
                                <td colspan="4">
                                    <div class="oi-card">
                                        <table class="table table-hover align-middle mb-0 ix-table">
                                            <?= $attrHead ?>
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
                        <?php endif; ?>
                    </tbody>
                <?php endforeach; ?>
            </table>
        </div>

        <?php if (count($records) > $pageSize): ?>
            <div class="px-3 py-2 border-top">
                <?= $this->element('Values/View/value_pager', array(
                    'size' => $pageSize,
                    'shown' => count($records),
                    'total' => count($records),
                    'noun' => array('one' => __('record'), 'many' => __('records')),
                )) ?>
            </div>
        <?php endif; ?>

        <div class="vp-ref-foot">
            <span><i class="fas fa-arrow-right-long" aria-hidden="true"></i><?= __('this value\'s object names it') ?></span>
            <span><i class="fas fa-arrow-left-long" aria-hidden="true"></i><?= __('it names this value') ?></span>
            <span><i class="fas fa-arrows-left-right" aria-hidden="true"></i><?= __('both ways') ?></span>
            <span class="ms-auto"><?= h(sprintf(
                __('Read from %1$s and %2$s of this value.'),
                __n('%s occurrence', '%s occurrences', $references['occurrences'], number_format($references['occurrences'])),
                __n('%s object', '%s objects', $references['read_objects'], number_format($references['read_objects']))
            )) ?><?= empty($references['cap']['applied']) ? '' : ' ' . h(sprintf(
                __('The object read stops at %s.'),
                number_format($references['cap']['limit'])
            )) ?></span>
        </div>
    <?php endif; ?>
</div>
