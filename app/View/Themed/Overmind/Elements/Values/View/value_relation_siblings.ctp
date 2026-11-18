<?php
/**
 * The Relationships tab's "In the same object" card: the objects this
 * value sits in, drawn as the objects index draws them. One row per
 * object (its header, its event, its creator org) opens on its
 * attributes; this value is marked, and every other value says how
 * specific it is to this one — in how many of the objects read it sits
 * beside this value, against how many objects hold it on the instance.
 *
 * Rendered by value_relation_cooccurrence.ctp.
 *
 * @var array $siblings The fold's `siblings`, with `by_object`
 * @var callable $specificRead ($shared, $spread, $unit, $least) => string
 */
$byObject = $siblings['by_object'] ?? array();
$objects = $byObject['rows'] ?? array();
if (empty($objects)) {
    return;
}
$events = $byObject['events'] ?? array();
$total = (int)($byObject['total'] ?? count($objects));
$capped = !empty($siblings['cap']['applied']);
$floor = $capped ? "\u{2265}\u{00A0}" : '';
$pageSize = max(1, (int)($siblings['page_size'] ?? 8));

$attrCell = function (array $attribute) {
    return $this->element('genericElementsBS5/IndexTable/Fields/attribute_value', array(
        'row' => array('Attribute' => array(
            'id' => $attribute['id'],
            'value' => $attribute['value'],
            'type' => $attribute['type'],
            'category' => $attribute['category'],
            'object_relation' => $attribute['relation'],
            'distribution' => $attribute['distribution'],
            'sharing_group_id' => $attribute['sharing_group_id'],
            'timestamp' => $attribute['timestamp'],
        )),
        'field' => array('data_path' => 'Attribute'),
    ));
};

// How specific a value is to this one, as a meter and its sentence.
$withCell = function (array $attribute) use ($specificRead) {
    if ($attribute['ours']) {
        return '<span class="vp-sib-self">' . h(__('This value')) . '</span>';
    }
    $with = $attribute['with'] ?? array();
    $spread = $with['spread'] ?? null;
    $read = $specificRead($with['shared'] ?? 0, $spread, 'object', !empty($with['least']));
    if ($read === '') {
        return '';
    }
    $share = $spread > 0 ? min(100, max(3, round(100 * $with['shared'] / $spread))) : 0;
    return '<span class="vp-sib-with" title="' . h(sprintf(
        __('%1$s sits beside this value %2$s'),
        $attribute['value'],
        $read
    )) . '"><span class="vp-sib-meter"><i style="width: ' . h($share) . '%;"></i></span>'
        . '<span>' . h($read) . '</span></span>';
};

$sub = '<span class="vp-rel-tag me-1"><i class="fas fa-link"></i>' . h(__('Co-occurrence')) . '</span>'
    . h(sprintf(
        __('%1$s in %2$s'),
        __n('%s other value', '%s other values', (int)$siblings['total'], number_format((int)$siblings['total'])),
        $floor . __n('%s object', '%s objects', $total, number_format($total))
    ))
    . '&nbsp;·&nbsp;<span class="vp-rel-prov"><i class="fas fa-gauge"></i>' . h(__('Machine-derived')) . '</span>';

$search = null;
if (count($objects) > 3) {
    $search = '<div class="input-group input-group-sm vp-card-search">'
        . '<span class="input-group-text"><i class="fas fa-magnifying-glass" aria-hidden="true"></i></span>'
        . '<input type="search" class="form-control" data-vp-filter-text autocomplete="off"'
        . ' placeholder="' . h(__('Filter values, relations, events…')) . '"'
        . ' aria-label="' . h(__('Filter the objects')) . '"></div>';
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-co"
     style="--vp-panel-color: var(--vp-rel-co);"
     data-vp-list
     data-vp-rel-summary="siblings"
     data-vp-rel-count="<?= h($floor . number_format($total)) ?>"
     <?= $capped ? 'data-vp-rel-note="' . h(__('a floor — the join was capped')) . '"' : '' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('In the same object'),
        'panelIcon' => 'misp-icon misp-icon-object misp-simple',
        'panelColor' => 'var(--vp-rel-co)',
        'panelSub' => $sub,
        'panelExtra' => $search,
    )) ?>

    <?php if ($capped): ?>
        <div class="vp-rel-cap">
            <i class="fas fa-circle-info" aria-hidden="true"></i>
            <span><?= sprintf(
                h(__('Read over the %1$s most recent of the %2$s objects this value sits in.')),
                '<strong>' . h(number_format((int)$siblings['objects'])) . '</strong>',
                '<strong>' . h(number_format((int)$siblings['in_objects'])) . '</strong>'
            ) ?></span>
        </div>
    <?php endif; ?>

    <div class="table-responsive" data-vp-list-rows>
        <table class="table align-middle mb-0 ix-table oi-table vp-sib-table">
            <thead>
                <tr>
                    <th><?= h(__('Object')) ?></th>
                    <th><?= h(__('Event')) ?></th>
                    <th><?= h(__('Creator org')) ?></th>
                </tr>
            </thead>
            <?php foreach ($objects as $index => $object): ?>
                <?php
                $open = $index === 0;
                $first = null;
                $text = array($object['name'], $object['meta-category'], '#' . $object['event']['id'],
                    $object['event']['info'], $object['org']['name']);
                foreach ($object['attributes'] as $attribute) {
                    if ($first === null && !$attribute['ours']) {
                        $first = $attribute;
                    }
                    array_push($text, $attribute['value'], $attribute['relation'], $attribute['type'],
                        $attribute['category']);
                }
                $event = $events[$object['event']['id']] ?? $object['event'];
                ?>
                <tbody data-vp-list-row data-vp-obj
                       data-vp-text="<?= h(mb_strtolower(implode(' ', $text))) ?>"
                       <?= $index >= $pageSize ? 'class="d-none"' : '' ?>>
                    <tr<?= $open ? ' class="oi-open"' : '' ?>>
                        <td class="oi-col-object">
                            <div class="oi-object">
                                <button type="button" class="oi-expand" data-vp-obj-disc
                                        aria-expanded="<?= $open ? 'true' : 'false' ?>"
                                        title="<?= h(__('Show its attributes')) ?>">
                                    <i class="fas fa-chevron-right" aria-hidden="true"></i>
                                </button>
                                <?= $this->element('Objects/object_header', array(
                                    'object' => $object,
                                    'ctx' => array(
                                        'count' => count($object['attributes']),
                                        'deleted' => false,
                                        'firstValue' => $first === null ? '' : (string)$first['value'],
                                        'firstRelation' => $first === null ? '' : (string)$first['relation'],
                                    ),
                                )) ?>
                            </div>
                            <?= $this->element('genericElementsBS5/Badges/comment', array(
                                'comment' => $object['comment'],
                                'class' => 'oi-comment',
                            )) ?>
                        </td>
                        <td class="oi-col-event"><?= $this->element('Attributes/event_ref', array('event' => $event)) ?></td>
                        <td class="oi-col-org">
                            <?= $this->element('Values/View/value_org_link', array('org' => $object['org'], 'small' => true)) ?>
                        </td>
                    </tr>
                    <tr class="oi-detail<?= $open ? '' : ' d-none' ?>" data-vp-obj-fold>
                        <td colspan="3">
                            <div class="oi-card">
                                <table class="table table-hover align-middle mb-0 ix-table vp-sib-attrs">
                                    <thead>
                                        <tr>
                                            <th><?= h(__('Value')) ?></th>
                                            <th><?= h(__('Category')) ?></th>
                                            <th><?= h(__('Type')) ?></th>
                                            <th><?= h(__('With this value')) ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($object['attributes'] as $attribute): ?>
                                            <tr<?= $attribute['ours'] ? ' class="vp-sib-is-self"' : '' ?>>
                                                <td class="text-break">
                                                    <?= $attrCell($attribute) ?>
                                                    <?php if (!empty($attribute['warninglists'])): ?>
                                                        <?= $this->element('Values/View/value_warninglist_mark', array(
                                                            'lists' => $attribute['warninglists'],
                                                        )) ?>
                                                    <?php endif; ?>
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
                                                <td class="text-nowrap"><?= $withCell($attribute) ?></td>
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

    <div class="p-3 d-none" data-vp-list-empty>
        <div class="vp-empty vp-empty-inline">
            <i class="fas fa-filter" aria-hidden="true"></i>
            <span><?= __('No object matches the filter.') ?></span>
        </div>
    </div>

    <?php // One page needs no pager: the header already counts the objects. ?>
    <?php if (count($objects) > $pageSize || $total > count($objects)): ?>
        <div class="px-3 py-2 border-top">
            <?= $this->element('Values/View/value_pager', array(
                'size' => $pageSize,
                'shown' => count($objects),
                'total' => $total,
                'noun' => array('one' => __('object'), 'many' => __('objects')),
            )) ?>
        </div>
    <?php endif; ?>
</div>
