<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/**
 * The Relationships rail's Dated relations: the values this one is paired
 * with inside an object that records a start and an end date (a passive-DNS
 * record, a whois history), each as a span on one time axis, oldest first.
 * The other value opens its own page; the event its object sits in carries
 * its preview.
 *
 * Lazily loaded from ValuesController::viewRelationDated.
 *
 * @var array $valueIntelligence
 */
$relations = $valueIntelligence['relationships'];
$dated = $relations['dated'];
$rows = $dated['rows'];
$peeks = $dated['event_peeks'] ?? array();
$fold = 6;

usort($rows, function ($a, $b) {
    return (int)$a['first']['at'] - (int)$b['first']['at'];
});
$from = (int)$dated['span']['from'];
$seconds = (int)$dated['span']['seconds'];

/**
 * The end of a span, as short as the start beside it allows.
 *
 * @param int $first
 * @param int $last
 * @return string
 */
$lastLabel = function ($first, $last) {
    if ($last === $first) {
        return __('same instant');
    }
    if (date('Y-m-d', $first) === date('Y-m-d', $last)) {
        return date('H:i', $last);
    }
    return date(date('Y', $first) === date('Y', $last) ? 'm-d H:i' : 'Y-m-d H:i', $last);
};

$sub = empty($rows)
    ? h(__('None recorded'))
    : h(sprintf(
        __('%1$s · %2$s'),
        __n('%s dated relation', '%s dated relations', $dated['total'], number_format($dated['total'])),
        implode(', ', $dated['templates'])
    ));
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-object"
     style="--vp-panel-color: var(--vp-rel-object);"
     data-vp-entries
     data-vp-rel-summary="dated"
     data-vp-rel-count="<?= h(number_format($dated['total'])) ?>"
     <?= empty($dated['cap']['applied']) ? '' : 'data-vp-rel-note="' . h(__('of the objects read')) . '"' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Dated relations'),
        'panelIcon' => 'fas fa-clock-rotate-left',
        'panelColor' => 'var(--vp-rel-object)',
        'panelSub' => $sub,
    )) ?>

    <?php if (empty($rows)): ?>
        <div class="vp-rail-none">
            <?= h($dated['read_objects'] === 0
                ? __('This value sits in no object you can see.')
                : __n(
                    'The object this value sits in records no start and end date.',
                    'None of the %s objects this value sits in records both a start and an end date.',
                    $dated['read_objects'],
                    number_format($dated['read_objects'])
                )) ?>
        </div>
    <?php else: ?>
        <div class="vp-dt">
            <div class="vp-dt-axis" aria-hidden="true">
                <span><?= h(date('Y-m-d', $from)) ?></span>
                <span><?= h(date('Y-m-d', $from + $seconds)) ?></span>
            </div>
            <ul class="vp-dt-list">
                <?php foreach ($rows as $index => $row): ?>
                    <?php
                    $first = (int)$row['first']['at'];
                    $last = (int)$row['last']['at'];
                    $left = $seconds > 0 ? ($first - $from) / $seconds * 100 : 50;
                    $width = $seconds > 0 ? ($last - $first) / $seconds * 100 : 0;
                    $folded = $index >= $fold;
                    ?>
                    <li class="vp-dt-row<?= $folded ? ' d-none' : '' ?>" data-vp-entry<?= $folded ? ' data-vp-entry-fold' : '' ?>>
                        <div class="vp-dt-line">
                            <a class="vp-dt-value<?= empty($row['warninglists']) ? '' : ' vp-rel-listed' ?>"
                               href="<?= h($baseurl . '/values/view/' . ValueUrlTool::address($row['value'])) ?>"
                               title="<?= h(sprintf(__('%1$s, open its page'), $row['type'])) ?>"><?= h($row['value']) ?></a>
                            <?php if (!empty($row['warninglists'])): ?>
                                <?= $this->element('Values/View/value_warninglist_mark', array('lists' => $row['warninglists'])) ?>
                            <?php endif; ?>
                        </div>
                        <div class="vp-dt-track" title="<?= h($row['first']['raw'] . ' → ' . $row['last']['raw']) ?>">
                            <?php $instant = $width < 1.5; ?>
                            <i class="<?= $instant ? 'is-instant' : '' ?>"
                               style="left: <?= h(round($left, 2)) ?>%;<?= $instant ? '' : ' width: ' . h(round($width, 2)) . '%;' ?>"></i>
                        </div>
                        <div class="vp-dt-when">
                            <span><?= h(date('Y-m-d H:i', $first)) ?></span>
                            <span class="vp-dt-arrow" aria-hidden="true">→</span>
                            <span><?= h($lastLabel($first, $last)) ?></span>
                            <span class="vp-dt-sep">·</span>
                            <span class="vp-dt-rel" title="<?= h((string)$row['origin']) ?>"><?= h(trim($row['relation'] . ' · ' . $row['object'], ' ·')) ?></span>
                            <?= $this->element('Attributes/event_ref', array(
                                'event' => $peeks[(int)$row['event']] ?? array('id' => (int)$row['event']),
                            )) ?>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ul>
            <?= $this->element('Values/View/value_entries_more', array('count' => count($rows), 'fold' => $fold)) ?>
        </div>
        <?php if (!empty($dated['cap']['applied'])): ?>
            <div class="vp-rail-foot">
                <?= h(sprintf(
                    __('Read from the %1$s most recent of the %2$s objects this value sits in.'),
                    number_format($dated['read_objects']),
                    number_format($dated['in_objects'])
                )) ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>
