<?php
/**
 * The Sightings tab's list: every sighting of this value, newest first,
 * drawn as the indexes draw rows. The type in the chart's colours, when,
 * which organisation (and the source it gave), and the occurrence it was
 * reported against as an event reference with its preview.
 *
 * It follows the chart above: a range dragged there narrows these rows
 * (value-intelligence.js `refreshSightList`), and the type switch in the
 * header narrows them by kind. Ten rows, then Show all.
 *
 * Lazily loaded from ValuesController::viewSightingList.
 *
 * @var array $valueIntelligence
 */
$rows = array_reverse($valueIntelligence['sighting_rows']);
$events = $valueIntelligence['sighting_events'] ?? array();
$total = count($rows);
$pageSize = 10;
$types = array(
    0 => array('key' => 'sighting', 'label' => __('sighting'), 'plural' => __('Sightings')),
    1 => array('key' => 'fp', 'label' => __('false positive'), 'plural' => __('False positives')),
    2 => array('key' => 'expiration', 'label' => __('expiration'), 'plural' => __('Expirations')),
);
$byType = array(0 => 0, 1 => 0, 2 => 0);
$withSource = false;
foreach ($rows as $row) {
    $byType[$row['type']] = ($byType[$row['type']] ?? 0) + 1;
    $withSource = $withSource || $row['source'] !== null;
}

$columns = array(
    'type' => __('Type'),
    'date' => __('Date'),
    'org' => __('Organisation'),
);
if ($withSource) {
    $columns['source'] = __('Source');
}
$columns['against'] = __('Reported against');

$rowSort = function ($row, $index) {
    $data = array(
        'vp-sort-org' => mb_strtolower($row['org']),
        'vp-sort-source' => mb_strtolower((string)$row['source']),
        'vp-sort-date' => preg_replace('/\D/', '', $row['date']),
        'vp-sort-type' => (string)$row['type'],
        'vp-sort-against' => str_pad((string)(int)$row['against']['event'], 12, '0', STR_PAD_LEFT)
            . ' ' . mb_strtolower((string)$row['against']['type']),
        'vp-sort-default' => str_pad((string)$index, 6, '0', STR_PAD_LEFT),
    );
    $out = '';
    foreach ($data as $key => $token) {
        $out .= ' data-' . $key . '="' . h($token) . '"';
    }
    return $out;
};

// The type switch, when there is more than one type to tell apart.
$kindSwitch = null;
if (count(array_filter($byType)) > 1) {
    $kindSwitch = '<div class="vp-seg" role="group" aria-label="' . h(__('Type')) . '">'
        . '<button type="button" class="vp-seg-btn active" data-vp-sight-kind="all" aria-pressed="true">'
        . h(sprintf(__('All %s'), $total)) . '</button>';
    foreach ($types as $code => $type) {
        if ($byType[$code] === 0) {
            continue;
        }
        $kindSwitch .= '<button type="button" class="vp-seg-btn" data-vp-sight-kind="' . (int)$code . '" aria-pressed="false">'
            . '<i class="vp-sight-dot is-' . h($type['key']) . '" aria-hidden="true"></i>'
            . h($type['plural']) . ' ' . (int)$byType[$code] . '</button>';
    }
    $kindSwitch .= '</div>';
}

// The total only: the range strip and the type switch say what they narrow.
$subtitle = $total === 0
    ? h(__('No individual sighting to list'))
    : h(sprintf(__n('%s report, newest first', '%s reports, newest first', $total), number_format($total)));
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--sighting);"
     data-vp-sight-list
     data-vp-sight-page-size="<?= (int)$pageSize ?>">
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Individual sightings'),
        'panelIcon' => 'misp-icon misp-icon-sighting misp-simple',
        'panelColor' => 'var(--sighting)',
        'panelSub' => $subtitle,
        'panelExtra' => $kindSwitch,
    )) ?>
    <?php if ($total === 0): ?>
        <div class="p-3">
            <div class="vp-empty">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('Nobody has reported seeing this.') ?></span>
            </div>
        </div>
    <?php else: ?>
        <?php // Set by a range dragged across the chart above. ?>
        <div class="vp-filter-note d-none" data-vp-sight-range-note>
            <i class="fas fa-filter" aria-hidden="true"></i>
            <span>
                <?= h(__('Range')) ?>
                <strong data-vp-sight-range-from></strong> → <strong data-vp-sight-range-to></strong>
                · <strong data-vp-sight-range-shown></strong> <?= h(sprintf(__('of %s sightings'), $total)) ?>
            </span>
            <button type="button" class="vp-filter-clear ms-auto" data-vp-sight-clear><?= __('Clear') ?></button>
        </div>
        <div class="table-responsive" data-vp-sight-rows>
            <table class="table table-hover align-middle mb-0 ix-table vp-sight-table">
                <thead>
                    <tr>
                        <?php foreach ($columns as $key => $label): ?>
                            <th>
                                <button type="button" class="vp-th-sort" data-vp-sort-col="<?= h($key) ?>">
                                    <span class="sortable-header"><?= h($label) ?><i class="sort-icon"></i></span>
                                </button>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $index => $row): ?>
                        <?php
                        $type = $types[$row['type']] ?? $types[0];
                        $against = $row['against'];
                        $event = $events[(int)$against['event']] ?? array('id' => (int)$against['event']);
                        list($day, $time) = array_pad(explode(' ', $row['date'], 2), 2, '');
                        ?>
                        <tr data-vp-sight-date="<?= h($day) ?>" data-vp-sight-type="<?= (int)$row['type'] ?>"<?= $rowSort($row, $index) ?>
                            class="<?= $index >= $pageSize ? 'd-none' : '' ?>">
                            <td>
                                <span class="vp-sight-kind is-<?= h($type['key']) ?>">
                                    <i class="vp-sight-dot is-<?= h($type['key']) ?>" aria-hidden="true"></i><?= h($type['label']) ?>
                                </span>
                            </td>
                            <td class="text-nowrap">
                                <span class="vp-sight-day"><?= h($day) ?></span>
                                <span class="vp-sight-time"><?= h($time) ?></span>
                            </td>
                            <td>
                                <?= $this->element('Values/View/value_org_link', array(
                                    'org' => array('id' => $row['org_id'], 'name' => $row['org']),
                                )) ?>
                            </td>
                            <?php if ($withSource): ?>
                                <td class="vp-sight-source">
                                    <?= $row['source'] === null ? '<span class="text-body-secondary">&mdash;</span>' : h($row['source']) ?>
                                </td>
                            <?php endif; ?>
                            <td class="text-nowrap">
                                <span class="vp-sight-against"
                                      title="<?= h($against['attribute'] === null
                                          ? __('An occurrence you cannot see')
                                          : sprintf(__('Attribute %1$s in event %2$s'), $against['attribute'], $against['event'])) ?>">
                                    <?= $this->element('Attributes/event_ref', array('event' => $event)) ?>
                                    <?php if ($against['attribute'] === null): ?>
                                        <span class="text-body-secondary"><?= h($against['type']) ?></span>
                                    <?php else: ?>
                                        <?= $this->element('genericElementsBS5/Badges/type', array('type' => $against['type'])) ?>
                                    <?php endif; ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="p-3 d-none" data-vp-sight-empty>
            <div class="vp-empty vp-empty-inline">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('No sighting matches the range or the type you picked.') ?></span>
            </div>
        </div>
        <div class="vp-sight-foot">
            <span>
                <?= h(__('Showing')) ?>
                <strong data-vp-sight-shown><?= h(min($pageSize, $total)) ?></strong>
                <?= h(__('of')) ?>
                <strong data-vp-sight-of><?= h($total) ?></strong>
            </span>
            <button type="button" class="vp-filter-clear" data-vp-sight-more<?= $total <= $pageSize ? ' hidden' : '' ?>>
                <?= __('Show all') ?> <i class="fas fa-chevron-down" aria-hidden="true"></i>
            </button>
        </div>
        <div class="vp-acl-note vp-acl-note-band">
            <i class="fas fa-user-shield" aria-hidden="true"></i>
            <span><?= h($valueIntelligence['sighting_notes']['policy']) ?></span>
        </div>
    <?php endif; ?>
</div>
