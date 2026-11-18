<?php
/*
 * An event's peek: the popover an index opens on the event's id
 * (Events/peek_link), drawn with the events index card's pieces
 * (Events/index_card) — title and dates, publish state and distribution,
 * creator org and markings, the context lanes, the counts and the UUID.
 * Served by EventsController::peek(); its chips and markings come from
 * events-index-cards.css, which peek_link loads with the page.
 *
 * @var array $event EventPeekBatch::forIds() row: the Event, with its Orgc,
 *                   Org, SharingGroup and EventPeek
 */
App::uses('EventCardTool', 'Tools/EventOverview');

$id = (int)($event['id'] ?? 0);
$info = (string)($event['info'] ?? '');
$eventUrl = $baseurl . '/events/view/' . $id;
$peek = $event['EventPeek'];
$ei = $this->EventIndex;
$now = time();
$date = (string)($event['date'] ?? '');
$changed = (int)($event['timestamp'] ?? 0);
$orgc = $event['Orgc'] ?? [];
$org = $event['Org'] ?? [];
$uuid = (string)($event['uuid'] ?? '');

$state = $peek['state'];
$stateIcons = [
    'published' => 'fa-circle-check',
    'unpublished' => 'fa-floppy-disk',
    'pending' => 'fa-clock-rotate-left',
];
$stateLabels = [
    'published' => empty($event['publish_timestamp'])
        ? __('Published')
        : __('Published %s', gmdate('j M Y', (int)$event['publish_timestamp'])),
    'unpublished' => __('Unpublished'),
    'pending' => __('Changes pending'),
];
$dist = $peek['distribution'];

/*
 * A lane keeps to two lines of chips and folds the rest into +N, named in its
 * title. The chips' widths are estimated from their labels (px, at the peek's
 * font sizes), the last line keeping room for the +N.
 */
$fit = function (array $chips) {
    $line = 252;
    $more = 40;
    $last = count($chips) - 1;
    $lines = 1;
    $used = 0;
    foreach ($chips as $i => $c) {
        $label = (string)($c['label'] ?? (isset($c['count']) ? '00 unresolved' : ''))
            . (empty($c['namespace']) ? '' : ' ' . $c['namespace']);
        $mono = in_array($c['kind'] ?? '', ['technique', 'mitigation'], true);
        $width = min($line, (int)(mb_strlen($label) * ($mono ? 6.7 : 6.2)) + 30);
        // On the second line a chip leaves room for the +N, unless it is the last one.
        $need = function () use (&$lines, $width, $i, $last, $more) {
            return $width + ($lines === 2 && $i < $last ? 4 + $more : 0);
        };
        if ($need() > $line - $used - ($used ? 4 : 0)) {
            if ($lines === 2) {
                return $i;
            }
            $lines = 2;
            $used = 0;
            if ($need() > $line) {
                return $i;
            }
        }
        $used += ($used ? 4 : 0) + $width;
    }
    return count($chips);
};
$lane = function ($name, $count, array $chips, $empty) use ($ei, $fit) {
    $html = '<span class="ev-pop-rl">' . $ei->laneIcon($name) . h($ei->laneLabel($name))
        . ($count ? ' <small>' . (int)$count . '</small>' : '') . '</span>';
    if (empty($chips)) {
        return $html . '<span class="ev-pop-chips"><span class="ev-pop-none">' . h($empty) . '</span></span>';
    }
    $cap = max(1, $fit($chips));
    $shown = array_slice($chips, 0, $cap);
    $rest = array_slice($chips, $cap);
    $more = '';
    if ($rest) {
        $names = array_map(function ($c) {
            return $c['label'] ?? '';
        }, $rest);
        $more = sprintf(
            '<span class="dk-chip is-fold" title="%s">+%d</span>',
            h(implode(', ', array_filter($names))),
            count($rest)
        );
    }
    return $html . '<span class="ev-pop-chips">' . implode('', array_map([$ei, 'chip'], $shown)) . $more . '</span>';
};
$rows = $peek['rows'];
$hasContext = !empty($rows['attribution']) || !empty($rows['behaviour']) || !empty($rows['classification']);

// A count above zero opens the event's tab that lists it.
$count = function ($n, $tab, $icon, $label, $more = false) use ($ei, $id) {
    $inner = $icon . '<b>' . EventCardTool::compactCount($n) . ($more ? '+' : '') . '</b>' . h($label);
    if (!$n) {
        return '<span class="ev-pop-n is-zero">' . $inner . '</span>';
    }
    return '<a class="ev-pop-n" href="' . h($ei->tabUrl($id, $tab)) . '">' . $inner . '</a>';
};
$attributeCount = (int)($event['attribute_count'] ?? 0);
[$attributesTab] = $ei->attributesTab([
    'attribute_count' => $attributeCount,
    'attributes_in_objects_only' => $peek['attributes_in_objects_only'],
]);
$objectCount = $peek['object_count'];
$reportCount = $peek['report_count'];
$ext = $ei->extension($peek);
$heldBy = !empty($org['name']) && (int)($org['id'] ?? 0) !== (int)($orgc['id'] ?? 0)
    ? __('held here by %s', $org['name'])
    : __('Creator organisation');
?>
<div class="ev-pop">
    <div class="ev-pop-head">
        <span class="ev-pop-ic"><i class="misp-icon misp-icon-event misp-simple"></i></span>
        <div class="ev-pop-heading">
            <a class="ev-pop-title" href="<?= h($eventUrl) ?>"><?= h($info) ?></a>
            <div class="ev-pop-meta">
                <?php if ($date !== '' && strtotime($date)): ?>
                    <span title="<?= h(__('Event date')) ?>"><i class="fa-regular fa-calendar"></i><?= h(date('j M Y', strtotime($date))) ?></span>
                <?php endif; ?>
                <?php if ($changed > 0): ?>
                    <span title="<?= h(__('Last change %s', $ei->utc($changed))) ?>"><i class="fas fa-pen"></i><?= h(EventCardTool::ago($changed, $now)) ?></span>
                <?php endif; ?>
                <?php if ($ext): ?>
                    <span class="ev-pop-ext"><?= implode('', $ext) ?></span>
                <?php endif; ?>
            </div>
            <div class="ev-pop-pills">
                <span class="ev-pop-pill is-<?= h($state) ?>" title="<?= h($ei->stateTitle($event, $state)) ?>"><i class="fas <?= $stateIcons[$state] ?>"></i><?= h($stateLabels[$state]) ?></span>
                <span class="ev-pop-pill is-dist" style="<?= h($dist['style']) ?>" title="<?= h(__('Distribution: %s', $dist['label'])) ?>"><i class="<?= h($dist['icon']) ?>"></i><span><?= h($dist['label']) ?></span></span>
            </div>
        </div>
    </div>

    <?php if (!empty($orgc['name'])): ?>
        <div class="ev-pop-org">
            <?= $ei->orgTile($orgc, 28) ?>
            <span class="ev-pop-orgname">
                <a href="<?= h($baseurl . '/organisations/view/' . (int)($orgc['id'] ?? 0)) ?>"><?= h($orgc['name']) ?></a>
                <small><?= h($heldBy) ?></small>
            </span>
            <?= $ei->grade($peek['grade'] ?? null, $orgc) ?>
            <span class="dk-marks"><?= $ei->markings($peek['markings']) ?></span>
        </div>
    <?php endif; ?>

    <div class="ev-pop-ctx">
        <?php if ($hasContext): ?>
            <?= $lane('attribution', $rows['attribution_count'], $rows['attribution'], __('None stated')) ?>
            <?= $lane('behaviour', $rows['technique_count'], $rows['behaviour'], '—') ?>
            <?= $lane('classification', 0, $rows['classification'], '—') ?>
        <?php else: ?>
            <span class="ev-pop-none is-all"><?= h(__('No tags or galaxy clusters on this event')) ?></span>
        <?php endif; ?>
    </div>

    <div class="ev-pop-counts">
        <?= $count($attributeCount, $attributesTab, '<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>', __n('attribute', 'attributes', $attributeCount)) ?>
        <?= $count($objectCount, 'objects', '<i class="misp-icon misp-icon-object misp-simple text-object"></i>', __n('object', 'objects', $objectCount), $peek['object_count_more']) ?>
        <?= $count($reportCount, 'reports', '<i class="misp-icon misp-icon-report misp-simple text-report"></i>', __n('report', 'reports', $reportCount)) ?>
    </div>

    <?php if ($uuid !== ''): ?>
        <div class="ev-pop-uuid">
            <span class="ev-pop-k"><?= h(__('UUID')) ?></span>
            <code><?= h($uuid) ?></code>
            <button type="button" class="ev-pop-copy" data-copy-value="<?= h($uuid) ?>"
                    data-copy-msg="<?= h(__('UUID copied to clipboard')) ?>"
                    title="<?= h(__('Copy UUID')) ?>" aria-label="<?= h(__('Copy UUID')) ?>"><i class="fas fa-copy"></i></button>
        </div>
    <?php endif; ?>
</div>
