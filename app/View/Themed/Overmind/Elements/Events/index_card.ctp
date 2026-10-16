<?php
/*
 * One event in the Overmind events index card view, wired in through
 * `card_element` (see genericElementsBS5/IndexTable/index_card).
 *
 * $row['EventCard'] is built by EventsController::__attachCardsToEvents();
 * the pieces it shares with the table come from EventIndexHelper.
 * The selection checkbox and the action menu are the scaffold's own
 * ($sections['selector'] / ['extra']), placed and restyled here.
 */
App::uses('EventCardTool', 'Tools/EventOverview');

$event = $row['Event'] ?? [];
$card = $row['EventCard'] ?? null;
if (empty($event['id']) || $card === null) {
    return;
}

$id = (int)$event['id'];
$orgc = $row['Orgc'] ?? [];
$now = time();
$ei = $this->EventIndex;
$plural = [$ei, 'plural'];

$state = $card['state'];
$stateTitle = $ei->stateTitle($event, $state);
if ($state === 'pending') {
    $stateHtml = sprintf('<span class="dk-state is-pending" title="%s">%s</span>', h($stateTitle), __('Changes pending'));
} elseif ($state === 'published') {
    $stateHtml = sprintf(
        '<span class="dk-state" title="%s">%s</span>',
        h($stateTitle),
        empty($event['publish_timestamp']) ? __('Published') : h(__('Published %s', gmdate('j M Y', (int)$event['publish_timestamp'])))
    );
} else {
    $stateHtml = sprintf('<span class="dk-state is-unpub" title="%s">%s</span>', h(__('Never published')), __('Unpublished'));
}

$ext = $ei->extension($card);

$line = function ($lane, $count, array $chips, $empty) use ($ei) {
    $html = '<div class="dk-rl">' . $ei->laneIcon($lane) . h($ei->laneLabel($lane)) . ($count ? ' <small>' . (int)$count . '</small>' : '') . '</div>';
    if (empty($chips)) {
        return $html . '<div class="dk-ctx"><span class="dk-none">' . h($empty) . '</span></div>';
    }
    return $html . '<div class="dk-ctx" data-dk-lane="' . h($lane) . '">' . $ei->chips($lane, $chips) . '</div>';
};
$rows = $card['rows'];

$count = function ($n, $icon, $title, $more = false) {
    $n = (int)$n;
    return sprintf(
        '<span class="dk-n%s" title="%s">%s<b>%s</b></span>',
        $n || $more ? '' : ' is-zero',
        h($title),
        $icon,
        EventCardTool::compactCount($n) . ($more ? '+' : '')
    );
};
$counts = $count(
    $event['attribute_count'] ?? 0,
    '<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>',
    $plural((int)($event['attribute_count'] ?? 0), '%s attribute', '%s attributes')
);
if (isset($event['object_count'])) {
    $more = !empty($event['object_count_more']);
    $counts .= $count(
        $event['object_count'],
        '<i class="misp-icon misp-icon-object misp-simple text-object"></i>',
        $more
            ? __('At least %s objects', (int)$event['object_count'])
            : $plural((int)$event['object_count'], '%s object', '%s objects'),
        $more
    );
}
if (isset($event['correlation_count'])) {
    $more = !empty($event['correlation_count_more']);
    $counts .= $count(
        $event['correlation_count'],
        '<i class="fas fa-link text-correlation"></i>',
        $more
            ? __('At least %s correlations', (int)$event['correlation_count'])
            : $plural((int)$event['correlation_count'], '%s correlation', '%s correlations'),
        $more
    );
}

$extras = $ei->extras($event, $card['graphs']);

?>
<article class="dk-card" data-event-id="<?= $id ?>">
    <div class="dk-kick">
        <span class="dk-lead">
            <i class="misp-icon misp-icon-event misp-simple" aria-hidden="true"></i>
            <?php if (!empty($sections['selector'])): ?>
                <span class="dk-sel"><?= implode('', $sections['selector']) ?></span>
            <?php endif; ?>
        </span>
        <?= $stateHtml ?>
        <span class="dk-id">#<?= $id ?></span>
        <?php if (!empty($sections['extra'])): ?>
            <div class="dk-menu"><?= implode('', $sections['extra']) ?></div>
        <?php endif; ?>
    </div>
    <h3 class="dk-title">
        <a href="<?= h($baseurl . '/events/view/' . $id) ?>" title="<?= h($event['info']) ?>"><?= h($event['info']) ?></a>
    </h3>
    <div class="dk-org">
        <?= $ei->orgTile($orgc) ?>
        <a class="dk-orgname" href="<?= h($baseurl . '/organisations/view/' . ($orgc['id'] ?? '')) ?>" title="<?= h($ei->orgTitle($row)) ?>"><?= h($orgc['name'] ?? '') ?></a>
        <?= $ei->grade($card['grade'] ?? null, $orgc, $orgGrading ?? null) ?>
        <span class="dk-marks"><?= $ei->markings($card['markings']) ?></span>
    </div>
    <div class="dk-meta">
        <span title="<?= h(__('Event date')) ?>"><i class="fa-regular fa-calendar"></i><?= h(date('j M Y', strtotime($event['date']))) ?></span>
        <span class="dk-when" title="<?= h(__('Last change %s', $ei->utc($event['timestamp']))) ?>"><i class="fas fa-pen"></i><?= h(EventCardTool::ago($event['timestamp'], $now)) ?></span>
        <?php if ($ext): ?>
            <span class="dk-ext"><?= implode('', $ext) ?></span>
        <?php endif; ?>
    </div>
    <div class="dk-rows">
        <?= $line('attribution', $rows['attribution_count'], $rows['attribution'], __('None stated')) ?>
        <?= $line('behaviour', $rows['technique_count'], $rows['behaviour'], '—') ?>
        <?= $line('classification', 0, $rows['classification'], '—') ?>
    </div>
    <?= $ei->contextTemplate($event, $rows) ?>
    <div class="dk-foot">
        <?= $counts ?>
        <?php if ($extras): ?>
            <span class="dk-xtra"><?= implode('', $extras) ?></span>
        <?php endif; ?>
        <?= $ei->distribution($card['distribution']) ?>
    </div>
</article>
