<?php
/*
 * An attribute's event as an icon at the head of its value, for an index
 * whose rows come from any event: the event's title, state, organisations
 * and facts in a popover on hover, the event page on click.
 *
 * The popover goes through Bootstrap's sanitizer, which drops inline styles:
 * every tone is a class.
 *
 * @var array $event the row's Event, with its Orgc, Org and SharingGroup
 */
App::uses('DistributionLevel', 'Tools');
App::uses('EventCardTool', 'Tools/EventOverview');

$id = (int)($event['id'] ?? 0);
if ($id === 0) {
    return;
}
$info = (string)($event['info'] ?? '');
$date = (string)($event['date'] ?? '');
$orgc = $event['Orgc'] ?? [];
$org = $event['Org'] ?? [];

$states = [
    'published' => ['fa-circle-check', __('Published')],
    'unpublished' => ['fa-floppy-disk', __('Unpublished')],
    'pending' => ['fa-clock-rotate-left', __('Changes pending')],
];
$state = EventCardTool::state($event);
$distribution = EventCardTool::distribution((int)($event['distribution'] ?? 0), $event['SharingGroup'] ?? null);
$threats = [
    1 => ['high', __('High')],
    2 => ['medium', __('Medium')],
    3 => ['low', __('Low')],
    4 => ['undefined', __('Undefined')],
];
$analyses = [
    0 => ['initial', __('Initial')],
    1 => ['ongoing', __('Ongoing')],
    2 => ['completed', __('Completed')],
];
$threat = $threats[(int)($event['threat_level_id'] ?? 4)] ?? $threats[4];
$analysis = $analyses[(int)($event['analysis'] ?? 0)] ?? $analyses[0];
$dateLabel = $date !== '' && strtotime($date) ? date('j M Y', strtotime($date)) : $date;
$changed = (int)($event['timestamp'] ?? 0);

$fact = function ($label, $value) {
    return '<span class="ev-peek-fact"><small>' . h($label) . '</small><span>' . $value . '</span></span>';
};

$content = '<div class="ev-peek-head">'
    . '<span class="ev-peek-ic"><i class="misp-icon misp-icon-event misp-simple"></i></span>'
    . '<span class="ev-peek-title"><b>' . h($info) . '</b>'
    . '<small><span class="ev-peek-id">#' . $id . '</span>' . ($dateLabel !== '' ? ' · ' . h($dateLabel) : '') . '</small>'
    . '<span class="ev-peek-pills">'
    . '<span class="ev-peek-pill is-' . $state . '"><i class="fas ' . $states[$state][0] . '"></i>' . h($states[$state][1]) . '</span>'
    . '<span class="ev-peek-pill is-dist-' . (int)($event['distribution'] ?? 0) . '"><i class="' . h($distribution['icon']) . '"></i>' . h($distribution['label']) . '</span>'
    . '</span></span></div>';

if (!empty($orgc['name'])) {
    $heldBy = !empty($org['name']) && (int)($org['id'] ?? 0) !== (int)($orgc['id'] ?? 0)
        ? ' · ' . h(__('held here by %s', $org['name']))
        : '';
    $content .= '<div class="ev-peek-org">' . $this->EventIndex->orgTile($orgc, 28)
        . '<span class="ev-peek-org-text"><b>' . h($orgc['name']) . '</b>'
        . '<small>' . h(__('Creator organisation')) . $heldBy . '</small></span></div>';
}

$content .= '<div class="ev-peek-facts">'
    . $fact(__('Threat level'), '<i class="ev-peek-dot is-' . $threat[0] . '"></i>' . h($threat[1]))
    . $fact(__('Analysis'), '<i class="ev-peek-dot is-' . $analysis[0] . '"></i>' . h($analysis[1]))
    . $fact(__('Attributes'), h(EventCardTool::compactCount((int)($event['attribute_count'] ?? 0))))
    . $fact(__('Last change'), $changed > 0 ? h(EventCardTool::ago($changed, time())) : '&mdash;')
    . '</div>';
// The distribution pills' tones, once per page, from the one table that sets them.
if (empty($this->viewVars['_eventPeekStyleEmitted'])) {
    $this->viewVars['_eventPeekStyleEmitted'] = true;
    $rules = '';
    foreach (range(0, 5) as $level) {
        $meta = DistributionLevel::get($level);
        $rules .= sprintf(
            '.ev-peek-pill.is-dist-%d{background:%s;color:%s;border-color:%s}',
            $level,
            DistributionLevel::themed($meta, 'bg'),
            DistributionLevel::themed($meta, 'fg'),
            DistributionLevel::themed($meta, 'border', '33')
        );
    }
    echo '<style>' . $rules . '</style>';
}
?>
<a href="<?= h($baseurl . '/events/view/' . $id) ?>" class="ev-peek om-lazy-popover"
   aria-label="<?= h(__('Event #%s: %s', $id, $info)) ?>"
   data-bs-content="<?= h($content) ?>"
   data-bs-custom-class="ev-peek-popover"><i class="misp-icon misp-icon-event misp-simple"></i></a>
