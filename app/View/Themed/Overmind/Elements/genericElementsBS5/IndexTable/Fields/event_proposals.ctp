<?php
// Overmind proposal index: the event's open proposals, their count opening
// the event's proposal list, and the organisations that made them, most
// proposals first (EventsController::__attachProposalsToEvents()).
App::uses('EventCardTool', 'Tools/EventOverview');
$proposals = $row['Event']['Proposals'] ?? null;
if (empty($proposals['count'])) {
    echo '<span class="te-faint">&mdash;</span>';
    return;
}
$ei = $this->EventIndex;
$orgs = $proposals['orgs'];
$shown = array_slice($orgs, 0, 3);
$tiles = '';
foreach ($shown as $org) {
    $tiles .= $ei->orgTile($org, 18);
}
if (count($orgs) > count($shown)) {
    $tiles .= '<span class="te-prop-more">+' . (count($orgs) - count($shown)) . '</span>';
}
$title = $ei->plural((int)$proposals['count'], '%s open proposal', '%s open proposals')
    . "\n" . implode("\n", array_map(function ($org) {
        return $org['name'] . ': ' . $org['count'];
    }, $orgs))
    . (empty($proposals['last']) ? '' : "\n" . __('Last one %s', EventCardTool::ago($proposals['last'], time())));
printf(
    '<a class="te-prop" href="%s" title="%s"><i class="fas fa-comment-medical"></i><b>%s</b><span class="te-prop-orgs">%s</span></a>',
    h($baseurl . '/shadow_attributes/index/' . (int)$row['Event']['id']),
    h($title),
    EventCardTool::compactCount((int)$proposals['count']),
    $tiles
);
