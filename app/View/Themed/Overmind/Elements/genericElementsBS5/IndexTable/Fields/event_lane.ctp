<?php
/*
 * Overmind events index: one context lane — attribution, behaviour or
 * classification (`lane`). The attribution lane also carries the row's
 * popover template.
 */
$card = $row['EventCard'] ?? null;
if ($card === null) {
    return;
}
$ei = $this->EventIndex;
$lane = $field['lane'];
$chips = $card['rows'][$lane];
if (empty($chips)) {
    echo '<div class="te-ctx"><span class="dk-none">—</span></div>';
} else {
    $lead = '';
    if ($lane === 'behaviour' && $card['rows']['technique_count']) {
        $n = (int)$card['rows']['technique_count'];
        $lead = sprintf(
            '<span class="te-tn" title="%s">%d</span>',
            h($ei->plural($n, '%s ATT&CK technique', '%s ATT&CK techniques')),
            $n
        );
    }
    echo '<div class="te-ctx" data-dk-lane="' . h($lane) . '">' . $lead . $ei->chips($lane, $chips) . '</div>';
}
if ($lane === 'attribution') {
    echo $ei->contextTemplate($row['Event'], $card['rows']);
}
