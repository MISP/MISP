<?php
// Overmind events index: the org holding the event here.
$org = $row['Org'] ?? [];
$synced = (int)($org['id'] ?? 0) !== (int)($row['Orgc']['id'] ?? 0);
printf(
    '<span class="%s" title="%s">%s</span>',
    $synced ? 'te-quiet' : 'te-faint',
    h(__('Held here by %s', $org['name'] ?? '')),
    h($org['name'] ?? '')
);
