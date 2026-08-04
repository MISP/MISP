<?php

$on     = !empty(Hash::get($row, $field['data_path']));
$isCard = isset($viewMode) && $viewMode === 'card';
$label  = $field['name'] ?? '';
$yesNo  = $on ? __('Yes') : __('No');

if ($isCard) {
    echo sprintf(
        '<span class="badge rounded-pill %s d-inline-flex align-items-center gap-1" title="%s">'
            . '<i class="fas fa-%s"></i>%s</span>',
        $on ? 'text-bg-success' : 'text-bg-secondary',
        h($label . ': ' . $yesNo),
        $on ? 'check' : 'xmark',
        h($label)
    );
} else {
    echo sprintf(
        '<i class="fas fa-%s %s" role="img" title="%s" aria-label="%s"></i>',
        $on ? 'check' : 'xmark',
        $on ? 'text-success' : 'text-muted',
        h($yesNo),
        h($yesNo)
    );
}
