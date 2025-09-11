<?php
$cards = '';
$max_length = 32;
foreach ($data as $galaxy) {
    $cardData = '';
    foreach ($galaxy['GalaxyCluster'] as $gc) {
        $cardData .= sprintf(
            '<div class="list-group-item d-flex justify-content-between align-items-center py-0"><a href="%s" style="text-decoration: none;">%s</a> <a href="%s"><i class="fas fa-filter"></i></a></div>',
            $baseurl . '/galaxy_clusters/view/' . h($gc['id']),
            mb_strlen($gc['value']) > $max_length ? h(mb_substr($gc['value'], 0, $max_length - 3) . '...') : h($gc['value']),
            $baseurl . '/events/index/searchtag:' . h($gc['tag_id']),
        );
    }
    $cardData = '<div class="list-group list-group-flush">' . $cardData . '</div>';
    $cards .= sprintf(
        '<div class="card-header py-0 ps-2"><h6 class="mb-0"><a href="%s" style="text-decoration: none;">%s</a></h6></div><div class="list-group list-group-flush">%s</div>',
        $baseurl . '/galaxies/view/' . h($galaxy['id']),
        mb_strlen($galaxy['name']) > $max_length ? h(mb_substr($galaxy['name'], 0, $max_length - 3) . '...') : h($galaxy['name']),
        $cardData
    );
}

if (!empty($data)) {
    echo sprintf(
        '<div class="card mb-3" style="width: 300px;">%s</div>',
        $cards
    );
}