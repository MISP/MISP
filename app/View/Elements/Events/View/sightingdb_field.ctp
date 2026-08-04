<?php
    $hits = array();
    if (!empty($object['Sightingdb'])) {
        foreach ($object['Sightingdb'] as $sightingdb_hit) {
            $popover = array();
            $popoverData = array(
                'SightingDB' => $sightingdbs[$sightingdb_hit['sightingdb_id']]['Sightingdb']['name'],
                'Count' => $sightingdb_hit['count'],
                'First seen' => date('Y-m-d H:i:s', $sightingdb_hit['first_seen']),
                'Last seen' => date('Y-m-d H:i:s', $sightingdb_hit['last_seen']),
                'SightingDB owner' => $sightingdbs[$sightingdb_hit['sightingdb_id']]['Sightingdb']['owner'],
                'SightingDB description' => $sightingdbs[$sightingdb_hit['sightingdb_id']]['Sightingdb']['description']
            );
            foreach ($popoverData as $k => $v) {
                $popover[] = sprintf(
                    '<span class="bold black">%s</span>: <span class="blue">%s</span>',
                    h($k),
                    h($v)
                );
            }
            $hits[] = sprintf(
                '<span data-toggle="popover" data-content="%s" data-trigger="hover" data-placement="left"><span class="blue bold">%s</span>: %s</span>',
                implode('<br />', h($popover)),
                h($sightingdbs[$sightingdb_hit['sightingdb_id']]['Sightingdb']['name']),
                h($sightingdb_hit['count'])
            );
        }
    }
    echo sprintf(
        '<td class="short">%s</td>',
        implode('<br />', $hits)
    );
?>
