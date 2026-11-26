<?php
    $hits = array();
    if (!empty($object['Sightingdb'])) {
        foreach ($object['Sightingdb'] as $sightingdb_hit) {
            $popover = array();
            $sightingdb = $sightingdbs[$sightingdb_hit['sightingdb_id']]['Sightingdb'];
            $popoverData = array(
                'SightingDB' => $sightingdb['name'],
                'Count' => $sightingdb_hit['count'],
            );
            // A value only ever reported as a false-positive has no sighting of its own
            if (!empty($sightingdb_hit['count'])) {
                $popoverData['First seen'] = date('Y-m-d H:i:s', $sightingdb_hit['first_seen']);
                $popoverData['Last seen'] = date('Y-m-d H:i:s', $sightingdb_hit['last_seen']);
            }
            if (!empty($sightingdb_hit['false_positive'])) {
                $popoverData['False-positives'] = $sightingdb_hit['false_positive']['count'];
                $popoverData['Last false-positive'] = date('Y-m-d H:i:s', $sightingdb_hit['false_positive']['last_seen']);
            }
            if (!empty($sightingdb_hit['expiration'])) {
                $popoverData['Expires'] = date('Y-m-d H:i:s', $sightingdb_hit['expiration']);
            }
            $popoverData['SightingDB owner'] = $sightingdb['owner'];
            $popoverData['SightingDB description'] = $sightingdb['description'];
            foreach ($popoverData as $k => $v) {
                $popover[] = sprintf(
                    '<span class="bold black">%s</span>: <span class="blue">%s</span>',
                    h($k),
                    h($v)
                );
            }
            $falsePositives = '';
            if (!empty($sightingdb_hit['false_positive'])) {
                $falsePositives = sprintf(' / <span class="red bold">%s</span>', h($sightingdb_hit['false_positive']['count']));
            }
            $hits[] = sprintf(
                '<span data-toggle="popover" data-content="%s" data-trigger="hover" data-placement="left"><span class="blue bold">%s</span>: %s%s</span>',
                implode('<br />', h($popover)),
                h($sightingdb['name']),
                h($sightingdb_hit['count']),
                $falsePositives
            );
        }
    }
    echo sprintf(
        '<td class="short">%s</td>',
        implode('<br />', $hits)
    );
?>
