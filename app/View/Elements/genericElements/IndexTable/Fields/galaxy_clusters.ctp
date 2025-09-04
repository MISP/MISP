<?php
    $galaxies = array();
    $data = $this->Hash->extract($row, $field['data_path']);
    if (!empty($data)) {
        foreach ($data as $galaxy_cluster) {
            $galaxy_id = $galaxy_cluster['Galaxy']['id'];
            if (!isset($galaxies[$galaxy_id])) {
                $galaxies[$galaxy_id] = $galaxy_cluster['Galaxy'];
            }
            unset($galaxy_cluster['Galaxy']);
            $galaxies[$galaxy_id]['GalaxyCluster'][] = $galaxy_cluster;
        }
        echo $this->element('galaxyQuickView', array(
            'data' => $galaxies,
            'event' => $row,
            'target_id' => $row['Event']['id'],
            'target_type' => 'event',
            'static_tags_only' => true,
        ));
    }