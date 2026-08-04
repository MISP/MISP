<?php
    $elementId = Hash::extract($row, $field['data_path'])[0];
    if (!empty($field['csv_data_path'])) {
        $csv = Hash::extract($row, $field['csv_data_path']);
        if (!empty($csv)) {
            $csv = $csv[0];
        }
    } else {
        $csv = $field['csv']['data'];
    }
    if (!empty($csv)) {
        $scope = empty($field['csv']['scope']) ? '' : $field['csv']['scope'];
        echo $this->element('sparkline', array('scope' => $scope, 'id' => $elementId, 'csv' => $csv));
    }
?>
