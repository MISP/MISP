<?php
$elementId = Hash::extract($data, $field['path'])[0];
if (!empty($field['csv_data_path'])) {
    $csv = Hash::extract($data, $field['csv_data_path']);
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
