<?php
    if (!isset($arrayData) && isset($field['arrayData'])) {
        $arrayData = $field['arrayData'];
    }
    echo h($arrayData[$this->Hash->extract($row, $field['data_path'])[0]]);
?>
