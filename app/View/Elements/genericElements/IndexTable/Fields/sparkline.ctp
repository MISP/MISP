<?php
    $elementId = $this->Hash->extract($row, $field['data_path'])[0];
    echo $this->element('sparkline', array('scope' => $field['csv']['scope'], 'id' => $elementId, 'csv' => $field['csv']['data'][$k]));
?>
