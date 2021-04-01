<?php
    echo h($field['arrayData'][Hash::extract($row, $field['data_path'])[0]]);
?>
