<?php
    $timestamp = Hash::extract($row, $field['data_path'])[0];
    $datetime = (new DateTime())->setTimestamp($timestamp);
    echo h($datetime->format('D, d M Y H:i'));
?>
