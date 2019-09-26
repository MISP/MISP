<?php
    $data = h(Hash::extract($row, $field['data_path']));
    echo sprintf(
        '<div style="white-space:pre;" class="blue bold">%s</div>',
        json_encode($data, JSON_PRETTY_PRINT)
    );
?>
