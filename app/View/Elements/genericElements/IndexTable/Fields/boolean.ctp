<?php
    echo sprintf(
        '<i class="black fa fa-%s"></i>',
        (Hash::extract($row, $field['data_path'])[0]) ? 'check' : 'times'
    );
?>
