<?php
    $authKey = Hash::extract($row, $field['data_path']);
    echo sprintf(
        '<span class="red bold">%s</span>%s<span class="red bold">%s</span>',
        h($authKey['authkey_start']),
        str_repeat('&bull;', 32),
        h($authKey['authkey_end'])
    );
?>
