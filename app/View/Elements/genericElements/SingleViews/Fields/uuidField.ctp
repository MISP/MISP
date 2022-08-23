<?php
    $uuid = Hash::extract($data, $field['path'])[0];
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );
