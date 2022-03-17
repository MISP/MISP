<?php
    $threatLevel = Hash::extract($data, $field['path']);
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );
