<?php
    $uuidHalfWidth = 3;
    $shortUUID = sprintf('%s...%s', substr($uuid, 0, $uuidHalfWidth), substr($uuid, 36-$uuidHalfWidth, $uuidHalfWidth));
    echo sprintf('<span title="%s">%s</span>', $uuid, $shortUUID);