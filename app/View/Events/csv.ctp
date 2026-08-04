<?php
    if (isset($headerless) && !$headerless) {
        $size = sizeof($headers);
        foreach ($headers as $k => $header) {
            echo $header;
            if ($k != ($size-1)) echo ',';
        }
        echo PHP_EOL;
    }
    foreach ($final as $line) {
        echo $line;
        echo PHP_EOL;
    }
