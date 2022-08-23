<?php
    foreach ($field['warnings'] as $key => $values) {
        $values = is_array($values) ? $values : [$values];
        foreach ($values as $value) {
            echo sprintf(
                '<span class="bold">%s</span>: <p style="margin-left:10px;">%s</p>',
                h($key),
                h($value)
            );
        }
    }
