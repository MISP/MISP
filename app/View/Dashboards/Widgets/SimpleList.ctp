<?php
    foreach ($data as $element) {
        echo sprintf(
            '<div><span class="bold">%s</span>: <span class="blue">%s</span>%s</div>',
            h($element['title']),
            empty($element['value']) ? '' : h($element['value']),
            empty($element['html']) ? '' : $element['html']
        );
    }
