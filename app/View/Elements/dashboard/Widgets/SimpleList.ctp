<?php
    foreach ($data as $element) {
        if (!empty($element['type']) && $element['type'] === 'gap') {
            echo '<br />';
        } else {
            echo sprintf(
                '<div><span class="bold">%s</span>: <span class="%s">%s</span>%s</div>',
                h($element['title']),
                empty($element['class']) ? 'blue' : h($element['class']),
                !isset($element['value']) ? '' : h($element['value']),
                empty($element['html']) ? '' : $element['html']
            );
        }
    }
