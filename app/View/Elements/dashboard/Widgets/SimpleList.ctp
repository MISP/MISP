<div>
<?php
    foreach ($data as $element) {
        if (!empty($element['type']) && $element['type'] === 'gap') {
            echo '<br />';
        } else {
            if (!empty($element['value'])) {
                if (is_array($element['value'])) {
                    foreach ($element['value'] as &$value) {
                        if (is_array($value)) {
                            $value = 'Array';
                        } else {
                            $value = h($value);
                        }
                    }
                    $element['value'] = '<br />' . implode('<br />', $element['value']);
                } else {
                    $element['value'] = h($element['value']);
                }
            }
            echo sprintf(
                '<div><span class="bold">%s</span>: <span class="%s">%s</span>%s</div>',
                h($element['title']),
                empty($element['class']) ? 'blue' : h($element['class']),
                !isset($element['value']) ? '' : $element['value'],
                empty($element['html']) ? '' : $element['html']
            );
        }
    }
?>
</div>