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
            $change = '';
            if (!empty($element['change'])) {
                $change = (int)$element['change'];
                if ($change > 0) {
                    $change = '<span class="green bold"> (+' . $change . ')</span>';
                } else {
                    $change = '<span class="red bold"> (-' . $change . ')</span>';
                }
            }
            if (!empty($element['html_title'])) {
                $title = $element['html_title'];
            } else {
                $title = h($element['title']);
            }
            echo sprintf(
                '<div><span class="bold">%s</span>: <span class="%s">%s</span>%s%s</div>',
                $title,
                empty($element['class']) ? 'blue' : h($element['class']),
                !isset($element['value']) ? '' : $element['value'],
                empty($element['html']) ? '' : $element['html'],
                $change
            );
        }
    }
?>
</div>