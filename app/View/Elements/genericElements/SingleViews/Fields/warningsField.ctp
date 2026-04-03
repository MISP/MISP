<?php
$grouped = [
    'error' => [],
    'warning' => [],
    'info' => [],
];

foreach ($field['warnings'] as $key => $values) {
    $values = is_array($values) ? $values : [$values];

    foreach ($values as $value) {
        $level = 'error'; // default

        if (is_array($value) && !empty($value['type'])) {
            $level = in_array($value['type'], ['error', 'warning', 'info'])
                ? $value['type']
                : 'error';
        }

        $grouped[$level][] = [
            'key' => $key,
            'value' => $value,
        ];
    }
}

// Render blocks
$first = true;
foreach ($grouped as $level => $messages) {
    if (empty($messages)) {
        continue;
    }

    $style = $first ? 'margin-bottom:0;' : 'margin-top:8px; margin-bottom:0;';
    $first = false;

    echo sprintf('<div class="alert alert-%s" style="%s">', h($level), $style);

    foreach ($messages as $item) {
        $key = $item['key'];
        $value = $item['value'];

        if (is_array($value) && !empty($value['html'])) {
            echo sprintf(
                '<b>%s</b>: <p style="margin-left:10px;">%s</p>',
                h($key),
                $value['html']
            );
        } else {
            echo sprintf(
                '<b>%s</b>: <p style="margin-left:10px;">%s</p>',
                h($key),
                h(is_array($value) ? '' : $value)
            );
        }
    }

    echo '</div>';
}
?>