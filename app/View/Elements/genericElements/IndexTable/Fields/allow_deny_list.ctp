<?php
    $data = Hash::extract($row, $field['data_path']);
    $setup = [
        'allow' => [
            'name' => __('Allowed'),
            'color' => 'green'
        ],
        'deny' => [
            'name' => __('Denied'),
            'color' => 'red'
        ]
    ];
    foreach ($setup as $state => $settings) {
        if (!empty($data[$state])) {
            echo sprintf(
                '<div class="bold %s">%s</div>',
                $settings['color'],
                $settings['name']
            );
            foreach ($data[$state] as $k => $element) {
                $data[$state][$k] = sprintf(
                    '<span class="%s">%s</span>',
                    $settings['color'],
                    h($element)
                );
            }
            echo implode('<br />', $data[$state]);
        }
    }
    
?>
