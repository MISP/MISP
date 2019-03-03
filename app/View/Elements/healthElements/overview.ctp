<?php
    $health = array(
        0 => __('Critical, your MISP instance requires immediate attention.'),
        1 => __('Issues found, it is recommended that you resolve them.'),
        2 => __('Good, but there are some optional settings that are incorrect / not set.'),
        3 => __('In perfect health.')
    );
    $colour_coding = array(
        0 => 'error',
        1 => 'warning',
        2 => 'success',
        3 => 'info'
    );
    $fields = array(
        'test' => __('Test'),
        'value' => __('Value'),
        'description' => __('Description')
    );
    if ($diagnostic_errors > 0) $issues['overallHealth'] = 0;
    $rows = array(
        array(
            'test' => __('Overall health'),
            'value' => h($health[$issues['overallHealth']]),
            'description' => __('The overall health of your instance depends on the most severe unresolved issues.'),
            'severity' => 0,
            'coloured' => $issues['overallHealth'] < 3
        )
    );
    foreach ($issues['errors'] as $k => $v) {
        $rows[] = array(
            'test' => h($priorities[$k]) . __(' settings incorrectly or not set'),
            'value' => __('%s incorrect settings.', h($v['value'])),
            'description' => h($v['description']),
            'severity' => $k,
            'coloured' => $v > 0
        );
    }
    $rows[] = array(
        'test' => __('Critical issues revealed by the diagnostics'),
        'value' => __('%s issues detected.', h($diagnostic_errors)),
        'description' => __('Issues revealed here can be due to incorrect directory permissions or not correctly installed dependencies.'),
        'severity' => 0,
        'coloured' => $diagnostic_errors > 0
    );
    $headers = array();
    foreach ($fields as $k => $header) {
        $headers[] = sprintf('<th>%s</th>', $header);
    }
    $row_data = sprintf('<tr>%s</tr>', implode('', $headers));
    foreach ($rows as $row) {
        $column_data = '';
        foreach (array_keys($fields) as $field) {
            $column_data .= sprintf(
                '<td>%s</td>',
                $row[$field]
            );
        }
        $row_data .= sprintf(
            '<tr class="%s">%s</tr>',
            ($row['coloured']) ? $colour_coding[$row['severity']] : '',
            $column_data
        );
    }
    echo sprintf(
        '<table class="table table-hover table-condensed settingsTableContainer">%s</table>',
        $row_data
    );
?>
