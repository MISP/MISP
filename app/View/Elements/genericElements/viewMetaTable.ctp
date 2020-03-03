<?php
    /*
    UI tool to build meta-field key-value tables for views (such as the event view, org view, etc)
    Use the following input for the element, defined as "table_data" in the input
    $table_data = array(
        array(
            'key' => 'key to use',
            'key_title' => 'title for hover-descriptions',
            'value' => 'raw value to use',
            'html' => 'raw html to echo - needs to be pre-sanitised',
            'boolean' => 'pass a value to evaluate as empty() and subsequently use a simple yes/no boolean field'
            'element' => 'element name to use as value',
            'element_params' => array(parameters to be passed to the element),
            'class' => 'classes appended to both the key and value',
            'key_class' => 'classes appended to the key',
            'value_class' => 'classes appended to the value'
        ),
        ...
    );
    */
    $rows = array();
    foreach ($table_data as $row) {
        $element = false;
        if (!empty($row['element'])) {
            $element = $this->element($row['element'], empty($row['element_params']) ? array() : $row['element_params']);
        }
        $rows[] = sprintf(
            '<tr><td class="%s" title="%s">%s</td><td class="%s">%s</td></tr>',
            sprintf(
                'meta_table_key %s %s',
                empty($row['class']) ? '' : h($row['class']),
                empty($row['key_class']) ? '' : h($row['key_class'])
            ),
            empty($row['key_title']) ? '' : h($row['key_title']),
            empty($row['key']) ? 'Undefined' : h($row['key']),
            sprintf(
                'meta_table_value %s %s',
                empty($row['class']) ? '' : h($row['class']),
                empty($row['value_class']) ? '' : h($row['value_class'])
            ),
            sprintf(
                '%s%s%s%s%s',
                !isset($row['boolean']) ? '' : sprintf(
                    '<span class="%s">%s</span>',
                    (empty($row['class']) && empty($row['value_class'])) ?
                        (empty($row['boolean']) ? 'bold red' : 'bold green') : '',
                    empty($row['boolean']) ? 'No' : 'Yes'
                ),
                empty($row['value']) ? '' : nl2br(h(trim($row['value']))),
                empty($row['html']) ? '' : $row['html'],
                empty($row['url']) ? '' : sprintf('<a href="%s">%s</a>', h($row['url']), h($row['url'])),
                empty($element) ? '' : $element
            )
        );
    }
    $rows = implode(PHP_EOL, $rows);
    echo sprintf(
        '<table class="%s">%s</table>',
        'meta_table table table-striped table-condensed',
        $rows
    );
