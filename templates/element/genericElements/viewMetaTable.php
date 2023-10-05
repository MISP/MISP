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
    echo '<table class="meta_table table table-striped table-condensed">';
    foreach ($table_data as $row) {
        $html = "";
        if (isset($row['boolean'])) {
            $html = sprintf(
                '<span class="%s">%s</span>',
                (empty($row['class']) && empty($row['value_class'])) ?
                    (empty($row['boolean']) ? 'label label-important label-padding' : 'label label-success label-padding') : '',
                empty($row['boolean']) ? __('No') : __('Yes'));
        }
        if (!empty($row['value'])) {
            $html .= nl2br(h(trim($row['value'])), false);
        }
        if (!empty($row['html'])) {
            $html .= $row['html'];
        }
        if (!empty($row['url'])) {
            $html .= sprintf('<a href="%s">%s</a>', h($row['url']), h($row['url']));
        }
        if (!empty($row['element'])) {
            $html .= $this->element($row['element'], empty($row['element_params']) ? array() : $row['element_params']);
        }
        echo sprintf(
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
            $html
        ) . PHP_EOL;
    }
    echo '</table>';
