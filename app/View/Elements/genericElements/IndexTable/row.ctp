<?php
    /*
     * Constructs the individual rows for the index system
     * Each row has a list of fields and optionally a set of actions
     * These are passed via the main constructor passed to the index_table
     *
     * Rows optionally have doubleclick actions and can store 2 data points
     * to ease front-end scripting:
     * - data-row-id is the n-th row currently rendered
     * - data-primary-id is the database ID of the element described by each row
     */
    $rowHtml = '';
    foreach ($fields as $column => $field) {
        $field['data_path'] = empty($field['data_path']) ? '' : $field['data_path'];
        if (!isset($field['requirement']) || $field['requirement']) {
            if (empty($field['element'])) {
                $valueField = $this->element('/genericElements/IndexTable/Fields/generic_field', array('field' => $field, 'row' => $row, 'data_path' => empty($field['data_path']) ? '' : $field['data_path'], 'k' => $k, 'column' => $column));
            } else {
                $valueField = $this->element(
                    '/genericElements/IndexTable/Fields/' . $field['element'],
                    array(
                        'field' => $field,
                        'row' => $row,
                        'column' => $column,
                        'data_path' => empty($field['data_path']) ? '' : $field['data_path'],
                        'k' => $k,
                        'primary' => $primary
                    )
                );
            }
            if (!empty($field['decorator'])) {
                $valueField = $field['decorator']($valueField);
            }
            $rowHtml .= sprintf(
                '<td%s%s%s%s%s%s%s>%s</td>',
                (empty($field['id'])) ? '' : sprintf('id="%s"', $field['id']),
                (empty($field['class'])) ? '' : sprintf(' class="%s"', $field['class']),
                (empty($field['style'])) ? '' : sprintf(' style="%s"', $field['style']),
                (empty($field['title'])) ? '' : sprintf(' title="%s"', $field['title']),
                (empty($field['name'])) ? '' : sprintf(
                    ' data-path="%s"',
                    is_array($field['data_path']) ?
                        h(implode(', ', $field['data_path'])) :
                        (h($field['data_path']))
                ),
                (empty($field['encode_raw_value']) || empty($field['data_path'])) ? '' : sprintf(' data-value="%s"', (h(Hash::extract($row, $field['data_path'])[0]))),
                (empty($field['ondblclick'])) ? '' : sprintf(' ondblclick="%s"', $field['ondblclick']),
                $valueField
            );
        }
    }
    if (!empty($actions)) {
        $rowHtml .= $this->element(
            '/genericElements/IndexTable/Fields/actions',
            array(
                'actions' => $actions,
                'row' => $row,
                'column' => $column,
                'primary' => $primary
            )
        );
    }
    echo $rowHtml;
