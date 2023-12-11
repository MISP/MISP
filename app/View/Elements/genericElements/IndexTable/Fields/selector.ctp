<?php
    $data = array();
    if (!empty($field['data'])) {
        foreach ($field['data'] as $dataField => $dataValue) {
            $value = '';
            if (!empty($dataValue['value'])) {
                $value = $dataValue['value'];
            }
            if (!empty($dataValue['value_path']) && !empty(Hash::extract($row, $dataValue['value_path'])[0])) {
                $value = Hash::extract($row, $dataValue['value_path'])[0];
            }
            $data[] = 'data-' . h($dataField) . '="' . h($value) . '"';
        }
    }
    echo sprintf(
        '<input class="select_attribute select" ondblclick="event.stopPropagation();" type="checkbox" data-rowid="%s" %s>',
        h($k),
        empty($data) ? '' : implode(' ', $data)
    );
?>
