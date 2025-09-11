<?php
if (!empty($data['path'])) {
    $fields = Hash::extract($data['fields'], '{n}.name');
    $fields = array_map(function ($f) {
        return '<th>' . h($f) . '</th>';
    }, $fields);
    $fields = implode('', $fields);
    $childRows = Hash::get($data_row, $data['path']);
    if (!empty($childRows) && is_array($childRows)) {
        $content = '';
        foreach ($childRows as $i => $childRow) {
            $content .= sprintf(
                '<tr class="child-rows" id="child-rows-%s">%s</tr>',
                h($k),
                $this->element('/genericElements/IndexTable/row', [
                    'k' => $k,
                    'row' => $childRow,
                    'parent' => $data_row,
                    'fields' => $data['fields'],
                    'options' => $options,
                    'actions' => null,
                    'primary' => $primary,
                    'tableRandomValue' => $tableRandomValue,
                    'multi-select' => false
                ])
            );
        }
        echo sprintf(
            '<td colspan=%s><table class="table table-hover mb-0">%s<tr>%s</tr></table></td>',
            h($colspan),
            $fields,
            $content
        );
    }
}