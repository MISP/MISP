<?php
$data = $scaffold_data['data'];
$Paginator = $this->Paginator;

if (!empty($data['paginatorOptions'])) {
    $Paginator->options($data['paginatorOptions']);
}

$rows = '';

$tableFields = array_filter($data['fields'], function($field) {
    if (empty($field['display_in'])) {
        return true;
    }
    return in_array('table', $field['display_in']);
});

foreach ($data['data'] as $k => $data_row) {

    $primary = !empty($data['primary_id_path']) ? Hash::get($data_row, $data['primary_id_path']) : null;

    $row = '<tr data-row-id="' . h($k) . '"';
    if (!empty($primary)) {
        $row .= ' data-primary-id="' . h($primary) . '"';
    }
    $row .= '>';

    $row .= $this->element(
        'genericElementsBS5/IndexTable/row',
        [
            'k' => $k,
            'row' => $data_row,
            'fields' => $tableFields,
            'options' => $data['options'] ?? [],
            'actions' => $data['actions'] ?? [],
            'primary' => $primary,
        ]
    );

    $row .= '</tr>';

    $rows .= $row;
}
?>

<div class="table-responsive table-scroll">
    <table class="table table-hover align-middle mb-0">

        <?= $this->element(
            'genericElementsBS5/IndexTable/headers',
            [
                'fields' => $tableFields,
                'paginator' => $Paginator,
                'actions' => !empty($data['actions'])
            ]
        ); ?>

        <tbody>
            <?= $rows ?>
        </tbody>

    </table>
</div>