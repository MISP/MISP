<?php
$data = $scaffold_data['data'];
$Paginator = $this->Paginator;

if (!empty($data['paginatorOptions'])) {
    $Paginator->options($data['paginatorOptions']);
}

$rows = '';
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
            'fields' => $data['fields'],
            'options' => $data['options'] ?? [],
            'actions' => $data['actions'] ?? [],
            'primary' => $primary,
        ]
    );

    $row .= '</tr>';

    $rows .= $row;
}
?>

<div class="table-responsive">
    <table class="table table-hover align-middle mb-0">

        <?= $this->element(
            'genericElementsBS5/IndexTable/headers',
            [
                'fields' => $data['fields'],
                'paginator' => $Paginator,
                'actions' => !empty($data['actions'])
            ]
        ); ?>

        <tbody>
            <?= $rows ?>
        </tbody>

    </table>
</div>