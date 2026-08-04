<?php
$data = $scaffold_data['data'];
$Paginator = $this->Paginator;

if (!empty($data['paginatorOptions'])) {
    $Paginator->options($data['paginatorOptions']);
}

$dblclickUrl = (!empty($data['row_dblclick_url']) && !empty($data['primary_id_path']))
    ? $data['row_dblclick_url']
    : null;
$tableId = 'tbl-' . dechex(mt_rand());

$rows = '';

$tableFields = array_filter($data['fields'], function($field) {
    if (empty($field['display_in'])) {
        return true;
    }
    return in_array('table', $field['display_in']);
});

foreach ($data['data'] as $k => $data_row) {

    $primary = !empty($data['primary_id_path']) ? Hash::get($data_row, $data['primary_id_path']) : null;

    $rowClass = '';
    if (!empty($data['row_class_callable']) && is_callable($data['row_class_callable'])) {
        $rowClass = call_user_func($data['row_class_callable'], $data_row);
    }

    $row = '<tr data-row-id="' . h($k) . '"';
    if (!empty($primary)) {
        $row .= ' data-primary-id="' . h($primary) . '"';
    }
    if ($rowClass !== '') {
        $row .= ' class="' . h($rowClass) . '"';
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

<?php if (empty($data['data'])): ?>

<div class="d-flex flex-column align-items-center text-secondary py-5">
    <i class="fas fa-inbox fa-2x d-block mb-2"></i>
    <?= __('No items to display') ?>
</div>

<?php else: ?>

<div class="table-responsive table-scroll">
    <table id="<?= h($tableId) ?>" class="table table-hover align-middle mb-0"
        <?= $dblclickUrl !== null ? 'data-dblclick-url="' . h($dblclickUrl) . '"' : '' ?>>

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

<?php endif; ?>

<?php if (!empty($data['data']) && $dblclickUrl !== null): ?>
<script>
(function () {
    var table = document.getElementById(<?= json_encode($tableId) ?>);
    if (!table) return;
    var urlPattern = table.dataset.dblclickUrl;
    table.addEventListener('dblclick', function (e) {
        if (e.target.closest('a, button, input, label, .dropdown, td:first-child')) return;
        var tr = e.target.closest('tr[data-primary-id]');
        if (!tr) return;
        window.location.href = urlPattern.replace('%id%', tr.dataset.primaryId);
    });
}());
</script>
<?php endif; ?>