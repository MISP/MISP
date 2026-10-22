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
    $viewUrl = ($dblclickUrl !== null && $primary !== null && $primary !== '')
        ? str_replace('%id%', (string)$primary, $dblclickUrl)
        : null;

    $rowClass = '';
    if (!empty($data['row_class_callable']) && is_callable($data['row_class_callable'])) {
        $rowClass = call_user_func($data['row_class_callable'], $data_row);
    }

    /*
     * `row_data_callable` returns name => value pairs to hang on the <tr>
     * as `data-` attributes. A row that has to be matched on several
     * independent keys at once — the Value Intelligence's facet rail filters on
     * type and organisation and tag together — cannot express that as a
     * class string without the reader parsing class names back into
     * fields. Names are restricted to what may follow `data-`; absent for
     * every existing caller.
     */
    $rowData = array();
    if (!empty($data['row_data_callable']) && is_callable($data['row_data_callable'])) {
        $rowData = (array)call_user_func($data['row_data_callable'], $data_row);
    }

    // For extending/extended View
    $rowStyle = '';
    if (!empty($data['row_style_callable']) && is_callable($data['row_style_callable'])) {
        $rowStyle = call_user_func($data['row_style_callable'], $data_row);
    }
    // HTML placed at the start of the row's first cell
    $rowMarker = '';
    if (!empty($data['row_marker_callable']) && is_callable($data['row_marker_callable'])) {
        $rowMarker = (string)call_user_func($data['row_marker_callable'], $data_row);
    }

    $row = '<tr data-row-id="' . h($k) . '"';
    if (!empty($primary)) {
        $row .= ' data-primary-id="' . h($primary) . '"';
    }
    foreach ($rowData as $name => $value) {
        $name = strtolower(preg_replace('/[^A-Za-z0-9-]/', '', (string)$name));
        if ($name === '' || $value === null) {
            continue;
        }
        $row .= ' data-' . $name . '="' . h($value) . '"';
    }
    if ($rowClass !== '') {
        $row .= ' class="' . h($rowClass) . '"';
    }
    if ($rowStyle !== '') {
        $row .= ' style="' . h($rowStyle) . '"';
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
            'viewUrl' => $viewUrl,
            'marker' => $rowMarker,
        ]
    );

    $row .= '</tr>';

    $rows .= $row;
}
?>

<?php if (empty($data['data'])): ?>

<div class="d-flex flex-column align-items-center text-secondary py-5">
    <i class="fas fa-inbox fa-2x d-block mb-2"></i>
    <?= h($data['empty_message'] ?? __('No items to display')) ?>
</div>

<?php else: ?>

<div class="table-responsive table-scroll">
    <table id="<?= h($tableId) ?>" class="table table-hover align-middle mb-0 ix-table<?= empty($data['table_class']) ? '' : ' ' . h($data['table_class']) ?>"
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