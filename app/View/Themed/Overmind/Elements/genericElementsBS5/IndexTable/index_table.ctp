<?php
$data = $scaffold_data['data'];
$Paginator = $this->Paginator;

if (!empty($data['paginatorOptions'])) {
    $Paginator->options($data['paginatorOptions']);
}

$rows = '';
foreach ($data['data'] as $k => $data_row) {

    $row = '<tr>';

    $row .= $this->element(
        'genericElementsBS5/IndexTable/row',
        [
            'k' => $k,
            'row' => $data_row,
            'fields' => $data['fields'],
            'options' => $data['options'] ?? [],
            'actions' => $data['actions'] ?? [],
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
<script>
    var passedArgsArray = <?= isset($passedArgs) ? $passedArgs : '{}'; ?>;
    var url = "<?= $url ?>";
    <?php if ($hasSearch): ?>
    $(function() {
        <?php
        if (isset($containerId)) {
            echo 'var target = "#' . $containerId . '_content";';
        }
        ?>
        $('#quickFilterScopeSelector').change(function() {
            $('#quickFilterField').data('searchkey', this.value)
        });
        $('#quickFilterButton').click(function() {
            if (typeof(target) !== 'undefined') {
                runIndexQuickFilterFixed(passedArgsArray, url, target);
            } else {
                runIndexQuickFilterFixed(passedArgsArray, url);
            }
        });
    });
    <?php endif; ?>
</script>


