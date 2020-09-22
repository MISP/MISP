<div>
<table class="table table-striped table-hover table-condensed">
<?php
    /*
    * Display a simple array.
    * The size of the keys array is considered for the width.
    * Expected input:
    * { keys: <array of string>, rows: <array of arrays>}
    *
    * Example:
    * {keys: ['id', 'name', 'score'], rows: [['1', 'test', '10'], ['2', 'john', '5']]}
    *
    */
    $count = count($data['keys']);
    echo '<tr>';
    foreach ($data['keys'] as $key) {
        echo '<th>'.h($key).'</th>';
    }
    echo '</tr>';
    foreach ($data['rows'] as $row) {
        echo '<tr>';
        for ($i=0; $i<$count; $i++) {
            if (isset($row[$i])) {
                echo '<td>'.h($row[$i]).'</td>';
            }
        }
    echo '</tr>';
    }
?>
</table>
</div>
