<?php
    /*
    Expect:
    
    $dbSchemaDiagnostics = array(
        $table_name1 => array(
            'description' => $description1,
            'column_name' => $column_name1,
            'actual' => array(
                (int) 0 => 'object_relation',
                (int) 1 => 'varchar(128)',
                [...]
            ),
            'expected' => array(
                (int) 0 => 'object_relation',
                (int) 1 => 'varchar(255)',
                [...]
            )
        ),
        [...]
    );


    */



    function highlightAndSanitize($dirty, $to_highlight, $color_type = 'success')
    {
        if (is_array($dirty)) {
            $array_sane = array();
            foreach ($dirty as $i => $item) {
                if (in_array($item, $to_highlight)) {
                    $array_sane[] = sprintf('<span class="label label-%s">', $color_type) . h($item) . '</span>';
                } else {
                    $array_sane[] = h($item);
                }
            }
            return $array_sane;
        } else {
            $sane = h($dirty);
            $sane = str_replace($to_highlight, sprintf('<span class="label label-%s">', $color_type)  . h($to_highlight) . '</span>', $sane);
            return $sane;
        }
    }
?>

<?php
    if (count($dbSchemaDiagnostics) > 0) {
        echo sprintf('<span  style="margin-bottom: 5px;" class="label label-important" title="%s">%s<i style="font-size: larger;" class="fas fa-times"></i></span>',
            __('The current database schema does not match the excpect format'),
            __('Database schema diagnostic: ')
        );
        $table = sprintf('%s%s%s', 
            '<table class="table table-bordered table-condensed">',
            sprintf('<thead><th>%s</th><th>%s</th><th>%s</th><th>%s</th></thead>', __('Table name'),  __('Description'), __('Expected schema'), __('Actual schema')),
            '<tbody>'
        );
        $rows = '';
        foreach ($dbSchemaDiagnostics as $table_name => $table_diagnostic) {
            $rows .= '<tr>';
                $rows .= sprintf('<td rowspan="%s" colspan="0" class="bold">%s</td>', count($table_diagnostic)+1, h($table_name));
            $rows .= '</tr>';

            foreach ($table_diagnostic as $i => $column_diagnostic) {
                $column_diagnostic['expected'] = isset($column_diagnostic['expected']) ? $column_diagnostic['expected'] : array();
                $column_diagnostic['actual'] = isset($column_diagnostic['actual']) ? $column_diagnostic['actual'] : array();
                $column_diagnostic['description'] = isset($column_diagnostic['expected']) ? $column_diagnostic['description'] : '';
                $column_diagnostic['column_name'] = isset($column_diagnostic['column_name']) ? $column_diagnostic['column_name'] : '';

                $intersect = array_intersect($column_diagnostic['expected'], $column_diagnostic['actual']);
                $diff_expected = array_diff($column_diagnostic['expected'], $intersect);
                $diff_actual = array_diff($column_diagnostic['actual'], $intersect);

                $sane_description = highlightAndSanitize($column_diagnostic['description'], $column_diagnostic['column_name'], '');
                $sane_expected = highlightAndSanitize($column_diagnostic['expected'], $diff_expected);
                $sane_actual = highlightAndSanitize($column_diagnostic['actual'], $diff_actual, 'important');

                $rows .= '<tr>';
                    $rows .= sprintf('<td>%s</td>', $sane_description);
                    $rows .= sprintf('<td class="dbColumnDiagnosticRow" data-table="%s" data-index="%s">%s</td>', h($table_name), h($i), implode(' ', $sane_expected));
                    $rows .= sprintf('<td class="dbColumnDiagnosticRow" data-table="%s" data-index="%s">%s</td>', h($table_name), h($i), implode(' ', $sane_actual));
                $rows .= '</tr>';
            }
        }
        $table .= $rows . '</tbody></table>';
        echo $table;
    } else {
        if (empty($error)) {
            echo sprintf('<span class="label label-success" title="%s">%s <i class="fas fa-check"></i></span>',
                __('The current database is correct'),
                __('Database schema diagnostic: ')
            );
        } else {
            echo sprintf('<span class="label label-important" style="margin-left: 5px;" >%s <i class="fas fa-times"></i></span>',
                h($error)
            );
        }
    }
    echo sprintf('<span class="label label-%s" style="margin-left: 5px;">%s</span>',
        is_numeric($expectedDbVersion) ? 'success' : 'important',
        __('Expected DB_version: ') . h($expectedDbVersion)
    );
    if ($expectedDbVersion == $actualDbVersion) {
        echo sprintf('<span class="label label-success" style="margin-left: 5px;" title="%s">%s <i class="fas fa-check"></i></span>',
            __('The current database version matches the expected one'),
            __('Actual DB_version: ') . h($actualDbVersion)
        );
    } else {
        echo sprintf('<span class="label label-important" style="margin-left: 5px;" title="%s">%s <i class="fas fa-times"></i></span>',
            __('The current database version does not matche the expected one'),
            __('Actual DB_version: ') . h($actualDbVersion)
        );
    }
?>
<script>
var db_schema_diagnostics = <?php echo json_encode($dbSchemaDiagnostics); ?>;
var db_schema_diagnostics_columns = <?php echo json_encode($checkedTableColumn); ?>;

$(document).ready(function() {
    var popover_diagnostic = $('td.dbColumnDiagnosticRow').popover({
        title: '<?php echo __('Column diagnostic'); ?>',
        content: function() {
            var $row = $(this);
            var tableName = $row.data('table');
            var column_id = $row.data('index');
            var popover_html = arrayToNestedTable(
                db_schema_diagnostics_columns,
                [
                    db_schema_diagnostics[tableName][column_id].expected,
                    db_schema_diagnostics[tableName][column_id].actual,
                ]
            );
            return popover_html;
        },
        html: true,
        placement: function(context, src) {
            $(context).css('max-width', 'fit-content'); // make popover larger
            return 'bottom';
        },
        container: 'body',
        trigger: 'hover'
    });
});
</script>