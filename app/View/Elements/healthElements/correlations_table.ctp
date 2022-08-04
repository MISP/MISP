<?php
    $engine_contents = sprintf(
        '<tr><th title="%s">%s</th><th title="%s">%s</th><th title="%s">%s</th><th title="%s">%s</th></tr>',
        __('Table name'),
        __('Table'),
        __('Number of entries in the table'),
        __('# of rows'),
        __('The table\'s size in MB on disk'),
        __('Size on disk'),
        __('The saturation of the ID space of the given table. Be careful, reaching the limit will block further correlations from being created - make sure you recorrelate in time or extend the ID space by changing the column type.'),
        __('ID space saturation')
    );
    foreach ($currentEngineData['tables'] as $table_name => $table_data) {
        $engine_contents .= sprintf(
            '<tr><td>%s</td><td>%s</td><td title="%s">%s</td><td title="%s">%s</td></tr>',
            h($table_name),
            h($table_data['row_count']),
            h($table_data['size_on_disk']) . ' B',
            h(round($table_data['size_on_disk']/1024/1024), 2) . ' MB',
            sprintf(
                "Last inserted correlation ID: %s\nHighest possible ID: %s",
                h($table_data['last_id']),
                h($table_data['id_limit'])
            ),
            h($table_data['id_saturation']) . '%'

        );
    }
    echo sprintf(
        '<table class="meta_table table table-striped table-condensed">%s</table>',
        $engine_contents
    );
