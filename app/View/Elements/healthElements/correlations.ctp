<?php
    echo '<div style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">';
    echo sprintf(
        '<p>%s</p><p>%s</p>',
        __('This is the correlation management interface. Its goal is to provide you with information about the currently used correlation engine as well as the data stores of currently dormant engines.'),
        __('You will also find management tools for the various engines below, make sure that you keep an eye on the disk requirements as well as the exhaustion of IDs and recorrelate the instance when needed.')
    );
    echo sprintf(
        '<div style="width:300px;">%s</div>',
        $this->element(
            '/healthElements/correlations_generic_data',
            [
                'correlation_metrics' => $correlation_metrics
            ]
        )
    );
    $currentEngineData = $correlation_metrics['db'][$correlation_metrics['engine']];
    unset($correlation_metrics['db'][$correlation_metrics['engine']]);

    echo sprintf(
        '<hr /><h2 class="overflow label label-success">%s</h2><div style="width:800px;">%s<div>%s</div></div>',
        __('Active engine: %s', $currentEngineData['name']),
        $this->element('/healthElements/correlations_table', ['currentEngineData' => $currentEngineData]),
        sprintf(
            '<div class="btn btn-primary" onClick="simplePopup(\'%s\');">%s</div>',
            $baseurl . '/attributes/generateCorrelation',
            __('Recorrelate')
        )
    );
    foreach ($correlation_metrics['db'] as $engine => $engineData) {
        echo sprintf(
            '<hr /><h2 class="overflow label">%s</h2><div style="width:800px;">%s<div>%s %s</div></div>',
            __('Dormant engine: %s', $engineData['name']),
            $this->element('/healthElements/correlations_table', ['currentEngineData' => $engineData]),
            $engine === 'Legacy' ? '' : sprintf(
                '<div class="btn btn-primary" onClick="simplePopup(\'%s\');">%s</div>',
                $baseurl . '/correlations/switchEngine/' . h($engine),
                __('Activate engine')
            ),
            sprintf(
                '<div class="btn btn-danger" onClick="simplePopup(\'%s\');">%s</div>',
                $baseurl . '/correlations/truncate/' . h($engine),
                __('Truncate')
            )
        );
    }
    echo '</div>';
?>
