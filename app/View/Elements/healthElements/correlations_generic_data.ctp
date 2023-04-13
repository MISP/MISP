<?php

    $rows = '';
    $rows .= sprintf(
        '<tr><td><a href="%s">%s</a></td><td style="text-align:right;">%s</td></tr>',
        $baseurl . '/correlations/overCorrelations',
        __('Over correlations'),
        h($correlation_metrics['over_correlations'])
    );
    $rows .= sprintf(
        '<tr><td><a href="%s">%s</a></td><td style="text-align:right;">%s</td></tr>',
        $baseurl . '/correlation_exclusions/index',
        __('Excluded correlations'),
        h($correlation_metrics['excluded_correlations'])
    );
    echo sprintf(
        '<table class="meta_table table table-striped table-condensed"><tr><th>Field</th><th style="text-align:right;">Value</th></tr>%s</table>',
        $rows
    );
