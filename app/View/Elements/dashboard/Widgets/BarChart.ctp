<?php
    // If you want to force log scale, set the `forceLogarithm` option to true in the widget config: `{"widget_config": {"forceLogarithm": "1"}}`
    // Or the widget already contains data in log, set `logarithmic` to 1

?>
<table style="border-spacing:0px;">
<?php
    if (!empty($data['logarithmic'])) {
        $max = max($data['logarithmic']);
    } else {
        if (empty($data['data'])) {
            $max = 0;
        } else {
            $max = max($data['data']);
            $max = !empty($config['widget_config']['forceLogarithm']) ? ($max == 1 ? 0.1 : log10($max)) : $max;
        }
    }
    if (!empty($max)) {
        foreach ($data['data'] as $entry => $count) {
            $value = $count;
            if (!empty($data['logarithmic'])) {
                $value = $data['logarithmic'][$entry];
            } else if (!empty($config['widget_config']['forceLogarithm'])) {
                $value = $count == 1 ? 0.1 : log10($count);
            }
            $shortlabel = $entry;
            if (mb_strlen($shortlabel) > 30) {
                $shortlabel = mb_substr($shortlabel, 0, 30) . '...';
            }
            echo sprintf(
                '<tr><td style="%s" title="%s">%s</td><td style="%s">%s</td></tr>',
                'text-align:right;width:35em;white-space:nowrap;',
                h($entry),
                h($shortlabel),
                'width:100%',
                sprintf(
                    '<div title="%s" style="%s">%s%s</div>',
                    h($entry) . ': ' . h($count),
                    sprintf(
                        'background-color:%s; width:%s; color:white; text-align:center;',
                        (empty($data['colours'][$entry]) ? '#0088cc' : h($data['colours'][$entry])),
                        ($max == 0 ? 0 : 100 * h($value) / $max) . '%;'
                    ),
                    h($count),
                    !empty($data['output_decorator']) ? '%' : ''
                ),
                '&nbsp;'
            );
        }
    } else {
        echo __('No data.');
    }
?>
</table>
