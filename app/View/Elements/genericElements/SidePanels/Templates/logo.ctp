<?php
    $styles = [];
    $div_style = [];
    $style_keywords = ['width', 'height', 'text-align'];
    $style_mappings = ['div', 'img'];
    foreach ($style_mappings as $style_mapping) {
        foreach ($style_keywords as $style_keyword) {
            if (!empty($side_panel[$style_mapping]['css'][$style_keyword])) {
                $styles[$style_mapping][] = $style_keyword . ': ' . $side_panel[$style_mapping]['css'][$style_keyword];
            }
        }
    }
    echo sprintf(
        '<div %s><img src="%s" %s></img></div>',
        empty($styles['div']) ? '' : sprintf('style="%s"', implode('; ', $styles['div'])),
        $side_panel['source'],
        empty($styles['img']) ? '' : sprintf('style="%s"', implode('; ', $styles['img']))
    );

?>
