<?php
    if (!isset($params['requirement']) || $params['requirement']) {
        echo sprintf('<a href="%s" style="%s" title="%s" %s>%s%s%s</a>',
            h($params['url']),
            h($params['style']),
            h($params['title']),
            empty($params['onclick']) ? '' : sprintf('onClick="%s"', $params['onClick']),
            empty($params['html']) ? '' : h($params['html']),
            empty($params['text']) ? '' : h($params['text']),
            empty($params['icon']) ? '' : sprintf('<i class="fas fa-%s"></i>', h($params['icon']))
        );
    }
 ?>
