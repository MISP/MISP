<?php
    echo sprintf(
        '<div><a href="%s" class="%s" style="%s" title="%s" %s>%s %s</a></div>',
        empty($fieldData['url']) ? '#' : h($fieldData['url']),
        empty($fieldData['class']) ? '' : h($fieldData['class']),
        empty($fieldData['style']) ? '' : h($fieldData['style']),
        empty($fieldData['title']) ? '' : h($fieldData['title']),
        empty($fieldData['onClick']) ? '' : sprintf('onClick="%s"', h($fieldData['onClick'])),
        empty($fieldData['icon']) ? '' : sprintf('<i class="fas fa-%s"></i>', h($fieldData['icon'])),
        empty($fieldData['text']) ? '#' : h($fieldData['text'])
    );
