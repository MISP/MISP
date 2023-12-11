<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        echo sprintf(
            '<span class="btn btn-small disabled %s" %s %s %s>%s%s%s %s</span>',
            empty($data['class']) ? '' : h($data['class']),
            empty($data['title']) ? '' : sprintf('title="%s"', h($data['title'])),
            empty($data['style']) ? '' : sprintf('style="%s"', h($data['style'])),
            !empty($data['text']) ? '' : (!empty($data['title']) ? sprintf('aria-label="%s"', h($data['title'])) : ''),
            empty($data['fa-icon']) ? '' : sprintf(
                '<i class="%s fa-%s"></i> ',
                empty($data['fa-source']) ? 'fas' : h($data['fa-source']),
                $data['fa-icon']
            ),  // this has to be sanitised beforehand!
            empty($data['html']) ? '' : $data['html'],  // this has to be sanitised beforehand!
            empty($data['text']) ? '' : h($data['text']),
            empty($data['badge']) ? '' : sprintf('<span class="badge badge-%s">%s</span>', empty($data['badge']['type']) ? 'info' : $data['badge']['type'], h($data['badge']['text']))
        );
    }
?>
