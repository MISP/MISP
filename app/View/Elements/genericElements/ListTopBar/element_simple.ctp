<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        if (!empty($data['onClick']) || empty($data['url'])) {
            $onClickParams = array();
            if (!empty($data['onClickParams'])) {
                foreach ($data['onClickParams'] as $param) {
                    if ($param === 'this') {
                        $onClickParams[] = h($param);
                    } else {
                        $onClickParams[] = '\'' . h($param) . '\'';
                    }
                }
            }
            $onClickParams = implode(',', $onClickParams);
            $onClick = sprintf(
                'onClick="%s%s"',
                (empty($data['url'])) ? 'event.preventDefault();' : '',
                (!empty($data['onClick']) ? sprintf(
                    '%s(%s)',
                    h($data['onClick']),
                    $onClickParams
                ) : '')
            );
        }
        $dataFields = array();
        if (!empty($data['data'])) {
            foreach ($data['data'] as $dataKey => $dataValue) {
                $dataFields[] = sprintf(
                    'data-%s="%s"',
                    h($dataKey),
                    h($dataValue)
                );
            }
        }
        $dataFields = implode(' ', $dataFields);
        echo sprintf(
            '<a class="btn btn-small %s %s" %s href="%s" %s %s %s %s %s>%s%s%s %s</a>',
            empty($data['class']) ? '' : h($data['class']),
            empty($data['active']) ? 'btn-inverse' : 'btn-primary',   // Change the default class for highlighted/active toggles here
            empty($data['id']) ? '' : 'id="' . h($data['id']) . '"',
            empty($data['url']) ? '#' : h($data['url']),    // prevent default is passed if the url is not set
            empty($onClick) ? '' : $onClick,    // pass $data['onClick'] for the function name to call and $data['onClickParams'] for the parameter list
            empty($dataFields) ? '' : $dataFields,
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
