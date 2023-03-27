<?php
    $seed = 'f_' . mt_rand();
    if (!isset($data['requirement']) || $data['requirement']) {
        if (!empty($data['popover_url'])) {
            $onClick = sprintf(
                'openModalForButton%s(this, \'%s\', \'%s\')',
                $seed,
                h($data['popover_url']),
                h(!empty($data['reload_url']) ? $data['reload_url'] : '')
            );
        }
        if (empty($onClick)) {
            if (!empty($data['onClick']) || empty($data['url'])) {
                $onClickParams = array();
                if (!empty($data['onClickParams'])) {
                    foreach ($data['onClickParams'] as $param) {
                        if ($param === 'this') {
                            $onClickParams[] = $param;
                        } else {
                            $onClickParams[] = '\'' . $param . '\'';
                        }
                    }
                }
                $onClickParams = implode(',', $onClickParams);
                $onClick = sprintf(
                    '%s%s',
                    (empty($data['url'])) ? 'event.preventDefault();' : '',
                    (!empty($data['onClick']) ? sprintf(
                        '%s(%s)',
                        h($data['onClick']),
                        $onClickParams
                    ) : '')
                );
            } else if(!empty($data['url'])) {
                $onClick = sprintf(
                    '%s',
                    sprintf('window.location=\'%s\'', $data['url'])
                );
            }
        }

        $btnOptions = $data['button'] ?? [];
        if (empty($data['isFilter'])) {
            $btnOptions['variant'] = !empty($btnOptions['variant']) ? $btnOptions['variant'] : 'primary';
        } else if (empty($data['active'])) {
            $btnOptions['variant'] = 'light';
        } else {
            $btnOptions['variant'] = 'secondary';
        }
        $btnOptions['text'] = $data['button']['text'] ?? $data['text'];
        if (!empty($onClick)) {
            $btnOptions['onclick'] = $onClick;
        }
        if (!empty($data['html'])) {
            $btnOptions['html'] = $data['html'];
        }
        $btnOptions['attrs'] = array_merge([
            'href' => empty($data['url']) ? '#' : $baseurl . h($data['url']),
            'style' => $data['style'] ?? '',
            'aria-label' => !empty($data['text']) && !empty($data['title']) ? $data['title'] : '',
        ], $data['attrs'] ?? []);
        if (!empty($data['data'])) {
            $btnOptions['attrs'][sprintf('data-%s', h($dataKey))] = h($dataValue);
        }

        echo $this->Bootstrap->button($btnOptions);
    }
?>

<script>
    function openModalForButton<?= $seed ?>(clicked, url, reloadUrl='') {
        const fallbackReloadUrl = '<?= $this->Url->build(['action' => 'index']); ?>'
        reloadUrl = reloadUrl != '' ? reloadUrl : fallbackReloadUrl
        UI.overlayUntilResolve(clicked, UI.submissionModalForIndex(url, reloadUrl, '<?= $tableRandomValue ?>'))
    }
</script>