<?php
    $data = array(
        'children' => array(
            array(
                'children' => array(
                    array(
                        'text' => __('Overview'),
                        'url' => $baseurl . '/servers/serverSettings/',
                        'active' => $active_tab === false
                    )
                )
            )
        )
    );
    foreach ($tabs as $k => $tab) {
        $data['children'][0]['children'][] = array(
            'html' => sprintf(
                __('%s settings%s'),
                ucfirst(h($k)),
                ($tab['errors'] == 0) ? '' : sprintf(
                    ' (<span>%s%s</span>)',
                    h($tab['errors']),
                    ($tab['severity'] == 0) ? ' <i class="fa fa-exclamation-triangle" title="' . __('This tab reports some potential critical misconfigurations.') . '"></i>' : ''
                )
            ),
            'url' => $baseurl . '/servers/serverSettings/' . h($k),
            'active' => $k == $active_tab
        );
    }
    $data['children'][0]['children'][] = array(
        'url' => $baseurl . '/servers/serverSettings/diagnostics',
        'html' => sprintf(
            '%s%s',
            __('Diagnostics'),
            ($diagnostic_errors == 0) ? '' : sprintf(
                ' (<span>%s</span>)',
                h($diagnostic_errors)
            )
        ),
        'active' => $active_tab === 'diagnostics'
    );

    $data['children'][0]['children'][] = array(
        'url' => $baseurl . '/servers/serverSettings/files',
        'text' => __('Manage files'),
        'active' => $active_tab === 'files'
    );
    $data['children'][0]['children'][] = array(
        'url' => $baseurl . '/servers/serverSettings/workers',
        'title' => __('Workers'),
        'active' => 'workers' == $active_tab,
        'html' => sprintf(
            '%s %s%s',
            '<i class="fab fa-android"></i>',
            __('Workers'),
            ($workerIssueCount == 0) ? '' : sprintf(
                ' (<span>%s</span>)',
                h($workerIssueCount)
            )
        ),
        'requirement' => !empty($worker_array)
    );
    $data['children'][0]['children'][] = array(
        'url' => $baseurl . '/servers/serverSettings/download',
        'title' => __('Download report'),
        'html' => '<i class="fa fa-download"></i>'
    );
    if ($active_tab && !in_array($active_tab, array('diagnostics', 'files', 'workers'))) {
        $data['children'][] = array(
                'type' => 'live_search',
                'placeholder' => __('Filter the table(s) below')
        );
    }
    if (!$ajax) {
        echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
    }
?>
