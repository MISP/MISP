<?php
/*
 *  echo $this->element('/genericElements/SingleViews/single_view', [
 *      'title' => '' //page title,
 *      'description' => '' //description,
 *      'description_html' => '' //html description, unsanitised,
 *      'data' => $data, // the raw data passed for display
 *      'fields' => [
 *           elements passed as to be displayed in the <ul> element.
 *           format:
 *           [
                 'key' => '' // key to be displayed
 *               'path' => '' // path for the value to be parsed
 *               'type' => '' // generic assumed if not filled, uses SingleViews/Fields/* elements
 *           ]
 *      ],
 *      'children' => [
 *          // Additional elements attached to the currently viewed object. index views will be appended via ajax calls below.
            [
 *               'title' => '',
 *               'url' => '', //cakephp compatible url, can be actual url or array for the constructor
 *               'open' => true|false  // defaults to false, whether to display it by default or not
 *               'loadOn' => 'ready|expand'  // load the data directly or only when expanded from a collapsed state
 *
 *          ],
 *      ]
 *  ]);
 *
 */
    $listElements = '';
    if (!empty($fields)) {
        foreach ($fields as $field) {
            if (isset($field['requirement']) && !$field['requirement']) {
                continue;
            }

            if (empty($field['type'])) {
                $field['type'] = 'generic';
            }
            $action_buttons = '';
            if (!empty($field['action_buttons'])) {
                foreach ($field['action_buttons'] as $action_button) {
                    $action_buttons .= $this->element(
                        '/genericElements/Common/action_button',
                        ['data' => $data, 'params' => $action_button]
                    );
                }
            }
            $listElements .= sprintf(
                '<tr><td class="meta_table_key %s" title="%s">%s%s</td><td class="meta_table_value %s" title="%s">%s %s</td></tr>',
                empty($field['key_class']) ? '' : h($field['key_class']),
                empty($field['key_title']) ? '' : h($field['key_title']),
                h($field['key']),
                empty($field['key_info']) ? '' : sprintf(
                    ' <i class="fas fa-info-circle" title="%s"></i>',
                    h($field['key_info'])
                ),
                empty($field['class']) ? '' : h($field['class']),
                empty($field['title']) ? '' : h($field['title']),
                $this->element(
                    '/genericElements/SingleViews/Fields/' . $field['type'] . 'Field',
                    ['data' => $data, 'field' => $field]
                ),
                $action_buttons
            );
        }
    }
    if (!empty($data['metaFields'])) {
        foreach ($data['metaFields'] as $metaField => $value) {
            $listElements .= sprintf(
                '<tr><td class="meta_table_key">%s</td><td class="meta_table_value">%s</td></tr>',
                h($metaField),
                $this->element(
                    '/genericElements/SingleViews/Fields/genericField',
                    [
                        'data' => $value,
                        'field' => [
                        	'raw' => $value
                        ]
                    ]
                )
            );
        }
    }
    $ajaxLists = '<br>';
    if (!empty($children)) {
        foreach ($children as $child) {
            $ajaxLists .= $this->element(
                '/genericElements/SingleViews/child',
                array(
                    'child' => $child,
                    'data' => $data
                )
            );
        }
    }
    if (!empty($side_panels)) {
        $side_panels = $this->element(
            '/genericElements/SidePanels/scaffold',
            [
                'side_panels' => $side_panels,
                'data' => $data
            ]
        );
    } else {
        $side_panels = '';
    }
    $appendHtml = '';
    if (!empty($append)) {
        foreach ($append as $appendElement) {
            $appendHtml .= $this->element(
                $appendElement['element'],
                empty($appendElement['element_params']) ? [] : $appendElement['element_params']
            );
        }
    }
    $title = empty($title) ?
        __('%s view', Inflector::singularize(Inflector::humanize($this->request->params['controller']))) :
        $title;
    echo sprintf(
        '<div class="view"><div class="row-fluid"><div class="span8">%s</div><div class="span4">%s</div></div><div id="accordion"></div>%s%s</div>%s',
        sprintf(
            '<div><h2 class="ellipsis-overflow">%s</h2>%s%s<table class="meta_table table table-striped table-condensed">%s</table></div>',
            h($title),
            empty($description) ? '' : sprintf('<p>%s</p>', h($description)),
            empty($description_html) ? '' : sprintf('<p>%s</p>', $description_html),
            $listElements
        ),
        $side_panels,
        $ajaxLists,
        $appendHtml,
        $ajax ? '' : $this->element('/genericElements/SideMenu/side_menu', $menuData)
    );

