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
 *               'collapsed' => 0|1  // defaults to 0, whether to display it by default or not
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
            $listElements .= sprintf(
                '<tr><td class="meta_table_key">%s</td><td class="meta_table_value">%s</td></tr>',
                h($field['key']),
                $this->element(
                    '/genericElements/SingleViews/Fields/' . $field['type'] . 'Field',
                    ['data' => $data, 'field' => $field]
                )
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
    $ajaxLists = '';
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
    $title = empty($title) ?
        __('%s view', Inflector::singularize(Inflector::humanize($this->request->params['controller']))) :
        $title;
    echo sprintf(
        '<div class="view"><div class="row-fluid"><div class="span8">%s</div><div class="span4">%s</div></div><div id="accordion"></div>%s</div>%s',
        sprintf(
            '<div><h2 class="ellipsis-overflow">%s</h2>%s%s<table class="meta_table table table-striped table-condensed">%s</table></div>',
            h($title),
            empty($description) ? '' : sprintf('<p>%s</p>', h($description)),
            empty($description_html) ? '' : sprintf('<p>%s</p>', $description_html),
            $listElements
        ),
        $side_panels,
        $ajaxLists,
        $ajax ? '' : $this->element('/genericElements/SideMenu/side_menu', $menuData)
    );
?>
