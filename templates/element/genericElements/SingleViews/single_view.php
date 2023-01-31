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
 *               'key' => '' // key to be displayed
 *               'path' => '' // path for the value to be parsed
 *               'type' => '' // generic assumed if not filled, uses SingleViews/Fields/* elements
 *           ]
 *      ],
 *      'children' => [
 *          // Additional elements attached to the currently viewed object. index views will be appended via ajax calls below.
*          [
 *               'title' => '',
 *               'url' => '', //cakephp compatible url, can be actual url or array for the constructor
 *               'collapsed' => 0|1  // defaults to 0, whether to display it by default or not
 *               'loadOn' => 'ready|expand'  // load the data directly or only when expanded from a collapsed state
 *
 *          ],
 *      ],
 *      'skip_meta_templates' => false // should the meta templates not be displayed
 *      'combinedFieldsView' => false // should the default fields and meta fields displayed in a merged interface
 *  ]);
 *
 */
    $tableRandomValue = Cake\Utility\Security::randomString(8);
    $listTableOptions = [
        'id' => "single-view-table-{$tableRandomValue}",
        'hover' => false,
        'tableClass' => 'col-sm-8',
        'elementsRootPath' => '/genericElements/SingleViews/Fields/'
    ];
    if (!empty($data['MetaTemplates']) && (empty($skip_meta_templates)) && !empty($combinedFieldsView)) {
        $listTableOptions['tableClass'] = '';
    }
    $listTable = $this->Bootstrap->listTable($listTableOptions,[
        'item' => $entity,
        'fields' => $fields
    ]);

    $metafieldsPanel = '';
    if (!empty($data['MetaTemplates']) && (empty($skip_meta_templates))) {
        $metaFieldsData = [
            'data' => $data,
        ];
        if (!empty($combinedFieldsView)) {
            $metaFieldsData['additionalTabs'] = [
                'navs' => [
                    ['text' => __('Default')]
                ],
                'content' => [
                    $listTable
                ]
            ];
            $listTable = '';
        }
        $metafieldsPanel = $this->element('/genericElements/SingleViews/metafields_panel', $metaFieldsData);
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
    $title = empty($title) ?
        __('{0} view', \Cake\Utility\Inflector::singularize(\Cake\Utility\Inflector::humanize($this->request->getParam('controller')))) :
        $title;
    echo sprintf(
    "<div id=\"single-view-table-container-%s\">
            <h2 class=\"fw-light\">%s</h2>
            %s%s
            <div class=\"col-xl-10 col-xxl-8 px-0\">%s</div>
            <div id=\"metafieldsPanel\" class=\"col-xl-12 col-xxl-10 px-0\">%s</div>
            <div id=\"accordion\">%s</div>
        </div>",
        $tableRandomValue,
        h($title),
        empty($description) ? '' : sprintf('<p>%s</p>', h($description)),
        empty($description_html) ? '' : sprintf('<p>%s</p>', $description_html),
        $listTable,
        $metafieldsPanel,
        $ajaxLists
    );
?>
