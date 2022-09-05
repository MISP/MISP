<?php
$filterTagsConditions = [];
$availableConditions = ['enabled', 'filter'];
foreach ($availableConditions as $key) {
    if (isset($this->request->params['named'][$key])) {
        $filterTagsConditions[$key] = $this->request->params['named'][$key];
    }
}
$filterTags = '';
foreach ($filterTagsConditions as $key => $value) {
    $filterTags .= sprintf('/%s:%s', h($key), h($value));
}

$enableHTML = '';
if ($isSiteAdmin) {
    if ($taxonomy['enabled']) {
        $enableHTML .= $this->Form->postLink(__('Disable taxonomy'), array('action' => 'disable', h($taxonomy['id'])), array('title' => __('Disable')), (__('Are you sure you want to disable this taxonomy library?')));
    } else {
        $enableHTML .= $this->Form->postLink(__('Enable taxonomy'), array('action' => 'enable', h($taxonomy['id'])), array('title' => __('Enable')), (__('Are you sure you want to enable this taxonomy library?')));
    }
}
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('%s Taxonomy Library', h(strtoupper($taxonomy['namespace']))),
        'data' => $taxonomy,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Namespace'),
                'path' => 'namespace'
            ],
            [
                'key' => __('Description'),
                'path' => 'description'
            ],
            [
                'key' => __('Version'),
                'path' => 'version'
            ],
            [
                'key' => __('Enabled'),
                'path' => 'enabled',
                'type' => 'boolean'
            ],
            [
                'key' => __('Action'),
                'type' => 'custom',
                'requirement' => !empty($enableHTML),
                'function' => function ($taxonomy) use ($enableHTML) {
                    return $enableHTML;
                }
            ],
        ],
        'children' => [
            [
                'url' => sprintf('/taxonomies/taxonomy_tags/{{0}}%s', $filterTags),
                'url_params' => ['id'],
                'title' => __('Taxonomy Tags'),
                'elementId' => 'preview_taxonomy_tags_container',
                'open' => true,
            ],
        ],
        'menuData' => [
            'menuList' => 'taxonomies',
            'menuItem' => 'view'
        ]
    ]
);
