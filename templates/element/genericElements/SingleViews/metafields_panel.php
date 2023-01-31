<?php
use \Cake\Routing\Router;

$tabData = [
    'navs' => [],
    'content' => []
];
foreach($data['MetaTemplates'] as $metaTemplate) {
    if (!empty($metaTemplate->meta_template_fields)) {
        $tabData['navs'][] = [
            'html' => $this->element('/genericElements/MetaTemplates/metaTemplateNav', ['metaTemplate' => $metaTemplate])
        ];
        $fields = [];
        foreach ($metaTemplate->meta_template_fields as $metaTemplateField) {
            $labelPrintedOnce = false;
            if (!empty($metaTemplateField->metaFields)) {
                foreach ($metaTemplateField->metaFields as $metaField) {
                    $fields[] = [
                        'key' => !$labelPrintedOnce ? $metaField->field : '',
                        'raw' => $metaField->value,
                        'warning' => $metaField->warning ?? null,
                        'info' => $metaField->info ?? null,
                        'danger' => $metaField->danger ?? null
                    ];
                    $labelPrintedOnce = true;
                }
            }
        }
        $listTable = $this->Bootstrap->listTable([
            'hover' => false,
            'elementsRootPath' => '/genericElements/SingleViews/Fields/'
        ],[
            'item' => false,
            'fields' => $fields,
            'caption' => __n(
                'This meta-template contains {0} meta-field',
                'This meta-template contains {0} meta-fields',
                count($fields),
                count($fields)
            )
        ]);
        if (!empty($metaTemplate['hasNewerVersion']) && !empty($fields)) {
            $listTable = $this->Bootstrap->alert([
                'html' => sprintf(
                    '<div>%s</div><div>%s</div>',
                    __('These meta-fields are registered under an outdated template. Newest template is {0}, current is {1}.', $metaTemplate['hasNewerVersion']->version, $metaTemplate->version),
                    $this->Bootstrap->button([
                        'text' => __('Migrate to version {0}', $metaTemplate['hasNewerVersion']->version),
                        'variant' => 'success',
                        'nodeType' => 'a',
                        'params' => [
                            'href' => Router::url([
                                'controller' => 'metaTemplates',
                                'action' => 'migrateOldMetaTemplateToNewestVersionForEntity',
                                $metaTemplate->id,
                                $data->id,
                            ])
                        ]
                    ])
                ),
                'variant' => 'warning',
            ]) . $listTable;
        }
        $tabData['content'][] = $listTable;
    }
}
if (!empty($additionalTabs)) {
    $tabData['navs'] = array_merge($additionalTabs['navs'], $tabData['navs']);
    $tabData['content'] = array_merge($additionalTabs['content'], $tabData['content']);
}
if (!empty($tabData['navs'])) {
    $metaTemplateTabs = $this->Bootstrap->Tabs([
        'pills' => true,
        'card' => true,
        'body-class' => ['p-1'],
        'data' => $tabData
    ]);
}
echo $metaTemplateTabs;