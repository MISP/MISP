<?php

$backupTemplates = $this->Form->getTemplates();
$tabData = [];
foreach ($entity->MetaTemplates as $i => $metaTemplate) {
    $tabData['navs'][$i] = [
        'html' => $this->element('/genericElements/MetaTemplates/metaTemplateNav', ['metaTemplate' => $metaTemplate])
    ];
    $fieldsHtml = '';
    $fieldsHtml .= $this->element(
        'genericElements/Form/metaTemplateForm',
        [
            'metaTemplate' => $metaTemplate,
        ]
    );
    $tabData['content'][$i] = $fieldsHtml;
}
$this->Form->setTemplates($backupTemplates);
echo $this->Bootstrap->Tabs([
    'pills' => true,
    'data' => $tabData,
    'nav-class' => ['shadow mb-3 p-2 rounded'],
    'content-class' => ['pt-2 px-3']
]);
