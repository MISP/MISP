<?php
$template = $data['ObjectTemplate'] ?? [];
$railCards = $railCards ?? [];
$elementCount = count($templateElements ?? []);

$this->set('headerIdentity', $template);
$this->set('headerTitle', $template['name'] ?? '');
$this->set('headerTitleHtml', sprintf(
    '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 align-self-center rounded-3 shadow-sm me-3"'
    . ' style="width:1.4em;height:1.4em;background:rgba(var(--bs-object-rgb),.12);color:rgb(var(--bs-object-rgb));">'
    . '<i class="misp-icon misp-icon-object misp-simple" style="font-size:.6em;"></i></span>'
    . '<span class="d-flex flex-column justify-content-center min-w-0"><span>%s</span>'
    . '<span class="fw-normal text-body-secondary mt-1" style="font-size:.4em;" title="%s">'
    . '<i class="fas fa-folder-tree me-1 opacity-50"></i>%s</span></span>',
    h($template['name'] ?? ''),
    h(__('Meta-category')),
    h($template['meta-category'] ?? '')
));
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'ObjectTemplates/View/objectTemplate_general',
                'ObjectTemplates/View/objectTemplate_elements_card',
            ],
            'right' => array_merge([
                'ObjectTemplates/View/objectTemplate_actions',
            ], $this->RailCard->rail($railCards, [
                'template-usage', 'template-inventory', 'template-versions', 'template-required-by',
            ], 'general')),
        ],
        [
            'id' => 'elements',
            'title' => __('Elements'),
            'icon' => 'fas fa-cube',
            'count' => $elementCount,
            'left' => [
                [
                    'ajax' => sprintf('%s/objectTemplateElements/viewElements/%s/all', $baseurl, (int)$template['id']),
                ],
            ],
            'right' => $this->RailCard->rail($railCards, ['template-inventory'], 'elements'),
        ],
    ],
]);
