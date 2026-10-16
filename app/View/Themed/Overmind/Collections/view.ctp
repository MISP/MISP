<?php
$collection = $data['Collection'];

App::uses('CollectionType', 'Tools');

$titleHtml = h($collection['name'] ?? __('Collection'));
if (!empty($collection['type'])) {
    $typeLabel = CollectionType::label($collection['type']);
    $titleHtml = sprintf(
        '<span class="badge d-inline-flex align-items-center align-self-center py-1 me-2"'
        . ' style="background:rgba(var(--bs-primary-rgb),.12);color:var(--bs-primary);'
        . 'border:1px solid rgba(var(--bs-primary-rgb),.25);font-size:.55em;"'
        . ' data-bs-toggle="tooltip" title="%s" aria-label="%s"><i class="%s"></i></span>',
        h($typeLabel),
        h($typeLabel),
        h(CollectionType::icon($collection['type']))
    ) . $titleHtml;
}
$this->set('headerTitleHtml', $titleHtml);
$this->set('headerCountText', '');

$this->set('headerIdentity', $collection);

$descParts = [];
if (!empty($collection['created'])) {
    $descParts[] = '<span title="' . h(__('Created')) . '">'
        . '<i class="fas fa-calendar-day me-1 opacity-50"></i>'
        . $this->Time->time($collection['created'])
        . '</span>';
}
if (!empty($collection['modified'])) {
    $descParts[] = '<span title="' . h(__('Last modified')) . '">'
        . '<i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($collection['modified'])
        . '</span>';
}
$this->set(
    'headerDescription',
    '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $descParts) . '</span>'
);

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $collection['Orgc'] ?? [],
        'org' => $collection['Org'] ?? [],
        'user' => $collection['User'] ?? [],
        'distribution' => $collection['distribution'] ?? null,
        'sharingGroup' => $collection['SharingGroup'] ?? [],
    ],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Collections/View/collection_general',
                'Collections/View/collection_elements_card',
            ],
            'right' => [
                'Collections/View/collection_actions',
            ]
        ],
        [
            'id' => 'elements',
            'title' => __('Elements'),
            'icon' => 'fas fa-file',
            'left' => [
                'Collections/View/collection_elements',
            ],
        ]
    ]
]);
