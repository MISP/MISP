<?php
$collection = $data['Collection'];
$railCards = $railCards ?? [];

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
$this->set('headerTimestamps', $collection);

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
            'right' => array_merge([
                'Collections/View/collection_actions',
                'Collections/View/collection_analyst_data',
                'Collections/View/collection_graphs',
            ], $this->RailCard->rail($railCards, [
                'collection-inventory', 'collection-sources',
            ], 'general')),
        ],
        [
            'id' => 'elements',
            'title' => __('Elements'),
            'icon' => 'fas fa-file',
            'left' => [
                'Collections/View/collection_elements',
            ],
            'right' => $this->RailCard->rail($railCards, ['collection-inventory'], 'elements'),
        ]
    ]
]);
