<?php
$cerebrate = $data['Cerebrate'] ?? [];
$cerebrateId = (int)($cerebrate['id'] ?? 0);

$this->set('headerIdentity', $cerebrate);
$this->set('headerTitle', $cerebrate['name'] ?? '');
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Cerebrates/View/cerebrates_general',
            ],
            'right' => [
                'Cerebrates/View/cerebrates_actions',
            ],
        ],
        [
            'id' => 'organisations',
            'title' => __('Organisations'),
            'icon' => 'fas fa-building-user',
            'description' => __('Preview of the organisations known to the remote Cerebrate instance.'),
            'left' => [
                ['ajax' => sprintf('%s/cerebrates/preview_orgs/%s', $baseurl, $cerebrateId)],
            ],
        ],
        [
            'id' => 'sgs',
            'title' => __('Sharing Groups'),
            'icon' => 'fas fa-share-alt',
            'description' => __('Preview of the sharing groups known to the remote Cerebrate instance.'),
            'left' => [
                ['ajax' => sprintf('%s/cerebrates/preview_sharing_groups/%s', $baseurl, $cerebrateId)],
            ],
        ],
    ],
]);
