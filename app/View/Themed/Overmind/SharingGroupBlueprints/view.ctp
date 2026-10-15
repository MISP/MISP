<?php
$blueprint = $data['SharingGroupBlueprint'] ?? [];
$railCards = $railCards ?? [];

$this->set('headerIdentity', $blueprint);
$this->set('headerTitle', $blueprint['name'] ?? '');
$this->set('headerDescription', empty($blueprint['timestamp'])
    ? ''
    : '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($blueprint['timestamp']) . '</span>');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'SharingGroupBlueprints/View/sharingGroupBlueprints_general',
                'SharingGroupBlueprints/View/sharingGroupBlueprints_orgs_card',
            ],
            'right' => array_merge([
                'SharingGroupBlueprints/View/sharingGroupBlueprints_actions',
            ], $this->RailCard->rail($railCards, ['blueprint-pending', 'blueprint-result'], 'general')),
        ],
        [
            'id' => 'organisations',
            'title' => __('Organisations'),
            'icon' => 'fas fa-building-user',
            'count' => $matchingOrgCount ?? null,
            'left' => [
                [
                    'ajax' => sprintf('%s/SharingGroupBlueprints/viewOrgs/%s', $baseurl, (int)$blueprint['id']),
                ],
            ],
            'right' => $this->RailCard->rail($railCards, ['blueprint-pending'], 'organisations'),
        ],
    ],
]);
