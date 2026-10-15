<?php
$list = $warninglist['Warninglist'] ?? [];
$railCards = $railCards ?? [];
$warninglistId = (int)($list['id'] ?? 0);

$this->set('headerIdentity', $list);
$this->set('headerTitle', $list['name'] ?? '');
$this->set('headerDescription', '');

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $warninglist,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Warninglists/View/warninglists_general',
            ],
            'right' => array_merge([
                'Warninglists/View/warninglists_actions',
                'Warninglists/View/warninglists_test',
            ], $this->RailCard->rail($railCards, ['warninglist-inventory'], 'general')),
        ],
        [
            'id' => 'entries',
            'title' => __('Entries'),
            'icon' => 'fas fa-list',
            'left' => [
                ['ajax' => sprintf('%s/warninglists/entries/%s', $baseurl, $warninglistId)],
            ],
            'right' => array_merge([
                'Warninglists/View/warninglists_test',
            ], $this->RailCard->rail($railCards, ['warninglist-inventory'], 'entries')),
        ],
    ],
]);
