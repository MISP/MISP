<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $entries,
            'filter_bar' => [
                'pull' => 'right',
                'base_url' => $baseurl . '/warninglists/entries/' . h($id),
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search entries'),
                        'name' => 'filter',
                        'mode' => 'legacy',
                    ],
                ],
            ],
            'fields' => [
                [
                    'name' => __('Value'),
                    'data_path' => 'WarninglistEntry.value',
                    'card_section' => 'title',
                    'display_in' => ['table', 'card'],
                ],
                [
                    'name' => __('Comment'),
                    'data_path' => 'WarninglistEntry.comment',
                    'card_section' => 'extra',
                    'display_in' => ['table', 'card'],
                ],
            ],
        ],
    ],
    'item_url' => '/warninglists/entries/' . h($id),
]);
