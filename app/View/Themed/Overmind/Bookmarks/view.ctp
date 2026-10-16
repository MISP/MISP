<?php
$railCards = $railCards ?? [];
echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Bookmarks/View/bookmarks_general',
            ],
            'right' => array_merge([
                'Bookmarks/View/bookmarks_actions',
            ], $this->RailCard->rail($railCards, ['bookmark-audience', 'bookmark-others'], 'general')),
        ],
    ]
]);
?>
