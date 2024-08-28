<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Bookmark view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Name'),
                'path' => 'Bookmark.name',
            ],
            [
                'key' => __('ID'),
                'path' => 'Bookmark.id',
            ],
            [
                'key' => __('URL'),
                'path' => 'Bookmark.url',
            ],
            [
                'key' => __('Comment'),
                'path' => 'Bookmark.comment',
            ],
            [
                'key' => __('Exposed to Organisation'),
                'path' => 'Bookmark.exposed_to_org',
                'type' => 'boolean'
            ],
            [
                'key' => __('User'),
                'path' => 'User.email',
            ],
            [
                'key' => __('Organisation'),
                'path' => 'Organisation',
                'pathName' => 'Bookmark.orgc_id',
                'type' => 'org',
                'model' => 'organisations'
            ],
        ],
    ]
);

?>

<style>
    .restrict-height > div {
        height: 200px;
        overflow: auto;
        resize: both;
    }
</style>
