<?php
$forSidebar = !empty($forSidebar);

$table = $this->Bootstrap->table([
    'hover' => false,
], [
    'fields' => [
        ['path' => 'label', 'label' => __('Label')],
        ['path' => 'name', 'label' => __('Name')],
        ['path' => 'url', 'label' => __('URL'), 'formatter' => function ($value, $row) {
            return sprintf('<span class="font-monospace">%s</span>', h($value));
        }],
        ['path' => 'action', 'label' => __('Action'), 'formatter' => function ($value, $row, $index) {
            return $this->Bootstrap->button([
                'icon' => 'trash',
                'variant' => 'danger',
                'size' => 'sm',
                'onclick' => sprintf('deleteBookmark(window.bookmarks[%s])', $index),
            ]);
        }],
    ],
    'items' => $bookmarks,
    'caption' => empty($bookmarks) ? __('No bookmark saved') : ''
]);
?>

<?php if (!empty($forSidebar)) : ?>
    <li class="bookmarks">
        <?php foreach ($bookmarks as $parentName => $entry) : ?>
            <?= $this->element('layouts/sidebar/bookmark-entry', [
                'entry' => $entry,
            ])
            ?>
        <?php endforeach; ?>
        <?= $this->element('layouts/sidebar/bookmark-add') ?>
    </li>
<?php else : ?>
    <div class="bookmark-table-container m-2">
        <button class="btn btn-primary mb-2" onclick="openSaveBookmarkModal()">
            <?= __('Create bookmark') ?>
        </button>
        <?= $table ?>
    </div>

    <script>
        window.bookmarks = <?= json_encode($bookmarks) ?>;
    </script>
<?php endif; ?>