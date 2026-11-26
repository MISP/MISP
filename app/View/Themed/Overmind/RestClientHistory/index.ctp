<?php
$isBookmark = !empty($bookmarked);
?>
<?php if (empty($data)): ?>
    <div class="text-center text-body-secondary small p-4">
        <?= $isBookmark ? __('No bookmarks yet. Use the star next to Send.') : __('No queries yet.') ?>
    </div>
<?php else: ?>
    <?php foreach ($data as $item): ?>
        <?= $this->element('Api/View/endpoint_row', [
            'kind' => 'query',
            'method' => $item['http_method'],
            'url' => $item['url'] ?? '',
            'title' => $isBookmark ? ($item['bookmark_name'] ?: '#' . $item['id']) : null,
            'bookmark' => !$isBookmark && !empty($item['bookmark']),
            'status' => $item['outcome'],
            'timestamp' => $item['timestamp'],
            'id' => $item['id'],
            'payload' => $item,
        ]) ?>
    <?php endforeach; ?>
<?php endif; ?>
