<?php
    $isBookmark = !empty($bookmarked);
    $jsVarName = $isBookmark ? 'bookmarkedQueriesData' : 'historyQueriesData';
?>

<?php if (empty($data)): ?>
    <div class="text-muted small p-3 text-center border rounded bg-light">
        <?= __('No queries found.') ?>
    </div>
<?php else: ?>
    <?php foreach ($data as $k => $item): ?>
        <?php
            $payload = htmlspecialchars(json_encode($item), ENT_QUOTES, 'UTF-8');

            echo $this->element('genericElementsBS5/Cards/card_query', [
                'method' => $item['http_method'],
                'title' => !empty($item['bookmark_name']) ? $item['bookmark_name'] : "#{$item['id']}",
                'url' => $item['url'] ?? '#',
                'id' => $item['id'],
                'favorite' => (!empty($bookmarked)),
                'status' => $item['outcome'],
                'payload' => $payload,
                'onClickAction' => "applyQuery(this)"
            ]);
        ?>
    <?php endforeach; ?>
<?php endif; ?>