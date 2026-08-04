<?php
    $data_container = $bookmarked ? 'rest_client_bookmarks' : 'rest_client_history';
    foreach ($list as $k => $item) {
        $name = '';
        if (!empty($item['bookmark_name'])) {
            $name = sprintf(
                '<span class="bold">%s</span> - ',
                h($item['bookmark_name'])
            );
        }
        $name .= sprintf(
            '%s - %s',
            h($item['http_method']),
            sprintf(
                '<a href="#" onclick="loadRestClientHistory(%s, %s);">%s</a>',
                $k,
                $data_container,
                h($item['url'])
            )
        );
        if (intval($item['outcome']) >= 400) {
            $colour = 'red';
        } else if (intval($item['outcome']) >= 300) {
            $colour = 'orange';
        } else {
            $colour = 'green';
        }
        echo sprintf(
            '<div title="%s" class="useCursorPointer">(%s) %s %s</div>',
            sprintf(
                "URL: %s\n\nHeaders: %s\n\nBody: %s",
                h($item['url']),
                h($item['headers']),
                h($item['body'])
            ),
            sprintf(
                '<span class="bold %s">%s</span>',
                $colour,
                h($item['outcome'])
            ),
            $name,
            sprintf(
                '<a href="#" class="fa fa-trash black" title="Delete" aria-label="Delete" onclick="removeRestClientHistoryItem(\'%s\');"></a>',
                h($item['id'])
            )
        );
    }
?>
<script type="text/javascript">
    var <?php echo $data_container; ?> = <?php echo json_encode($list); ?>;
</script>
