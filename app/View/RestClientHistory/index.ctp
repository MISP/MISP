<?php
    $data_container = $bookmarked ? 'rest_client_bookmarks' : 'rest_client_history';
    foreach ($list as $k => $item) {
        $name = '';
        if (!empty($item['RestClientHistory']['bookmark_name'])) {
            $name = sprintf(
                '<span class="bold">%s</span> - ',
                h($item['RestClientHistory']['bookmark_name'])
            );
        }
        $name .= sprintf(
            '%s - %s',
            h($item['RestClientHistory']['http_method']),
            h($item['RestClientHistory']['url'])
        );
        $colour = 'green';
        if (intval($item['RestClientHistory']['outcome']) >= 300) {
            $colour = 'orange';
        }
        if (intval($item['RestClientHistory']['outcome']) >= 400) {
            $colour = 'red';
        }
        echo sprintf(
            '<div title="%s" class="useCursorPointer">(%s) %s %s</div>',
            sprintf(
                "URL: %s\n\nHeaders: %s\n\nBody: %s",
                h($item['RestClientHistory']['url']),
                h($item['RestClientHistory']['headers']),
                h($item['RestClientHistory']['body'])
            ),
            sprintf(
                '<span class="bold %s">%s</span>',
                $colour,
                h($item['RestClientHistory']['outcome'])
            ),
            sprintf(
                '<span onClick="loadRestClientHistory(%s, %s);">%s</span>',
                $k,
                $data_container,
                $name
            ),
            sprintf(
                '<a href="#" class="fa fa-trash black" title="Delete" aria-label="Delete" onclick="removeRestClientHistoryItem(\'%s\');"></a>',
                h($item['RestClientHistory']['id'])
            )
        );
    }
?>
<script type="text/javascript">
    var <?php echo $data_container; ?> = <?php echo json_encode($list); ?>;
</script>
