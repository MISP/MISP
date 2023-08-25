<?php
    $randomId = dechex(mt_rand());
    echo sprintf(
        '<pre id="%s">%s</pre>',
        $randomId,
        json_encode($json)
    );
?>

<script type="text/javascript">
$(document).ready(function() {
    $('#<?= $randomId ?>').html(syntaxHighlightJson(<?php echo json_encode($json); ?>, 4));
});
</script>