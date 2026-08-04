<?php
    $randomId = dechex(mt_rand());
    echo sprintf(
        '<pre id="%s">%s</pre>',
        $randomId,
        json_encode($data)
    );f
?>

<script type="text/javascript">
$(document).ready(function() {
    $('#<?= $randomId ?>').html(syntaxHighlightJson(<?php echo json_encode($data); ?>, 4));
});
</script>