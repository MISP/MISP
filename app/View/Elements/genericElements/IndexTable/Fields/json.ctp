<?php
    $data = h(Hash::extract($row, $field['data_path']));
    // I feed dirty for this...
    if (is_array($data) && count($data) === 1 && isset($data[0])) {
        $data = $data[0];
    }
    echo sprintf(
        '<div class="json_container_%s"></div>',
        h($k)
    );
?>
<script type="text/javascript">
$(document).ready(function() {
    $('.json_container_<?php echo h($k);?>').html(syntaxHighlightJson(<?php echo json_encode($data); ?>, 4));
});
</script>
