<?php
    $data = h(Hash::extract($row, $field['data_path']));
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
