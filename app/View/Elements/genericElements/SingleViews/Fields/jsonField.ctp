<?php
    $value = Hash::extract($data, $field['path']);
    // I feed dirty for this...
    if (is_array($value) && count($value) === 1 && isset($value[0])) {
        $value = $value[0];
    }
    $containerClassSuffix = Inflector::variable(h($field['key']));
    echo sprintf(
        '<div class="json_container_%s"></div>',
        $containerClassSuffix
    );
    if (is_string($value)) {
        $value = json_decode($value);
    }
?>
<script type="text/javascript">
$(document).ready(function() {
    $('.json_container_<?= $containerClassSuffix ?>').html(syntaxHighlightJson(<?php echo json_encode($value); ?>, 4));
});
</script>
