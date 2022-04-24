<?php
if (!is_array($fieldDesc)) {
    $fieldDesc = [h(Inflector::humanize($field['field'])) => $fieldDesc];
}
echo sprintf(
    ' <span id="%sInfoPopover" class="fas fa-info-circle" data-toggle="popover" data-trigger="hover" data-field-desc="%s"></span>',
    h($field['field']),
    h(json_encode($fieldDesc, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))
);
?>
<script>
    $(function() {
        $('#<?php echo h($field['field']); ?>InfoPopover').popover({
            html: true,
            content: function() {
                var fieldDesc = $(this).data('field-desc');
                var $source = $('#<?php echo h($modelForForm . Inflector::camelize($field['field'])); ?>');
                if ($source[0].nodeName === "SELECT" && Object.keys(fieldDesc).length > 1) {
                    return $('<div>').append(
                        $('<b>').attr('class', 'blue').text($source.find("option:selected").text())
                    ).append(
                        $('<span>').text(': ' + fieldDesc[$source.val()])
                    );
                } else {
                    return $('<div>').append(
                        $('<b>').attr('class', 'blue').text(Object.keys(fieldDesc)[0])
                    ).append(
                        $('<span>').text(": " + Object.values(fieldDesc)[0])
                    );
                }
            }
        });
    });
</script>
