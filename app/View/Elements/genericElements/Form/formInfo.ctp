<?php
    if (!is_array($fieldDesc)) {
        $fieldDesc = array('info' => $fieldDesc);
        $default = 'info';
    } else {
        if (!empty($field['options'])) {
            if (isset($this->request->data[$modelForForm][$field['field']])) {
                $default = $this->request->data[$modelForForm][$field['field']];
            } else {
                reset($field['options']);
                $default = key($field['options']);
            }
        } else {
            reset($fieldDesc);
            $fieldDesc = array('info' => key($fieldDesc));
            $default = 'info';
        }
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
                var tempSelector = '#<?php echo h($modelForForm . Inflector::camelize($field['field'])); ?>';
                if ($(tempSelector)[0].nodeName === "SELECT" && Object.keys(fieldDesc).length > 1) {
                    return $('<div>').append(
                        $('<span>').attr('class', 'blue bold').text($(tempSelector +" option:selected").text())
                    ).append(
                        $('<span>').text(': ' + fieldDesc[$(tempSelector).val()])
                    );
                } else {
                    return $('<div>').append(
                        $('<span>').attr('class', 'blue bold').text('<?php echo h(Inflector::humanize($field['field'])); ?>')
                    ).append(
                        $('<span>').text(": " + fieldDesc["info"])
                    );
                }
            }
        });
    });
</script>
