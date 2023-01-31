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
        '<span id = "%sInfoPopover" class="icon-info-sign" data-bs-toggle="popover" data-bs-trigger="hover"></span>',
        h($field['field'])
    );
?>
<script type="text/javascript">
    $(document).ready(function() {
        new bootstrap.Popover('#<?php echo h($field['field']); ?>InfoPopover', {
            html: true,
            content: function() {
                var tempSelector = '#<?php echo h($modelForForm . \Cake\Utility\Inflector::camelize($field['field'])); ?>';
                if ($(tempSelector)[0].nodeName === "SELECT" && Object.keys(fieldDesc).length > 1) {
                    return $('<div>').append(
                        $('<span>').attr('class', 'blue bold').text($(tempSelector +" option:selected").text())
                    ).append(
                        $('<span>').text(': ' + fieldDesc[$(tempSelector).val()])
                    );
                } else {
                    return $('<div>').append(
                        $('<span>').attr('class', 'blue bold').text('<?php echo h(\Cake\Utility\Inflector::humanize($field['field'])); ?>')
                    ).append(
                        $('<span>').text(": " + fieldDesc["info"])
                    );
                }
            }
        });
        var fieldDesc = <?php echo json_encode($fieldDesc); ?>;
    });
</script>
