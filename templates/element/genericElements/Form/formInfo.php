<?php
    $seed = mt_rand();
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
    $popoverID = sprintf("%sInfoPopover%s", h($field['field']), $seed);
    echo $this->Bootstrap->icon('info-circle', [
        'id' => $popoverID,
        'class' => ['ms-1'],
        'attrs' => [
            'data-bs-toggle' => 'popover',
            'data-bs-trigger' => 'hover',
            'data-bs-placement' => 'right',
        ]
    ]);
?>
<script type="text/javascript">
    $(document).ready(function() {
        new bootstrap.Tooltip('#<?= $popoverID ?>', {
            html: true,
            title: function() {
                return $('<div>')
                    .append(
                        $('<span>')
                            .attr('class', 'text-primary fw-bold')
                            .text('<?php echo h(\Cake\Utility\Inflector::humanize($field['field'])); ?>')
                    )
                    .append(
                        $('<span>').text(": <?= h($fieldDesc["info"]) ?>")
                    );
                // var tempSelector = '#<?php echo h($modelForForm . \Cake\Utility\Inflector::camelize($field['field'])); ?>';
                // if ($(tempSelector)[0].nodeName === "SELECT" && Object.keys(fieldDesc).length > 1) {
                //     return $('<div>').append(
                //         $('<span>').attr('class', 'blue bold').text($(tempSelector +" option:selected").text())
                //     ).append(
                //         $('<span>').text(': ' + fieldDesc[$(tempSelector).val()])
                //     );
                // } else {
                //     return $('<div>').append(
                //         $('<span>').attr('class', 'blue bold').text('<?php echo h(\Cake\Utility\Inflector::humanize($field['field'])); ?>')
                //     ).append(
                //         $('<span>').text(": " + fieldDesc["info"])
                //     );
                // }
            }
        });
        // var fieldDesc = <?php echo json_encode($fieldDesc); ?>;
    });
</script>
