<?php
/*
 *  Toggle element - a simple checkbox with the current state selected
 *  On click, issues a GET to a given endpoint, retrieving a form with the
 *  value flipped, which is immediately POSTed.
 *  to fetch it.
 *
 */
    $data = Hash::extract($row, $field['data_path']);
    $seed = rand();
    $checkboxId = 'GenericToggle-' . $seed;
    $checkboxClass = empty($field['checkbox_class']) ? 'genericCheckbox' : h($field['checkbox_class']);
    $tempboxId = 'TempBox-' . $seed;
    echo sprintf(
        '<input type="checkbox" id="%s" class="%s" %s><span id="%s" class="hidden">',
        $checkboxId,
        $checkboxClass,
        empty($data[0]) ? '' : 'checked',
        $tempboxId
    );
?>
<script type="text/javascript">
$(function() {
    var url = "<?= h($field['url']) ?>";
    <?php
        if (!empty($field['url_params_data_paths'][0])) {
            $id = Hash::extract($row, $field['url_params_data_paths'][0]);
            echo 'url = url +  "/' . h($id[0]) . '";';
        }
    ?>
    $('#<?= $checkboxId ?>').on('click', function() {
        <?php
            if (!empty($field['beforeHook'])) {
                echo $field['beforeHook'];
            }
        ?>
        $.ajax({
            type: "get",
            url: url,
            error: function() {
                showMessage('fail', '<?= __('Could not retrieve current state.') ?>');
                $('#<?= $checkboxId ?>').prop("checked", false);
            },
            success: function (data) {
                $('#<?= $tempboxId ?>').html(data);
                // Make @mokaddem aka Graphman happy
                var $form = $('#<?= $tempboxId ?>').find('form');
                $.ajax({
                    data: $form.serialize(),
                    cache: false,
                    type:"post",
                    url: $form.attr('action'),
                    success: function() {
                        showMessage('success', '<?= __('Field updated.') ?>');
                    },
                    error: function() {
                        showMessage('fail', '<?= __('Could not update field.') ?>');
                        $('#<?= $checkboxId ?>').prop("checked", false);
                    },
                    complete: function() {
                        $('#<?= $tempboxId ?>').empty();
                        <?php
                            if (!empty($field['afterHook'])) {
                                echo $field['afterHook'];
                            }
                        ?>
                    }
                });
            }
        });
    });
});
</script>
