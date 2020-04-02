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
    $tempboxId = 'TempBox-' . $seed;
    echo sprintf(
        '<input type="checkbox" id="%s" %s><span id="%s" class="hidden">',
        $checkboxId,
        empty($data[0]) ? '' : 'checked',
        $tempboxId
    );
?>
<script type="text/javascript">
$(document).ready(function() {
    var url = baseurl + "<?= h($field['url']) ?>";
    <?php
        if (!empty($field['url_params_data_paths'][0])) {
            $id = Hash::extract($row, $field['url_params_data_paths'][0]);
            echo 'url = url +  "/' . h($id[0]) . '";';
        }
    ?>
    $('#<?= $checkboxId ?>').on('click', function() {
        $.ajax({
            type:"get",
            url: url,
            error:function() {
                showMessage('fail', '<?= __('Could not retrieve current state.') ?>.');
            },
            success: function (data, textStatus) {
                $('#<?= $tempboxId ?>').html(data);
                // Make @mokaddem aka Graphman happy
                var $form = $('#<?= $tempboxId ?>').find('form');
                $.ajax({
                    data: $form.serialize(),
                    cache: false,
                    type:"post",
                    url: $form.attr('action'),
                    success:function(data, textStatus) {
                        showMessage('success', '<?= __('Field updated.') ?>.');
                    },
                    error:function() {
                        showMessage('fail', '<?= __('Could not update field.') ?>.');
                    },
                    complete:function() {
                        $('#<?= $tempboxId ?>').empty();
                    }
                });
            }
        });
    });
});
</script>
