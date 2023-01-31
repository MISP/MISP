<?php
    $random = Cake\Utility\Security::randomString(8);
    $params['div'] = false;
    $this->Form->setTemplates([
        'inputContainer' => '{{content}}',
        'inputContainerError' => '{{content}}',
        'formGroup' => '{{input}}',
    ]);
    $label = $fieldData['label'];
    $formElement = $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
    $temp = sprintf(
        '<div class="row mb-3">
            <div class="col-sm-2 form-label">%s</div>
            <div class="col-sm-10">
                <div class="input-group">
                    %s<span>%s</span>
                </div>
            </div>
        </div>',
        h($label),
        $formElement,
        sprintf(
            '<span id="uuid-gen-%s" class="btn btn-secondary">%s</span>',
            $random,
            __('Generate')
        )
    );
    echo $temp;
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#uuid-gen-<?= h($random) ?>').on('click', function() {
            $.ajax({
                success:function (data, textStatus) {
                    $('#uuid-field').val(data["uuid"]);
                },
                type: "get",
                cache: false,
                url: "/organisations/generateUUID",
            });
        });
    });
</script>
