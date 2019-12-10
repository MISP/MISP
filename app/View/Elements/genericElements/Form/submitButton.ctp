<?php
    if ($ajax) {
        echo sprintf(
            '%s%s',
            sprintf(
                '<span id="submitButton" class="btn btn-primary" style="margin-bottom:5px;float:left;" title="%s" role="button" tabindex="0" aria-label="%s" onClick="%s">%s</span>',
                __('Submit'),
                __('Submit'),
                $ajaxSubmit,
                __('Submit')
            ),
            sprintf(
                '<span class="btn btn-inverse" style="margin-bottom:5px;float:right;" title="%s" role="button" tabindex="0" aria-label="%s" id="cancel_attribute_add" onClick="%s">%s</span>',
                __('Cancel'),
                __('Cancel'),
                'cancelPopoverForm();',
                __('Cancel')
            )
        );
    } else {
        echo sprintf(
            '<button onClick="%s" class="btn btn-%s">%s</button>',
            sprintf(
                "$('#%s%sForm').submit();",
                h($model),
                h(Inflector::classify($action))
            ),
            empty($type) ? 'primary' : h($type),
            empty($text) ? __('Submit') : h($text)
        );
    }
?>
