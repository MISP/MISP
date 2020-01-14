<?php
    if ($ajax) {
        echo sprintf(
            '%s%s',
            sprintf(
                '<button id="submitButton" class="btn btn-primary" onClick="%s">%s</button>',
                $ajaxSubmit,
                __('Submit')
            ),
            sprintf(
                '<button class="btn" data-dismiss="modal" aria-hidden="true" onClick="%s">%s</button>',
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
